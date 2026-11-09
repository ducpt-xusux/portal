"""SQLite Portal overlay service. Has no P17, P16H or cloud clients."""
from contextlib import contextmanager
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from uuid import uuid4

from .config import BusinessConfig
from .models import Principal, Role, SourceRef, READ_ROLES, WRITE_ROLES, EVIDENCE_ROLES
from .privacy import plain_text


class BusinessError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def iso(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise BusinessError(422, 'PASSWORD_POLICY')
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64*1024*1024)
    return 'scrypt-v1$' + salt.hex() + '$' + derived.hex()


def verify_password(password, encoded):
    try:
        version, salt, expected = encoded.split('$')
        if version != 'scrypt-v1' or len(salt) != 32 or len(expected) != 128:
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=64*1024*1024)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def roles_checked(roles):
    if not roles or len(roles) > 6 or any(r not in READ_ROLES for r in roles) or len(set(roles)) != len(roles):
        raise BusinessError(422, 'INVALID_ROLES')
    return sorted(roles)


def user_view(row):
    return {'user_id': row['user_id'], 'username': row['username'], 'roles': json.loads(row['roles']),
            'active': bool(row['active']), 'version': row['version']}


class BusinessService:
    def __init__(self, config: BusinessConfig, *, source_resolver=None, clock=time.time):
        self.config, self.source_resolver, self.clock = config, source_resolver, clock
        self._dummy = password_hash(secrets.token_urlsafe(24))

    @contextmanager
    def connection(self, write=False):
        path = self.config.database_path
        if path is None or not Path(path).is_file():
            raise BusinessError(503, 'BUSINESS_STORE_UNAVAILABLE')
        try:
            # Never create a database during a request; initialize is operator-only.
            db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=rw', uri=True, timeout=2)
            db.row_factory = sqlite3.Row
            try:
                db.execute('PRAGMA foreign_keys=ON')
                marker = dict(db.execute('SELECT key,value FROM business_meta'))
                if marker != {'owner': 'n91-business-v1', 'context': self.config.context, 'schema': '1'}:
                    raise BusinessError(503, 'BUSINESS_STORE_CONTEXT_MISMATCH')
                if write:
                    db.execute('BEGIN IMMEDIATE')
                else:
                    db.execute('PRAGMA query_only=ON')
                yield db
                if write:
                    db.commit()
            except Exception:
                if write:
                    db.rollback()
                raise
            finally:
                db.close()
        except sqlite3.Error:
            raise BusinessError(503, 'BUSINESS_STORE_UNAVAILABLE') from None

    def initialize(self):
        """Explicit operator action. Refuses existing foreign databases, even empty schemas."""
        path = self.config.database_path
        if path is None:
            raise BusinessError(503, 'BUSINESS_STORE_UNAVAILABLE')
        path = Path(path)
        if path.exists():
            with self.connection():
                return
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create prevents racing with another file/database owner.
        with path.open('xb'):
            pass
        try:
            with sqlite3.connect(path) as db:
                db.executescript('BEGIN IMMEDIATE;\n' + (Path(__file__).parent / 'migrations/001_business.sql').read_text())
                db.executemany('INSERT INTO business_meta VALUES (?,?)', [
                    ('owner', 'n91-business-v1'), ('context', self.config.context), ('schema', '1')])
                db.execute('INSERT INTO cursor_key VALUES(1,?)', (secrets.token_hex(32),))
                db.commit()
        except sqlite3.Error:
            raise BusinessError(503, 'BUSINESS_STORE_UNAVAILABLE') from None

    def _audit(self, db, actor_id, action, target, request_id, before=None, after=None, outcome='SUCCESS'):
        db.execute('INSERT INTO admin_audit(audit_id,actor_id,action,target_ref,outcome,timestamp,request_id,before_json,after_json) '
                   'VALUES (?,?,?,?,?,?,?,?,?)', (str(uuid4()), actor_id, action, target, outcome,
                   iso(self.clock()), request_id, json.dumps(before) if before is not None else None,
                   json.dumps(after) if after is not None else None))

    def bootstrap(self, username, password, roles, *, portal_admin=False):
        """Operator-only CLI; API never calls this. First account only, no default identity."""
        if not re.fullmatch(r'[a-z][a-z0-9_.-]{2,63}', username):
            raise BusinessError(422, 'INVALID_USERNAME')
        roles = roles_checked(roles)
        encoded = password_hash(password)
        with self.connection(True) as db:
            if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise BusinessError(409, 'BOOTSTRAP_ALREADY_COMPLETED')
            user_id = str(uuid4())
            db.execute('INSERT INTO users(user_id,username,password_hash,roles,portal_admin,created_at) VALUES (?,?,?,?,?,?)',
                       (user_id, username, encoded, json.dumps(roles), int(portal_admin), iso(self.clock())))
            self._audit(db, 'OPERATOR_CLI', 'USER_BOOTSTRAP', user_id, 'operator-cli', after={'roles': roles, 'active': True,
                        'portal_admin': bool(portal_admin)})
            return user_id

    def _rate(self, username, peer):
        now = int(self.clock())
        limited = False
        with self.connection(True) as db:
            db.execute('DELETE FROM login_limits WHERE start<=?', (now-300,))
            buckets = [('global', 100), ('ip:' + digest(peer), 20), ('user:' + digest(username), 10)]
            for bucket, maximum in buckets:
                if limited:
                    break
                row = db.execute('SELECT attempts FROM login_limits WHERE bucket=?', (bucket,)).fetchone()
                attempts = (row['attempts'] if row else 0) + 1
                db.execute('INSERT INTO login_limits VALUES (?,?,?) ON CONFLICT(bucket) DO UPDATE SET attempts=excluded.attempts',
                           (bucket, now, attempts))
                limited = limited or attempts > maximum
        if limited:
            raise BusinessError(429, 'LOGIN_RATE_LIMITED')

    def login(self, username, password, peer, request_id):
        self._rate(username, peer)
        with self.connection() as db:
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        valid = verify_password(password, user['password_hash'] if user else self._dummy)
        if not valid or not user or not user['active']:
            # Unknown account names are not persisted; no password/token in audit.
            with self.connection(True) as db:
                self._audit(db, 'UNAUTHENTICATED', 'LOGIN', None, request_id, outcome='DENIED')
            raise BusinessError(401, 'INVALID_CREDENTIALS')
        token = secrets.token_urlsafe(32)
        now = int(self.clock())
        with self.connection(True) as db:
            current = db.execute('SELECT * FROM users WHERE user_id=?', (user['user_id'],)).fetchone()
            if not current['active'] or current['version'] != user['version']:
                raise BusinessError(401, 'INVALID_CREDENTIALS')
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,0)', (digest(token), user['user_id'], now, now+self.config.session_seconds))
            self._audit(db, user['user_id'], 'LOGIN', user['user_id'], request_id)
        return token, self.authenticate(token)

    def _session_row(self, db, hashed):
        row = db.execute('SELECT u.*,s.expires_at,s.revoked FROM sessions s JOIN users u ON s.user_id=u.user_id WHERE s.token_hash=?',
                         (hashed,)).fetchone()
        if row is None or row['revoked'] or not row['active'] or row['expires_at'] <= self.clock():
            raise BusinessError(401, 'SESSION_REQUIRED')
        return row

    def authenticate(self, token):
        if not token or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise BusinessError(401, 'SESSION_REQUIRED')
        with self.connection() as db:
            row = self._session_row(db, digest(token))
            roles = tuple(roles_checked(json.loads(row['roles'])))
            return Principal(row['user_id'], row['username'], roles, bool(row['portal_admin']), row['expires_at'],
                             digest('n91-csrf-v1:' + token), digest(token))

    def _actor(self, db, actor, required):
        row = self._session_row(db, actor.session_hash)
        if row['user_id'] != actor.user_id:
            raise BusinessError(401, 'SESSION_REQUIRED')
        roles = set(json.loads(row['roles']))
        if required == 'admin':
            allowed = bool(row['portal_admin'])
        elif required == 'audit':
            allowed = 'Auditor' in roles or bool(row['portal_admin'])
        elif required == 'write':
            allowed = bool(roles.intersection(WRITE_ROLES))
        elif required == 'evidence':
            allowed = bool(roles.intersection(EVIDENCE_ROLES))
        else:
            allowed = bool(roles.intersection(READ_ROLES))
        if not allowed:
            raise BusinessError(403, 'ROLE_REQUIRED')

    def logout(self, actor, request_id):
        with self.connection(True) as db:
            self._actor(db, actor, 'read')
            db.execute('UPDATE sessions SET revoked=1 WHERE token_hash=?', (actor.session_hash,))
            self._audit(db, actor.user_id, 'LOGOUT', actor.user_id, request_id)

    def resolve(self, kind, object_id, stream_id=None):
        if self.source_resolver is None:
            raise BusinessError(503, 'SOURCE_REFERENCE_UNAVAILABLE')
        try:
            ref = self.source_resolver(kind, object_id, stream_id)
        except BusinessError:
            raise
        except Exception:
            raise BusinessError(503, 'SOURCE_REFERENCE_UNAVAILABLE') from None
        if ref is None:
            raise BusinessError(404, 'SOURCE_OBJECT_NOT_FOUND')
        if (not isinstance(ref, SourceRef) or ref.kind != kind or ref.object_id != object_id or not ref.stream_id
                or (stream_id is not None and stream_id != ref.stream_id)):
            raise BusinessError(503, 'SOURCE_REFERENCE_INVALID')
        if (ref.execution_mode == 'TEST') != (self.config.context == 'TEST'):
            raise BusinessError(409, 'SOURCE_CONTEXT_MISMATCH')
        if ref.execution_mode not in {'LIVE', 'HISTORICAL', 'STAGING', 'ISOLATED', 'TEST'}:
            raise BusinessError(503, 'SOURCE_REFERENCE_INVALID')
        return ref

    @staticmethod
    def _key(ref):
        return (ref.kind, ref.object_id, ref.stream_id, ref.execution_mode)

    def _overlay(self, db, ref):
        row = db.execute('SELECT * FROM overlays WHERE kind=? AND object_id=? AND stream_id=? AND execution_mode=?', self._key(ref)).fetchone()
        if row:
            result = dict(row)
            result['acknowledged'] = bool(result['acknowledged'])
        else:
            result = dict(zip(('kind', 'object_id', 'stream_id', 'execution_mode'), self._key(ref)))
            result.update(review_state='UNREAD', acknowledged=False, assignee_id=None, priority='UNSET', version=0,
                          updated_at=None, actor_id=None)
        return {**result, 'owner': 'PORTAL_ANNOTATION', 'source_status_changed': False}

    def overlay(self, actor, ref):
        with self.connection() as db:
            self._actor(db, actor, 'read')
            return self._overlay(db, ref)

    def _idempotent(self, db, actor, key, scope, payload, mutate):
        if not key or not re.fullmatch(r'[A-Za-z0-9_.:-]{16,128}', key):
            raise BusinessError(422, 'IDEMPOTENCY_KEY_REQUIRED')
        key_hash = digest(key)
        fingerprint = digest(json.dumps([scope, payload], sort_keys=True, separators=(',', ':')))
        previous = db.execute('SELECT * FROM idempotency WHERE actor_id=? AND key_hash=?', (actor.user_id, key_hash)).fetchone()
        if previous:
            if not hmac.compare_digest(previous['fingerprint'], fingerprint):
                raise BusinessError(409, 'IDEMPOTENCY_CONFLICT')
            return json.loads(previous['result_json'])
        result = mutate()
        db.execute('INSERT INTO idempotency VALUES (?,?,?,?,?)',
                   (actor.user_id, key_hash, fingerprint, json.dumps(result), iso(self.clock())))
        return result

    def triage(self, actor, ref, payload, key, request_id):
        with self.connection(True) as db:
            self._actor(db, actor, 'write')
            def mutate():
                before = self._overlay(db, ref)
                if before['version'] != payload['version']:
                    raise BusinessError(409, 'VERSION_CONFLICT')
                assignee = payload.get('assignee_id')
                if assignee:
                    assigned = db.execute('SELECT roles,active FROM users WHERE user_id=?', (assignee,)).fetchone()
                    if not assigned or not assigned['active'] or not set(json.loads(assigned['roles'])).intersection(WRITE_ROLES):
                        raise BusinessError(422, 'ASSIGNEE_NOT_ELIGIBLE')
                version = before['version'] + 1
                db.execute('INSERT INTO overlays VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,object_id,stream_id,execution_mode) '
                           'DO UPDATE SET review_state=excluded.review_state,acknowledged=excluded.acknowledged,assignee_id=excluded.assignee_id,'
                           'priority=excluded.priority,version=excluded.version,updated_at=excluded.updated_at,actor_id=excluded.actor_id',
                           (*self._key(ref), payload['review_state'], int(payload['acknowledged']),
                            assignee, payload.get('priority', 'UNSET'), version, iso(self.clock()), actor.user_id))
                after = self._overlay(db, ref)
                self._audit(db, actor.user_id, 'PORTAL_TRIAGE', ':'.join(self._key(ref)), request_id, before, after)
                return after
            return self._idempotent(db, actor, key, ['triage', self._key(ref)], payload, mutate)

    def add_note(self, actor, ref, note, key, request_id):
        try:
            note = plain_text(note)
        except ValueError:
            raise BusinessError(422, 'NOTE_CONTENT_REJECTED') from None
        with self.connection(True) as db:
            self._actor(db, actor, 'write')
            def mutate():
                result = {'note_id': str(uuid4()), 'incident_id': ref.object_id, 'note': note,
                          'actor_id': actor.user_id, 'created_at': iso(self.clock())}
                db.execute('INSERT INTO notes VALUES (?,?,?,?,?,?,?)', (result['note_id'], ref.object_id,
                    ref.stream_id, ref.execution_mode, note, actor.user_id, result['created_at']))
                # Audit contains identity and note reference, not duplicated free text.
                self._audit(db, actor.user_id, 'NOTE_ADD', ':'.join(self._key(ref)), request_id,
                            after={'note_id': result['note_id'], 'note_length': len(note)})
                return result
            # Frozen notes has no idempotency header; optional extension is safe.
            return self._idempotent(db, actor, key, ['note', self._key(ref)], note, mutate) if key else mutate()

    def notes(self, actor, ref, limit=25, after=0):
        with self.connection() as db:
            self._actor(db, actor, 'evidence')
            rows = db.execute('SELECT note_id,incident_id,note,actor_id,created_at FROM notes '
                'WHERE incident_id=? AND stream_id=? AND execution_mode=? ORDER BY rowid LIMIT ? OFFSET ?',
                (ref.object_id, ref.stream_id, ref.execution_mode, limit, after)).fetchall()
            return [dict(row) for row in rows]

    def users(self, actor, limit=25, after=0, assignees=False):
        with self.connection() as db:
            self._actor(db, actor, 'write' if assignees else 'admin')
            if assignees:
                rows = db.execute("SELECT user_id,username FROM users WHERE active=1 AND (roles LIKE '%\"Analyst\"%' OR roles LIKE '%\"Operator\"%') ORDER BY rowid LIMIT ? OFFSET ?", (limit,after)).fetchall()
                return [dict(row) for row in rows]
            rows = db.execute('SELECT * FROM users ORDER BY rowid LIMIT ? OFFSET ?', (limit, after)).fetchall()
            return [user_view(row) for row in rows]

    def create_user(self, actor, payload, key, request_id):
        roles = roles_checked(payload['roles'])
        encoded = password_hash(payload['password'])
        safe_payload = {**payload, 'password': digest(payload['password'])}
        with self.connection(True) as db:
            self._actor(db, actor, 'admin')
            def mutate():
                if db.execute('SELECT 1 FROM users WHERE username=?', (payload['username'],)).fetchone():
                    raise BusinessError(409, 'USER_EXISTS')
                user_id = str(uuid4())
                db.execute('INSERT INTO users(user_id,username,password_hash,roles,created_at) VALUES (?,?,?,?,?)',
                           (user_id, payload['username'], encoded, json.dumps(roles), iso(self.clock())))
                result = user_view(db.execute('SELECT * FROM users WHERE user_id=?', (user_id,)).fetchone())
                self._audit(db, actor.user_id, 'USER_CREATE', user_id, request_id, after=result)
                return result
            return self._idempotent(db, actor, key, ['create_user'], safe_payload, mutate)

    def update_user(self, actor, user_id, payload, key, request_id):
        roles = roles_checked(payload['roles'])
        with self.connection(True) as db:
            self._actor(db, actor, 'admin')
            def mutate():
                row = db.execute('SELECT * FROM users WHERE user_id=?', (user_id,)).fetchone()
                if not row:
                    raise BusinessError(404, 'USER_NOT_FOUND')
                if row['version'] != payload['version']:
                    raise BusinessError(409, 'VERSION_CONFLICT')
                if row['portal_admin']:
                    raise BusinessError(403, 'OPERATOR_ACCOUNT_PROTECTED')
                before = user_view(row)
                db.execute('UPDATE users SET roles=?,active=?,version=version+1 WHERE user_id=?',
                           (json.dumps(roles), int(payload['active']), user_id))
                db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (user_id,))
                after = user_view(db.execute('SELECT * FROM users WHERE user_id=?', (user_id,)).fetchone())
                self._audit(db, actor.user_id, 'USER_UPDATE', user_id, request_id, before, after)
                return after
            return self._idempotent(db, actor, key, ['update_user', user_id], payload, mutate)

    def audit(self, actor, limit=25, after=0, *, extended=False):
        with self.connection() as db:
            self._actor(db, actor, 'audit')
            rows = db.execute('SELECT * FROM admin_audit WHERE seq>? ORDER BY seq LIMIT ?', (after, limit)).fetchall()
            result = []
            for row in rows:
                item = {key: row[key] for key in ('audit_id','actor_id','action','target_ref','outcome','timestamp','request_id')}
                item['source_ref'] = None
                if extended:
                    item.update(sequence=row['seq'], before=json.loads(row['before_json']) if row['before_json'] else None,
                                after=json.loads(row['after_json']) if row['after_json'] else None)
                result.append(item)
            return result

    def cursor(self, actor, scope, offset=None, token=None):
        """Signed, actor/scope/context-bound cursor; signing secret never leaves own DB."""
        with self.connection() as db:
            self._actor(db, actor, 'read')
            secret = bytes.fromhex(db.execute('SELECT secret FROM cursor_key WHERE singleton=1').fetchone()[0])
        binding = digest(json.dumps([actor.user_id, scope, self.config.context], sort_keys=True))
        if token is None:
            raw = json.dumps({'v':1, 'scope':binding, 'after':offset, 'exp':int(self.clock())+600}, separators=(',',':')).encode()
            encoded = base64.urlsafe_b64encode(raw).rstrip(b'=')
            return (encoded+b'.'+hmac.new(secret,encoded,hashlib.sha256).hexdigest().encode()).decode()
        try:
            encoded,signature=token.encode().split(b'.')
            if not hmac.compare_digest(signature,hmac.new(secret,encoded,hashlib.sha256).hexdigest().encode()):
                raise ValueError()
            data=json.loads(base64.b64decode(encoded+b'='*(-len(encoded)%4),altchars=b'-_',validate=True))
            if data['v']!=1 or data['scope']!=binding or data['exp']<=self.clock() or type(data['after']) is not int or not 0<=data['after']<=100_000:
                raise ValueError()
            return data['after']
        except (ValueError,KeyError,TypeError,UnicodeError):
            raise BusinessError(422,'INVALID_CURSOR') from None
