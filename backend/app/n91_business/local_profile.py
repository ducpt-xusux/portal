"""Operator-only conversion of an existing local store to one full-access account.

Preserves password verifiers, account IDs and audit history. Never called by API.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .config import BusinessConfig
from .models import READ_ROLES
from .service import BusinessService, user_view


def configure(service, username):
    if not service.config.allow_insecure_loopback or service.config.single_account_username != username:
        raise ValueError('Requires the explicit local single-account profile')
    with service.connection(write=True) as db:
        rows = db.execute('SELECT * FROM users ORDER BY username').fetchall()
        owner = next((row for row in rows if row['username'] == username), None)
        if not owner or not owner['portal_admin'] or not owner['active']:
            raise ValueError('The retained account must be an existing active Portal administrator')
        if any(row['username'] not in {username, 'lab-viewer', 'lab-executor'} and row['active'] for row in rows):
            raise ValueError('Unexpected active account; review the store before conversion')
        roles = sorted(READ_ROLES)
        for row in rows:
            active = row['username'] == username
            target_roles = roles if active else json.loads(row['roles'])
            if bool(row['active']) != active or json.loads(row['roles']) != target_roles:
                before = user_view(row)
                db.execute('UPDATE users SET roles=?,active=?,version=version+1 WHERE user_id=?',
                           (json.dumps(target_roles), int(active), row['user_id']))
                after = user_view(db.execute('SELECT * FROM users WHERE user_id=?', (row['user_id'],)).fetchone())
                service._audit(db, owner['user_id'], 'LOCAL_SINGLE_ACCOUNT_CONFIGURE', row['user_id'],
                               'operator-local-profile', before, after)
            if not active:
                db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (row['user_id'],))
        return [user_view(row) for row in db.execute('SELECT * FROM users ORDER BY username')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--username', required=True)
    args = parser.parse_args()
    path = args.database.resolve(strict=True)
    config = BusinessConfig(database_path=path, secure_cookie=False, allow_insecure_loopback=True,
                            single_account_username=args.username)
    service = BusinessService(config)
    # Validate ownership before making a private backup beside the original store.
    with service.connection():
        pass
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = path.with_name(path.stem + '-before-single-account-' + stamp + path.suffix)
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as source, sqlite3.connect(backup) as dest:
        source.backup(dest)
    rows = configure(service, args.username)
    print(json.dumps({'backup': str(backup), 'accounts': [
        {'username': row['username'], 'active': row['active']} for row in rows]}))


if __name__ == '__main__':
    main()
