"""Outer ASGI session boundary. Install after all shared middleware, before serving.

No header role, loopback exemption, API-key fallback or WebSocket bypass.
"""
import hmac
import json
from pathlib import Path
import re
from uuid import uuid4
from starlette.requests import Request
from starlette.responses import JSONResponse
from .models import READ_ROLES, WRITE_ROLES, EVIDENCE_ROLES
from .service import BusinessError, iso


INCIDENT_WRITE_POLICIES = (
    ('POST', '/api/v1/incidents/{id}/review', 'write'),
    ('POST', '/api/v1/incidents/{id}/evidence/exports', 'evidence'),
)


def envelope(request, service, data=None, code=None):
    request_id = getattr(request.state, 'request_id', str(uuid4()))
    return {'data': data, 'meta': {'request_id': request_id, 'read_at': iso(service.clock()),
        'source_system': 'PORTAL_BUSINESS', 'source_schema': 'n91-business-v1',
        'freshness_state': 'UNAVAILABLE' if code else 'FRESH', 'sources': [],
        'coverage_note': service.config.context + ' local Portal records only; no source status mutation.'},
        'error': {'code': code, 'message': 'Portal session, permission or data unavailable.', 'request_id': request_id} if code else None}


def trusted_roles(request):
    """Inject into evidence router. Missing gate state raises, never falls back to local owner."""
    actor = getattr(request.state, 'business_principal', None)
    if actor is None:
        raise BusinessError(401, 'SESSION_REQUIRED')
    return actor.roles


def _pattern(path):
    return re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(path)) + '$')


class SessionGate:
    def __init__(self, app, service, *, extra_policies=()):
        self.app, self.service = app, service
        policies = json.loads((Path(__file__).parent/'frozen_policies.json').read_text())['policies']
        # Extra policies require server-side code review; client input cannot alter them.
        policies += [list(p) for p in (*INCIDENT_WRITE_POLICIES, *extra_policies)]
        policies.sort(key=lambda row: (row[1].count('{'), -len(row[1])))
        self.policies = [(method, _pattern(path), permission) for method, path, permission in policies]

    def permission(self, method, path):
        for verb, pattern, permission in self.policies:
            if method == verb and pattern.fullmatch(path):
                return permission
        return None

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            return await self.app(scope, receive, send)
        if scope['type'] == 'websocket':
            # Current application has no session-aware websocket protocol.
            return await send({'type': 'websocket.close', 'code': 1008})
        if scope['type'] != 'http':
            return
        scope.setdefault('state', {})['request_id'] = str(uuid4())
        request = Request(scope)
        request.state.business_gate_service = self.service
        path, method = scope['path'], scope['method']
        config = self.service.config

        async def guarded_send(message):
            if message['type'] == 'http.response.start':
                headers = [(k,v) for k,v in message.get('headers', []) if k.lower() not in
                           {b'cache-control', b'x-request-id', b'x-content-type-options', b'x-frame-options'}]
                headers += [(b'cache-control', b'no-store'), (b'x-request-id', request.state.request_id.encode()),
                            (b'x-content-type-options', b'nosniff'), (b'x-frame-options', b'DENY'),
                            (b'referrer-policy', b'no-referrer')]
                if path.startswith('/api'):
                    headers.append((b'content-security-policy', b"default-src 'none'; frame-ancestors 'none'"))
                if scope.get('scheme') == 'https':
                    headers.append((b'strict-transport-security', b'max-age=31536000'))
                message = {**message, 'headers': headers}
            await send(message)

        async def denied(status, code):
            headers = {'Retry-After': '300'} if status == 429 else None
            response = JSONResponse(envelope(request, self.service, code=code), status_code=status, headers=headers)
            await response(scope, receive, guarded_send)

        try:
            if method == 'GET' and path in {'/health', '/healthz', '/api/v1/portal/access-mode'}:
                return await self.app(scope, receive, guarded_send)
            # HTTPS uses actual ASGI scheme. Proxy headers must only be trusted from a pinned proxy.
            if not config.secure_cookie and scope.get('client', ('',0))[0] not in {'127.0.0.1','::1'}:
                raise BusinessError(403,'LOCAL_AUTH_ONLY')
            if scope.get('scheme') != 'https':
                peer = scope.get('client', ('', 0))[0]
                if not config.allow_insecure_loopback or peer not in {'127.0.0.1', '::1'}:
                    raise BusinessError(403, 'HTTPS_REQUIRED')
            login = method == 'POST' and path == '/api/v1/auth/login'
            actor = None if login else self.service.authenticate(request.cookies.get(config.cookie_name))
            if actor:
                request.state.business_principal = actor
            # Every current/future non-public route is covered, including /api legacy and console.
            if not login:
                if re.search(r'(?:^|/)console(?:/|$)', path) or (path.startswith('/api/v1/actions') and method not in {'GET', 'HEAD'}):
                    raise BusinessError(403, 'FEATURE_DISABLED')
                permission = self.permission(method, path)
                if permission == 'disabled':
                    raise BusinessError(403, 'FEATURE_DISABLED')
                if permission is None:
                    raise BusinessError(403, 'ROUTE_POLICY_UNMAPPED')
                permitted = (actor.portal_admin if permission == 'admin' else
                    bool(set(actor.roles).intersection({'Auditor'})) or actor.portal_admin if permission == 'audit' else
                    bool(set(actor.roles).intersection(WRITE_ROLES)) if permission == 'write' else
                    bool(set(actor.roles).intersection(EVIDENCE_ROLES)) if permission == 'evidence' else
                    bool(set(actor.roles).intersection(READ_ROLES)) if permission in {'read', 'session'} else False)
                if not permitted:
                    raise BusinessError(403, 'ROLE_REQUIRED')
            if method not in {'GET', 'HEAD', 'OPTIONS'}:
                if request.headers.get('origin') not in config.trusted_origins:
                    raise BusinessError(403, 'CSRF_ORIGIN_REQUIRED')
                if actor and not hmac.compare_digest(request.headers.get('x-csrf-token', '').encode(), actor.csrf_token.encode()):
                    raise BusinessError(403, 'CSRF_INVALID')
                if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                    raise BusinessError(422, 'JSON_REQUIRED')
                body = bytearray()
                while True:
                    part = await receive()
                    if part['type'] == 'http.disconnect':
                        return
                    body.extend(part.get('body', b''))
                    if len(body) > config.body_limit:
                        raise BusinessError(413, 'BODY_TOO_LARGE')
                    if not part.get('more_body'):
                        break
                delivered = False
                original_receive = receive
                async def replay():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                    return await original_receive()
                receive = replay
        except BusinessError as exc:
            return await denied(exc.status, exc.code)
        return await self.app(scope, receive, guarded_send)
