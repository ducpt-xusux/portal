from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.main import create_app
from app.n91_business import BusinessConfig
from app.n91_business.service import BusinessService

VM = '12345678-1234-4321-8321-123456789abc'
ORIGIN = 'http://127.0.0.1:5173'


@pytest.mark.parametrize('role,expected', [('Viewer', 403), ('Analyst', 403), ('Executor', 200)])
def test_real_session_role_and_csrf_gate_precede_cloud_mutation(tmp_path, role, expected):
    config = BusinessConfig(database_path=tmp_path / 'TEST-business.db', secure_cookie=False,
        allow_insecure_loopback=True, trusted_origins=(ORIGIN,))
    service = BusinessService(config)
    service.initialize()
    service.bootstrap('test-user', 'TEST-password-12345', [role])
    settings = Settings(tmp_path / 'audit', tmp_path / 'cache.db', session_auth_enabled=True)
    app = create_app(settings, business_config=config)
    calls = []

    def quarantine(server, actor, request_id):
        calls.append((server, actor.roles))
        return {'state': 'QUARANTINED'}

    fake = SimpleNamespace(cloud=SimpleNamespace(require_allowed=lambda value: None,
        allows_target=lambda value: False), quarantine=quarantine)
    route = f'/api/v1/workloads/{VM}/quarantine'
    with TestClient(app, client=('127.0.0.1', 1)) as client:
        app.state.quarantine_recovery, app.state.quarantine_ready = fake, True
        assert client.post(route, json={'confirm': 'QUARANTINE'}).status_code == 401
        assert client.post('/api/v1/auth/login', headers={'Origin': ORIGIN}, json={
            'username': 'test-user', 'password': 'wrong'}).status_code == 401
        login = client.post('/api/v1/auth/login', headers={'Origin': ORIGIN}, json={
            'username': 'test-user', 'password': 'TEST-password-12345'})
        assert login.status_code == 200
        assert 'HttpOnly' in login.headers['set-cookie'] and 'SameSite=strict' in login.headers['set-cookie']
        csrf = login.json()['data']['csrf_token']
        assert client.post(route, headers={'Origin': ORIGIN}, json={'confirm': 'QUARANTINE'}).status_code == 403
        assert client.post(route, headers={'Origin': 'http://other.test', 'X-CSRF-Token': csrf}, json={'confirm': 'QUARANTINE'}).status_code == 403
        result = client.post(route, headers={'Origin': ORIGIN, 'X-CSRF-Token': csrf}, json={'confirm': 'QUARANTINE'})
        assert result.status_code == expected
        assert len(calls) == (1 if expected == 200 else 0)
        assert client.post('/api/v1/auth/logout', headers={'Origin': ORIGIN, 'X-CSRF-Token': csrf}, json={}).status_code == 200
        assert client.get('/api/v1/auth/me').status_code == 401


def test_two_local_workers_cannot_change_same_business_store_concurrently(tmp_path):
    from app.quarantine_recovery import QuarantineRecovery
    from app.workload_quarantine import QuarantineError
    config = BusinessConfig(database_path=tmp_path / 'TEST-business.db')
    service = BusinessService(config)
    service.initialize()
    cloud = SimpleNamespace(settings=None)
    first = QuarantineRecovery(cloud, service, None)
    second = QuarantineRecovery(cloud, service, None)
    with first.exclusive():
        with pytest.raises(QuarantineError, match='QUARANTINE_BUSY'):
            with second.exclusive():
                pytest.fail('Concurrent recovery lock must not be acquired')
    with second.exclusive():
        pass


def test_single_account_profile_preserves_passwords_revokes_lab_sessions_and_retains_audit(tmp_path):
    import json
    from app.n91_business.local_profile import configure
    from app.n91_business.models import READ_ROLES
    from app.n91_business.service import BusinessError
    path = tmp_path / 'TEST-business.db'
    normal = BusinessService(BusinessConfig(database_path=path, secure_cookie=False, allow_insecure_loopback=True))
    normal.initialize()
    normal.bootstrap('portal-admin', 'TEST-admin-password-12345', ['Analyst'], portal_admin=True)
    token, actor = normal.login('portal-admin', 'TEST-admin-password-12345', '127.0.0.1', 'TEST-login')
    lab = normal.create_user(actor, {'username': 'lab-viewer', 'password': 'TEST-viewer-password-12345', 'roles': ['Viewer']},
                             'TEST-create-lab-account-1', 'TEST-create')
    lab_token, _ = normal.login('lab-viewer', 'TEST-viewer-password-12345', '127.0.0.1', 'TEST-lab-login')
    single = BusinessService(BusinessConfig(database_path=path, secure_cookie=False, allow_insecure_loopback=True,
                                            single_account_username='portal-admin'))
    with normal.connection() as db:
        hashes = {row['username']: row['password_hash'] for row in db.execute('SELECT * FROM users')}
    rows = configure(single, 'portal-admin')
    assert [row['username'] for row in rows if row['active']] == ['portal-admin']
    current = single.authenticate(token)
    assert set(current.roles) == set(READ_ROLES) and current.portal_admin
    with single.connection() as db:
        assert hashes == {row['username']: row['password_hash'] for row in db.execute('SELECT * FROM users')}
        assert db.execute("SELECT COUNT(*) FROM admin_audit WHERE action='LOCAL_SINGLE_ACCOUNT_CONFIGURE'").fetchone()[0] == 2
        # Simulate an operator mistakenly enabling the old account: profile still rejects its existing session/login.
        db_count = db.execute('SELECT COUNT(*) FROM admin_audit').fetchone()[0]
    with pytest.raises(BusinessError, match='SESSION_REQUIRED'):
        single.authenticate(lab_token)
    with single.connection(write=True) as db:
        db.execute('UPDATE users SET active=1 WHERE user_id=?', (lab['user_id'],))
    with pytest.raises(BusinessError, match='INVALID_CREDENTIALS'):
        single.login('lab-viewer', 'TEST-viewer-password-12345', '127.0.0.1', 'TEST-denied')
    with pytest.raises(BusinessError, match='SINGLE_ACCOUNT_MODE'):
        single.create_user(current, {}, 'TEST-new', 'TEST-new')
    with pytest.raises(BusinessError, match='SINGLE_ACCOUNT_MODE'):
        single.update_user(current, lab['user_id'], {}, 'TEST-update', 'TEST-update')
    assert db_count > 0


def test_admin_audit_accepts_real_quarantine_port_arrays(tmp_path):
    config = BusinessConfig(database_path=tmp_path / 'TEST-business.db', secure_cookie=False,
                            allow_insecure_loopback=True, trusted_origins=(ORIGIN,))
    service = BusinessService(config)
    service.initialize()
    service.bootstrap('test-admin', 'TEST-password-12345', ['Executor'], portal_admin=True)
    _, actor = service.login('test-admin', 'TEST-password-12345', '127.0.0.1', 'TEST-login')
    ports = [{'port_id': 'TEST-port', 'security_group_ids': ['TEST-original-sg'], 'revision_number': 77}]
    service.record_quarantine(actor, VM, 'TEST-quarantine', outcome='SUCCESS', before=ports,
                               after={'state': 'QUARANTINED', 'ports': ports})
    settings = Settings(tmp_path / 'audit', tmp_path / 'cache.db', session_auth_enabled=True)
    with TestClient(create_app(settings, business_config=config), client=('127.0.0.1', 1)) as client:
        assert client.post('/api/v1/auth/login', headers={'Origin': ORIGIN}, json={
            'username': 'test-admin', 'password': 'TEST-password-12345'}).status_code == 200
        result = client.get('/api/v1/portal/admin/audit?limit=100')
        assert result.status_code == 200
        row = next(row for row in result.json()['data']['items'] if row['action'] == 'WORKLOAD_QUARANTINE')
        assert row['before'] == {'ports': ports} and row['after']['state'] == 'QUARANTINED'
