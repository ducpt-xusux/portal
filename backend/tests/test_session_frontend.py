from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.n91_business import BusinessConfig


def test_session_frontend_loads_before_login_but_data_requires_session(tmp_path):
    web = tmp_path / 'web'
    assets = web / 'assets'
    assets.mkdir(parents=True)
    (web / 'index.html').write_text('<html>Portal sign-in</html>', encoding='utf-8')
    (assets / 'index-Abcd1234.js').write_text('export {};', encoding='utf-8')
    (assets / 'private.json').write_text('{}', encoding='utf-8')
    settings = Settings(tmp_path / 'audit.jsonl', tmp_path / 'audit.db', session_auth_enabled=True)
    config = BusinessConfig(database_path=tmp_path / 'business.db')
    app = create_app(settings, business_config=config)

    with TestClient(app, base_url='https://portal.test') as client:
        assert client.get('/').status_code == 401
    app = create_app(settings, business_config=config, session_web_dir=web)
    with TestClient(app, base_url='https://portal.test') as client:
        assert client.get('/').text == '<html>Portal sign-in</html>'
        assert client.get('/index.html').status_code == 200
        assert client.get('/assets/index-Abcd1234.js').text == 'export {};'
        assert client.head('/assets/index-Abcd1234.js').status_code == 200
        assert client.get('/assets/missing-Abcd1234.js').status_code == 404
        assert client.get('/assets/private.json').status_code == 401
        assert client.get('/api/v1/workloads').json()['error']['code'] == 'SESSION_REQUIRED'
        assert client.post('/api/v1/workloads/clone/quarantine', json={}).status_code == 401
