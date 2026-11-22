from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.n91_business import BusinessConfig


def export_fixture():
    trace = {'event_id': 'TEST-EVENT-1', 'source_ip': '192.0.2.10',
             'event_time': '2026-11-21T15:52:00.353540+00:00',
             'p17': {'action_authorized': False, 'matched_signals': ['CORR-002']}}
    event = {'event_id': 'TEST-EVENT-1', 'stream_sequence': 1, 'blocked': False,
             'risk_score': 0, 'trace': trace}
    return {
        'schema_version': 'n91-portal-p17-vnext-1',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'profile': 'n91-vnext-source-evidence-v1',
        'source_mode': 'COMMITTED_SQLITE_READONLY_EXPORT', 'source_system': 'TEST_SYNTHETIC',
        'stream_id': 'TEST-stream', 'checkpoint': 1, 'legacy_incident_count': 0,
        'event_total': 1, 'case_total': 1, 'coverage': 'BOUNDED_LAST_EVENTS_AND_CASES',
        'security_boundary': 'REVIEW_ONLY_NO_OPENSTACK_ACTION',
        'detector_manifest': {'profile': 'n91-vnext-source-evidence-v1',
                              'detectors': [{'id': f'CORR-{i:03}'} for i in range(1, 23)]},
        'events': [event],
        'cases': [{'case_id': 'TEST-CASE-1', 'source_ip': '192.0.2.10',
                   'response': 'NO_ACTION', 'isolation_authorized': False,
                   'signals': ['CORR-002'], 'evidence': [event], 'evidence_count': 1}],
    }


@pytest.fixture
def source(tmp_path):
    path = tmp_path / 'vnext.json'
    path.write_text(json.dumps(export_fixture()), encoding='utf-8')
    settings = Settings(tmp_path / 'audit.jsonl', tmp_path / 'cache.db',
                        p17_local_readonly=True, p17_vnext_snapshot_path=path)
    return path, settings


def test_five_routes_use_real_application_and_keep_zero(source):
    path, settings = source
    original = path.read_bytes()
    with TestClient(create_app(settings), client=('127.0.0.1', 1)) as client:
        for suffix in ('status', 'cases', 'cases/TEST-CASE-1', 'events', 'events/TEST-EVENT-1'):
            response = client.get('/api/v1/p17-vnext/' + suffix)
            assert response.status_code == 200, response.text
            assert response.json()['meta']['review_only'] is True
            assert response.json()['meta']['source_action_authority'] is False
            assert client.post('/api/v1/p17-vnext/' + suffix, json={}).status_code == 405
        row = client.get('/api/v1/p17-vnext/events').json()['data']['events'][0]
        assert row['risk_score'] == 0 and row['blocked'] is False
        assert row['event_time'] == '2026-11-21T15:52:00.353540+00:00'
        assert client.get('/api/v1/p17-vnext/cases?source_ip=192.0.2.11').json()['data']['cases'] == []
        assert client.get('/api/v1/p17-vnext/cases/missing').status_code == 404
    assert path.read_bytes() == original


@pytest.mark.parametrize('invalid', ['secret', 'authority', 'missing_metadata', 'duplicate', 'member_authority'])
def test_invalid_exports_fail_without_exposing_payload(source, invalid):
    path, settings = source
    data = export_fixture()
    if invalid == 'secret': data['password'] = 'sensitive-test-value'
    elif invalid == 'authority': data['cases'][0]['isolation_authorized'] = True
    elif invalid == 'missing_metadata': del data['case_total']
    elif invalid == 'duplicate': data['events'] *= 2; data['event_total'] = 2
    elif invalid == 'member_authority': data['cases'][0]['evidence'][0]['trace']['p17']['action_authorized'] = True
    path.write_text(json.dumps(data), encoding='utf-8')
    with TestClient(create_app(settings), client=('127.0.0.1', 1)) as client:
        response = client.get('/api/v1/p17-vnext/status')
        assert response.status_code == 503
        assert response.json()['error']['code'] == 'VNEXT_SOURCE_INVALID'
        assert 'sensitive-test-value' not in response.text


def test_no_source_no_loopback_and_api_key_are_enforced(source):
    path, settings = source
    with TestClient(create_app(settings), client=('192.0.2.1', 1)) as client:
        assert client.get('/api/v1/p17-vnext/status').status_code == 403
    with TestClient(create_app(replace(settings, api_key='test-only-key')), client=('127.0.0.1', 1)) as client:
        assert client.get('/api/v1/p17-vnext/status').status_code == 401
        assert client.get('/api/v1/p17-vnext/status', headers={'X-API-Key': 'test-only-key'}).status_code == 200
    path.unlink()
    with TestClient(create_app(settings), client=('127.0.0.1', 1)) as client:
        assert client.get('/api/v1/p17-vnext/status').status_code == 503


def test_session_gate_does_not_allow_loopback_or_key_bypass(source, tmp_path):
    _, settings = source
    config = BusinessConfig(database_path=tmp_path / 'business.db', trusted_origins=('https://portal.test',))
    app = create_app(replace(settings, session_auth_enabled=True), business_config=config)
    business = app.state.quarantine_audit
    business.initialize()
    business.bootstrap('viewer', 'test-only-viewer-password', ['Viewer'])
    with TestClient(app, base_url='https://portal.test', client=('127.0.0.1', 1)) as client:
        assert client.get('/api/v1/p17-vnext/status', headers={'X-API-Key': 'anything'}).status_code == 401
        login = client.post('/api/v1/auth/login', json={'username': 'viewer', 'password': 'test-only-viewer-password'}, headers={'Origin': 'https://portal.test'})
        assert login.status_code == 200
        assert client.get('/api/v1/p17-vnext/status').status_code == 200
        assert client.post('/api/v1/p17-vnext/cases', json={}).status_code == 403
