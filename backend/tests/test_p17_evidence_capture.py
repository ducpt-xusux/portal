import importlib.util
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import pytest
import json
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.p17_snapshot import Snapshot, SnapshotError

path = Path(__file__).parents[1] / 'integrations/p17/evidence_capture.py'
spec = importlib.util.spec_from_file_location('evidence_capture', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def database():
    db = sqlite3.connect(':memory:', isolation_level=None)
    db.executescript('''CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,stream_id TEXT,evidence_count INTEGER);
        CREATE TABLE processed_events(stream_id TEXT,event_id TEXT,request_id TEXT,stream_sequence INTEGER,payload_sha256 TEXT);
        INSERT INTO incidents VALUES ('INC-TEST','TEST-stream',1);
        INSERT INTO processed_events VALUES ('TEST-stream','TEST-event','TEST-request',7,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');''')
    return db


def capture(db, **kwargs):
    return module.record_incident_evidence(db, incident_id='INC-TEST', stream_id='TEST-stream',
        trigger_event_id='TEST-event', signal_rule='CORR-002', detector_version='TEST-detector',
        detector_sha256='b'*64, recorded_at='2026-11-19T00:00:00Z', **kwargs)


def test_capture_uses_exact_persisted_identity_and_rolls_back_with_worker():
    db = database();db.execute('BEGIN')
    capture(db, evidence=[SimpleNamespace(event_id='TEST-event', request_id='TEST-request', payload_sha256='a'*64)])
    assert db.in_transaction
    assert db.execute('SELECT stream_sequence FROM portal_evidence_members_v1').fetchone()[0] == 7
    db.rollback()
    assert not db.execute("SELECT name FROM sqlite_master WHERE name='portal_evidence_snapshots_v1'").fetchall()


def test_capture_refuses_unmatched_evidence_and_autocommit_calls():
    db = database()
    with pytest.raises(ValueError, match='REQUIRES_WORKER_TRANSACTION'):
        capture(db, evidence=[])
    db.execute('BEGIN')
    with pytest.raises(ValueError, match='IDENTITY_MISMATCH'):
        capture(db, evidence=[SimpleNamespace(event_id='TEST-event', request_id='TEST-other', payload_sha256='a'*64)])
    assert db.execute('SELECT evidence_count FROM incidents').fetchone()[0] == 1


def test_captured_worker_export_serves_exact_members_and_detector_profile(tmp_path):
    source = Path(__file__).parent / 'fixtures/p17-TEST-captured.json'
    snapshot = Snapshot.parse(source.read_bytes())
    incident = next(row for row in snapshot.incidents if row.signal_rule == 'CORR-002')
    cfg = Settings(tmp_path / 'missing-audit', tmp_path / 'cache.db', mode='snapshot',
        p17_snapshot_path=source, p17_local_readonly=True, p16h_import_context='TEST', evidence_local_readonly=True)
    with TestClient(create_app(cfg), client=('127.0.0.1', 1)) as client:
        route = f'/api/v1/portal/incidents/{incident.incident_id}/investigation?stream_id={incident.stream_id}'
        response = client.get(route)
        assert response.status_code == 200, response.text
        body = response.json()['data']
        assert response.json()['meta']['data_as_of'] == max(row.received_utc for row in snapshot.events).isoformat().replace('+00:00', 'Z')
        assert body['event_members']['membership'] == 'DIRECT_PERSISTED'
        assert body['event_members']['verified_linked_count'] == incident.evidence_count == 5
        assert body['detection']['availability'] == 'AVAILABLE'
        assert len(body['detection']['detector_sha256']) == 64
        assert all(row['eligible_for_corr'] is True for row in body['event_members']['items'])


def test_captured_export_rejects_changed_member_hash():
    source = Path(__file__).parent / 'fixtures/p17-TEST-captured.json'
    value = json.loads(source.read_bytes())
    value['tables']['portal_evidence_members_v1'][0]['payload_sha256'] = 'f' * 64
    with pytest.raises(SnapshotError):
        Snapshot.parse(json.dumps(value).encode())
