import importlib.util
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sqlite3

import pytest

path = Path(__file__).parents[1] / 'integrations/p17/auto_feed.py'
spec = importlib.util.spec_from_file_location('auto_feed', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def source():
    db = sqlite3.connect(':memory:')
    db.executescript('''
        CREATE TABLE metadata(key TEXT,value TEXT);
        CREATE TABLE incidents(incident_id TEXT,stream_id TEXT,client_ip TEXT,signal_rule TEXT,last_ms INT,
          evidence_count INT,peak_p15 INT,confidence TEXT,status TEXT,created_utc TEXT);
        CREATE TABLE portal_evidence_snapshots_v1(snapshot_id TEXT,incident_id TEXT,member_count INT,
          detector_version TEXT,detector_sha256 TEXT,recorded_at TEXT,trigger_event_id TEXT,stream_id TEXT);
        CREATE TABLE portal_evidence_members_v1(snapshot_id TEXT,event_id TEXT,request_id TEXT,stream_sequence INT,payload_sha256 TEXT);
        CREATE TABLE processed_events(event_id TEXT,event_ms INT,risk_status TEXT,risk_score INT,blocked INT,
          rules_json TEXT,identity_complete INT,event_class TEXT,live_eligible INT,client_ip TEXT,stream_id TEXT,
          request_id TEXT,stream_sequence INT,payload_sha256 TEXT);
    ''')
    db.executemany('INSERT INTO metadata VALUES (?,?)', [('schema', 'p17-incident-durable-1'), ('stream_id', 'TEST-stream')])
    moment = datetime(2026, 11, 21, 13, 30, tzinfo=timezone.utc)
    db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?)', ('INC-TEST', 'TEST-stream', module.CLONE_IP,
        'CORR-002', int(moment.timestamp()*1000), 3, 80, 'CANDIDATE_CORRELATED', 'REVIEW_REQUIRED', moment.isoformat()))
    db.execute('INSERT INTO portal_evidence_snapshots_v1 VALUES (?,?,?,?,?,?,?,?)',
        ('TEST-snapshot', 'INC-TEST', 3, 'TEST-detector', 'a'*64, moment.isoformat(), 'TEST-event-2', 'TEST-stream'))
    deliveries = []
    for i in range(3):
        eid, rid = f'TEST-event-{i}', f'TEST-request-{i}'
        record = {'event_id': eid, 'timestamp': moment.isoformat(), 'client_ip': module.CLONE_IP,
            'risk_score': 80, 'risk_status': 'OK', 'policy_decision': 'BLOCK', 'effective_action': 'BLOCK',
            'action_result': 'BLOCKED', 'runtime_mode': 'enforce', 'matched_rules': ['INJ-001'],
            'policy_version': 'TEST-policy', 'db_user': 'TEST-reader'}
        envelope = {'event_id': eid, 'event_type': 'AUDIT_EVENT', 'schema_version': '1.2.0-candidate',
                    'record': record, 'metadata': {'request_id': rid, 'request_received_at': moment.isoformat()}}
        digest = hashlib.sha256(module.canon(envelope)).hexdigest()
        deliveries.append({'delivery_version': 'p16h-local-1', 'stream_id': 'TEST-stream',
                           'stream_sequence': i+1, 'envelope': envelope, 'payload_sha256': digest})
        db.execute('INSERT INTO portal_evidence_members_v1 VALUES (?,?,?,?,?)', ('TEST-snapshot', eid, rid, i+1, digest))
        db.execute('INSERT INTO processed_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (eid, int(moment.timestamp()*1000), 'OK', 80, 1, '["INJ-001"]', 1, 'LIVE', 1, module.CLONE_IP, 'TEST-stream', rid, i+1, digest))
    health = {'status': 'RUNNING', 'stream_id': 'TEST-stream', 'tail': 3, 'p17_cursor': 3}
    return db, health, deliveries


def test_readonly_feed_requires_exact_capture_and_canonical_hash_and_emits_no_sql():
    db, health, deliveries = source()
    feed = module.build_feed(db, health, deliveries)
    c = feed['candidates'][0]
    assert len(c['evidence']) == c['captured_member_count'] == 3
    assert c['feed_reason_codes'] == []
    assert all(event['canonical_hash_verified'] for event in c['evidence'])
    assert '"record":' not in json.dumps(feed) and 'password' not in json.dumps(feed)
    assert 'query_masked' not in json.dumps(feed) and 'query_raw' not in json.dumps(feed)
    deliveries[0]['payload_sha256'] = 'f'*64
    with pytest.raises(ValueError, match='HASH'):
        module.build_feed(db, health, deliveries)


@pytest.mark.parametrize('problem', ['retention', 'request', 'changed_hash', 'non_live', 'monitor'])
def test_incomplete_or_mismatched_feed_keeps_review_reason_instead_of_authorizing(problem):
    db, health, deliveries = source()
    if problem == 'retention': deliveries = deliveries[1:]
    if problem == 'request': db.execute("UPDATE portal_evidence_members_v1 SET request_id='TEST-wrong' WHERE stream_sequence=1")
    if problem == 'changed_hash': db.execute("UPDATE portal_evidence_members_v1 SET payload_sha256=? WHERE stream_sequence=1", ('f'*64,))
    if problem == 'non_live': db.execute("UPDATE processed_events SET event_class='HISTORICAL'")
    if problem == 'monitor':
        deliveries[0]['envelope']['record']['runtime_mode'] = 'monitor'
        digest = hashlib.sha256(module.canon(deliveries[0]['envelope'])).hexdigest()
        deliveries[0]['payload_sha256'] = digest
        db.execute('UPDATE portal_evidence_members_v1 SET payload_sha256=? WHERE stream_sequence=1', (digest,))
    feed = module.build_feed(db, health, deliveries)
    assert feed['candidates'][0]['feed_reason_codes']
    assert feed['action_executed'] == 'NONE' and feed['p16h_ack_operation'] == 'NONE'


def test_p17_request_clock_is_distinct_from_later_audit_record_clock():
    db, health, deliveries = source()
    deliveries[0]['envelope']['record']['timestamp'] = '2026-11-21T13:30:00.005628+00:00'
    digest = hashlib.sha256(module.canon(deliveries[0]['envelope'])).hexdigest()
    deliveries[0]['payload_sha256'] = digest
    db.execute('UPDATE portal_evidence_members_v1 SET payload_sha256=? WHERE stream_sequence=1', (digest,))
    db.execute('UPDATE processed_events SET payload_sha256=? WHERE stream_sequence=1', (digest,))
    evidence = module.build_feed(db, health, deliveries)['candidates'][0]
    assert evidence['feed_reason_codes'] == [] and len(evidence['evidence']) == 3
    assert evidence['evidence'][0]['time_basis'] == 'P16H_METADATA_REQUEST_RECEIVED_AT'


def test_equal_batch_timestamps_select_latest_trigger_sequence_not_lexical_hash():
    db, health, deliveries = source()
    db.execute('INSERT INTO portal_evidence_snapshots_v1 SELECT ?,incident_id,2,detector_version,detector_sha256,'
               'recorded_at,?,stream_id FROM portal_evidence_snapshots_v1', ('ZZZ-older-snapshot', 'TEST-event-1'))
    db.execute('INSERT INTO portal_evidence_members_v1 SELECT ?,event_id,request_id,stream_sequence,payload_sha256 '
               'FROM portal_evidence_members_v1 WHERE stream_sequence<=2', ('ZZZ-older-snapshot',))
    c = module.build_feed(db, health, deliveries)['candidates'][0]
    assert c['snapshot_id'] == 'TEST-snapshot' and len(c['evidence']) == 3
