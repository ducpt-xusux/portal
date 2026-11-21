"""Manual Linux smoke check against a copied candidate; SQLite and inputs are TEST-only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).parent))
import p17_durable as worker

db = sqlite3.connect(':memory:', isolation_level=None)
db.executescript(worker.DDL)
base = datetime.now(timezone.utc) - timedelta(seconds=10)
stream = 'TEST-capture-stream'
metadata = {'schema': worker.SCHEMA_ID, 'stream_id': stream, 'last_committed_sequence': '0',
            'activated_utc': worker.iso(base - timedelta(minutes=1)), 'approved_auto_containment': 'false'}
db.executemany('INSERT INTO metadata VALUES (?,?)', metadata.items())
worker.ensure_vnext_schema(db)
template = json.loads(Path(__file__).with_name('TEST-delivery.json').read_text())['delivery']


def event(sequence):
    delivery = deepcopy(template)
    eid, rid = 'TEST-capture-event-' + str(sequence), 'TEST-capture-request-' + str(sequence)
    delivery.update(stream_id=stream, stream_sequence=sequence, segment_index=1, journal_stream_id='TEST-journal')
    env = delivery['envelope']; record = env['record']; meta = env['metadata']
    at = worker.iso(base + timedelta(milliseconds=sequence))
    env.update(schema_version='1.2.0-candidate', stream_role='SHADOW', event_id=eid, timestamp=at)
    record.update(event_id=eid, timestamp=at, policy_version='1.4.1-G03-RC5', risk_version='1.0.1-G03-RC6',
                  action='BLOCK', effective_action='BLOCK', action_result='BLOCKED', policy_decision='BLOCK',
                  matched_rules=['INJ-001'], blocking_rules=['INJ-001'], risk_status='OK', risk_score=80,
                  raw_score=80, severity='CRITICAL', would_block=True, defaulted=False,
                  score_breakdown=[{'rule_id':'INJ-001','source':'matched_rule','score':80,'category':'injection','reason':'TEST fixture'}])
    meta.update(request_id=rid, request_received_at=at, producer_id='TEST-producer',
                privacy={'db_user_status':'CLEAR_ALLOWED'})
    delivery.update(event_role='CANONICAL_AUDIT_DELIVERY', payload_sha256=hashlib.sha256(worker.canonical(env)).hexdigest())
    return delivery


def batch(first, last):
    return {'stream_id':stream, 'consumer':'p17', 'items':[event(n) for n in range(first,last+1)], 'after_sequence':first-1,
            'through_sequence':last, 'ack_token':'TEST-token', 'journal_stream_id':'TEST-journal', 'segment_index':1}


result = worker.process_batch(db, batch(1,5), now=base+timedelta(seconds=1))
assert result['processed'] == 5
captures = db.execute('SELECT snapshot_id,member_count,detector_sha256 FROM portal_evidence_snapshots_v1').fetchall()
assert len(captures) == 4
for sid,count,sha in captures:
    assert sha == worker._PORTAL_DETECTOR_SHA256
    assert db.execute('SELECT COUNT(*) FROM portal_evidence_members_v1 WHERE snapshot_id=?',(sid,)).fetchone()[0] == count
worker.process_batch(db, batch(1,5), now=base+timedelta(seconds=2))
assert db.execute('SELECT COUNT(*) FROM portal_evidence_snapshots_v1').fetchone()[0] == 4
worker.record_incident_evidence = lambda *a,**kw: (_ for _ in ()).throw(RuntimeError('TEST_CAPTURE_FAILURE'))
try:
    worker.process_batch(db, batch(6,6), now=base+timedelta(seconds=3))
    raise AssertionError('Failure did not propagate')
except RuntimeError as error:
    assert str(error) == 'TEST_CAPTURE_FAILURE'
assert db.execute('SELECT COUNT(*) FROM processed_events').fetchone()[0] == 5
assert dict(db.execute('SELECT key,value FROM metadata'))['last_committed_sequence'] == '5'
db.row_factory = sqlite3.Row
tables = {name: [dict(row) for row in db.execute('SELECT * FROM ' + name)] for name in (
    'metadata', 'processed_events', 'incidents', 'outbox', 'portal_evidence_snapshots_v1', 'portal_evidence_members_v1')}
Path(__file__).with_name('TEST-captured-p17.json').write_text(json.dumps({
    'export_version':'portal-p17-snapshot-1', 'mode':'SNAPSHOT', 'exported_at':worker.iso(), 'tables':tables}))
print('TEST_LINUX_WORKER_CAPTURE_PASS: exact membership, duplicate replay, VNext coexistence, rollback before ACK')
