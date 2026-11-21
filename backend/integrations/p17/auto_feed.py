"""Restricted Proxy feed for the owner-approved clone automation.

Only reads committed P17 evidence and Canonical RECENT/HEALTH. Never ACKs,
modifies P17, emits SQL text, or grants the P17 Incident an authorization flag.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone

DB = Path('/var/lib/db-firewall-p17/state.sqlite3')
WORKER = Path('/opt/db-firewall/p17-incident-g03-dual-v3-20261104')
CLONE_IP = '10.0.0.204'
INJECTION = frozenset({'INJ-001', 'INJ-002', 'INJ-006', 'INJ-007', 'INJ-008'})
PROJECTION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def canonical_index(deliveries, stream_id):
    index = {}
    for row in deliveries:
        envelope = row['envelope']
        if (row['delivery_version'] != 'p16h-local-1' or row['stream_id'] != stream_id
                or hashlib.sha256(canon(envelope)).hexdigest() != row['payload_sha256']
                or envelope['event_type'] != 'AUDIT_EVENT'
                or envelope.get('schema_version') != '1.2.0-candidate'
                or envelope['event_id'] != envelope['record']['event_id']):
            raise ValueError('CANONICAL_IDENTITY_OR_HASH_INVALID')
        key = (envelope['event_id'], row['stream_sequence'])
        if key in index:
            raise ValueError('DUPLICATE_CANONICAL_IDENTITY')
        index[key] = row
    return index


def request_milliseconds(delivery):
    value = datetime.fromisoformat(delivery['envelope']['metadata']['request_received_at'].replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('REQUEST_TIMEZONE_REQUIRED')
    # Matches p17_core.aware_date(metadata.request_received_at) and p17_durable.millis.
    return int(value.timestamp() * 1000)


def build_feed(db, health, deliveries, now=None):
    metadata = dict(db.execute('SELECT key,value FROM metadata'))
    stream = metadata.get('stream_id')
    if metadata.get('schema') != 'p17-incident-durable-1' or not stream or health.get('stream_id') != stream:
        raise ValueError('SOURCE_STREAM_MISMATCH')
    if health.get('status') != 'RUNNING':
        raise ValueError('CANONICAL_READER_NOT_RUNNING')
    canonical = canonical_index(deliveries, stream)
    db.row_factory = sqlite3.Row
    candidates = []
    for row in db.execute("SELECT * FROM incidents WHERE client_ip=? AND stream_id=? "
                          'ORDER BY last_ms DESC LIMIT 30', (CLONE_IP, stream)).fetchall():
        capture = db.execute('SELECT s.* FROM portal_evidence_snapshots_v1 s JOIN processed_events t '
                             'ON t.event_id=s.trigger_event_id AND t.stream_id=s.stream_id WHERE s.incident_id=? '
                             'ORDER BY t.stream_sequence DESC,s.recorded_at DESC,s.snapshot_id DESC LIMIT 1',
                             (row['incident_id'],)).fetchone()
        members = db.execute('SELECT m.*, e.event_ms,e.risk_status,e.risk_score,e.blocked,e.rules_json,'
                             'e.identity_complete,e.event_class,e.live_eligible,e.client_ip,e.stream_id '
                             'FROM portal_evidence_members_v1 m JOIN processed_events e ON m.event_id=e.event_id '
                             'WHERE m.snapshot_id=? ORDER BY e.event_ms,m.stream_sequence', (capture['snapshot_id'],)).fetchall() if capture else []
        proof = []
        reasons = [] if capture else ['DIRECT_MEMBERSHIP_MISSING']
        for member in members:
            delivery = canonical.get((member['event_id'], member['stream_sequence']))
            if delivery is None:
                reasons.append('CANONICAL_RECORD_NOT_RETAINED')
                break
            record = delivery['envelope']['record']
            rules = set(json.loads(member['rules_json'])) & INJECTION
            if (delivery['payload_sha256'] != member['payload_sha256']
                    or delivery['envelope']['metadata'].get('request_id') != member['request_id']
                    or record.get('client_ip') != CLONE_IP or member['client_ip'] != CLONE_IP
                    or member['stream_id'] != stream or member['blocked'] != 1
                    or member['event_class'] != 'LIVE' or member['live_eligible'] != 1
                    or member['identity_complete'] != 1 or member['risk_status'] != 'OK'
                    or record.get('policy_decision') != 'BLOCK' or record.get('risk_status') != 'OK'
                    or record.get('effective_action') != 'BLOCK' or record.get('action_result') != 'BLOCKED'
                    or record.get('runtime_mode') != 'enforce'
                    or request_milliseconds(delivery) != member['event_ms']
                    or record.get('risk_score') != member['risk_score']
                    or not rules <= set(record.get('matched_rules', []))):
                reasons.append('EVIDENCE_IDENTITY_OR_HASH_MISMATCH')
                break
            proof.append({'event_id': member['event_id'], 'request_id': member['request_id'],
                          'seq': member['stream_sequence'], 'ms': member['event_ms'],
                          'p15': member['risk_score'], 'risk_status': 'OK', 'identity_complete': True,
                          'injection_rules': sorted(rules), 'payload_sha256': member['payload_sha256'],
                          'policy_version': record.get('policy_version'),
                          'db_user': record.get('db_user'),
                          'matched_rules': record.get('matched_rules', []),
                          'time_basis': 'P16H_METADATA_REQUEST_RECEIVED_AT',
                          'request_received_at': delivery['envelope']['metadata']['request_received_at'],
                          'audit_occurred_at': record['timestamp'],
                          'canonical_hash_verified': True})
        candidates.append({'incident_id': row['incident_id'], 'stream_id': stream,
                    'projection_sha256': PROJECTION_SHA256,
                    'source_ip': row['client_ip'], 'correlation_rule': row['signal_rule'],
                    'evidence_count_recorded': row['evidence_count'], 'evidence': proof,
                    'peak_p15': row['peak_p15'], 'confidence': row['confidence'], 'status': row['status'],
                    'created_utc': row['created_utc'], 'last_event_ms': row['last_ms'],
                    'membership_basis': 'DIRECT_PERSISTED' if capture else 'UNAVAILABLE',
                    'snapshot_id': capture['snapshot_id'] if capture else None,
                    'trigger_event_id': capture['trigger_event_id'] if capture else None,
                    'detector_version': capture['detector_version'] if capture else None,
                    'detector_sha256': capture['detector_sha256'] if capture else None,
                    'capture_recorded_at': capture['recorded_at'] if capture else None,
                    'captured_member_count': capture['member_count'] if capture else None,
                    'feed_reason_codes': reasons})
    recent_events = []
    for row in db.execute('SELECT event_id,request_id,stream_sequence,payload_sha256,event_ms,risk_status,risk_score '
                          'FROM processed_events WHERE client_ip=? AND stream_id=? ORDER BY stream_sequence DESC LIMIT 30', (CLONE_IP, stream)):
        delivery = canonical.get((row['event_id'], row['stream_sequence']))
        verified = bool(delivery and delivery['payload_sha256'] == row['payload_sha256']
                        and delivery['envelope']['metadata'].get('request_id') == row['request_id'])
        record = delivery['envelope']['record'] if verified else {}
        recent_events.append({'event_id': row['event_id'], 'request_id': row['request_id'],
            'stream_sequence': row['stream_sequence'], 'payload_sha256': row['payload_sha256'],
            'event_ms': row['event_ms'], 'canonical_hash_verified': verified,
            'risk_status': row['risk_status'], 'risk_score': row['risk_score'],
            'effective_action': record.get('effective_action'), 'db_user': record.get('db_user'),
            'matched_rules': record.get('matched_rules', [])})
    result = {'schema': 'n91-clone-auto-feed-1', 'stream_id': stream, 'projection_sha256': PROJECTION_SHA256,
              'generated_at_utc': (now or datetime.now(timezone.utc)).isoformat(),
              'reader_status': health['status'], 'reader_tail': health['tail'],
              'worker_cursor': health['p17_cursor'],
              'recent_clone_events': recent_events,
              'candidates': candidates, 'action_executed': 'NONE', 'p16h_ack_operation': 'NONE',
              'openstack_mutations': 0}
    result['payload_sha256'] = hashlib.sha256(canon(result)).hexdigest()
    return result


def main():
    sys.path.insert(0, str(WORKER))
    from p17_durable import reader_request
    if DB.is_symlink() or not DB.is_file():
        raise ValueError('SOURCE_DATABASE_INVALID')
    with sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True, timeout=3) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        db.execute('SELECT COUNT(*) FROM metadata').fetchone()
        health = reader_request({'op': 'HEALTH'})
        deliveries = reader_request({'op': 'RECENT', 'limit': 100})
        result = build_feed(db, health, deliveries)
        db.rollback()
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('AUTO_FEED_UNAVAILABLE:' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
