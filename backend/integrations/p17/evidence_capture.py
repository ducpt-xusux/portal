"""Additive evidence capture inside P17's existing commit-before-ACK transaction.

This module never opens a database, commits, ACKs, runs a detector or changes an
Incident. The worker calls it with the exact evidence that created/updated one.
Historical membership is never backfilled by guessing a time window.
"""
import hashlib
import json


DDL = (
    '''CREATE TABLE IF NOT EXISTS portal_evidence_snapshots_v1 (
       snapshot_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, stream_id TEXT NOT NULL,
       trigger_event_id TEXT NOT NULL, detector_version TEXT NOT NULL, detector_sha256 TEXT NOT NULL,
       signal_rule TEXT NOT NULL, member_count INTEGER NOT NULL, recorded_evidence_count INTEGER NOT NULL,
       recorded_at TEXT NOT NULL, FOREIGN KEY(incident_id) REFERENCES incidents(incident_id))''',
    '''CREATE TABLE IF NOT EXISTS portal_evidence_members_v1 (
       snapshot_id TEXT NOT NULL, event_id TEXT NOT NULL, request_id TEXT NOT NULL,
       stream_sequence INTEGER NOT NULL, payload_sha256 TEXT NOT NULL,
       PRIMARY KEY(snapshot_id,event_id), UNIQUE(snapshot_id,request_id),
       FOREIGN KEY(snapshot_id) REFERENCES portal_evidence_snapshots_v1(snapshot_id))''',
)


def record_incident_evidence(db, *, incident_id, stream_id, trigger_event_id, signal_rule,
                             evidence, detector_version, detector_sha256, recorded_at):
    if not db.in_transaction:
        raise ValueError('EVIDENCE_CAPTURE_REQUIRES_WORKER_TRANSACTION')
    if len(detector_sha256) != 64 or any(c not in '0123456789abcdef' for c in detector_sha256):
        raise ValueError('DETECTOR_HASH_REQUIRED')
    incident = db.execute('SELECT stream_id,evidence_count FROM incidents WHERE incident_id=?', (incident_id,)).fetchone()
    if incident is None or incident[0] != stream_id:
        raise ValueError('INCIDENT_SCOPE_MISMATCH')
    members = {}
    for event in evidence:
        row = db.execute('SELECT request_id,stream_sequence,payload_sha256 FROM processed_events '
                         'WHERE stream_id=? AND event_id=?', (stream_id, event.event_id)).fetchone()
        if row is None or row[0] != event.request_id or row[2] != event.payload_sha256:
            raise ValueError('EVIDENCE_MEMBER_IDENTITY_MISMATCH')
        if event.event_id in members:
            raise ValueError('EVIDENCE_MEMBER_DUPLICATE')
        members[event.event_id] = (event.event_id, *tuple(row))
    if not members:
        raise ValueError('EVIDENCE_MEMBERS_REQUIRED')
    for statement in DDL:
        db.execute(statement)
    snapshot_id = hashlib.sha256(json.dumps([stream_id, incident_id, trigger_event_id, signal_rule],
                                           separators=(',', ':')).encode()).hexdigest()
    db.execute('INSERT INTO portal_evidence_snapshots_v1 VALUES (?,?,?,?,?,?,?,?,?,?)',
               (snapshot_id, incident_id, stream_id, trigger_event_id, detector_version, detector_sha256,
                signal_rule, len(members), incident[1], recorded_at))
    db.executemany('INSERT INTO portal_evidence_members_v1 VALUES (?,?,?,?,?)',
                   [(snapshot_id, *row) for row in members.values()])
    return snapshot_id
