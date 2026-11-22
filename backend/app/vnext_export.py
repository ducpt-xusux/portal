#!/usr/bin/env python3
"""N91 P17 VNext read-only, bounded, atomic Portal snapshot publisher.

NEVER calls P16H POLL/ACK, writes P17 SQLite, changes Incident or cloud state.
Source tables are populated by the already-running P17 VNext review-only worker.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

SCHEMA = 'n91-portal-p17-vnext-1'
MAX_EVENTS = 100
MAX_CASES = 50
MAX_MEMBERS = 300
MAX_BYTES = 8 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def decoded(raw):
    return json.loads(raw)


def read_snapshot(db_path: str, *, event_limit: int = MAX_EVENTS, case_limit: int = MAX_CASES):
    collection_started_at = now()
    if not (1 <= event_limit <= MAX_EVENTS and 1 <= case_limit <= MAX_CASES):
        raise ValueError('VNEXT_EXPORT_LIMIT_INVALID')
    path = Path(db_path)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError('VNEXT_SOURCE_PATH_INVALID')
    manifest_path=Path(__file__).with_name('vnext_detector_manifest.json')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    if len(manifest.get('detectors', [])) != 22 or manifest.get('profile') != 'n91-vnext-source-evidence-v1':
        raise ValueError('VNEXT_MANIFEST_INVALID')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('VNEXT_SQLITE_INTEGRITY_INVALID')
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {'vnext_profile', 'vnext_events', 'vnext_cases', 'vnext_case_evidence', 'metadata'}
        if not required.issubset(names):
            raise ValueError('VNEXT_TABLES_NOT_INSTALLED')
        profile = db.execute("SELECT v FROM vnext_profile WHERE k='profile'").fetchone()
        if not profile or profile[0] != 'n91-vnext-source-evidence-v1':
            raise ValueError('VNEXT_PROFILE_MISMATCH')
        md = dict(db.execute('SELECT key,value FROM metadata').fetchall())
        if md.get('schema') != 'p17-incident-durable-1':
            raise ValueError('VNEXT_LEGACY_SCHEMA_INVALID')
        events_total = db.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0]
        cases_total = db.execute('SELECT COUNT(*) FROM vnext_cases').fetchone()[0]
        legacy_total = db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
        rows = db.execute('''SELECT stream_id,event_id,request_id,stream_sequence,event_ms,
            event_class,qualify_reason,blocked,risk_status,risk_score,trace_json
            FROM vnext_events ORDER BY stream_sequence DESC LIMIT ?''', (event_limit,)).fetchall()
        events = []
        for r in rows:
            trace = decoded(r['trace_json'])
            if trace.get('event_id') != r['event_id'] or trace.get('stream_id') != r['stream_id']:
                raise ValueError('VNEXT_TRACE_EVENT_LINK_MISMATCH')
            events.append({
                'event_id':r['event_id'], 'stream_id':r['stream_id'], 'request_id':r['request_id'],
                'stream_sequence':r['stream_sequence'], 'event_ms':r['event_ms'],
                'event_class':r['event_class'], 'qualification':r['qualify_reason'],
                'blocked':bool(r['blocked']), 'risk_status':r['risk_status'], 'risk_score':r['risk_score'],
                'trace':trace,
            })
        raw_cases = db.execute('''SELECT case_id,episode_id,stream_id,source_ip,first_event_id,
            last_event_id,severity,peak_p15,evidence_count,signal_ids_json,status,
            isolation_authorized,created_utc,updated_utc
            FROM vnext_cases ORDER BY updated_utc DESC,case_id DESC LIMIT ?''', (case_limit,)).fetchall()
        cases = []
        count_members = 0
        for c in raw_cases:
            n = min(MAX_MEMBERS - count_members, 100)
            members = db.execute('''SELECT m.event_id,m.request_id,m.stream_id,m.reason,
                    e.stream_sequence,e.event_ms,e.risk_score,e.risk_status,
                    e.trace_json
                FROM vnext_case_evidence m JOIN vnext_events e
                ON m.event_id=e.event_id AND m.stream_id=e.stream_id
                WHERE m.case_id=? ORDER BY e.stream_sequence ASC LIMIT ?''',(c['case_id'], max(0,n))).fetchall()
            count_members += len(members)
            evidence = []
            for m in members:
                tr = decoded(m['trace_json'])
                evidence.append({
                    'event_id':m['event_id'],'request_id':m['request_id'],
                    'stream_id':m['stream_id'],'stream_sequence':m['stream_sequence'],
                    'event_ms':m['event_ms'],'reason':m['reason'],
                    'risk_score':m['risk_score'] if m['risk_status']=='OK' else None,
                    'trace':tr,
                })
            if c['isolation_authorized'] != 0: raise ValueError('VNEXT_CASE_AUTHORIZATION_DRIFT')
            cases.append({
                'case_id':c['case_id'],'episode_id':c['episode_id'],'stream_id':c['stream_id'],
                'source_ip':c['source_ip'],'first_event_id':c['first_event_id'],
                'last_event_id':c['last_event_id'],'severity':c['severity'],
                'peak_p15':c['peak_p15'],'evidence_count':c['evidence_count'],
                'signals':decoded(c['signal_ids_json']),'status':c['status'],
                'isolation_authorized':False, 'response':'NO_ACTION',
                'created_at':c['created_utc'],'updated_at':c['updated_utc'],
                'evidence':evidence,'evidence_export_complete':len(evidence)==c['evidence_count'],
            })
        payload = {
            'schema_version':SCHEMA,'generated_at':now(), 'collection_started_at':collection_started_at, 'source_system':'P17_G03_V3_SQLITE',
            'source_mode':'COMMITTED_SQLITE_READONLY_EXPORT', 'profile':profile[0],
            'stream_id':md['stream_id'],
            'checkpoint':int(md['last_committed_sequence']),
            'legacy_incident_count':legacy_total,
            'event_total':events_total,'case_total':cases_total,
            'event_export_limit':event_limit,'case_export_limit':case_limit,
            'coverage':'BOUNDED_LAST_EVENTS_AND_CASES',
            'security_boundary':'REVIEW_ONLY_NO_OPENSTACK_ACTION',
            'events':events,'cases':cases,'detector_manifest':manifest,
        }
        raw = json.dumps(payload, ensure_ascii=True, separators=(',',':'),sort_keys=True).encode('ascii')
        if len(raw)>MAX_BYTES:raise ValueError('VNEXT_EXPORT_EXCEEDS_MAX_BYTES')
        return payload


def publish(source: str, output: str):
    payload = read_snapshot(source)
    path = Path(output)
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError('VNEXT_TARGET_PATH_INVALID')
    if path.resolve() == Path(source).resolve() or path.suffix != '.json':
        raise ValueError('VNEXT_TARGET_IS_SQLITE_OR_NOT_JSON')
    raw = json.dumps(payload, ensure_ascii=True, separators=(',',':'),sort_keys=True).encode('ascii')
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.p17-vnext-', delete=False) as f:
            temp=Path(f.name)
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        # fsync directory to persist atomic rename.
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temp is not None: temp.unlink(missing_ok=True)
    print('VNEXT_PORTAL_EXPORT_PASS', 'checkpoint='+str(payload['checkpoint']),
          'events='+str(len(payload['events'])), 'cases='+str(len(payload['cases'])), flush=True)


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--db', default='/var/lib/db-firewall-p17/state.sqlite3')
    a.add_argument('--out', default='/var/lib/n91-portal/p17_vnext.json')
    args=a.parse_args()
    publish(args.db,args.out)

if __name__=='__main__':main()
