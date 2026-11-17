"""P17 VNext additive, review-only detection over verified P16H events.

Runs *inside* the existing P17 SQLite transaction. Does not ACK P16H,
modify existing incidents, authorize containment, reparse SQL or rescore P15.
Only canonical allowlisted fields are persisted. No raw/masked SQL is copied.

Profile: source-scope review of latest MAX_EVIDENCE events (not a time window).
This is a lab candidate, NOT a calibrated attack classifier/production SOC.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

PROFILE = "n91-vnext-source-evidence-v1"
MAX_EVIDENCE = 256
INJECTION = frozenset({"INJ-001", "INJ-002", "INJ-006", "INJ-007", "INJ-008"})
SENSITIVE = frozenset({"OBJ-003", "OBJ-004"})
COMPAT = frozenset({"PROTO-001", "PROTO-010"})
MONITOR = frozenset({"INJ-003", "RES-002", "RES-004", "RES-005", "READ-001", "READ-004", "ADMIN-001", "ADMIN-002"})
GROUPS = {
    "injection": INJECTION,
    "sensitive_data": SENSITIVE,
    "reconnaissance": frozenset({"ENUM-001"}),
    "privilege_destructive": frozenset({"DCL-001", "DDL-001"}),
    "file": frozenset({"FILE-001"}),
    "stacked": frozenset({"PROTO-003"}),
    "authorization": frozenset({"CTX-003", "DML-010", "DML-011", "DML-012", "VIEW-001"}),
}
SEV_RANK = {"WARNING": 1, "HIGH": 2, "CRITICAL": 3}
# id: (severity, creates_review_case, criterion)
DETECTORS = {
    "CORR-001": ("WARNING", True, "5 distinct non-compatibility BLOCK requests in source scope"),
    "CORR-002": ("HIGH", True, "3 distinct BLOCK requests with enforced injection rules"),
    "CORR-003": ("HIGH", True, "3 distinct sensitive-object BLOCK requests"),
    "CORR-004": ("CRITICAL", True, "3 BLOCK requests; >=3 signal groups; >=2 distinct rule signatures"),
    "CORR-005": ("WARNING", False, "5 protocol compatibility events; operational only"),
    "CORR-006": ("CRITICAL", True, "1 privilege-management BLOCK (DCL-001)"),
    "CORR-007": ("CRITICAL", True, "1 schema-changing BLOCK (DDL-001)"),
    "CORR-008": ("HIGH", True, "1 DB file-access BLOCK (FILE-001)"),
    "CORR-009": ("HIGH", True, "1 unsafe DML BLOCK (DML-001/002)"),
    "CORR-010": ("HIGH", True, "2 distinct unauthorized write BLOCK requests"),
    "CORR-011": ("HIGH", False, "1 invalid or missing DB identity BLOCK"),
    "CORR-012": ("WARNING", False, "1 unexpected-source BLOCK (CTX-006)"),
    "CORR-013": ("HIGH", True, "1 BLOCK with both CTX-006 and enforced SQL injection"),
    "CORR-014": ("HIGH", True, "2 distinct system enumeration BLOCK requests"),
    "CORR-015": ("HIGH", True, "enumeration before injection/sensitive/privilege in separate requests"),
    "CORR-016": ("WARNING", False, "1 security_test_data table access BLOCK"),
    "CORR-017": ("HIGH", True, "1 multiple-statement BLOCK (PROTO-003)"),
    "CORR-018": ("WARNING", False, "2 distinct oversized SQL BLOCK requests"),
    "CORR-019": ("WARNING", False, "3 distinct monitor-only signal-bearing requests"),
    "CORR-020": ("WARNING", False, "5 distinct verified P14 default-deny BLOCK requests"),
    "CORR-021": ("HIGH", True, "1 BLOCK with injection and sensitive-object rules"),
    "CORR-022": ("CRITICAL", True, "injection/enum/sensitive before DCL/DDL/FILE in separate requests"),
}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS vnext_episodes (
 episode_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,source_key TEXT NOT NULL,
 policy_version TEXT NOT NULL,risk_version TEXT NOT NULL,first_seq INTEGER NOT NULL,
 last_seq INTEGER NOT NULL,created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL,
 UNIQUE(stream_id,source_key,policy_version,risk_version)
);
CREATE TABLE IF NOT EXISTS vnext_events (
 stream_id TEXT NOT NULL,event_id TEXT NOT NULL,request_id TEXT NOT NULL,
 stream_sequence INTEGER NOT NULL,source_key TEXT NOT NULL,episode_id TEXT NOT NULL,
 event_ms INTEGER NOT NULL,event_class TEXT NOT NULL,qualify_reason TEXT NOT NULL,
 blocked INTEGER NOT NULL,risk_status TEXT NOT NULL,risk_score INTEGER,
 evidence_json TEXT NOT NULL,trace_json TEXT NOT NULL,created_utc TEXT NOT NULL,
 PRIMARY KEY(stream_id,event_id), UNIQUE(stream_id,request_id),
 FOREIGN KEY(episode_id) REFERENCES vnext_episodes(episode_id)
);
CREATE INDEX IF NOT EXISTS ix_vnext_events_episode_seq ON vnext_events(episode_id,stream_sequence);
CREATE TABLE IF NOT EXISTS vnext_evaluations (
 stream_id TEXT NOT NULL,event_id TEXT NOT NULL,detector_id TEXT NOT NULL,
 episode_id TEXT NOT NULL,met INTEGER NOT NULL,actual INTEGER NOT NULL,
 required INTEGER NOT NULL,reason_code TEXT NOT NULL,evidence_ids_json TEXT NOT NULL,
 created_utc TEXT NOT NULL,PRIMARY KEY(stream_id,event_id,detector_id)
);
CREATE TABLE IF NOT EXISTS vnext_signals (
 episode_id TEXT NOT NULL,detector_id TEXT NOT NULL,first_event_id TEXT NOT NULL,
 last_event_id TEXT NOT NULL,hit_count INTEGER NOT NULL,evidence_ids_json TEXT NOT NULL,
 updated_utc TEXT NOT NULL,PRIMARY KEY(episode_id,detector_id)
);
CREATE TABLE IF NOT EXISTS vnext_cases (
 case_id TEXT PRIMARY KEY,episode_id TEXT NOT NULL UNIQUE,stream_id TEXT NOT NULL,
 source_key TEXT NOT NULL,source_ip TEXT NOT NULL,first_event_id TEXT NOT NULL,
 last_event_id TEXT NOT NULL,severity TEXT NOT NULL,peak_p15 INTEGER,
 evidence_count INTEGER NOT NULL,signal_ids_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED',isolation_authorized INTEGER NOT NULL DEFAULT 0,
 created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vnext_case_evidence (
 case_id TEXT NOT NULL,stream_id TEXT NOT NULL,event_id TEXT NOT NULL,
 request_id TEXT NOT NULL,reason TEXT NOT NULL,
 PRIMARY KEY(case_id,stream_id,event_id)
);
CREATE TABLE IF NOT EXISTS vnext_trace_outbox (
 trace_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,
 delivered INTEGER NOT NULL DEFAULT 0,created_utc TEXT NOT NULL
);
'''


def canonical(data):
    return json.dumps(data, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def nowiso():
    return datetime.now(timezone.utc).isoformat()


def digest(*parts):
    return hashlib.sha256(canonical(parts).encode()).hexdigest()[:24]


def ensure_schema(db):
    """Additive migration: run ONLY while original P17 worker is stopped."""
    db.executescript(SCHEMA)
    db.execute("CREATE TABLE IF NOT EXISTS vnext_profile (k TEXT PRIMARY KEY,v TEXT NOT NULL)")
    old = db.execute("SELECT v FROM vnext_profile WHERE k='profile'").fetchone()
    if old and old[0] != PROFILE:
        raise ValueError("VNEXT_PROFILE_VERSION_CONFLICT")
    db.execute("INSERT OR IGNORE INTO vnext_profile VALUES ('profile',?)", (PROFILE,))
    db.commit()


def _groups(rules):
    return sorted(k for k, rs in GROUPS.items() if set(rules) & rs)


def _safe_sha256(value):
    return value if isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value) else None


def _projection(delivery, ev, key, seq, event_class, live, episode_id):
    record = delivery['envelope']['record']
    meta = delivery['envelope']['metadata']
    rules = sorted(ev.matched_rules)
    blocking = sorted(x for x in record.get('blocking_rules', []) if x in ev.matched_rules) if isinstance(record.get('blocking_rules'), list) else None
    monitored = sorted(x for x in record.get('monitor_rules', []) if x in ev.matched_rules) if isinstance(record.get('monitor_rules'), list) else None
    allow = sorted(x for x in record.get('allow_rules', []) if x in ev.matched_rules) if isinstance(record.get('allow_rules'), list) else None
    score_breakdown = record.get('score_breakdown')
    # Only canonical numbers/rule ids and enum-like names; never persist explanation/free-text from producer.
    breakdown = None
    if isinstance(score_breakdown, list) and len(score_breakdown) <= 48:
        clean = []
        for item in score_breakdown:
            if not isinstance(item, dict) or type(item.get('score')) is not int or not (0 <= item['score'] <= 100):
                clean = []
                break
            clean.append({'rule_id': item.get('rule_id') if item.get('rule_id') in ev.matched_rules else None,
                          'score': item['score']})
        if clean and type(record.get('raw_score')) is int and sum(x['score'] for x in clean) == record['raw_score']:
            breakdown = clean
    source_status = 'CLEAR_ALLOWED' if ev.identity_complete else 'WITHHELD_SESSION_SCOPED'
    if not live:
        why = 'EVENT_CLASS_'+event_class
    elif ev.risk_status != 'OK':
        why = 'P15_SCORE_UNAVAILABLE'
    elif not ev.identity_complete:
        why = 'DB_USER_WITHHELD_REVIEW_ONLY'
    else:
        why = 'QUALIFIED_SOURCE_REVIEW'
    evidence = {
        'rules': rules, 'groups': _groups(rules), 'monitor_rules': monitored if monitored is not None else sorted(set(rules)&MONITOR),
        'blocking_rules': blocking, 'allow_rules': allow,
        'defaulted': record.get('defaulted') if type(record.get('defaulted')) is bool else None,
        'effective_action': record.get('effective_action'), 'action_result': ev.action_result,
        'risk_status': ev.risk_status,'risk_score': ev.risk_score,
        'raw_score': record.get('raw_score') if ev.risk_status == 'OK' and type(record.get('raw_score')) is int else None,
        'score_breakdown': breakdown,
        'policy_version': record.get('policy_version'), 'risk_version': record.get('risk_version'),
        'session_id': meta.get('session_id') if isinstance(meta.get('session_id'), str) else None,
        'client_ip': ev.client_ip,
    }
    return evidence, {
        'schema': PROFILE, 'event_id': ev.event_id, 'stream_id': delivery['stream_id'],
        'request_id': ev.request_id, 'stream_sequence': seq, 'source_key_hash': key,
        'episode_id': episode_id, 'source_ip': ev.client_ip,
        'db_user': ev.db_user if ev.identity_complete else None,
        'identity_status': source_status, 'event_time': ev.time_utc.isoformat(),
        'event_class': event_class, 'eligible_for_source_review': why == 'QUALIFIED_SOURCE_REVIEW',
        'eligibility_reason': why, 'payload_sha256': ev.payload_sha256,
        'p14': {'policy_version': record.get('policy_version'), 'policy_config_sha256': _safe_sha256(meta.get('policy_config_hash')),
                'effective_action': record.get('effective_action'),
                'actual_result': ev.action_result, 'matched_rules': rules,
                'blocking_rules': blocking, 'monitor_rules': monitored,
                'allow_rules': allow, 'defaulted': evidence['defaulted']},
        'p15': {'risk_version': record.get('risk_version'),'risk_config_sha256': _safe_sha256(meta.get('risk_config_hash')),
                'status': ev.risk_status,
                'raw_score': evidence['raw_score'], 'risk_score': ev.risk_score,
                'severity': record.get('severity') if ev.risk_status == 'OK' else None,
                'score_breakdown': breakdown,
                'breakdown_status': 'AUDIT_SUM_CONSISTENT' if breakdown is not None else 'UNAVAILABLE'},
        'p16h': {'stream_id': delivery['stream_id'], 'stream_sequence': seq,
                 'event_id': ev.event_id, 'request_id': ev.request_id,
                 'producer_id': ev.source_id, 'session_id': meta.get('session_id') if isinstance(meta.get('session_id'),str) else None,
                 'journal_stream_id': delivery.get('journal_stream_id'),
                 'payload_sha256': ev.payload_sha256},
        'p17': {'profile': PROFILE, 'matched_signals': [], 'case_id': None, 'action_authorized': False,
                'detection_scope': 'LAST_256_QUALIFIED_SOURCE_EVENTS_NO_TIME_WINDOW'},
    }, why


def _unique(rows):
    seen = set()
    out = []
    for r in rows:
        if r['request_id'] in seen:
            continue
        seen.add(r['request_id'])
        out.append(r)
    return out


def _has(r, groups):
    return bool(set(r['rules']) & set(groups))


def detect(rows):
    """Return detector_id -> (matched, actual, required, matching_event_ids).

    Input is a bounded, ordered source event history. A single event contributes
    once to a detector, regardless of how many policy rules it matched.
    """
    rows = _unique(sorted(rows, key=lambda r: r['seq']))
    blocked = [r for r in rows if r['blocked']]
    active_blocks = [r for r in blocked if not (r['rules'] and set(r['rules']) <= COMPAT)]
    injection = [r for r in blocked if _has(r, INJECTION)]
    sensitive = [r for r in blocked if _has(r, SENSITIVE)]
    compat = [r for r in rows if _has(r, COMPAT)]
    signals = []
    signatures = set()
    for r in blocked:
        grp = _groups(r['rules'])
        if grp:
            signals.extend(grp)
            signatures.add(tuple(sorted(set(r['rules']) & set().union(*GROUPS.values()))))
    unauthorized = [r for r in blocked if _has(r, {'CTX-003','DML-010','DML-011','DML-012','VIEW-001'})]
    enumerated = [r for r in blocked if _has(r, {'ENUM-001'})]
    oversized = [r for r in blocked if _has(r, {'RES-001'})]
    monitored = [r for r in rows if _has(r, MONITOR)]
    defaulted = [r for r in blocked if r['defaulted'] is True]
    target = {}
    def add(code, selected, required=1, extra_ok=True, actual_override=None):
        unique = _unique(selected)
        actual = len(unique) if actual_override is None else actual_override
        target[code] = (bool(actual >= required and extra_ok), actual, required, [x['event_id'] for x in unique])
    add('CORR-001', active_blocks, 5)
    add('CORR-002', injection, 3)
    add('CORR-003', sensitive, 3)
    add('CORR-004', [r for r in blocked if _groups(r['rules'])], 3,
        len(set(signals)) >= 3 and len(signatures) >= 2)
    add('CORR-005', compat, 5)
    add('CORR-006', [r for r in blocked if _has(r, {'DCL-001'})])
    add('CORR-007', [r for r in blocked if _has(r, {'DDL-001'})])
    add('CORR-008', [r for r in blocked if _has(r, {'FILE-001'})])
    add('CORR-009', [r for r in blocked if _has(r, {'DML-001','DML-002'})])
    add('CORR-010', unauthorized, 2)
    add('CORR-011', [r for r in blocked if _has(r, {'CTX-001','CTX-007'})])
    add('CORR-012', [r for r in blocked if _has(r, {'CTX-006'})])
    add('CORR-013', [r for r in blocked if _has(r, {'CTX-006'}) and _has(r, INJECTION)])
    add('CORR-014', enumerated, 2)
    ordered_combo = []
    for first in enumerated:
        later = next((r for r in blocked if r['seq'] > first['seq']
                    and _has(r, INJECTION | SENSITIVE | frozenset({'DCL-001','DDL-001'}))), None)
        if later:
            ordered_combo = [first, later]
            break
    add('CORR-015', ordered_combo, 2)
    add('CORR-016', [r for r in blocked if _has(r, {'OBJ-005'})])
    add('CORR-017', [r for r in blocked if _has(r, {'PROTO-003'})])
    add('CORR-018', oversized, 2)
    add('CORR-019', monitored, 3)
    add('CORR-020', defaulted, 5)
    add('CORR-021', [r for r in blocked if _has(r, INJECTION) and _has(r, SENSITIVE)])
    escalation = []
    for first in blocked:
        if not _has(first, INJECTION | SENSITIVE | frozenset({'ENUM-001'})):
            continue
        later = next((r for r in blocked if r['seq'] > first['seq']
                      and _has(r, {'DCL-001', 'DDL-001', 'FILE-001'})), None)
        if later:
            escalation = [first, later]
            break
    add('CORR-022', escalation, 2)
    assert set(target) == set(DETECTORS)
    return target


def _outbox(db, kind, unique, payload):
    trace_id = 'VN-'+digest(kind, unique)
    db.execute('INSERT OR IGNORE INTO vnext_trace_outbox(trace_id,event_type,payload_json,created_utc) VALUES (?,?,?,?)',
               (trace_id, kind, canonical(payload), nowiso()))


def observe(db, delivery, ev, source_key, event_class, live):
    """Invoked after legacy processed_events INSERT, inside same transaction."""
    stream_id = delivery['stream_id']
    record = delivery['envelope']['record']
    seq = delivery['stream_sequence']
    policy_version, risk_version = record.get('policy_version'), record.get('risk_version')
    if not isinstance(policy_version, str) or not isinstance(risk_version, str):
        raise ValueError('VNEXT_VERSION_REQUIRED')
    episode_id = 'EP-'+digest(stream_id, source_key, policy_version, risk_version)
    now = nowiso()
    db.execute('''INSERT OR IGNORE INTO vnext_episodes
        (episode_id,stream_id,source_key,policy_version,risk_version,first_seq,last_seq,created_utc,updated_utc)
        VALUES (?,?,?,?,?,?,?,?,?)''',
        (episode_id,stream_id,source_key,policy_version,risk_version,seq,seq,now,now))
    db.execute('''UPDATE vnext_episodes SET last_seq=MAX(last_seq,?),updated_utc=? WHERE episode_id=?''',
               (seq,now,episode_id))
    evidence, trace, why = _projection(delivery, ev, source_key, seq, event_class, live, episode_id)
    db.execute('''INSERT INTO vnext_events
        (stream_id,event_id,request_id,stream_sequence,source_key,episode_id,event_ms,event_class,
         qualify_reason,blocked,risk_status,risk_score,evidence_json,trace_json,created_utc)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (stream_id,ev.event_id,ev.request_id,seq,source_key,episode_id,int(ev.time_utc.timestamp()*1000),
         event_class,why,int(ev.blocked),ev.risk_status,ev.risk_score,canonical(evidence),canonical(trace),now))
    qualified = why == 'QUALIFIED_SOURCE_REVIEW'
    if qualified:
        events = db.execute('''SELECT event_id,request_id,stream_sequence,blocked,evidence_json
             FROM vnext_events WHERE episode_id=? AND qualify_reason='QUALIFIED_SOURCE_REVIEW'
             ORDER BY stream_sequence DESC LIMIT ?''',(episode_id,MAX_EVIDENCE)).fetchall()
        rows = []
        for eid,rid,s,blocked,evidence_json in reversed(events):
            info = json.loads(evidence_json)
            rows.append({'event_id':eid,'request_id':rid,'seq':s,'blocked':bool(blocked),
                         'rules':info['rules'],'defaulted':info['defaulted']})
        evaluated = detect(rows)
    else:
        evaluated = {k:(False,0,1,[]) for k in DETECTORS}
    matched = []
    active_matched = []
    meaningful = {}
    for det_id, (met,actual,required,ids) in evaluated.items():
        # Existing source-context evidence may remain sufficient even when this
        # specific request did not participate. Never retrigger a case from an
        # unrelated ALLOW or unrelated BLOCK event.
        newly_relevant = met and ev.event_id in ids
        reason = ('EVIDENCE_NOT_LIVE_QUALIFIED' if not qualified else
                  'MATCHED_CURRENT_REQUEST' if newly_relevant else
                  'MET_BY_PRIOR_REQUESTS' if met else 'INSUFFICIENT_OR_UNMATCHED_EVIDENCE')
        db.execute('''INSERT INTO vnext_evaluations
            (stream_id,event_id,detector_id,episode_id,met,actual,required,reason_code,evidence_ids_json,created_utc)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (stream_id,ev.event_id,det_id,episode_id,int(met),actual,required,reason,canonical(ids),now))
        if met:
            active_matched.append(det_id)
        if newly_relevant:
            matched.append(det_id)
            meaningful[det_id] = ids
            db.execute('''INSERT INTO vnext_signals
                (episode_id,detector_id,first_event_id,last_event_id,hit_count,evidence_ids_json,updated_utc)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(episode_id,detector_id) DO UPDATE SET
                  last_event_id=excluded.last_event_id,
                  hit_count=hit_count+1,evidence_ids_json=excluded.evidence_ids_json,
                  updated_utc=excluded.updated_utc''',
                (episode_id,det_id,ev.event_id,ev.event_id,1,canonical(ids),now))
    caseworthy = [det_id for det_id in matched if DETECTORS[det_id][1]]
    case_id = None
    if caseworthy:
        case_id = 'VNC-'+digest(episode_id)
        severity = max((DETECTORS[d][0] for d in caseworthy),key=lambda s:SEV_RANK[s])
        before = db.execute('SELECT severity,signal_ids_json FROM vnext_cases WHERE case_id=?',(case_id,)).fetchone()
        db.execute('''INSERT OR IGNORE INTO vnext_cases
            (case_id,episode_id,stream_id,source_key,source_ip,first_event_id,last_event_id,
             severity,peak_p15,evidence_count,signal_ids_json,status,isolation_authorized,created_utc,updated_utc)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (case_id,episode_id,stream_id,source_key,ev.client_ip,ev.event_id,ev.event_id,
             severity,ev.risk_score,0,canonical(caseworthy),'REVIEW_REQUIRED',0,now,now))
        for det_id in caseworthy:
            ids = meaningful[det_id]
            for eid in ids:
                e_row = db.execute('SELECT request_id FROM vnext_events WHERE stream_id=? AND event_id=?',(stream_id,eid)).fetchone()
                if e_row:
                    db.execute('''INSERT OR IGNORE INTO vnext_case_evidence
                        (case_id,stream_id,event_id,request_id,reason) VALUES (?,?,?,?,?)''',
                        (case_id,stream_id,eid,e_row[0],det_id))
        new_signals = sorted(set(caseworthy) | (set(json.loads(before[1])) if before else set()))
        newer_sev = max([severity,before[0]] if before else [severity],key=lambda s:SEV_RANK[s])
        n = db.execute('SELECT COUNT(*) FROM vnext_case_evidence WHERE case_id=?',(case_id,)).fetchone()[0]
        peakrow = db.execute('''SELECT MAX(e.risk_score) FROM vnext_case_evidence ce
            JOIN vnext_events e ON ce.stream_id=e.stream_id AND ce.event_id=e.event_id
            WHERE ce.case_id=? AND e.risk_status='OK' ''',(case_id,)).fetchone()
        db.execute('''UPDATE vnext_cases SET last_event_id=?,severity=?,peak_p15=?,evidence_count=?,
            signal_ids_json=?,updated_utc=? WHERE case_id=?''',
            (ev.event_id,newer_sev,peakrow[0],n,canonical(new_signals),now,case_id))
        if before is None or set(new_signals) != set(json.loads(before[1])):
            _outbox(db,'P17_VNEXT_CASE_'+('CREATED' if before is None else 'UPDATED'),
                    (case_id,ev.event_id),
                    {'case_id':case_id,'event_id':ev.event_id,'source_ip':ev.client_ip,
                     'detectors':new_signals,'severity':newer_sev,'evidence_count':n,
                     'p15_peak':peakrow[0],'status':'REVIEW_REQUIRED',
                     'isolation_authorized':False,'profile':PROFILE})
    trace['p17']['matched_signals']=matched
    trace['p17']['active_source_signals']=active_matched
    trace['p17']['case_id']=case_id
    trace['p17']['detector_evaluations']={k:{'met':met,'actual':actual,'required':required,
        'reason':'MATCHED' if met else ('EXCLUDED_'+why if not qualified else 'NOT_MET'),
        'evidence_ids':ids[-12:]} for k,(met,actual,required,ids) in evaluated.items()}
    db.execute('UPDATE vnext_events SET trace_json=? WHERE stream_id=? AND event_id=?',
               (canonical(trace),stream_id,ev.event_id))
    _outbox(db,'P17_VNEXT_EVENT_EVALUATED',(stream_id,ev.event_id),
            {'stream_id':stream_id,'event_id':ev.event_id,'request_id':ev.request_id,
             'stream_sequence':seq,'source_ip':ev.client_ip,'p14_action':trace['p14']['effective_action'],
             'matched_rules':evidence['rules'],'p15_risk_score':ev.risk_score,
             'p15_risk_status':ev.risk_status,'event_class':event_class,'qualification':why,
             'matched_signals':matched,'case_id':case_id,'isolation_authorized':False,'profile':PROFILE})
    return {'case_id':case_id,'signals':matched,'qualified':qualified}


def export_trace(db,filepath,limit=256):
    """At-least-once JSONL output. Consumer dedups by trace_id. No raw SQL."""
    p = Path(filepath)
    if p.is_symlink() or not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError('VNEXT_LOG_PATH_UNSAFE')
    batch = db.execute('''SELECT trace_id,event_type,payload_json FROM vnext_trace_outbox
                         WHERE delivered=0 ORDER BY rowid LIMIT ?''',(limit,)).fetchall()
    for trace_id,kind,payload in batch:
        line = canonical({'trace_id':trace_id,'event_type':kind,'payload':json.loads(payload)})+'\n'
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
        try:
            data=line.encode('ascii')
            while data:
                n=os.write(fd,data)
                if n <= 0:raise OSError('VNEXT_LOG_WRITE_FAILED')
                data=data[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('UPDATE vnext_trace_outbox SET delivered=1 WHERE trace_id=?',(trace_id,))
            db.commit()
        except Exception:
            db.rollback()
            raise
    return len(batch)
