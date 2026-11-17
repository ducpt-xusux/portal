"""P17.2 durable local incident worker: P16H canonical POLL -> SQLite commit -> ACK.

This code NEVER issues SQL queries, NEVER uses OpenStack APIs, NEVER mutates P16H
SQLite, and NEVER authorizes isolation. Detection thresholds are laboratory
candidates, not calibrated production security-response thresholds.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from p17_core import Event, EvidenceError, GROUPS, COMPAT, normalize, aware_date, canonical
from p17_vnext import ensure_schema as ensure_vnext_schema, observe as observe_vnext, export_trace as export_vnext_trace

DEFAULT_DB = '/var/lib/db-firewall-p17/state.sqlite3'
DEFAULT_ALERTS = '/var/log/db-firewall-p17/alerts.jsonl'
DEFAULT_MARKER = '/home/ubuntu/P16H_LOCAL_READY_FOR_P17'
CORR_SEVERITY = {'CORR-001':'WARNING','CORR-002':'HIGH','CORR-003':'HIGH',
                 'CORR-004':'CRITICAL','CORR-005':'WARNING'}
SCHEMA_ID='p17-incident-durable-1'
MAX_LIVE_LATENCY_S=300
SOURCE_WINDOW_S=120

class P17Stop(Exception):
    pass


def utcnow():
    return datetime.now(timezone.utc)


def iso(t=None):
    return (t or utcnow()).isoformat()


def millis(t):
    return int(t.timestamp()*1000)


def path_check(p, *, exists=True):
    p=Path(p)
    if p.is_symlink():raise P17Stop('SYMLINK_DENIED:'+str(p))
    if exists and not p.is_file():raise P17Stop('FILE_MISSING:'+str(p))
    if p.parent.is_symlink():raise P17Stop('PARENT_SYMLINK_DENIED:'+str(p))
    return p


def marker_release(marker=DEFAULT_MARKER):
    m=json.loads(path_check(marker).read_text())
    p=Path(m.get('release',''))
    if (m.get('status')!='LOCAL_ACCEPTANCE_PASS' or
        not str(p).startswith('/opt/db-firewall/releases/p16h-local-') or
        not p.is_dir() or p.is_symlink()):
        raise P17Stop('P16H_ACCEPTANCE_MARKER_INVALID')
    return p,m


def reader_request(cmd, *, marker=DEFAULT_MARKER):
    release,_=marker_release(marker)
    if str(release) not in sys.path:sys.path.insert(0,str(release))
    from p16h_local.client import request
    return request(cmd)


def preflight(marker=DEFAULT_MARKER):
    release,_=marker_release(marker)
    health=reader_request({'op':'HEALTH'},marker=marker)
    if health.get('status')!='RUNNING':
        raise P17Stop('P16H_COLLECTOR_NOT_RUNNING')
    if not isinstance(health.get('stream_id'),str) or not health['stream_id']:
        raise P17Stop('P16H_STREAM_ID_INVALID')
    if (type(health.get('p17_cursor')) is not int or
        type(health.get('p17_pending')) is not int):
        raise P17Stop('P16H_CURSOR_INVALID')
    recent=reader_request({'op':'RECENT','limit':16},marker=marker)
    if not isinstance(recent,list):raise P17Stop('P16H_RECENT_INVALID')
    for x in recent:normalize(x)
    return health,len(recent),str(release)


def dbconnect(dbpath,*,create=False):
    path=path_check(dbpath,exists=not create)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise P17Stop('P17_STATE_DIRECTORY_UNSAFE')
    db=sqlite3.connect(str(path), timeout=10,isolation_level=None)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=5000')
        if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':
            raise P17Stop('P17_SQLITE_INTEGRITY_CHECK_FAILED')
        if path.exists():os.chmod(path,0o600)
    except Exception:
        db.close();raise
    return db


DDL='''
CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE processed_events (
 stream_id TEXT NOT NULL,event_id TEXT NOT NULL,request_id TEXT NOT NULL,
 stream_sequence INTEGER NOT NULL,payload_sha256 TEXT NOT NULL,
 source_id TEXT NOT NULL,client_ip TEXT NOT NULL,source_key TEXT NOT NULL,
 session_id TEXT,db_user TEXT,identity_complete INTEGER NOT NULL,
 event_ms INTEGER NOT NULL,received_utc TEXT NOT NULL,
 risk_status TEXT NOT NULL,risk_score INTEGER,blocked INTEGER NOT NULL,
 rules_json TEXT NOT NULL,groups_json TEXT NOT NULL,
 event_class TEXT NOT NULL,live_eligible INTEGER NOT NULL,
 PRIMARY KEY (stream_id,event_id),
 UNIQUE (stream_id,stream_sequence),
 UNIQUE (stream_id,request_id)
);
CREATE INDEX ix_p17_features ON processed_events (source_key,live_eligible,event_ms);
CREATE TABLE incidents (
 incident_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
 source_key TEXT NOT NULL,client_ip TEXT NOT NULL,signal_rule TEXT NOT NULL,
 first_ms INTEGER NOT NULL,last_ms INTEGER NOT NULL,
 evidence_count INTEGER NOT NULL,peak_p15 INTEGER,
 severity TEXT NOT NULL,confidence TEXT NOT NULL,
 status TEXT NOT NULL,source_verified INTEGER NOT NULL DEFAULT 0,
 isolation_authorized INTEGER NOT NULL DEFAULT 0,
 created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL
);
CREATE INDEX ix_p17_incidents ON incidents (stream_id,source_key,signal_rule,last_ms);
CREATE TABLE outbox (
 alert_id TEXT PRIMARY KEY,incident_id TEXT,event_id TEXT NOT NULL,
 alert_json TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,
 created_utc TEXT NOT NULL
);
'''


def initialize(dbpath,*,marker=DEFAULT_MARKER,health=None,when=None):
    h=health if health is not None else preflight(marker)[0]
    if h['p17_cursor']!=0:
        raise P17Stop('INITIAL_BOOTSTRAP_REQUIRES_P16H_CURSOR_ZERO')
    p=Path(dbpath)
    if p.exists():raise P17Stop('P17_DB_ALREADY_EXISTS_USE_RUN')
    db=dbconnect(p,create=True)
    try:
        db.executescript(DDL)
        state={'schema':SCHEMA_ID,'stream_id':h['stream_id'],
               'last_committed_sequence':str(h['p17_cursor']),
               'activated_utc':iso(when),'source_p16h_release':marker_release(marker)[0].name,
               'approved_auto_containment':'false'}
        db.executemany('INSERT INTO metadata(key,value) VALUES (?,?)',state.items())
        db.commit()
    except Exception:
        db.close()
        # Do not automatically remove a possibly partly initialized DB.
        raise
    finally:
        try:db.close()
        except Exception:pass
    return state


def meta(db):
    d=dict(db.execute('SELECT key,value FROM metadata').fetchall())
    if d.get('schema')!=SCHEMA_ID:raise P17Stop('P17_SCHEMA_MISMATCH')
    return d


def source_group(ev,raw,stream_id):
    m=raw['envelope']['metadata']
    # If db_user is withheld, do not merge *different* unknown users.
    # Group only within the same source IP + verified P16H session identifier.
    if ev.identity_complete:
        qualifier='clear-user:'+ev.db_user
    else:
        sid=m.get('session_id')
        if not isinstance(sid,str) or not sid:
            raise P17Stop('WITHHELD_USER_WITHOUT_SESSION_ID')
        qualifier='withheld-session:'+sid
    material=json.dumps([stream_id,ev.source_id,ev.client_ip,qualifier],separators=(',',':'))
    return hashlib.sha256(material.encode()).hexdigest()


def classify_event(ev,now,activated,last_max_ms):
    ems=millis(ev.time_utc)
    if ems<millis(activated):return 'HISTORICAL',0
    if (now-ev.time_utc).total_seconds()>MAX_LIVE_LATENCY_S:
        return 'STALE',0
    if (ev.time_utc-now).total_seconds()>30:
        return 'FUTURE_SKEW',0
    if last_max_ms is not None and ems<last_max_ms:
        return 'OUT_OF_ORDER',0
    return 'LIVE',1


def _event_from_row(row):
    return Event(source_id=row[0],event_id=row[1],request_id=row[2],
        time_utc=datetime.fromtimestamp(row[3]/1000,tz=timezone.utc),
        client_ip=row[4],db_user=row[5],identity_complete=bool(row[6]),
        matched_rules=frozenset(json.loads(row[7])),
        risk_score=row[8],risk_status=row[9],blocked=bool(row[10]),
        action_result='BLOCKED' if row[10] else 'FORWARDED',payload_sha256=row[11])


def correlate_current(db,key,ev):
    cutoff=millis(ev.time_utc)-120000
    r=db.execute('''SELECT source_id,event_id,request_id,event_ms,client_ip,db_user,
                    identity_complete,rules_json,risk_score,risk_status,blocked,payload_sha256
                    FROM processed_events WHERE source_key=? AND live_eligible=1 AND event_ms>?
                    ORDER BY event_ms DESC,stream_sequence DESC LIMIT 512''',(key,cutoff)).fetchall()
    evs=sorted((_event_from_row(x) for x in r),key=lambda x:(x.time_utc,x.event_id))
    w60=[x for x in evs if 0<=(ev.time_utc-x.time_utc).total_seconds()<60]
    w120=[x for x in evs if 0<=(ev.time_utc-x.time_utc).total_seconds()<120]
    signals={}
    a=[x for x in w60 if x.blocked and not (x.matched_rules and x.matched_rules<=COMPAT)]
    if len(a)>=5:signals['CORR-001']=a
    a=[x for x in w60 if x.blocked and x.matched_rules&GROUPS['injection']]
    if len(a)>=3:signals['CORR-002']=a
    a=[x for x in w120 if x.blocked and x.matched_rules&GROUPS['sensitive_data']]
    if len(a)>=3:signals['CORR-003']=a
    a=[x for x in w120 if x.blocked and x.group_signals]
    if len(a)>=3 and len(set().union(*(x.group_signals for x in a)))>=3 and len({x.signature for x in a})>=2:
        signals['CORR-004']=a
    a=[x for x in w120 if x.matched_rules&COMPAT]
    if len(a)>=5:signals['CORR-005']=a
    return signals


def store_incident(db,stream_id,key,ev,rule,evidence):
    ts=millis(ev.time_utc)
    row=db.execute('''SELECT incident_id,first_ms,last_ms,evidence_count,peak_p15
                     FROM incidents WHERE stream_id=? AND source_key=? AND signal_rule=?
                     ORDER BY last_ms DESC LIMIT 1''',(stream_id,key,rule)).fetchone()
    scores=[x.risk_score for x in evidence if x.risk_score is not None]
    peak=max(scores) if scores else None
    if row and 0<=ts-row[2]<120000:
        peaknew=max([x for x in (row[4],peak) if x is not None],default=None)
        db.execute('''UPDATE incidents SET last_ms=?,evidence_count=?,peak_p15=?,updated_utc=?
                      WHERE incident_id=?''',
                   (ts,max(row[3],len({x.event_id for x in evidence})),peaknew,iso(),row[0]))
        return row[0],False
    iid='INC-'+hashlib.sha256(f'{stream_id}|{key}|{rule}|{ev.event_id}'.encode()).hexdigest()[:20]
    confidence='CANDIDATE_CORRELATED' if rule in ('CORR-002','CORR-003','CORR-004') else 'REVIEW_REQUIRED'
    status='REVIEW_REQUIRED' if rule!='CORR-005' else 'OPERATIONAL_REVIEW'
    db.execute('''INSERT INTO incidents
       (incident_id,stream_id,source_key,client_ip,signal_rule,first_ms,last_ms,
        evidence_count,peak_p15,severity,confidence,status,created_utc,updated_utc)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
       (iid,stream_id,key,ev.client_ip,rule,ts,ts,len({x.event_id for x in evidence}),
        peak,CORR_SEVERITY[rule],confidence,status,iso(),iso()))
    return iid,True


def alert_outbox(db,alertid,incidentid,ev,rule,peak,count,key):
    category='OPERATIONAL' if rule=='CORR-005' else 'SECURITY_REVIEW'
    data={'schema':'p17-alert-1','alert_id':alertid,'incident_id':incidentid,
          'source_ip':ev.client_ip,'source_key_hash':key,'event_id':ev.event_id,
          'rule':rule,'alert_category':category,'severity':CORR_SEVERITY.get(rule,'HIGH'),
          'p15_peak_risk_score':peak,'evidence_request_count':count,
          'identity_complete':ev.identity_complete,'action_executed':'NONE',
          'isolation_authorized':False,'status':'REVIEW_REQUIRED','timestamp':iso()}
    db.execute('''INSERT OR IGNORE INTO outbox(alert_id,incident_id,event_id,alert_json,created_utc)
                  VALUES(?,?,?,?,?)''',(alertid,incidentid,ev.event_id,
                                        canonical(data).decode(),iso()))


def ensure_batch(batch,stream_id):
    if not isinstance(batch,dict) or batch.get('stream_id')!=stream_id or batch.get('consumer')!='p17':
        raise P17Stop('POLL_STREAM_MISMATCH')
    items=batch.get('items')
    if not isinstance(items,list) or len(items)>32:raise P17Stop('POLL_ITEMS_INVALID')
    if items:
        for prop in ('ack_token','journal_stream_id'):
            if not isinstance(batch.get(prop),str) or not batch[prop]:raise P17Stop('POLL_TOKEN_INVALID')
        if type(batch.get('segment_index')) is not int:raise P17Stop('POLL_SEGMENT_INVALID')
        if (type(batch.get('after_sequence')) is not int or
            type(batch.get('through_sequence')) is not int or
            batch['through_sequence']-batch['after_sequence']!=len(items)):
            raise P17Stop('POLL_RANGE_INVALID')
        for n,item in enumerate(items,1):
            if (type(item.get('stream_sequence')) is not int or
                item['stream_sequence']!=batch['after_sequence']+n or
                item.get('stream_id')!=stream_id or
                item.get('segment_index')!=batch['segment_index'] or
                item.get('journal_stream_id')!=batch['journal_stream_id']):
                raise P17Stop('POLL_ITEM_ORDER_INVALID')
    return items


def process_batch(db,batch,*,now=None):
    """Process one exact P16H POLL response. No ACK in this function."""
    now=now or utcnow()
    md=meta(db);items=ensure_batch(batch,md['stream_id'])
    if not items:return {'processed':0,'duplicates':0,'historical':0,'alerts':0,'last_seq':int(md['last_committed_sequence'])}
    # Verify all envelopes *before* the state transaction.
    normalized=[normalize(d) for d in items]
    result={'processed':0,'duplicates':0,'historical':0,'alerts':0}
    db.execute('BEGIN IMMEDIATE')
    try:
        md=meta(db);last=int(md['last_committed_sequence'])
        active=aware_date(md['activated_utc'])
        for d,ev in zip(items,normalized):
            seq=d['stream_sequence'];stored=db.execute('''SELECT payload_sha256,request_id,stream_sequence
                    FROM processed_events WHERE stream_id=? AND event_id=?''',
                    (md['stream_id'],ev.event_id)).fetchone()
            if stored is not None:
                if (stored[0]!=ev.payload_sha256 or stored[1]!=ev.request_id or stored[2]!=seq):
                    raise P17Stop('EVENT_ID_PAYLOAD_OR_SEQUENCE_CONFLICT')
                if seq>last:raise P17Stop('DUPLICATE_SEQUENCE_AHEAD_OF_CHECKPOINT')
                result['duplicates']+=1;continue
            if seq!=last+1:raise P17Stop('SOURCE_STREAM_SEQUENCE_GAP')
            key=source_group(ev,d,md['stream_id'])
            maxrow=db.execute('SELECT MAX(event_ms) FROM processed_events WHERE source_key=? AND live_eligible=1',(key,)).fetchone()[0]
            event_class,live=classify_event(ev,now,active,maxrow)
            m=d['envelope']['metadata']
            db.execute('''INSERT INTO processed_events
              (stream_id,event_id,request_id,stream_sequence,payload_sha256,
               source_id,client_ip,source_key,session_id,db_user,identity_complete,
               event_ms,received_utc,risk_status,risk_score,blocked,rules_json,groups_json,
               event_class,live_eligible)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
              (md['stream_id'],ev.event_id,ev.request_id,seq,ev.payload_sha256,
               ev.source_id,ev.client_ip,key,m.get('session_id'),ev.db_user,int(ev.identity_complete),
               millis(ev.time_utc),iso(now),ev.risk_status,ev.risk_score,int(ev.blocked),
               canonical(sorted(ev.matched_rules)).decode(),canonical(sorted(ev.group_signals)).decode(),
               event_class,live))
            last=seq;result['processed']+=1
            # VNext: additive, review-only trace inside the legacy commit boundary.
            # Never modifies legacy Incident/outbox semantics or P16H ACK logic.
            if os.environ.get('P17_VNEXT_ENABLED','1') == '1':
                observe_vnext(db,d,ev,key,event_class,live)
            if not live:
                result['historical']+=1
                continue
            if (ev.blocked and ev.risk_score is not None and ev.risk_score>=60
                and ev.group_signals and not (ev.matched_rules and ev.matched_rules<=COMPAT)):
                alertid='P15-'+hashlib.sha256(f'{md["stream_id"]}|{ev.event_id}|single'.encode()).hexdigest()[:24]
                alert_outbox(db,alertid,None,ev,'SINGLE_P15_HIGH',ev.risk_score,1,key)
                result['alerts']+=1
            matches=correlate_current(db,key,ev)
            for rule,evidence in sorted(matches.items()):
                iid,created=store_incident(db,md['stream_id'],key,ev,rule,evidence)
                if created:
                    alertid='P17-'+hashlib.sha256(f'{iid}|open'.encode()).hexdigest()[:24]
                    peak=max((x.risk_score for x in evidence if x.risk_score is not None),default=None)
                    alert_outbox(db,alertid,iid,ev,rule,peak,len({x.event_id for x in evidence}),key)
                    result['alerts']+=1
        db.execute('UPDATE metadata SET value=? WHERE key=?',(str(last),'last_committed_sequence'))
        db.commit()
        result['last_seq']=last
    except Exception:
        db.rollback();raise
    return result


def export_alerts(db,filepath):
    p=Path(filepath)
    if p.is_symlink() or not p.parent.is_dir() or p.parent.is_symlink():
        raise P17Stop('ALERT_OUTPUT_PATH_UNSAFE')
    pending=db.execute('SELECT alert_id,alert_json FROM outbox WHERE delivered=0 ORDER BY rowid LIMIT 128').fetchall()
    for aid,line in pending:
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
        try:
            data=line.encode('ascii')+b'\n'
            while data:
                n=os.write(fd,data);data=data[n:]
            os.fsync(fd)
        finally:os.close(fd)
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('UPDATE outbox SET delivered=1 WHERE alert_id=?',(aid,))
            db.commit()
        except Exception:db.rollback();raise
    return len(pending)


def work_once(db,request_fn,*,alert_log=DEFAULT_ALERTS,vnext_trace='/var/log/db-firewall-p17/vnext-trace.jsonl',now=None):
    md=meta(db)
    health=request_fn({'op':'HEALTH'})
    if health.get('stream_id')!=md['stream_id']:raise P17Stop('P16H_STREAM_CHANGED_STOP')
    if health.get('status')!='RUNNING':raise P17Stop('P16H_HEALTH_DEGRADED_STOP')
    if type(health.get('p17_cursor')) is not int or health['p17_cursor']>int(md['last_committed_sequence']):
        raise P17Stop('P16H_CURSOR_AHEAD_OF_LOCAL_DB')
    batch=request_fn({'op':'POLL','limit':32})
    r=process_batch(db,batch,now=now)
    if batch['items']:
        acknowledgement=request_fn({'op':'ACK','batch':batch})
        if (acknowledgement.get('status')!='ACK_COMMITTED' or
                acknowledgement.get('stream_id')!=md['stream_id'] or
                acknowledgement.get('through_sequence')!=batch['through_sequence']):
            raise P17Stop('P16H_ACK_RECEIPT_INVALID')
    count=export_alerts(db,alert_log)
    vnext_exported=(export_vnext_trace(db,vnext_trace)
                    if os.environ.get('P17_VNEXT_ENABLED','1') == '1' else 0)
    return dict(r,exported=count,vnext_exported=vnext_exported,ack=bool(batch['items']))


def worker_lock(dbpath):
    p=Path(str(dbpath)+'.lock')
    if p.is_symlink():raise P17Stop('LOCK_SYMLINK_DENIED')
    fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd);raise P17Stop('P17_WORKER_ALREADY_RUNNING')
    return fd


def show_state(db,*,marker=DEFAULT_MARKER):
    md=meta(db)
    evt=db.execute('SELECT COUNT(*) FROM processed_events').fetchone()[0]
    hist=db.execute('SELECT COUNT(*) FROM processed_events WHERE live_eligible=0').fetchone()[0]
    incidents=db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
    alerts=db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]
    pending=db.execute('SELECT COUNT(*) FROM outbox WHERE delivered=0').fetchone()[0]
    health=reader_request({'op':'HEALTH'},marker=marker)
    return {'p17_schema':md['schema'],'p17_stream_id':md['stream_id'],
       'p17_last_committed_sequence':int(md['last_committed_sequence']),
       'p16h_cursor':health.get('p17_cursor'),'p16h_pending':health.get('p17_pending'),
       'local_processed_events':evt,'historical_or_late_events':hist,
       'incident_count':incidents,'outbox_total':alerts,'outbox_not_exported':pending,
       'auto_isolation':False,'openstack_access':False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('cmd',choices=['preflight','init','once','run','status','incidents'])
    p.add_argument('--db',default=DEFAULT_DB)
    p.add_argument('--alerts',default=DEFAULT_ALERTS)
    p.add_argument('--marker',default=DEFAULT_MARKER)
    p.add_argument('--max-batches',type=int,default=100)
    p.add_argument('--vnext-trace',default='/var/log/db-firewall-p17/vnext-trace.jsonl')
    args=p.parse_args(argv)
    if args.cmd=='preflight':
        h,n,release=preflight(args.marker)
        print('P17_2_READER_PREFLIGHT_PASS')
        print('P16H_RELEASE='+release)
        print('P16H_STREAM='+h['stream_id'])
        print('P16H_CURSOR='+str(h['p17_cursor']))
        print('P16H_PENDING='+str(h['p17_pending']))
        print('P16H_RECENT_VALIDATED='+str(n))
        print('NO_POLL_NO_ACK_NO_OPENSTACK')
        return
    if args.cmd=='init':
        h,_,_=preflight(args.marker)
        info=initialize(args.db,marker=args.marker,health=h)
        print('P17_2_STATE_INITIALIZED')
        print('P17_2_ACTIVATED_UTC='+info['activated_utc'])
        print('BACKLOG_BEFORE_ACTIVATION_IS_HISTORICAL')
        return
    if args.cmd in ('once','run'):
        fd=worker_lock(args.db)
    else:fd=None
    try:
        db=dbconnect(args.db)
        if args.cmd in ('once','run') and os.environ.get('P17_VNEXT_ENABLED','1') == '1':
            ensure_vnext_schema(db)
        try:
            if args.cmd=='status':
                print(json.dumps(show_state(db,marker=args.marker),sort_keys=True,indent=2))
            elif args.cmd=='incidents':
                rows=db.execute('''SELECT incident_id,client_ip,signal_rule,
                     evidence_count,peak_p15,severity,confidence,status,
                     source_verified,isolation_authorized FROM incidents
                     ORDER BY updated_utc DESC LIMIT 25''').fetchall()
                keys=['incident_id','client_ip','signal_rule','evidence_count','peak_p15',
                      'severity','confidence','status','source_verified','isolation_authorized']
                print(json.dumps([dict(zip(keys,r)) for r in rows],indent=2,sort_keys=True))
        finally:
            if args.cmd in ('status','incidents'):db.close()
        if args.cmd in ('once','run'):
            marker_release(args.marker)
            # Ensure import from the exact accepted release, not caller PYTHONPATH.
            release,_=marker_release(args.marker)
            if str(release) not in sys.path:sys.path.insert(0,str(release))
            from p16h_local.client import request
            db=db if not (args.cmd in ('status','incidents')) else dbconnect(args.db)
            stop=[False]
            def handler(*_):stop[0]=True
            if args.cmd=='run':
                signal.signal(signal.SIGTERM,handler)
                signal.signal(signal.SIGINT,handler)
            i=0
            while not stop[0]:
                res=work_once(db,request,alert_log=args.alerts,vnext_trace=args.vnext_trace)
                i+=1
                if args.cmd=='once' or res['ack'] or i%30==0:
                    print('P17_2_BATCH_PASS '+json.dumps(res,sort_keys=True),flush=True)
                if args.cmd=='once' and (not res['ack'] or i>=args.max_batches):break
                if args.cmd=='run' and not res['ack']:time.sleep(2)
            db.close()
            print('P17_2_LOCAL_WORKER_PASS; NO_OPENSTACK; NO_ISOLATION',flush=True)
    finally:
        if fd is not None:os.close(fd)


if __name__=='__main__':
    try:main()
    except (P17Stop,EvidenceError,sqlite3.DatabaseError,ValueError,OSError,KeyError) as exc:
        print('P17_2_STOP '+type(exc).__name__+': '+str(exc),file=sys.stderr)
        raise SystemExit(2)
