"""Offline regression tests built against the captured G03 V3 production modules.
No P16H socket, Neutron, MariaDB, root or external network access.
"""
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import p17_core
import p17_durable as durable
import p17_vnext as vnext
sys.path.insert(0, str(HERE / 'scripts'))
import vnext_report

BASE = dt.datetime(2026, 11, 15, 1, 0, tzinfo=dt.timezone.utc)
STREAM = 'test-stream'


def delivery(seq, *, offset=0, ip='10.0.0.204', user='app_reader', rule_ids=None,
             score=60, status='OK', blocked=True, session='session-a', defaulted=False,
             version='1.4.1-G03-RC5', risk_version='1.0.1-G03-RC6', eid=None):
    rule_ids = list(['INJ-008'] if rule_ids is None else rule_ids)
    eid = eid or f'e{seq}'
    epoch = BASE + dt.timedelta(seconds=offset)
    risk = score if status == 'OK' else None
    record = {'event_type':'AUDIT_EVENT', 'event_id':eid,'policy_id':'db-firewall-main',
              'risk_id':'db-firewall-risk','policy_version':version,'risk_version':risk_version,
              'runtime_mode':'enforce','effective_action':'BLOCK' if blocked else 'ALLOW',
              'action_result':'BLOCKED' if blocked else 'FORWARDED',
              'matched_rules':rule_ids,'blocking_rules':rule_ids if blocked else [],
              'monitor_rules':[r for r in rule_ids if r in vnext.MONITOR],
              'allow_rules':[r for r in rule_ids if r.startswith('ALLOW-')],
              'defaulted':bool(defaulted),'client_ip':ip,'db_user':user,
              'risk_status':status,'risk_score':risk,
              'raw_score':risk,'score_breakdown':[{'rule_id':rule_ids[0] if rule_ids else None,'score':risk}] if risk is not None else None,
              'severity':'CRITICAL' if score is not None and score>=60 else 'HIGH' if score is not None and score>=40 else 'WARNING'}
    env={'schema_version':'1.2.0-candidate','stream_role':'SHADOW', 'event_id':eid,
         'metadata':{'producer_id':'proxy','request_id':'req-'+eid,'request_received_at':epoch.isoformat(),
                     'session_id':session,'privacy':{'db_user_status':'CLEAR_ALLOWED' if user else 'WITHHELD'}},
         'record':record}
    return {'delivery_version':'p16h-local-1','event_role':'CANONICAL_AUDIT_DELIVERY',
            'stream_id':STREAM,'stream_sequence':seq,'segment_index':1,
            'journal_stream_id':STREAM,'payload_sha256':hashlib.sha256(p17_core.canonical(env)).hexdigest(),
            'envelope':env}


def batch(d):
    seq=d['stream_sequence']
    return {'consumer':'p17','stream_id':STREAM,'ack_token':'test-token','journal_stream_id':STREAM,
            'segment_index':1,'after_sequence':seq-1,'through_sequence':seq,'items':[d]}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript(durable.DDL)
        state={'schema':durable.SCHEMA_ID,'stream_id':STREAM,'last_committed_sequence':'0',
               'activated_utc':(BASE-dt.timedelta(seconds=15)).isoformat(),
               'source_p16h_release':'test','approved_auto_containment':'false'}
        self.db.executemany('INSERT INTO metadata(key,value) VALUES (?,?)',state.items())
        vnext.ensure_schema(self.db)

    def ingest(self, seq, **k):
        d = delivery(seq,**k)
        event_time = p17_core.aware_date(d['envelope']['metadata']['request_received_at'])
        with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'1'}):
            return durable.process_batch(self.db,batch(d),now=event_time+dt.timedelta(seconds=2))

    def cases(self):
        return self.db.execute('SELECT case_id,evidence_count,severity,isolation_authorized,signal_ids_json FROM vnext_cases').fetchall()

    def signals(self):
        return {r[0] for r in self.db.execute('SELECT detector_id FROM vnext_signals')}

    def test_migration_additive_and_idempotent(self):
        vnext.ensure_schema(self.db)
        self.assertEqual(self.db.execute("SELECT v FROM vnext_profile WHERE k='profile'").fetchone()[0],vnext.PROFILE)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)

    def test_3_sqli_spanning_hours_vnext_only(self):
        for seq,offset in enumerate((0,1800,3700),1):self.ingest(seq,offset=offset,score=40)
        rows=self.cases()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0][1],3)
        self.assertEqual(rows[0][2],'HIGH')
        self.assertEqual(rows[0][3],0)
        self.assertIn('CORR-002',json.loads(rows[0][4]))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)

    def test_legacy_3_sqli_fast_unchanged(self):
        for seq,offset in enumerate((0,10,20),1):self.ingest(seq,offset=offset,score=40)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM incidents WHERE signal_rule='CORR-002'").fetchone()[0],1)
        self.assertEqual(self.cases()[0][3],0)

    def test_source_ip_isolation(self):
        self.ingest(1,ip='10.0.0.204',offset=0,score=40)
        self.ingest(2,ip='10.0.0.30',offset=1000,score=40)
        self.ingest(3,ip='10.0.0.204',offset=2000,score=40)
        self.assertNotIn('CORR-002',self.signals())

    def test_user_isolation(self):
        self.ingest(1,user='app_reader',offset=0,score=40)
        self.ingest(2,user='app_writer',offset=500,score=40)
        self.ingest(3,user='app_reader',offset=1000,score=40)
        self.assertNotIn('CORR-002',self.signals())

    def test_duplicate_delivery_not_double_count(self):
        self.ingest(1,score=40)
        d=delivery(1,score=40)
        with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'1'}):
            res=durable.process_batch(self.db,batch(d),now=BASE+dt.timedelta(seconds=5))
        self.assertEqual(res['duplicates'],1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0],1)

    def test_conflicting_payload_rolls_back(self):
        self.ingest(1,score=40)
        d=delivery(2,score=40)
        d['payload_sha256']='0'*64
        with self.assertRaises(p17_core.EvidenceError):
            with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'1'}):
                durable.process_batch(self.db,batch(d),now=BASE+dt.timedelta(seconds=5))
        self.assertEqual(durable.meta(self.db)['last_committed_sequence'],'1')

    def test_monitor_only_no_sqli(self):
        for seq in range(1,4):
            self.ingest(seq,offset=seq*2,blocked=False,score=20,rule_ids=['INJ-003'])
        self.assertIn('CORR-019',self.signals())
        self.assertNotIn('CORR-002',self.signals())
        self.assertEqual(len(self.cases()),0)

    def test_risk_error_not_attack_evidence(self):
        for seq in range(1,4):
            self.ingest(seq,offset=seq*2,status='ERROR',score=None,rule_ids=['INJ-008'])
        self.assertEqual(len(self.cases()),0)
        trace=json.loads(self.db.execute('SELECT trace_json FROM vnext_events WHERE event_id=?',( 'e3', )).fetchone()[0])
        self.assertEqual(trace['eligibility_reason'],'P15_SCORE_UNAVAILABLE')

    def test_stale_not_qualify(self):
        d=delivery(1,offset=-3600,rule_ids=['INJ-008'],score=40)
        with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'1'}):
            durable.process_batch(self.db,batch(d),now=BASE)
        self.assertEqual(len(self.cases()),0)
        self.assertEqual(self.db.execute('SELECT event_class FROM vnext_events').fetchone()[0], 'HISTORICAL')

    def test_sqli_sensitive_one_request_one_evidence(self):
        self.ingest(1,rule_ids=['INJ-008','OBJ-003','OBJ-004'],score=100)
        self.assertIn('CORR-021',self.signals())
        self.assertEqual(self.cases()[0][1],1)
        self.assertNotIn('CORR-002',self.signals())

    def test_enumeration_before_attack_order(self):
        self.ingest(1,rule_ids=['ENUM-001'],score=35)
        self.ingest(2,rule_ids=['INJ-008'],score=40)
        self.assertIn('CORR-015',self.signals())
        self.assertNotIn('CORR-022',self.signals())
        self.ingest(3,rule_ids=['DCL-001'],score=80)
        self.assertIn('CORR-022',self.signals())
        self.assertEqual(self.cases()[0][2],'CRITICAL')

    def test_protocol_operational_only(self):
        for i in range(1,6):self.ingest(i,offset=i*2,rule_ids=['PROTO-010'],score=70)
        self.assertIn('CORR-005',self.signals())
        self.assertEqual(len(self.cases()),0)

    def test_source_context_by_sequence_without_time_window(self):
        for i,offset in enumerate((0,10,30,60,90),1):
            self.ingest(i,offset=offset,rule_ids=[],score=30,defaulted=True)
        self.assertIn('CORR-020',self.signals())
        self.assertIn('CORR-001',self.signals())
        self.assertEqual(self.cases()[0][1],5)

    def test_trace_no_sql_leak(self):
        self.ingest(1,rule_ids=['INJ-008'],score=40)
        trace=self.db.execute('SELECT trace_json FROM vnext_events').fetchone()[0]
        self.assertNotIn('raw_sql',trace)
        self.assertNotIn('password_hash',trace)
        data=json.loads(trace)
        self.assertEqual(data['p14']['matched_rules'],['INJ-008'])
        self.assertEqual(data['p15']['risk_score'],40)

    def test_outbox_export_idempotence(self):
        self.ingest(1,rule_ids=['DCL-001'],score=80)
        out=Path(self.tmp.name)/'vnext.jsonl'
        n=vnext.export_trace(self.db,out)
        self.assertGreaterEqual(n,2)
        self.assertEqual(vnext.export_trace(self.db,out),0)
        lines=[json.loads(s) for s in out.read_text().splitlines()]
        self.assertEqual(len({s['trace_id'] for s in lines}),len(lines))

    def test_not_modify_legacy_incidents_or_outbox_for_slow_sqli(self):
        for seq,offset in enumerate((0,1100,2200),1):self.ingest(seq,offset=offset,score=40)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],0)
        self.assertEqual(len(self.cases()),1)

    def test_disabled_flag_keeps_legacy_only(self):
        d=delivery(1,offset=0,rule_ids=['DCL-001'],score=80)
        with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'0'}):
            durable.process_batch(self.db,batch(d),now=BASE+dt.timedelta(seconds=2))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM processed_events').fetchone()[0],1)

    def test_unrelated_allow_does_not_retrigger_case(self):
        self.ingest(1,offset=0,rule_ids=['DCL-001'],score=80)
        first=self.db.execute('SELECT last_event_id FROM vnext_cases').fetchone()[0]
        self.ingest(2,offset=3,rule_ids=['ALLOW-READER-001'],score=0,blocked=False)
        second=self.db.execute('SELECT last_event_id FROM vnext_cases').fetchone()[0]
        self.assertEqual(first,second)
        trace=json.loads(self.db.execute("SELECT trace_json FROM vnext_events WHERE event_id='e2'").fetchone()[0])
        self.assertNotIn('CORR-006',trace['p17']['matched_signals'])
        self.assertIn('CORR-006',trace['p17']['active_source_signals'])

    def test_poll_commit_ack_order_and_trace_output(self):
        d=delivery(1,rule_ids=['CTX-006','INJ-008'],score=100)
        calls=[]
        def request(command):
            calls.append(command['op'])
            if command['op']=='HEALTH':
                return {'stream_id':STREAM,'status':'RUNNING','p17_cursor':0}
            if command['op']=='POLL':
                return batch(d)
            if command['op']=='ACK':
                row=self.db.execute('SELECT case_id FROM vnext_cases').fetchone()
                self.assertIsNotNone(row, 'VNext case must commit before P16H ACK')
                self.assertEqual(durable.meta(self.db)['last_committed_sequence'],'1')
                return {'status':'ACK_COMMITTED','stream_id':STREAM,'through_sequence':1}
            raise AssertionError('Unexpected P16H op')
        event_log=Path(self.tmp.name)/'legacy.jsonl'
        trace_log=Path(self.tmp.name)/'trace.jsonl'
        with patch.dict(os.environ, {'P17_VNEXT_ENABLED':'1'}):
            result=durable.work_once(self.db,request,alert_log=event_log,
                    vnext_trace=trace_log,now=BASE+dt.timedelta(seconds=2))
        self.assertEqual(calls,['HEALTH','POLL','ACK'])
        self.assertGreaterEqual(result['vnext_exported'],2)
        self.assertTrue(trace_log.is_file())
        self.assertEqual(self.cases()[0][3],0)

    def test_new_tables_do_not_mutate_legacy_incidents(self):
        self.db.execute('''INSERT INTO incidents
            (incident_id,stream_id,source_key,client_ip,signal_rule,first_ms,last_ms,
             evidence_count,peak_p15,severity,confidence,status,created_utc,updated_utc)
            VALUES ('INC-existing',?,?,?,'CORR-001',1,1,5,30,'WARNING','REVIEW_REQUIRED','REVIEW_REQUIRED',?,?)''',
            (STREAM,'old-source','10.0.0.30',BASE.isoformat(),BASE.isoformat()))
        self.ingest(1,rule_ids=['CTX-006','INJ-008'],score=100)
        row=self.db.execute("SELECT signal_rule,evidence_count,peak_p15 FROM incidents WHERE incident_id='INC-existing'").fetchone()
        self.assertEqual(row,('CORR-001',5,30))
        self.assertEqual(len(self.cases()),1)

    def test_live_report_reads_from_consistent_sqlite_copy(self):
        self.ingest(1,rule_ids=['CTX-006','INJ-008'],score=100)
        db_path=Path(self.tmp.name)/'p17-copy.sqlite3'
        with sqlite3.connect(db_path) as backup:
            self.db.backup(backup)
        before=db_path.stat().st_size
        info=vnext_report.fetch(db_path)
        self.assertEqual(info['vnext_cases'],1)
        self.assertEqual(info['vnext_events'],1)
        content=vnext_report.render(info)
        self.assertIn('Actual committed SQLite',content)
        self.assertIn('CORR-013',content)
        self.assertEqual(db_path.stat().st_size,before)

    def test_22_detectors_defined(self):
        self.assertEqual(len(vnext.DETECTORS),22)
        r=vnext.detect([])
        self.assertEqual(set(r),set(vnext.DETECTORS))

    def test_legacy_schema_unchanged(self):
        columns={x[1] for x in self.db.execute('PRAGMA table_info(incidents)')}
        self.assertNotIn('vnext',columns)
        self.assertTrue({'incident_id','signal_rule','evidence_count'}.issubset(columns))


if __name__=='__main__':unittest.main()
