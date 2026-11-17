"""Read-only export and Portal API smoke/regression tests, no live services."""
import contextlib
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI
try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'deploy/portal-local'))
sys.path.insert(0,str(ROOT/'components/p17-worker'))
from publish_vnext import read_snapshot,publish
import p17_vnext
import p17_durable
import p17_core
from test_vnext_runtime import STREAM,BASE,delivery,batch

spec=importlib.util.spec_from_file_location('portal_p17_vnext_api',ROOT/'backend/app/p17_vnext_api.py')
portal_api=importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal_api)

class ExportApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.dbpath=Path(self.tmp.name)/'state.sqlite3'
        self.db=sqlite3.connect(str(self.dbpath),isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript(p17_durable.DDL)
        self.db.executemany('INSERT INTO metadata(key,value) VALUES (?,?)',{
            'schema':p17_durable.SCHEMA_ID,
            'stream_id':STREAM,'last_committed_sequence':'0',
            'activated_utc':(BASE-dt.timedelta(seconds=20)).isoformat(),
            'source_p16h_release':'test','approved_auto_containment':'false',
        }.items())
        p17_vnext.ensure_schema(self.db)

    def add(self,seq,offset,rule_ids,score):
        d=delivery(seq,offset=offset,rule_ids=rule_ids,score=score)
        now=BASE+dt.timedelta(seconds=offset+2)
        with patch.dict(os.environ,{'P17_VNEXT_ENABLED':'1'}):
            p17_durable.process_batch(self.db,batch(d),now=now)

    def test_export_real_commit_evidence_and_api(self):
        self.add(1,0,['CTX-006','INJ-008'],100)
        self.add(2,130,['CTX-006','INJ-008'],100)
        self.add(3,267,['CTX-006','INJ-008'],100)
        data=read_snapshot(str(self.dbpath))
        self.assertEqual(data['checkpoint'],3)
        self.assertEqual(data['legacy_incident_count'],0)
        self.assertEqual(data['event_total'],3)
        self.assertEqual(data['case_total'],1)
        self.assertEqual(data['cases'][0]['evidence_count'],3)
        self.assertTrue(data['cases'][0]['evidence_export_complete'])
        self.assertEqual(len(data['cases'][0]['evidence']),3)
        self.assertEqual(data['cases'][0]['signals'],['CORR-002','CORR-013'])
        self.assertFalse(data['cases'][0]['isolation_authorized'])
        self.assertEqual(data['cases'][0]['response'],'NO_ACTION')
        self.assertEqual(data['events'][0]['trace']['p15']['risk_score'],100)
        self.assertTrue(data['events'][0]['trace']['p17']['detector_evaluations']['CORR-002']['met'])
        self.assertNotIn('raw_sql',str(data))
        outfile=Path(self.tmp.name)/'p17_vnext.json'
        publish(str(self.dbpath),str(outfile))
        if TestClient is None:
            self.skipTest('httpx not installed; API TestClient skipped, exporter tests available separately')
        app=FastAPI()
        app.include_router(portal_api.router)
        with patch.dict(os.environ,{'P17_VNEXT_SNAPSHOT_PATH':str(outfile)}):
            with TestClient(app) as client:
                res=client.get('/api/v1/p17-vnext/status')
                self.assertEqual(res.status_code,200)
                self.assertEqual(res.json()['data']['checkpoint'],3)
                res=client.get('/api/v1/p17-vnext/cases')
                self.assertEqual(res.status_code,200)
                c=res.json()['data']['cases'][0]
                self.assertNotIn('evidence',c)
                full=client.get('/api/v1/p17-vnext/cases/'+c['case_id'])
                self.assertEqual(len(full.json()['data']['evidence']),3)
                e=client.get('/api/v1/p17-vnext/events/e3')
                self.assertEqual(e.status_code,200)
                self.assertEqual(e.json()['data']['trace']['p14']['effective_action'],'BLOCK')
                missing=client.get('/api/v1/p17-vnext/events/no-such-id')
                self.assertEqual(missing.status_code,404)
                self.assertEqual(missing.json()['detail']['code'],'VNEXT_EVENT_NOT_IN_BOUNDED_EXPORT')

    def test_no_vnext_on_missing_database_tables(self):
        self.db.execute('DROP TABLE vnext_cases')
        with self.assertRaisesRegex(ValueError,'VNEXT_TABLES_NOT_INSTALLED'):
            read_snapshot(str(self.dbpath))

    def test_export_does_not_mutate_sqlite(self):
        self.add(1,0,['CTX-006'],60)
        count_before=self.db.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0]
        snapshot=read_snapshot(str(self.dbpath))
        count_after=self.db.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0]
        self.assertEqual(count_before,count_after)
        self.assertEqual(snapshot['legacy_incident_count'],0)

    def test_portal_fails_closed_without_source_and_on_secret(self):
        if TestClient is None:self.skipTest('httpx not installed')
        app=FastAPI();app.include_router(portal_api.router)
        with TestClient(app) as client:
            with patch.dict(os.environ,{},clear=True):
                res=client.get('/api/v1/p17-vnext/status')
                self.assertEqual(res.status_code,503)
                self.assertEqual(res.json()['detail']['code'],'VNEXT_SOURCE_NOT_CONFIGURED')
            f=Path(self.tmp.name)/'invalid.json'
            payload={'schema_version':'n91-portal-p17-vnext-1','generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                     'checkpoint':0,'cases':[],'events':[],'security_boundary':'REVIEW_ONLY_NO_OPENSTACK_ACTION',
                     'raw_sql':'SELECT secret'}
            f.write_text(json.dumps(payload))
            with patch.dict(os.environ,{'P17_VNEXT_SNAPSHOT_PATH':str(f)}):
                res=client.get('/api/v1/p17-vnext/status')
                self.assertEqual(res.status_code,503)
                self.assertEqual(res.json()['detail']['code'],'VNEXT_SOURCE_INVALID')

class DetectorMatrixTests(unittest.TestCase):
    def row(self,seq,rules=None,blocked=True,defaulted=False):
        return {'event_id':f'e{seq}','request_id':f'req-{seq}','seq':seq,
                'blocked':blocked,'rules':rules or [],'defaulted':defaulted}

    def test_all_22_detector_positive(self):
        r=self.row
        cases={
            'CORR-001':[r(i,['CTX-006']) for i in range(1,6)],
            'CORR-002':[r(i,['INJ-008']) for i in range(1,4)],
            'CORR-003':[r(i,['OBJ-003']) for i in range(1,4)],
            'CORR-004':[r(1,['INJ-008']),r(2,['OBJ-003']),r(3,['ENUM-001'])],
            'CORR-005':[r(i,['PROTO-010']) for i in range(1,6)],
            'CORR-006':[r(1,['DCL-001'])],
            'CORR-007':[r(1,['DDL-001'])],
            'CORR-008':[r(1,['FILE-001'])],
            'CORR-009':[r(1,['DML-001'])],
            'CORR-010':[r(1,['DML-010']),r(2,['CTX-003'])],
            'CORR-011':[r(1,['CTX-001'])],
            'CORR-012':[r(1,['CTX-006'])],
            'CORR-013':[r(1,['CTX-006','INJ-008'])],
            'CORR-014':[r(1,['ENUM-001']),r(2,['ENUM-001'])],
            'CORR-015':[r(1,['ENUM-001']),r(2,['INJ-008'])],
            'CORR-016':[r(1,['OBJ-005'])],
            'CORR-017':[r(1,['PROTO-003'])],
            'CORR-018':[r(1,['RES-001']),r(2,['RES-001'])],
            'CORR-019':[r(i,['READ-001'],blocked=False) for i in range(1,4)],
            'CORR-020':[r(i,[],defaulted=True) for i in range(1,6)],
            'CORR-021':[r(1,['INJ-008','OBJ-003'])],
            'CORR-022':[r(1,['INJ-008']),r(2,['DCL-001'])],
        }
        self.assertEqual(len(cases),22)
        for det,events in cases.items():
            with self.subTest(detector=det):
                result=p17_vnext.detect(events)
                self.assertTrue(result[det][0],(det,result[det]))

    def test_multi_rule_still_one_request_and_two_sqli_not_enough(self):
        self.assertFalse(p17_vnext.detect([self.row(1,['INJ-008','INJ-001','INJ-002'])])['CORR-002'][0])
        self.assertFalse(p17_vnext.detect([self.row(1,['INJ-008']),self.row(2,['INJ-008'])])['CORR-002'][0])
        self.assertFalse(p17_vnext.detect([self.row(1,['READ-001'],blocked=False)])['CORR-001'][0])

if __name__=='__main__':unittest.main()
