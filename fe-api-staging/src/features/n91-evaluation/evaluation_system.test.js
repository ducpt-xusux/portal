import test from 'node:test'
import assert from 'node:assert/strict'
import { createEvaluationApi, readEvaluation, readPanel, filterCases, evidenceRoute } from './api.js'

const scope = { run_id: 'TEST-run', context: 'TEST', execution_mode: 'HISTORICAL', source_system: 'TEST',
  data_as_of: '2026-11-08T10:00:00Z', observed_at: '2026-11-08T10:00:00Z', freshness_state: 'HISTORICAL' }
const evaluation = () => ({ schema_version:'n91-evaluation-panel-1', run:{run_id:'TEST-run'}, catalog_basis:'DESIGN_ONLY',catalog_flag:'NOT_RUN',
  expected_partitions:{LIVE_READ_ONLY:18,OFFLINE_POLICY:32,PROTOCOL_OFFLINE:3,P17_OFFLINE:7},
  observed_partitions:{LIVE_READ_ONLY:1,OFFLINE_POLICY:0,PROTOCOL_OFFLINE:0,P17_OFFLINE:0},expected_correlations:13,
  cases:[{scope:{...scope,execution_mode:'LIVE'},case_id:'C-011',partition:'LIVE_READ_ONLY',verdict:'PASS',observed_action:'ALLOW',
    request_count:2,request_refs:['TEST-req1','TEST-req2'],event_refs:['TEST-event1','TEST-event2'],incident_refs:[],evidence_refs:['TEST-evidence']}],
  correlations:[{scope:{...scope,execution_mode:'ISOLATED'},scenario_id:'neg_corr_002',input_event_count:2,observed_incident:false,verdict:'PASS',evidence_refs:['TEST-corr']}] })
const panel = (kind, row) => ({schema_version:'n91-system-panel-1',kind,items:[{scope:{...scope},evidence_refs:['TEST-evidence'],...row}]})

test('run context, distinct request references and false negative boolean preserved', () => {
  const data=readEvaluation(evaluation(),'TEST-run')
  assert.equal(data.cases[0].request_count,2)
  assert.equal(data.correlations[0].observed_incident,false)
  assert.equal(data.cases[0].scope.context,'TEST')
  assert.equal(filterCases(data.cases,{mode:'LIVE'}).length,1)
  assert.equal(filterCases(data.cases,{partition:'OFFLINE_POLICY'}).length,0)
})

test('cross-run, false pass, duplicate IDs and request mismatch reject', () => {
  const mutations=[d=>{d.cases[0].scope.run_id='TEST-other'},d=>{d.cases[0].observed_action=null},
    d=>{d.cases[0].evidence_refs=[]},d=>{d.cases[0].request_count=1},d=>{d.cases.push(structuredClone(d.cases[0]))},
    d=>{d.cases[0].request_refs=['TEST-req1','TEST-req1']},d=>{d.correlations[0].observed_incident=null},
    d=>{d.cases[0].partition='OFFLINE_POLICY'},d=>{d.cases[0].scope.freshness_state='FRESH'},
    d=>{d.expected_partitions.LIVE_READ_ONLY=60}]
  for(const mutate of mutations){const data=evaluation();mutate(data);assert.throws(()=>readEvaluation(data,'TEST-run'),/schema/)}
})

test('decimal LAB seconds and null production remain separate', () => {
  const data=panel('recoveries',{production_rpo_seconds:null,production_rto_seconds:null,production_rpo_measured:false,
    full_app_proxy_galera_rto_measured:false,unit:'seconds',rpo_gap_seconds:1.283115,lab_rto_seconds:2.834685,
    lost_marker_count:1,production_measurement:'NOT_MEASURED'})
  assert.equal(readPanel(data,'recoveries').items[0].lab_rto_seconds,2.834685)
  for(const patch of [{rpo_gap_seconds:0},{production_rto_seconds:2.8},{unit:'ms'},{lab_rto_seconds:NaN}]) {
    assert.throws(()=>readPanel({...data,items:[{...data.items[0],...patch}]},'recoveries'),/schema/)
  }
})

test('P19 source absent cannot claim acceptance or strict ready', () => {
  assert.equal(readPanel(panel('p19',{strict_ready:false,authority:'UNAVAILABLE',lab_scope_status:'UNKNOWN'}),'p19').items[0].strict_ready,false)
  assert.throws(()=>readPanel(panel('p19',{strict_ready:true,authority:'SIGNED_LAB_SCOPE'}),'p19'),/schema/)
  assert.throws(()=>readPanel(panel('p19',{strict_ready:false,authority:'UNAVAILABLE',lab_scope_status:'ACCEPTED_WITH_EXCEPTIONS'}),'p19'),/schema/)
})

test('staging cannot claim production fixed; negotiated TLS evidence required', () => {
  const staging=panel('staging',{scope:{...scope,execution_mode:'STAGING'},production_cutover_verified:false,production_status:'OPEN',passed:37,total:37})
  assert.equal(readPanel(staging,'staging').items[0].production_status,'OPEN')
  staging.items[0].production_status='FIXED';assert.throws(()=>readPanel(staging,'staging'),/schema/)
  const tls=panel('tls',{handshake_retry_limitation:'OPEN',status:'VERIFIED',negotiated_version:null,peer_verified:true})
  assert.throws(()=>readPanel(tls,'tls'),/schema/)
  tls.items[0].status='UNAVAILABLE';assert.equal(readPanel(tls,'tls').items[0].status,'UNAVAILABLE')
})

test('API only uses read endpoints and safe encoded identifiers',async()=>{
  const calls=[]
  const api=createEvaluationApi(async(path,options)=>{calls.push([path,options]);return {data:evaluation(),meta:{}}})
  await api.evaluation('TEST-run',{signal:new AbortController().signal})
  assert.equal(calls[0][0],'/n91/evaluation-system/runs/TEST-run')
  assert.equal(calls[0][1].method,undefined)
  assert.equal(evidenceRoute('TEST-evidence'),'/evidence/TEST-evidence')
  assert.throws(()=>evidenceRoute('../secret'),/schema/)
  await assert.rejects(()=>api.evaluation('../secret'),/schema/)
  await assert.rejects(()=>api.panel('raw'),/schema/)
})

test('transport 503 propagates without cached result or fabricated source',async()=>{
  let available=true
  const api=createEvaluationApi(async()=>{if(available)return {data:evaluation()};throw Object.assign(new Error('source'),{status:503,code:'TEST_MISSING'})})
  assert.equal((await api.evaluation('TEST-run')).data.cases.length,1)
  available=false
  await assert.rejects(()=>api.evaluation('TEST-run'),{status:503,code:'TEST_MISSING'})
})
