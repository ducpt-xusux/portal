import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createBusinessClient,permissions,sourceKey} from './businessApi.js'
const session={username:'test.analyst',roles:['Analyst'],expires_at:'2030-01-01T00:00:00Z',csrf_token:'TEST-csrf-token-000000000000'}
const ok=data=>({status:200,ok:true,json:async()=>({data,meta:{source_system:'PORTAL_BUSINESS'},error:null})})
test('business session cookie only; CSRF held in memory and sent on writes',async()=>{
  const calls=[]
  const client=createBusinessClient({fetchImpl:async(path,options)=>{calls.push({path,...options});return ok(path.endsWith('/login')?session:{note_id:'TEST-note'})}})
  await client.login('test.analyst','TEST-password-only')
  await client.addNote('TEST-INC','TEST note','TEST-idempotency-0001')
  assert.equal(calls[0].credentials,'same-origin')
  assert.equal(calls[1].headers['X-CSRF-Token'],session.csrf_token)
  assert.equal(calls[1].headers['Idempotency-Key'],'TEST-idempotency-0001')
  assert.equal(calls[1].headers['X-Role'],undefined)
  assert.equal(calls[1].headers.Authorization,undefined)
  assert.equal(calls[1].cache,'no-store')
})
test('business failed auth expires state and wipes csrf; unknown server messages withheld',async()=>{
  let expired=0,sequence=0
  const calls=[]
  const client=createBusinessClient({onExpired:()=>expired++,fetchImpl:async(path,options)=>{calls.push(options);sequence++;return sequence===1?ok(session):{status:401,ok:false,json:async()=>({error:{code:'C:/private token secret'}})}}})
  await client.me()
  await assert.rejects(client.logout(),e=>e.code==='BUSINESS_UNAVAILABLE')
  await assert.rejects(client.addNote('TEST-INC','TEST note','TEST-intent-00001'))
  assert.equal(expired,2)
  assert.equal(calls[2].headers['X-CSRF-Token'],undefined)
})
test('business source refs reject traversal and preserve streams',()=>{
  assert.equal(sourceKey('TEST-INC','TEST:stream'),'TEST-INC?stream_id=TEST%3Astream')
  assert.throws(()=>sourceKey('../private'))
  assert.throws(()=>sourceKey('TEST-INC','https://evil.test'))
})
test('business API same origin only and no unexpected network destination',async()=>{
  const client=createBusinessClient({fetchImpl:async()=>{throw new Error('must not call')}})
  await assert.rejects(client.request('https://evil.test/api/v1/auth/me'),e=>e.code==='INVALID_API_PATH')
  await assert.rejects(client.request('/api/v1/../secrets'),e=>e.code==='INVALID_API_PATH')
})
test('business client role and capabilities both required; Operator is not portal admin',()=>{
  assert.equal(permissions({roles:['Viewer']},{can_triage:true,can_read_notes:true}).canTriage,false)
  assert.equal(permissions({roles:['Operator']},{can_triage:true}).canAdmin,false)
  assert.equal(permissions({roles:['Analyst']},{can_triage:false}).canTriage,false)
  assert.equal(permissions(session,{can_triage:true}).canTriage,true)
  assert.equal(permissions({roles:['Executor']},{network_actions_enabled:true}).networkActionsEnabled,false)
  assert.equal(permissions({roles:['Auditor']},{}).canAudit,true)
})
test('business conflict stays typed and is never auto retried',async()=>{
  let count=0
  const client=createBusinessClient({fetchImpl:async()=>{count++;return {status:409,ok:false,json:async()=>({error:{code:'VERSION_CONFLICT'}})}}})
  await assert.rejects(client.triage('TEST-INC','TEST-stream',{version:1},'TEST-intent-00001'),e=>e.status===409&&e.code==='VERSION_CONFLICT')
  assert.equal(count,1)
})
test('business sanitized CSV uses same session transport and does not inject HTML',async()=>{
  const client=createBusinessClient({fetchImpl:async(path,options)=>{assert.equal(options.credentials,'same-origin');assert.ok(path.endsWith('notes.csv?stream_id=TEST-stream'));return {ok:true,text:async()=>"note\r\n'=TEST\r\n"}}})
  assert.equal(await client.notesCsv('TEST-INC','TEST-stream'),"note\r\n'=TEST\r\n")
})
test('business invalid session response cannot become authenticated',async()=>{
  const client=createBusinessClient({fetchImpl:async()=>ok({user:null,access_mode:'LOCAL_SNAPSHOT_READONLY'})})
  await assert.rejects(client.me(),e=>e.code==='INVALID_SESSION')
})
test('business bridge adopts only a shaped server session without another login; clearing wipes csrf',async()=>{
  const calls=[]
  const client=createBusinessClient({fetchImpl:async(path,options)=>{calls.push({path,...options});return ok({note_id:'TEST-note'})}})
  client.adoptSession(session)
  await client.addNote('TEST-INC','TEST bridge','TEST-bridge-000001')
  assert.equal(calls.length,1)
  assert.equal(calls[0].headers['X-CSRF-Token'],session.csrf_token)
  client.adoptSession(null)
  await client.addNote('TEST-INC','TEST bridge','TEST-bridge-000002')
  assert.equal(calls[1].headers['X-CSRF-Token'],undefined)
  assert.throws(()=>client.adoptSession({role:'Operator'}),e=>e.code==='INVALID_SESSION')
})
