import test from 'node:test'

test('P16H keeps independent timestamps, source metadata and upstream hash without verification claims', () => {
  const event = mapEvent({ event_id: 'TEST-event', stream_id: 'TEST-stream', request_id: 'TEST-request', stream_sequence: 0,
    request_received_at: '2026-11-08T01:00:00Z', storage_recorded_at: '2026-11-08T01:00:01Z', imported_at: '2026-11-08T02:00:00Z',
    time_basis: { request_received_at: 'TEST_PRODUCER', imported_at: 'PORTAL_CLOCK', unknown: 'private' },
    decision: 'ALLOW', decision_basis: 'P14_POLICY_DECISION', effective_action: 'ALLOW', action_result: 'FORWARDED', runtime_mode: 'monitor', would_block: true,
    source_metadata: { request_sequence: 0, producer_id: 'TEST-producer', backend: 'UNAVAILABLE', unknown: 'private' },
    source_provenance: { payload_sha256: 'a'.repeat(64), payload_hash_basis: 'UPSTREAM_UNVERIFIED', context: 'TEST', verification: 'IMPORTED_UNVERIFIED', human_review: 'UNAVAILABLE', private: 'private' },
  })
  assert.equal(event.stream_sequence, 0)
  assert.equal(event.source_metadata.request_sequence, 0)
  assert.equal(event.time_basis.imported_at, 'PORTAL_CLOCK')
  assert.equal(event.request_received_at, '2026-11-08T01:00:00Z')
  assert.equal(event.storage_recorded_at, '2026-11-08T01:00:01Z')
  assert.equal(event.imported_at, '2026-11-08T02:00:00Z')
  assert.equal(event.ingested_at, null)
  assert.equal(event.source_provenance.payload_hash_basis, 'UPSTREAM_UNVERIFIED')
  assert.equal(event.source_provenance.human_review, 'UNAVAILABLE')
  assert.equal(event.decision_basis, 'P14_POLICY_DECISION')
  assert.equal(event.effective_action, 'ALLOW')
  assert.equal(JSON.stringify(event).includes('private'), false)
})

test('P17 blocked projection is explicitly retained independently from P14 effective action', () => {
  const event = mapEvent({ event_id: 'TEST-projection', view_kind: 'P17_EVENT_PROJECTION', decision: 'BLOCK', decision_basis: 'P17_PERSISTED_BLOCKED_FLAG' })
  assert.equal(event.decision_basis, 'P17_PERSISTED_BLOCKED_FLAG')
  assert.equal(event.effective_action, null)
})

test('withheld SQL and risk ERROR never become displayed text or zero', () => {
  const event = mapEvent({ event_id: 'TEST-withheld', sql_text_status: 'WITHHELD', masked_query: 'TEST-PRIVATE', risk: { status: 'ERROR', score: 0, severity: 'HIGH' } })
  assert.equal(event.masked_query, null)
  assert.equal(event.risk.score, null)
  assert.equal(event.risk.severity, null)
})
import { consoleSocketUrl, typingText, typeConsoleText, asciiKey } from './consoleTyping.js'

test('console typing rejects control keys, Unicode and unapproved Enter before sending', () => {
  for (const value of ['abc\n', '\t', '\x1b[A', '\x03', 'tiếng Việt', 'x'.repeat(2001)]) assert.throws(() => typingText(value))
  assert.equal(typingText('one\r\ntwo', true), 'one\ntwo')
  assert.equal(typingText('echo "$a"; SQL != 1 \\ / @#'), 'echo "$a"; SQL != 1 \\ / @#')
})

test('console sends exact symbols with no appended Enter and stops on cancellation/disconnect', async () => {
  const keys = [], control = new AbortController()
  const result = await typeConsoleText(typingText('Ab_!"$'), { signal: control.signal, connected: () => true, sendKey: key => { if (key !== 0xffe1) keys.push(key) }, pause: async () => {} })
  assert.equal(result.complete, true)
  assert.deepEqual(keys, [...'Ab_!"$'].map(c => c.charCodeAt(0)))
  assert.equal(keys.includes(0xff0d), false)
  const multiline = []
  await typeConsoleText(typingText('a\nb', true), { signal: control.signal, connected: () => true, sendKey: k => multiline.push(k), pause: async () => {} })
  assert.deepEqual(multiline, [97, 0xff0d, 98])
  const cancel = new AbortController(), partial = []
  assert.deepEqual(await typeConsoleText('abc', { signal: cancel.signal, connected: () => true, sendKey: k => { partial.push(k); cancel.abort() }, pause: async () => {} }), { complete: false, sent: 1 })
  assert.deepEqual(partial, [97])
  assert.deepEqual(await typeConsoleText('abc', { signal: control.signal, connected: () => false, sendKey: () => assert.fail(), pause: async () => {} }), { complete: false, sent: 0 })
})

test('console WebSocket derives only from validated Nova URL', () => {
  assert.equal(consoleSocketUrl({ url: 'http://console:6080/vnc_lite.html?path=%3Ftoken%3Dtest' }), 'ws://console:6080/?token=test')
  assert.equal(consoleSocketUrl({ url: 'https://console/vnc.html?path=websockify%3Ftoken%3Dtest' }), 'wss://console/websockify?token=test')
  assert.equal(consoleSocketUrl({ url: 'http://console:6080/vnc_lite.html?path=%3Ftoken%3Dtest' }, 'http://127.0.0.1:5173'), 'ws://127.0.0.1:5173/console-ws/?token=test')
})

test('QEMU receives US scancodes and balanced Shift for uppercase and punctuation', async () => {
  assert.deepEqual(asciiKey('A'), { code: 'KeyA', shift: true })
  assert.deepEqual(asciiKey('@'), { code: 'Digit2', shift: true })
  assert.deepEqual(asciiKey('"'), { code: 'Quote', shift: true })
  assert.deepEqual(asciiKey('\\'), { code: 'Backslash', shift: false })
  const events = []
  await typeConsoleText('A_', { signal: new AbortController().signal, connected: () => true, sendKey: (...args) => events.push(args), pause: async () => {} })
  assert.deepEqual(events, [[0xffe1,'ShiftLeft',true],[65,'KeyA'],[0xffe1,'ShiftLeft',false],[0xffe1,'ShiftLeft',true],[95,'Minus'],[0xffe1,'ShiftLeft',false]])
})
import { createConsole, validateConsole, consoleMessage } from './consoleApi.js'
import assert from 'node:assert/strict'
import { canWriteNotes, freshness, isFreshMapping, isLocalSnapshotAccess, isVerifiedNetwork, mapEvent, mapIncident, mapWorkload, portalRequest, queryString, readCollection, mapDecision, mappingState, mapRiskExposure, riskExposureState, mapSgHistory, mapSecurityGroups, mapPort, currentMappingState } from './portalApi.js'
import { parseRoute } from '../hooks/useHashRoute.js'
import { alertEventHref, alertIncidentHref, alertRequestFilters, mapAlert, readAlertsPage } from './alertsApi.js'

const base = { event_id: 'evt-1', stream_id: 'stream-a', request_id: 'req-1', matched_rules: ['INJ-001', 'CTX-006'], decision: 'BLOCK' }

test('console validates trusted origin, VM, project and token without echoing rejected URLs', async () => {
  const capabilities = { project_id: 'project', console_origin: 'http://console:6080' }
  const data = { server_id: 'vm', project_id: 'project', protocol: 'vnc', type: 'novnc', url: 'http://console:6080/vnc_lite.html?path=%3Ftoken%3D00000000-0000-0000-0000-000000000001' }
  assert.equal(validateConsole(data, 'vm', capabilities), data)
  for (const bad of [{ ...data, server_id: 'other' }, { ...data, project_id: 'other' }, { ...data, url: data.url.replace('console:', 'evil:') }, { ...data, url: data.url + '#secret' }, { ...data, url: 'javascript:secret' }]) {
    assert.throws(() => validateConsole(bad, 'vm', capabilities), error => error.code === 'CONSOLE_URL_REJECTED' && !error.message.includes('secret'))
  }
  let calls = 0
  await createConsole('vm', capabilities, { fetcher: async (url, options) => {
    calls++
    assert.equal(options.method, 'POST')
    assert.equal(options.headers['X-Portal-Console'], 'connect')
    assert.deepEqual(JSON.parse(options.body), { protocol: 'vnc', type: 'novnc' })
    assert.equal(options.cache, 'no-store')
    return { ok: true, status: 200, json: async () => ({ data, meta: {} }) }
  } })
  assert.equal(calls, 1)
  assert.match(consoleMessage({ code: 'CONSOLE_PERMISSION_DENIED' }), /403/)
})

const recordedAlert = {
  alert_id: 'P15-alert-1', created_at: '2026-11-04T12:00:00Z', signal_code: 'SINGLE_P15_HIGH', kind: 'SINGLE_P15_HIGH',
  severity: 'HIGH', title: 'P15 cao', summary: 'Một request theo P17.', source_ip: '10.0.0.204', incident_id: null,
  event_refs: ['evt-1'], risk_peak: 100, source_record_ref: 'p17:stream-a:alert:P15-alert-1',
  provenance: { source_system: 'P17 outbox', freshness_state: 'STALE', data_as_of: '2026-11-01T12:00:00Z' },
}

test('single-request alerts keep recorded event references without inventing an incident or review state', () => {
  const alert = mapAlert(recordedAlert)
  assert.equal(alert.incident_id, null)
  assert.equal(alert.risk_peak, 100)
  assert.deepEqual(alert.event_refs, ['evt-1'])
  assert.equal(alert.provenance.freshness_state, 'STALE')
  assert.equal(alertIncidentHref(alert.incident_id), null)
  assert.equal(mapAlert({ ...recordedAlert, risk_peak: 0 }).risk_peak, 0)
  assert.equal(mapAlert({ ...recordedAlert, risk_peak: null, source_ip: null }).risk_peak, null)
  assert.equal(mapAlert({ ...recordedAlert, risk_peak: 101 }).risk_peak, null)
})
test('alert projection discards SQL secrets source keys delivery status and arbitrary provenance', () => {
  const alert = mapAlert({ ...recordedAlert, raw_sql: 'PRIVATE_SQL', source_key_hash: 'PRIVATE_KEY', delivered: true,
    review_state: 'ACKNOWLEDGED', provenance: { ...recordedAlert.provenance, token: 'PRIVATE_TOKEN' } })
  assert.ok(!JSON.stringify(alert).includes('PRIVATE'))
  assert.equal(alert.review_state, undefined)
  assert.equal(alert.delivered, undefined)
})
test('alert pages distinguish a valid empty outbox from malformed or duplicated responses', () => {
  assert.deepEqual(readAlertsPage({ items: [], total_count: 0, has_more: false, next_cursor: null }), { items: [], total_count: 0, has_more: false })
  for (const data of [{}, { items: [] }, { items: [], total_count: null, has_more: false },
    { items: [recordedAlert, recordedAlert], total_count: 2, has_more: false },
    { items: [], total_count: 10, has_more: true }]) assert.throws(() => readAlertsPage(data), /schema/)
  assert.throws(() => mapAlert({ ...recordedAlert, alert_id: '../other' }), /schema/)
  assert.throws(() => mapAlert({ ...recordedAlert, event_refs: ['evt-1', 'evt-1'] }), /schema/)
})
test('alert evidence navigation explicitly selects P17 projection and preserves stream identity', () => {
  assert.equal(alertEventHref('evt-1', 'stream:a'), '#/events/evt-1?source=p17&stream_id=stream%3Aa')
  assert.equal(alertEventHref('evt-1', null), null)
  assert.equal(alertEventHref('evt/other', 'stream'), null)
  assert.equal(alertIncidentHref('INC-1'), '#/incidents/INC-1')
  assert.equal(alertIncidentHref('INC-1?severity=LOW'), null)
})
test('alert filters use an explicit independent time anchor and never inherit the dashboard audit window', () => {
  const now = Date.parse('2026-11-04T12:00:00Z')
  assert.deepEqual(alertRequestFilters({ window: 'all', audit_window: '15m', review_state: 'ACKNOWLEDGED' }, now), {})
  assert.deepEqual(alertRequestFilters({ window: '15m', source_ip: ' 10.0.0.204 ', signal_code: 'CORR-002' }, now), {
    source_ip: '10.0.0.204', signal_code: 'CORR-002', from: '2026-11-04T11:45:00.000Z', to: '2026-11-04T12:00:00.000Z',
  })
})
test('risk score 0 is preserved only when risk_status is valid', () => {
  assert.equal(mapEvent({ ...base, risk: { score: 0, status: 'OK' } }).risk.score, 0)
  assert.equal(mapEvent({ ...base, risk: { score: 0, status: 'ERROR' } }).risk.score, null)
  assert.equal(mapEvent({ ...base, risk: { score: 100 } }).risk.score, null)
})
test('flat DOCX risk fields are mapped and errors never become zero', () => {
  assert.equal(mapEvent({ ...base, risk_score: 100, risk_status: 'OK' }).risk.score, 100)
  assert.equal(mapEvent({ ...base, risk_score: 100, risk_status: 'ERROR' }).risk.score, null)
  assert.equal(mapEvent({ ...base, risk: { score: 101, status: 'OK' } }).risk.score, null)
})
test('raw SQL and arbitrary secrets never enter Event Detail projection', () => {
  const mapped = mapEvent({ ...base, raw_sql: 'PRIVATE_SQL', query_raw: 'PRIVATE_SQL', token: 'PRIVATE_TOKEN', source_provenance: { source_ref: 'ref-1', token: 'PRIVATE_TOKEN' } })
  assert.equal(mapped.masked_query, null)
  assert.ok(!JSON.stringify(mapped).includes('PRIVATE'))
  assert.equal(mapped.source_provenance.source_ref, 'ref-1')
})
test('matched rules do not multiply requests or fabricate incident memberships', () => {
  const mapped = mapEvent({ ...base, matched_rules: ['INJ-001', 'CTX-006', 'OBJ-003', 'OBJ-004'] })
  assert.equal(mapped.event_id, 'evt-1')
  assert.equal(mapped.request_id, 'req-1')
  assert.equal(mapped.matched_rules.length, 4)
  assert.deepEqual(mapped.incident_refs, [])
})
test('missing identity and invalid list payloads reject instead of displaying empty data', () => {
  assert.throws(() => mapEvent({}), /schema/)
  assert.throws(() => mapIncident({}), /schema/)
  assert.throws(() => readCollection({ broken: [] }, 'events'), /schema/)
  assert.deepEqual(readCollection({ items: [] }), [])
})
test('incident detection remains REVIEW_REQUIRED after response restore', () => {
  const incident = mapIncident({ incident_id: 'INC-1', incident_status: 'REVIEW_REQUIRED', response_state: 'RESTORED', evidence_count: 3, p15_peak_score: 100, mapping: { verified: true } })
  assert.equal(incident.incident_status, 'REVIEW_REQUIRED')
  assert.equal(incident.response_state, 'RESTORED')
  assert.equal(incident.evidence_count, 3)
  assert.equal(incident.mapping.verified, true)
})
test('workload inventory preserves all ports and exact SG UUIDs', () => {
  const vm = mapWorkload({ server_id: 'vm-1', ports: [{ port_id: 'p-1', fixed_ips: [{ ip_address: '10.0.0.204' }], security_group_ids: ['sg-a', 'sg-b'] }, { port_id: 'p-2', fixed_ips: ['10.1.0.2'], security_group_ids: ['sg-c'] }] })
  assert.equal(vm.ports.length, 2)
  assert.deepEqual(vm.ports[0].security_group_ids, ['sg-a', 'sg-b'])
  assert.deepEqual(vm.ports[1].fixed_ips, ['10.1.0.2'])
  assert.equal(vm.protected, null)
})
test('idle source stays fresh when a recent successful read returns no new events', () => {
  const now = Date.now()
  assert.equal(freshness({ freshness_state: 'FRESH', read_at: new Date(now).toISOString(), data_as_of: '2020-01-01T00:00:00Z', stale_after_seconds: 15 }, false, now), 'FRESH')
})
test('old successful reads, upstream failures and unknown metadata are explicit', () => {
  assert.equal(freshness({ freshness_state: 'FRESH', read_at: '2020-01-01T00:00:00Z', stale_after_seconds: 15 }), 'STALE')
  assert.equal(freshness({ freshness_state: 'FRESH', read_at: new Date().toISOString() }, true), 'STALE')
  assert.equal(freshness(null), 'UNKNOWN')
  assert.equal(freshness(null, true), 'UNKNOWN')
  assert.equal(freshness({ freshness_state: 'FRESH' }), 'UNKNOWN')
})
test('a restored action record cannot prove current network state', () => {
  const meta = { freshness_state: 'FRESH', read_at: new Date().toISOString() }
  assert.equal(isVerifiedNetwork({ state: 'NORMAL', verification: 'ACTION_RECORD', observed_at: new Date().toISOString() }, meta), false)
  assert.equal(isVerifiedNetwork({ state: 'NORMAL', verification: 'LIVE_NEUTRON_READ', observed_at: new Date(Date.now() - 60000).toISOString() }, meta), false)
  assert.equal(isVerifiedNetwork({ state: 'QUARANTINED', verification: 'LIVE_NEUTRON_READ', observed_at: new Date().toISOString() }, meta), true)
  assert.equal(isVerifiedNetwork({ state: 'QUARANTINED', verification: 'LIVE_NEUTRON_READ', observed_at: new Date().toISOString() }, meta, true), false)
})
test('Viewer and unknown role cannot add notes; CSRF is required', () => {
  assert.equal(canWriteNotes({ role: 'Viewer' }, 'csrf'), false)
  assert.equal(canWriteNotes({ role: 'Admin' }, 'csrf'), false)
  assert.equal(canWriteNotes({ role: 'Analyst' }, null), false)
  assert.equal(canWriteNotes({ role: 'Analyst' }, 'csrf'), true)
})
test('filter values and cursors are encoded without losing the signed cursor', () => {
  const params = new URLSearchParams(queryString({ cursor: 'a+b/==', source_ip: '10.0.0.204', rule: '', severity: 'ALL', limit: 25 }))
  assert.equal(params.get('cursor'), 'a+b/==')
  assert.equal(params.get('limit'), '25')
  assert.equal(params.has('severity'), false)
})
test('API v4 sends session cookies, safe CSRF header and exact note body', async () => {
  let seen
  const result = await portalRequest('/incidents/INC-1/notes', { method: 'POST', csrfToken: 'csrf', idempotencyKey: 'same-key-on-retry', body: { note: 'Reviewed' }, fetcher: async (url, options) => {
    seen = { url, options }
    return { ok: true, status: 200, json: async () => ({ data: { note_id: 'n-1' }, meta: { request_id: 'r-1' }, error: null }) }
  } })
  assert.equal(seen.url, '/api/v1/incidents/INC-1/notes')
  assert.equal(seen.options.credentials, 'include')
  assert.equal(seen.options.headers['X-CSRF-Token'], 'csrf')
  assert.equal(seen.options.headers['Idempotency-Key'], 'same-key-on-retry')
  assert.equal(seen.options.body, '{"note":"Reviewed"}')
  assert.equal(result.data.note_id, 'n-1')
})
test('upstream errors never expose traceback or secret error messages', async () => {
  await assert.rejects(portalRequest('/events', { fetcher: async () => ({ ok: false, status: 503, json: async () => ({ error: { code: 'UPSTREAM_UNAVAILABLE', message: 'SECRET traceback' }, meta: { request_id: 'r-2' } }) }) }), error => error.status === 503 && error.requestId === 'r-2' && !error.message.includes('SECRET'))
})
test('POST failures are not silently retried', async () => {
  let calls = 0
  await assert.rejects(portalRequest('/incidents/INC-1/notes', { method: 'POST', body: {}, fetcher: async () => { calls++; throw new Error('network') } }))
  assert.equal(calls, 1)
})
test('HTML and malformed envelopes are not accepted as successful data', async () => {
  await assert.rejects(portalRequest('/events', { fetcher: async () => ({ ok: true, status: 200, json: async () => { throw new Error('html') } }) }), /định dạng/)
  await assert.rejects(portalRequest('/events', { fetcher: async () => ({ ok: true, status: 200, json: async () => ({ items: [] }) }) }), /thiếu data/)
})

test('mapping verified flag alone does not override stale identity or missing TTL', () => {
  const meta = { freshness_state: 'FRESH', read_at: new Date().toISOString() }
  assert.equal(isFreshMapping({ verified: true, observed_at: new Date().toISOString(), ttl_seconds: 600 }, meta), true)
  assert.equal(isFreshMapping({ verified: true, observed_at: '2020-01-01T00:00:00Z', ttl_seconds: 600 }, meta), false)
  assert.equal(isFreshMapping({ verified: true, observed_at: new Date().toISOString() }, meta), false)
  assert.equal(isFreshMapping({ verified: true, observed_at: new Date().toISOString(), ttl_seconds: 600 }, meta, true), false)
})

test('deep links preserve stream identity and filters; malformed paths do not crash', () => {
  const route = parseRoute('#/events/evt%2F1?stream_id=stream-a&decision=BLOCK')
  assert.equal(route.id, 'evt/1')
  assert.equal(route.params.stream_id, 'stream-a')
  assert.equal(route.params.decision, 'BLOCK')
  assert.equal(parseRoute('#/events/%FF').id, null)
  assert.equal(parseRoute('#/system/policies').systemTab, 'policies')
})

test('local snapshot capability is explicit and never fabricates an authenticated user', () => {
  const data = { access_mode: 'LOCAL_SNAPSHOT_READONLY', source_mode: 'SNAPSHOT', user: null,
    write_enabled: false, session_supported: false, capabilities: ['incidents:read'] }
  assert.equal(isLocalSnapshotAccess(data), true)
  assert.equal(isLocalSnapshotAccess({ ...data, write_enabled: true }), false)
  assert.equal(isLocalSnapshotAccess({ ...data, user: { role: 'Executor' } }), false)
  assert.equal(isLocalSnapshotAccess({ ...data, source_mode: 'LIVE' }), false)
})

test('historical snapshots can never verify live mapping or network state', () => {
  const meta = { source_mode: 'SNAPSHOT', freshness_state: 'FRESH', read_at: new Date().toISOString() }
  const mapping = { verified: true, observed_at: new Date().toISOString(), ttl_seconds: 600 }
  const observation = { state: 'QUARANTINED', verification: 'LIVE_NEUTRON_READ', observed_at: new Date().toISOString() }
  assert.equal(isFreshMapping(mapping, meta), false)
  assert.equal(isVerifiedNetwork(observation, meta), false)
})

test('P17 projections preserve provenance and never claim canonical completeness', () => {
  const event = mapEvent({ ...base, view_kind: 'P17_EVENT_PROJECTION', canonical_complete: false, risk: { score: 0, status: 'OK' } })
  assert.equal(event.view_kind, 'P17_EVENT_PROJECTION')
  assert.equal(event.canonical_complete, false)
  assert.equal(event.masked_query, null)
})

test('remote readonly capability requires the explicit matching access/source pair', () => {
  const data = { access_mode: 'LOCAL_REMOTE_READONLY', source_mode: 'REMOTE_READONLY', user: null,
    write_enabled: false, session_supported: false, capabilities: ['incidents:read'] }
  assert.equal(isLocalSnapshotAccess(data), true)
  assert.equal(isLocalSnapshotAccess({ ...data, source_mode: 'LIVE' }), false)
  assert.equal(isLocalSnapshotAccess({ ...data, write_enabled: true }), false)
  assert.equal(isLocalSnapshotAccess({ ...data, access_mode: 'LOCAL_SNAPSHOT_READONLY' }), false)
})

test('a fresh P17 SSH read cannot verify cloud mapping or current network state', () => {
  const meta = { source_mode: 'REMOTE_READONLY', freshness_state: 'FRESH', read_at: new Date().toISOString() }
  assert.equal(isFreshMapping({ verified: true, observed_at: new Date().toISOString(), ttl_seconds: 600 }, meta), false)
  assert.equal(isVerifiedNetwork({ state: 'QUARANTINED', verification: 'LIVE_NEUTRON_READ', observed_at: new Date().toISOString() }, meta), false)
})


test('Event Detail retains canonical policy reasons and score components without unknown fields', () => {
  const event = mapEvent({ ...base, policy_id: 'policy-1', monitor_rules: ['CTX-006'], reasons: ['Policy reason'],
    risk: { status: 'OK', score: 100 }, raw_score: 130,
    score_breakdown: [{ source: 'default_deny', rule_id: null, category: 'default', score: 40, reason: 'No allow rule', raw_sql: 'PRIVATE' }] })
  assert.equal(event.policy_id, 'policy-1')
  assert.deepEqual(event.monitor_rules, ['CTX-006'])
  assert.deepEqual(event.reasons, ['Policy reason'])
  assert.equal(event.raw_score, 130)
  assert.equal(event.score_breakdown[0].rule_id, null)
  assert.equal(event.score_breakdown[0].score, 40)
  assert.ok(!JSON.stringify(event).includes('PRIVATE'))
  assert.equal(mapEvent(base).score_breakdown, null)
})

test('risk errors cannot display fabricated zero component scores or raw totals', () => {
  const event = mapEvent({ ...base, risk: { status: 'ERROR', score: 0 }, raw_score: 0,
    score_breakdown: [{ source: 'test', score: 0 }] })
  assert.equal(event.risk.score, null)
  assert.equal(event.raw_score, null)
  assert.equal(event.score_breakdown[0].score, null)
})

test('each incident mapping expires by its own timestamp and TTL despite a fresh list read', () => {
  const now = Date.now(), meta = { freshness_state: 'FRESH', read_at: new Date(now).toISOString() }
  const current = { verified: true, observed_at: new Date(now - 1000).toISOString(), ttl_seconds: 30 }
  const old = { ...current, observed_at: new Date(now - 60000).toISOString() }
  assert.deepEqual(mappingState(current, meta, false, now), { verification: 'VERIFIED', freshness: 'FRESH' })
  assert.deepEqual(mappingState(old, meta, false, now), { verification: 'UNKNOWN', freshness: 'STALE' })
  assert.equal(mappingState({ ...current, verified: false }, meta, false, now).verification, 'UNVERIFIED')
  assert.equal(mappingState({ ...current, ttl_seconds: null }, meta, false, now).freshness, 'UNKNOWN')
  assert.equal(mappingState(current, { ...meta, source_mode: 'REMOTE_READONLY' }, false, now).verification, 'UNKNOWN')
  assert.equal(mappingState(current, meta, true, now).freshness, 'STALE')
})

test('mapping fixed/floating IPs remain separate and review does not mutate detection', () => {
  const row = mapIncident({ incident_id: 'INC-1', incident_status: 'REVIEW_REQUIRED', review_state: 'ACKNOWLEDGED', review_revision: 'r-1',
    mapping: { fixed_ips: [{ ip_address: '10.0.0.204' }], floating_ips: [{ floating_ip_address: '192.0.2.10' }] },
    review_annotations: [{ annotation_id: 'n-1', author: 'analyst', note: 'Checked', raw_sql: 'PRIVATE' }] })
  assert.equal(row.incident_status, 'REVIEW_REQUIRED')
  assert.equal(row.review_state, 'ACKNOWLEDGED')
  assert.deepEqual(row.mapping.fixed_ips, ['10.0.0.204'])
  assert.deepEqual(row.mapping.floating_ips, ['192.0.2.10'])
  assert.ok(!JSON.stringify(row).includes('PRIVATE'))
})

test('SG names are joined by exact ID and explicit empty groups stay empty', () => {
  const value = { security_group_ids: ['sg-b', 'sg-a'], security_groups: [{ id: 'sg-a', name: 'app' }, { id: 'sg-b', name: 'management' }, { id: 'other', name: 'ignored' }] }
  assert.deepEqual(mapSecurityGroups(value), [{ id: 'sg-b', name: 'management' }, { id: 'sg-a', name: 'app' }])
  assert.deepEqual(mapSecurityGroups({ ...value, security_group_ids: [] }), [])
  assert.deepEqual(mapSecurityGroups({ security_group_ids: ['x'], security_group_names: { x: 'name', y: 'wrong' } }), [{ id: 'x', name: 'name' }])
})

test('port identity and all subnet/IP pairs survive the view mapping', () => {
  const port = mapPort({ port_id: 'p-1', project_id: 'project-1', device_id: 'vm-1', device_owner: 'compute:nova',
    fixed_ips: [{ ip_address: '10.0.0.204', subnet_id: 'sub-1' }, { ip_address: '10.1.0.204', subnet_id: 'sub-2' }],
    security_group_ids: [], port_security_enabled: false })
  assert.equal(port.device_owner, 'compute:nova')
  assert.equal(port.project_id, 'project-1')
  assert.equal(port.fixed_ip_details[1].subnet_id, 'sub-2')
  assert.equal(port.port_security_enabled, false)
  assert.equal(port.security_groups_provided, true)
  assert.equal(mapPort({}).security_groups_provided, false)
})

test('SG snapshots preserve every port and never copy original groups into a missing restore', () => {
  const rows = mapSgHistory({ security_group_history: { ports: [
    { port_id: 'p-1', before: { security_group_ids: ['a', 'b'], observed_at: '2026-10-30T00:00:00Z' }, during: { security_group_ids: ['q'] }, after: {} },
    { port_id: 'p-2', before: { security_group_ids: [] }, after: { security_group_ids: ['c', 'd'] } },
  ] } })
  assert.equal(rows.length, 2)
  assert.deepEqual(rows[0].before.groups.map(group => group.id), ['a', 'b'])
  assert.equal(rows[0].after.provided, false)
  assert.equal(rows[1].before.provided, true)
  assert.deepEqual(rows[1].after.groups.map(group => group.id), ['c', 'd'])
  const flat = mapSgHistory({ port_id: 'p', original_security_group_ids: ['a'], created_at: '2026-10-30T00:00:00Z' })[0]
  assert.equal(flat.before.observed_at, null)
  assert.equal(flat.after.provided, false)
})

test('qualified evidence alone cannot invent allowlist, approval or freshness conditions', () => {
  const decision = mapDecision({ qualified: true, source_verified: false, blocking_reasons: [{ code: 'MAPPING_UNVERIFIED', message: 'Check mapping', token: 'PRIVATE' }] })
  assert.equal(decision.qualified, true)
  assert.equal(decision.source_verified, false)
  assert.equal(decision.operator_approved, null)
  assert.equal(decision.workload_allowed, null)
  assert.equal(decision.source_fresh, null)
  assert.ok(!JSON.stringify(decision).includes('PRIVATE'))
})

test('risk exposure requires recent incident provenance and never derives compromise from P15 or Nova', () => {
  assert.equal(mapWorkload({ server_id: 'vm', nova_status: 'ACTIVE', risk_score: 100, incident_refs: ['INC-1'] }).risk_exposure, null)
  assert.equal(mapRiskExposure({ basis: 'P15_SCORE', incident_count: 1 }), null)
  const now = Date.now(), meta = { freshness_state: 'FRESH', read_at: new Date(now).toISOString() }
  const exposure = mapRiskExposure({ basis: 'RECENT_INCIDENTS', incident_count: 0, window_from: new Date(now - 3600000).toISOString(),
    window_to: new Date(now).toISOString(), observed_at: new Date(now).toISOString(), ttl_seconds: 30 })
  assert.equal(exposure.incident_count, 0)
  assert.equal(riskExposureState(exposure, meta, false, now), 'FRESH')
  assert.equal(riskExposureState(exposure, meta, true, now), 'STALE')
  assert.equal(riskExposureState({ ...exposure, ttl_seconds: null }, meta, false, now), 'UNKNOWN')
  assert.equal(riskExposureState({ ...exposure, window_to: '2026-10-31T00:00:00' }, meta, false, now), 'UNKNOWN')
  assert.equal(riskExposureState({ ...exposure, observed_at: new Date(now - 60000).toISOString() }, meta, false, now), 'STALE')
  assert.equal(riskExposureState(exposure, { ...meta, source_mode: 'SNAPSHOT' }, false, now), 'HISTORICAL')
})

const mappingNow = Date.parse('2026-11-04T10:00:10Z')
const currentMapping = {
  state: 'MATCHED', server_id: 'vm /1', port_id: 'port/2', ttl_seconds: 45,
  observed_at: '2026-11-04T10:00:01Z', observation_from: '2026-11-04T10:00:00Z',
  historical_identity_verified: false,
  source: { source_mode: 'LIVE', freshness_state: 'FRESH', read_at: '2026-11-04T10:00:10Z', stale_after_seconds: 45 },
}
test('current mapping enables only a unique fresh VM/port link and keeps historical identity separate', () => {
  const incident = mapIncident({ incident_id: 'INC-current', mapping: { verified: false }, current_mapping: { ...currentMapping, server_name: 'client', fixed_ips: [{ ip_address: '10.0.0.30' }] } })
  const state = currentMappingState(incident.current_mapping, false, mappingNow)
  assert.equal(state.href, '#/workloads/vm%20%2F1?port_id=port%2F2')
  assert.equal(incident.mapping.verified, false)
  assert.equal(incident.current_mapping.historical_identity_verified, false)
  assert.deepEqual(incident.current_mapping.fixed_ips, ['10.0.0.30'])
  assert.equal(isFreshMapping(incident.mapping, { source_mode: 'SNAPSHOT' }, false, mappingNow), false)
})
test('mapping source freshness is independent, stale or ambiguous mappings never navigate', () => {
  for (const state of ['AMBIGUOUS', 'NO_MATCH', 'UNKNOWN', 'STALE']) {
    assert.equal(currentMappingState({ ...currentMapping, state }, false, mappingNow).href, null)
  }
  assert.equal(currentMappingState(currentMapping, false, mappingNow + 46000).state, 'STALE')
  assert.equal(currentMappingState({ ...currentMapping, source: { ...currentMapping.source, freshness_state: 'STALE' } }, false, mappingNow).href, null)
  assert.equal(currentMappingState(currentMapping, true, mappingNow).href, null)
  assert.equal(currentMappingState(undefined, false, mappingNow).state, 'UNKNOWN')
  assert.equal(currentMappingState({ ...currentMapping, source: { ...currentMapping.source, source_mode: 'SNAPSHOT' } }, false, mappingNow).href, null)
  assert.equal(currentMappingState({ ...currentMapping, observation_from: '2026-11-04T10:02:00Z' }, false, mappingNow).href, null)
  // A recent response cannot renew an old collection timestamp.
  assert.equal(currentMappingState({ ...currentMapping, observation_from: '2026-11-04T09:58:00Z' }, false, mappingNow).href, null)
})
