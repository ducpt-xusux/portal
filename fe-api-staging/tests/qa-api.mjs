// Local browser QA only. Never imported by the app, never connected to OpenStack.
import http from 'node:http'
import { randomUUID } from 'node:crypto'
if (process.env.DBSEC_QA !== '1') throw new Error('Set DBSEC_QA=1 explicitly to start the test-only fixture API.')
const state = { mode: 'healthy', role: 'Analyst', authenticated: true, notes: [], requests: [], reviewState: 'UNREVIEWED', reviewRevision: 1, annotations: [], exports: [], capabilitiesEnabled: true, filterSupportEnabled: true, idempotency: new Map() }
let quarantineState = 'QUARANTINED'
const date = (offset = 0) => new Date(Date.now() + offset).toISOString()
const meta = () => ({ request_id: `qa-${randomUUID()}`, read_at: date(), data_as_of: date(-1000), source_system: 'QA FIXTURE ONLY', source_schema: 'portal-v4-proposed', freshness_state: state.mode === 'stale' ? 'STALE' : 'FRESH', stale_after_seconds: 30, next_cursor: null })
const event = index => ({ stream_id: 'QA-STREAM', event_id: `evt-qa-${index}`, request_id: `req-qa-${index}`, occurred_at: date(-index * 3000), ingested_at: date(-index * 3000 + 100), source_ip: '192.0.2.204', db_user: 'qa_reader', database_name: 'qa_database', mysql_command: 'COM_QUERY', decision: index === 4 ? 'ALLOW' : 'BLOCK', matched_rules: index === 4 ? [] : ['INJ-001', 'CTX-006', 'OBJ-003', 'OBJ-004'], blocking_rules: index === 4 ? [] : ['INJ-001'], risk: { score: index === 4 ? 0 : index === 5 ? null : 100, status: index === 5 ? 'ERROR' : 'OK', severity: index === 4 ? 'LOW' : 'CRITICAL' }, masked_query: index === 1 ? null : 'SELECT [MASKED] FROM [MASKED]', policy_id: 'qa-policy-readonly', policy_version: 'QA-v1.4', monitor_rules: ['CTX-006'], reasons: ['QA: injection blocked before forwarding', 'QA: sensitive object policy'], raw_score: index === 4 ? 0 : index === 5 ? null : 130, score_breakdown: index === 5 ? null : index === 4 ? [] : [{ source: 'matched_rule', rule_id: 'INJ-001', score: 40, category: 'injection', reason: 'QA tautology pattern' }, { source: 'matched_rule', rule_id: 'OBJ-004', score: 50, category: 'sensitive_data', reason: 'QA sensitive object access' }, { source: 'default_deny', rule_id: null, score: 40, category: 'default_deny', reason: 'QA no matching allow rule' }], raw_sql: 'PRIVATE_QA_RAW', token: 'PRIVATE_QA_TOKEN', p17_event_class: 'LIVE', stream_sequence: index, incident_refs: index <= 3 ? ['INC-QA-002'] : [], source_provenance: { source_system: 'QA FIXTURE ONLY', source_ref: `qa:event:${index}` } })
const mapping = (expired = false) => ({ verified: true, source_ip: '192.0.2.204', server_id: 'vm-qa-clone', port_id: 'port-qa-clone', project_id: 'project-qa-only', network_id: 'network-qa-only', fixed_ips: ['192.0.2.204'], floating_ips: ['198.51.100.204'], observed_at: expired ? date(-120000) : date(), ttl_seconds: 30 })
const currentMapping = index => ({ ...mapping(), verified: false, server_name: 'clone-qa', port_id: 'port-qa-6', network_id: 'network-qa-6',
  fixed_ips: ['192.0.2.204'], floating_ips: [], state: state.mode === 'stale' ? 'STALE' : index === 3 ? 'AMBIGUOUS' : 'MATCHED',
  candidate_count: index === 3 ? 2 : 1, matched_by: ['FIXED_IP'], historical_identity_verified: false,
  observation_from: date(-1000), observed_at: date(), ttl_seconds: 45,
  reason: index === 3 ? 'MULTIPLE_CURRENT_PORT_MATCHES' : 'UNIQUE_CURRENT_IP_MATCH',
  source: { ...meta(), source_mode: 'LIVE', source_system: 'QA FIXTURE ONLY', stale_after_seconds: 45 },
})
const incident = index => ({ incident_id: index === 2 ? 'INC-QA-002' : `INC-QA-00${index}`, stream_id: 'QA-STREAM', source_ip: '192.0.2.204', signal_rule: `CORR-00${index}`, severity: 'HIGH', confidence: 'CANDIDATE_CORRELATED', first_seen: date(-30000), last_seen: date(-5000), evidence_count: 3, p15_peak_score: 100, incident_status: 'REVIEW_REQUIRED', response_state: state.filterSupportEnabled ? 'RESTORED' : 'UNKNOWN', evidence_membership: 'RECONSTRUCTED_WINDOW', review_state: state.reviewState, review_revision: `rev-${state.reviewRevision}`, review_annotations: state.annotations, mapping: { ...mapping(index === 3), verified: false }, current_mapping: currentMapping(index) })
const port = index => ({ port_id: `port-qa-${index}`, network_id: `network-qa-${index}`, project_id: 'project-qa-only', device_id: 'vm-qa-clone', device_owner: 'compute:nova', status: 'ACTIVE', mac_address: '02:00:00:00:00:01', fixed_ips: [{ ip_address: index === 6 ? '192.0.2.204' : `192.0.2.${index + 10}`, subnet_id: `subnet-qa-${index}` }], floating_ips: index === 5 ? ['198.51.100.204'] : [], security_groups: [{ id: 'sg-qa-app', name: 'QA application' }, { id: 'sg-qa-management', name: 'QA management' }], security_group_ids: ['sg-qa-management', 'sg-qa-app'], port_security_enabled: true, observed_at: date() })
const workload = index => ({ server_id: index === 5 ? 'vm-qa-clone' : `vm-qa-${index}`, name: ['app-qa', 'proxy-qa', 'galera-qa-1', 'galera-qa-2', 'galera-qa-3', 'clone-qa'][index], nova_status: 'ACTIVE', project_id: 'project-qa-only', role: index === 5 ? 'LAB_DEDICATED' : 'PROTECTED', protected: index !== 5, compute_host: 'qa-compute', observed_at: date(), ports: index === 5 ? [port(5), port(6)] : [port(index)], incident_refs: index === 5 ? ['INC-QA-002'] : [], risk_exposure: { basis: 'RECENT_INCIDENTS', incident_count: index === 5 ? 2 : 0, severity: index === 5 ? 'HIGH' : null, window_from: date(-3600000), window_to: date(), observed_at: date(), ttl_seconds: 30, incident_refs: index === 5 ? ['INC-QA-002', 'INC-QA-003'] : [], source_ref: 'qa:p17:recent-incidents' } })
const network = () => ({ state: 'NORMAL', verification: 'LIVE_NEUTRON_READ', observed_at: date(), security_group_ids: ['sg-qa-management', 'sg-qa-app'] })
const action = () => ({ action_id: 'act-qa-1', incident_id: 'INC-QA-002', server_id: 'vm-qa-clone', port_id: 'port-qa-clone', source_ref: 'qa:action:act-qa-1', original_security_groups: [{ id: 'sg-qa-management', name: 'QA management' }, { id: 'sg-qa-app', name: 'QA application' }], quarantine_security_groups: [{ id: 'sg-qa-quarantine', name: 'QA quarantine' }], restored_security_groups: [{ id: 'sg-qa-management', name: 'QA management' }, { id: 'sg-qa-app', name: 'QA application' }], before_observed_at: date(-26000), during_observed_at: date(-20000), after_observed_at: date(-5000), state: 'RESTORED', created_at: date(-25000), verified_at: date(-5000), original_security_group_ids: ['sg-qa-management', 'sg-qa-app'], quarantine_security_group_ids: ['sg-qa-quarantine'], restored_security_group_ids: ['sg-qa-management', 'sg-qa-app'], network_observation: network() })
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1')
  const chunks = []; for await (const chunk of request) chunks.push(chunk)
  let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}') } catch { /* Invalid JSON handled as no input. */ }
  const send = (data, status = 200, code = null, sourceMeta = {}) => { response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(JSON.stringify({ data, meta: { ...meta(), ...sourceMeta }, error: code ? { code, message: code } : null })) }
  if (url.pathname === '/__qa/state') {
    if (request.method === 'POST' && ['QUARANTINED', 'NORMAL', 'STALE', 'UNAVAILABLE'].includes(body.quarantineState)) quarantineState = body.quarantineState
    if (request.method === 'POST') { if (body.mode) state.mode = body.mode; if (body.role) state.role = body.role; if (typeof body.authenticated === 'boolean') state.authenticated = body.authenticated; if (typeof body.capabilitiesEnabled === 'boolean') state.capabilitiesEnabled = body.capabilitiesEnabled; if (typeof body.filterSupportEnabled === 'boolean') state.filterSupportEnabled = body.filterSupportEnabled }
    return send({ ...state, notes: state.notes.length, idempotency: undefined, requests: state.requests.slice(-30) })
  }
  const path = url.pathname.replace(/^\/api\/v1/, '')
  state.requests.push(`${request.method} ${url.pathname}${url.search}`)
  if (path === '/portal/access-mode') return send({ mode: 'SESSION' })
  if (path === '/auth/login' && request.method === 'POST') { state.authenticated = true; return send({ authenticated: true }) }
  if (path === '/auth/logout' && request.method === 'POST') { state.authenticated = false; return send({ authenticated: false }) }
  if (!state.authenticated) return send(null, 401, 'UNAUTHENTICATED')
  if (path === '/portal/session/capabilities') return send({ user_id: 'qa-user' })
  if (path === '/auth/me') return send({ username: 'qa-analyst', roles: [state.role], expires_at: date(3600000), user: { user_id: 'qa-user', login: 'qa-analyst', role: state.role, project_name: 'QA fixture · Dữ liệu kiểm thử, không phải lab live' }, csrf_token: 'qa-test-only-csrf', incident_filters: { review_state: state.filterSupportEnabled, response_states: state.filterSupportEnabled ? ['NONE', 'QUARANTINED', 'RESTORED', 'UNKNOWN'] : ['UNKNOWN'] }, write_enabled: state.role !== 'Viewer', capabilities: state.capabilitiesEnabled ? ['incidents:review', 'evidence:export'] : [] })
  if (state.mode === 'outage') return send(null, 503, 'UPSTREAM_UNAVAILABLE')
  if (path === '/dashboard/summary') return send({ event_counts: { allow: 84, block: 12, unknown: 0, risk_errors: 1 }, incident_counts: { review_required: 2, critical: 0 }, quarantined_workloads: null, sources: { neutron: { freshness_state: 'UNKNOWN' } }, protection_path: ['Application', 'DB Firewall', 'Galera Cluster'].map(name => ({ name, status: 'HEALTHY', observed_at: date() })) })
  if (path === '/dashboard/event-series') return send({ points: Array.from({ length: 15 }, (_, i) => ({ occurred_at: date(-(14 - i) * 60000), allow: [3, 5, 4, 6, 7, 4, 8, 6, 9, 6, 5, 7, 9, 8, 6][i], block: [0, 0, 1, 0, 0, 2, 1, 3, 0, 1, 0, 1, 2, 0, 1][i] })) })
  if (path === '/incidents') {
    if (!state.filterSupportEnabled && (url.searchParams.get('review_state') || (url.searchParams.get('response_state') && url.searchParams.get('response_state') !== 'UNKNOWN'))) return send(null, 503, 'FILTER_NOT_CONFIGURED')
    let items = [incident(2), incident(3)]
    if (url.searchParams.get('status')) items = items.filter(item => item.incident_status === url.searchParams.get('status'))
    if (url.searchParams.get('from')) items = items.filter(item => Date.parse(item.last_seen) >= Date.parse(url.searchParams.get('from')))
    if (url.searchParams.get('to')) items = items.filter(item => Date.parse(item.last_seen) <= Date.parse(url.searchParams.get('to')))
    for (const key of ['signal_rule', 'source_ip', 'severity', 'review_state', 'response_state']) if (url.searchParams.get(key)) items = items.filter(item => item[key] === url.searchParams.get(key))
    if (state.mode === 'empty') items = []
    return send({ items })
  }
  if (path.endsWith('/evidence')) return send({ items: [event(1), event(2), event(3)], evidence_membership: 'RECONSTRUCTED_WINDOW', recorded_evidence_count: 3, reconstructed_request_count: 3, matches_recorded_count: true })
  if (path.endsWith('/timeline')) return send({ timeline: ['LAB_ARMED', 'SQL_REQUEST', 'CORR_002_DETECTED', 'QUARANTINE_APPLIED', 'SG_RESTORED'].map((type, i) => ({ type, occurred_at: date(-30000 + i * 5000), source_system: i < 3 ? 'QA P17' : 'QA P17.5', source_ref: `qa:timeline:${i}`, verification: 'VERIFIED_RECORD' })), security_group_history: { ports: [action(), { ...action(), port_id: 'port-qa-secondary', action_id: 'act-qa-2' }] }, network_observation: network() })
  if (path.endsWith('/decision')) return send({ qualified: true, source_verified: true, workload_allowed: true, operator_approved: false, source_fresh: true, evaluated_at: date(), blocking_reasons: [{ code: 'OPERATOR_APPROVAL_REQUIRED', message: 'QA: operator approval has not been recorded' }] })
  if (path.endsWith('/notes') && request.method === 'POST') {
    if (state.role === 'Viewer') return send(null, 403, 'FORBIDDEN')
    if (request.headers['x-csrf-token'] !== 'qa-test-only-csrf') return send(null, 403, 'CSRF_INVALID')
    if (typeof body.note !== 'string' || !body.note.trim() || body.note.length > 1000) return send(null, 422, 'INVALID_NOTE'); state.notes.push(body.note); return send({ note_id: `qa-note-${state.notes.length}`, created_utc: date() })
  }
  if (/^\/incidents\/[^/]+\/review$/.test(path) && request.method === 'POST') {
    if (!state.capabilitiesEnabled || !['Analyst', 'Operator', 'Approver'].includes(state.role)) return send(null, 403, 'FORBIDDEN')
    if (request.headers['x-csrf-token'] !== 'qa-test-only-csrf') return send(null, 403, 'CSRF_INVALID')
    const key = `review:${request.headers['idempotency-key'] || ''}`
    if (!request.headers['idempotency-key']) return send(null, 400, 'IDEMPOTENCY_REQUIRED')
    if (state.idempotency.has(key)) return send(state.idempotency.get(key))
    if (body.expected_revision !== `rev-${state.reviewRevision}`) return send(null, 409, 'REVIEW_CONFLICT')
    if (!['ACKNOWLEDGED', 'REVIEWED'].includes(body.review_state) || typeof body.note !== 'string' || body.note.length > 1000) return send(null, 422, 'INVALID_REVIEW')
    state.reviewState = body.review_state; state.reviewRevision++
    const annotation_id = `qa-ann-${state.annotations.length + 1}`
    state.annotations.unshift({ annotation_id, review_state: body.review_state, note: body.note, author: 'qa-analyst', created_at: date() })
    const value = { incident_id: path.split('/')[2], annotation_id, review_state: state.reviewState, review_revision: `rev-${state.reviewRevision}` }
    state.idempotency.set(key, value); return send(value)
  }
  if (/^\/incidents\/[^/]+\/evidence\/exports$/.test(path) && request.method === 'POST') {
    if (!state.capabilitiesEnabled || !['Viewer', 'Analyst', 'Operator', 'Approver', 'Auditor'].includes(state.role)) return send(null, 403, 'FORBIDDEN')
    if (request.headers['x-csrf-token'] !== 'qa-test-only-csrf') return send(null, 403, 'CSRF_INVALID')
    if (!['json', 'csv'].includes(body.format) || body.scope !== 'EVIDENCE_REFERENCES') return send(null, 422, 'INVALID_EXPORT')
    const key = `export:${request.headers['idempotency-key'] || ''}`
    if (!request.headers['idempotency-key']) return send(null, 400, 'IDEMPOTENCY_REQUIRED')
    if (state.idempotency.has(key)) return send(state.idempotency.get(key))
    const export_id = `qa-export-${state.exports.length + 1}`, audit_id = `qa-audit-${state.exports.length + 1}`
    const value = { incident_id: path.split('/')[2], export_id, audit_id, generated_at: date(), format: body.format,
      complete: true, has_more: false, evidence_membership: 'RECONSTRUCTED_WINDOW', recorded_evidence_count: 3, items: [event(1), event(2), event(3)] }
    state.exports.push({ export_id, audit_id, format: body.format, created_at: date() }); state.idempotency.set(key, value); return send(value)
  }
  if (/^\/incidents\/[^/]+$/.test(path)) return send(incident(2))
  if (path === '/events') {
    let items = [event(1), event(2), event(3), event(4), event(5)]
    for (const key of ['decision', 'source_ip']) if (url.searchParams.get(key)) items = items.filter(item => item[key] === url.searchParams.get(key))
    if (url.searchParams.get('rule')) items = items.filter(item => item.matched_rules.includes(url.searchParams.get('rule')))
    if (state.mode === 'empty') items = []
    const paged = url.searchParams.has('cursor') ? items.slice(3) : items.slice(0, 3)
    const envelope = { data: { items: paged }, meta: { ...meta(), next_cursor: !url.searchParams.has('cursor') && items.length > 3 ? 'qa-cursor+/=' : null }, error: null }
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); return response.end(JSON.stringify(envelope))
  }
  if (/^\/events\/[^/]+$/.test(path)) return send(event(Number(path.split('-').at(-1)) || 1))
  if (path === '/workloads') {
    if (url.searchParams.get('network_state') !== 'QUARANTINED')
      return send({ items: Array.from({ length: 6 }, (_, i) => workload(i)) })
    if (quarantineState === 'UNAVAILABLE') return send(null, 503, 'NETWORK_CLASSIFICATION_NOT_CONFIGURED')
    const matches = quarantineState === 'NORMAL' ? [] : [4, 5].map((i) => ({
      ...workload(i), network_state: 'QUARANTINED',
      network_observation: { ...network(), state: 'QUARANTINED' },
    }))
    return send({ items: matches.slice(0, Number(url.searchParams.get('limit') || 25)) }, 200, null, {
      source_mode: 'LIVE', network_classification: 'CONFIGURED', total_count: matches.length,
      ...(quarantineState === 'STALE' ? { freshness_state: 'STALE' } : {}),
    })
  }
  if (path.endsWith('/ports')) return send({ items: [port(5), port(6)] })
  if (/^\/workloads\/[^/]+$/.test(path)) return send(workload(5))
  if (path === '/actions') return send({ items: [action()] })
  if (/^\/actions\/[^/]+$/.test(path)) return send(action())
  if (path === '/system/health') return send({ components: ['DB Firewall', 'P16H Collector', 'P17 Worker', 'OpenStack API', 'Portal Adapter', 'P17.5 Feed'].map((name, i) => ({ component_id: `qa-${i}`, name, status: 'HEALTHY', observed_at: date(), last_success: date(), last_attempt: date(), source_ref: 'qa:health' })) })
  if (path === '/system/galera') return send({ nodes: [1, 2, 3].map(i => ({ node_id: `qa-galera-${i}`, name: `galera-qa-${i}`, wsrep_cluster_status: 'Primary', wsrep_cluster_size: 3, wsrep_local_state_comment: 'Synced', wsrep_ready: true, observed_at: date() })) })
  if (path === '/system/policies') return send({ policy_id: 'qa-policy-readonly', policy_version: 'QA-v1.4', monitor_rules: ['CTX-006'], reasons: ['QA: injection blocked before forwarding', 'QA: sensitive object policy'], raw_score: index === 4 ? 0 : index === 5 ? null : 130, score_breakdown: index === 5 ? null : index === 4 ? [] : [{ source: 'matched_rule', rule_id: 'INJ-001', score: 40, category: 'injection', reason: 'QA tautology pattern' }, { source: 'matched_rule', rule_id: 'OBJ-004', score: 50, category: 'sensitive_data', reason: 'QA sensitive object access' }, { source: 'default_deny', rule_id: null, score: 40, category: 'default_deny', reason: 'QA no matching allow rule' }], raw_sql: 'PRIVATE_QA_RAW', token: 'PRIVATE_QA_TOKEN', policy_hash: 'QA-TEST-HASH', observed_at: date(), rules: ['INJ-001', 'CTX-006', 'OBJ-003', 'OBJ-004'].map(rule_id => ({ rule_id, name: 'QA rule fixture', score: 25, severity_hint: 'HIGH', enabled: true })) })
  if (path === '/system/data-sources') return send({ items: ['P16H', 'P17.2', 'P17.5', 'Neutron'].map(source_system => ({ source_system, source_schema: 'qa-only', freshness_state: 'FRESH', last_success: date(), last_attempt: date(), data_as_of: date(-3000), last_error_code: null })) })
  return send(null, 404, 'NOT_FOUND')
})
server.listen(8011, '127.0.0.1', () => console.log('QA FIXTURE ONLY on http://127.0.0.1:8011 — not a live Portal backend'))
