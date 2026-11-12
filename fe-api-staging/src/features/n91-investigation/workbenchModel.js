import { PortalApiError } from '../../services/portalApi.js'

export const WORKBENCH_TABS = [
  'overview',
  'timeline',
  'detection',
  'response',
  'notes',
]
export const isInvestigationId = (v) =>
  typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(v)
export function canReadWorkbench(auth, sessionEnabled) {
  if (!sessionEnabled) return auth?.status === 'local_snapshot'
  return (
    auth?.status === 'authenticated' &&
    (auth.user?.roles || [auth.user?.role]).some((r) =>
      ['Analyst', 'Operator', 'Approver', 'Executor', 'Auditor'].includes(r)
    )
  )
}
export function resolveLegacyIdentity(record, requestedId) {
  return record?.incident_id === requestedId &&
    isInvestigationId(record.stream_id)
    ? { incident_id: requestedId, stream_id: record.stream_id }
    : null
}
export function workbenchTab(value) {
  return WORKBENCH_TABS.includes(value) ? value : 'overview'
}
export function eventHref(ref, source) {
  if (
    !isInvestigationId(ref?.stream_id) ||
    !isInvestigationId(ref?.event_id) ||
    !['canonical', 'p17'].includes(source)
  )
    return null
  return `#/events/${encodeURIComponent(ref.event_id)}?${new URLSearchParams({ stream_id: ref.stream_id, source })}`
}
export function resetsMemberPage(error) {
  return (
    (error?.status === 409 && error?.code === 'INVESTIGATION_SOURCE_CHANGED') ||
    (error?.status === 422 && error?.code === 'INVESTIGATION_CURSOR_INVALID')
  )
}

// Closed, versioned wire contract. Unknown fields require an explicit contract review.
const invalid = () => {
  throw new PortalApiError(
    'Aggregate điều tra chưa đúng contract hoặc cặp định danh.',
    502,
    'INVESTIGATION_INVALID_RESPONSE'
  )
}
const check = (test) => {
  if (!test) invalid()
}
const id = (v) => check(isInvestigationId(v))
const text = (v) =>
  check(typeof v === 'string' && v.length > 0 && v.length <= 4096)
const bool = (v) => check(typeof v === 'boolean')
const count = (v) => check(Number.isInteger(v) && v >= 0)
const score = (v) => {
  count(v)
  check(v <= 100)
}
const hash = (v) => check(typeof v === 'string' && /^[a-f0-9]{64}$/.test(v))
const time = (v) =>
  check(
    typeof v === 'string' &&
      /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(v) &&
      Number.isFinite(Date.parse(v))
  )
const literal =
  (...values) =>
  (v) =>
    check(values.includes(v))
const nullable = (fn) => (v) => {
  if (v !== null) fn(v)
}
const list =
  (fn, max = 10000) =>
  (v) => {
    check(Array.isArray(v) && v.length <= max)
    v.forEach(fn)
  }
const obj = (shape) => (v) => {
  check(v !== null && typeof v === 'object' && !Array.isArray(v))
  check(
    Object.keys(v).length === Object.keys(shape).length &&
      Object.keys(v).every((k) => Object.hasOwn(shape, k))
  )
  Object.entries(shape).forEach(([key, fn]) => fn(v[key]))
}
const ids = list(id)
const nothing = literal(null),
  no = literal(false)
const identity = obj({ stream_id: id, incident_id: id })
const eventRef = obj({ stream_id: id, event_id: id, request_id: id })
const risk = obj({
  status: nullable(id),
  score: nullable(score),
  severity: nullable(id),
})
const projection = obj({
  stream_sequence: count,
  occurred_at: time,
  ingested_at: time,
  blocked: bool,
  event_class: id,
  live_eligible: bool,
  matched_rules: ids,
  risk,
  payload_sha256: hash,
  payload_hash_basis: literal('P17_RECORDED_UPSTREAM_HASH'),
})
const canonical = obj({
  stream_id: id,
  event_id: id,
  request_id: nullable(id),
  occurred_at: time,
  decision: literal('ALLOW', 'BLOCK'),
  effective_action: literal('ALLOW', 'BLOCK'),
  action_result: literal('FORWARDED', 'BLOCKED', 'ERROR'),
  policy_id: id,
  policy_version: id,
  runtime_mode: literal('monitor', 'enforce'),
  matched_rules: ids,
  blocking_rules: ids,
  monitor_rules: ids,
  risk,
  source_ref: id,
  payload_sha256: nullable(hash),
  payload_hash_basis: nullable(literal('UPSTREAM_UNVERIFIED')),
})
const member = obj({
  event_ref: eventRef,
  projection,
  canonical: nullable(canonical),
  canonical_availability: literal('AVAILABLE', 'UNAVAILABLE', 'MISMATCH'),
  join_state: literal('RECONSTRUCTED_WINDOW', 'MISMATCH', 'UNAVAILABLE'),
  candidate_basis: literal('LEGACY_UNPINNED'),
  hash_comparability: literal('NOT_PROVEN', 'UNAVAILABLE'),
  eligible_for_corr: nothing,
  reason_codes: ids,
})
const cursor = nullable((v) =>
  check(typeof v === 'string' && v.length > 0 && v.length <= 2048)
)
const members = obj({
  available: bool,
  items: list(member, 100),
  authoritative_count: count,
  total_candidates: nullable(count),
  verified_linked_count: nullable(literal(0)),
  direct_membership_supported: no,
  membership: literal('RECONSTRUCTED_WINDOW', 'UNAVAILABLE'),
  candidate_basis: literal('LEGACY_UNPINNED'),
  matches_recorded_count: nullable(bool),
  limit: (v) => {
    count(v)
    check(v >= 1 && v <= 100)
  },
  has_more: bool,
  next_cursor: cursor,
})
const alert = obj({
  alert_id: id,
  incident_id: id,
  stream_id: id,
  created_at: time,
  signal_code: id,
  severity: id,
  trigger_event: eventRef,
  link_basis: literal('P17_OUTBOX_INCIDENT_ID_IN_STREAM'),
  delivered_is_review: no,
})
const dependent = obj({
  availability: literal('UNAVAILABLE'),
  outcome: nothing,
  reason_codes: ids,
})
const metricSeconds = (v) => check(typeof v === 'number' && Number.isFinite(v) && v >= 0)
const cycleScope = { incident_id: id, cycle_id: id }
const phases = ['BEFORE', 'DURING', 'AFTER']
const sgSnapshot = obj({
  ...cycleScope, phase: literal(...phases), project_id: id, port_id: id,
  server_id: id, security_group_ids: list(id, 256), observed_at: nullable(time), source_ref: id,
})
const responseCycle = obj({
  cycle_id: id, id_authority: literal('PORTAL_PROJECTION_ID'), state: id,
  project_id: nullable(id), port_id: id, vm_id: id,
  original_sgs: nullable(list(id, 256)), quarantine_sg: nullable(id),
  clock_marks: list(obj({
    ...cycleScope, kind: id, timestamp: time, clock_id: id, time_basis: id, source_ref: id,
  }), 32),
  metrics: list(obj({
    ...cycleScope, metric: literal('detection_response', 'trigger_to_quarantine', 'quarantine_duration', 'ingestion_latency'),
    seconds: nullable(metricSeconds), unit: literal('seconds'), start_kind: id, end_kind: id,
    clock_id: nullable(id), time_basis: nullable(id), source_refs: list(id, 2), unavailable_reason: nullable(id),
  }), 4),
  history: obj({ BEFORE: nullable(sgSnapshot), DURING: nullable(sgSnapshot), AFTER: nullable(sgSnapshot) }),
  current: nullable(obj({ source_ref: id, observed_at: time, expires_at: time, security_group_ids: list(id, 256) })),
  current_state: literal('UNKNOWN', 'DRIFT', 'QUARANTINED', 'RESTORED'),
  current_reason: nullable(id),
})
const responseHistory = obj({
  schema_version: literal('portal-response-history-1'), availability: literal('PARTIAL'),
  incident_id: id, stream_id: nullable(id), binding_source_ref: nullable(id),
  arm_context: nullable(obj({ kind: literal('OWNER_ARM'), timestamp: time, link_quality: literal('CONTEXT_ONLY'), source_ref: id })),
  provenance: obj({
    run_id: id, archive_sha256: hash, registry_generation: hash, origin_mode: id,
    scope: literal('LAB', 'UNKNOWN'), source_context: literal('TEST', 'IMPORTED_UNVERIFIED'),
    artifacts: list(obj({
      label: literal('CONTAINMENT', 'CLONE_BEFORE', 'CLONE_AFTER', 'SG_SAMPLER', 'CONTROLLER_WATCH', 'RESTORE_VERIFICATION'),
      source_ref: id, sha256: hash,
    }), 6),
  }),
  cycles: list(responseCycle, 256), reason_codes: ids,
})

export function parseResponseHistory(history, expected = null) {
  responseHistory(history)
  check(history.cycles.length > 0 && history.provenance.artifacts.length > 0)
  if (expected) {
    check(history.incident_id === expected.incident_id && history.stream_id === expected.stream_id &&
      history.binding_source_ref !== null)
  } else {
    check(history.stream_id === null && history.binding_source_ref === null)
  }
  const cycles = new Set()
  for (const cycle of history.cycles) {
    check(!cycles.has(cycle.cycle_id))
    cycles.add(cycle.cycle_id)
    const sameCycle = (row) => row.incident_id === history.incident_id && row.cycle_id === cycle.cycle_id
    for (const mark of cycle.clock_marks) check(sameCycle(mark))
    for (const metric of cycle.metrics) {
      check(sameCycle(metric) && (metric.seconds === null) === (metric.unavailable_reason !== null))
      if (metric.seconds !== null) check(metric.clock_id !== null && metric.time_basis !== null)
    }
    for (const phase of phases) {
      const row = cycle.history[phase]
      if (row) check(sameCycle(row) && row.phase === phase && row.project_id === cycle.project_id &&
        row.port_id === cycle.port_id && row.server_id === cycle.vm_id)
    }
    if (!cycle.current) check(cycle.current_state === 'UNKNOWN' && cycle.current_reason !== null)
    else check(history.cycles.length === 1 && cycle.project_id !== null &&
      Date.parse(cycle.current.observed_at) < Date.parse(cycle.current.expires_at))
  }
  return history
}
const overlay = obj({
  kind: literal('incident', 'alert'),
  object_id: id,
  stream_id: id,
  execution_mode: literal('LIVE', 'HISTORICAL', 'ISOLATED', 'STAGING', 'TEST'),
  review_state: literal('UNREAD', 'REVIEWED'),
  acknowledged: bool,
  assignee_id: nullable(text),
  priority: literal('UNSET', 'LOW', 'MEDIUM', 'HIGH', 'URGENT'),
  version: count,
  updated_at: nullable(time),
  actor_id: nullable(text),
  owner: literal('PORTAL_ANNOTATION'),
  source_status_changed: no,
})
const registry = obj({
  source_system: literal('N91 defense source registry'),
  source_schema: literal('n91-defense-source-registry-1'),
  source_mode: literal('OFFLINE_METADATA_ONLY'),
  source_ref: text,
  generation: hash,
  run_id: id,
  run_context: literal('TEST', 'IMPORTED_UNVERIFIED'),
  freshness_state: literal('HISTORICAL'),
  overall_status: literal('COMPLETE', 'PARTIAL'),
  archive_count: count,
  artifact_count: count,
  missing_hosts: list(
    literal(
      'app',
      'controller',
      'g07-restore-c1',
      'galera-1',
      'galera-2',
      'galera-3',
      'p17-lab-clone',
      'proxy'
    )
  ),
  coverage_complete: no,
  content_review: literal('REQUIRED'),
  data_as_of: nothing,
  observed_at: nothing,
  read_at: time,
  imported_at: time,
  reason_codes: list(
    literal(
      'CONTENT_REVIEW_REQUIRED',
      'TIMESTAMP_UNAVAILABLE',
      'HOST_BUNDLE_MISSING'
    )
  ),
})
const source = obj({
  source_system: id,
  availability: literal('AVAILABLE', 'PARTIAL', 'UNAVAILABLE'),
  freshness_state: literal(
    'FRESH',
    'STALE',
    'PARTIAL',
    'UNKNOWN',
    'UNAVAILABLE',
    'HISTORICAL'
  ),
  read_at: time,
  data_as_of: nullable(time),
  observed_at: nullable(time),
  captured_at: nullable(time),
  source_ref: nullable(id),
  generation: nullable(hash),
  source_schema: nullable((v) =>
    check(
      typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,159}$/.test(v)
    )
  ),
  context: nullable(id),
  error_code: nullable(id),
  coverage_complete: no,
  reason_codes: ids,
})
const incident = obj({
  stream_id: id,
  incident_id: id,
  signal_rule: id,
  source_ip: text,
  source_key_hash: hash,
  source_key_hash_basis: literal('PORTAL_HASH_OF_SOURCE_KEY'),
  severity: id,
  status: id,
  confidence: id,
  evidence_count: count,
  peak_p15: nullable(score),
  source_verified: bool,
  isolation_authorized: bool,
  first_seen: time,
  last_seen: time,
  created_at: time,
  updated_at: time,
})
const data = obj({
  schema_version: literal('portal-investigation-1'),
  identity,
  incident,
  event_members: members,
  alerts: obj({
    availability: literal('AVAILABLE', 'UNAVAILABLE'),
    items: list(alert),
    total_count: nullable(count),
    has_more: bool,
    reason_codes: ids,
  }),
  detection: dependent,
  decision: dependent,
  response: (value) => value?.schema_version === 'portal-response-history-1'
    ? responseHistory(value)
    : dependent(value),
  analyst_case: obj({
    availability: literal('AVAILABLE', 'UNAVAILABLE'),
    overlay: nullable(overlay),
    write_enabled: no,
    reason_codes: ids,
  }),
  defense_registry: nullable(registry),
})
const meta = obj({
  request_id: id,
  read_at: time,
  data_as_of: nullable(time),
  source_system: literal('PORTAL_INVESTIGATION'),
  source_schema: literal('portal-investigation-1'),
  overall_status: literal('PARTIAL'),
  freshness_state: literal('FRESH', 'HISTORICAL', 'STALE'),
  execution_mode: literal('HISTORICAL'),
  source_context: literal('TEST', 'IMPORTED_UNVERIFIED'),
  sources: list(source, 32),
  missing_fields: ids,
  limitations: list(text),
  coverage_complete: no,
  next_cursor: cursor,
})

export function parseInvestigation(payload, expected) {
  obj({ data, meta, error: nothing })(payload)
  check(
    isInvestigationId(expected?.incident_id) &&
      isInvestigationId(expected?.stream_id)
  )
  const d = payload.data,
    m = d.event_members
  if (d.response.schema_version) {
    parseResponseHistory(d.response, expected)
    check(d.response.provenance.source_context === payload.meta.source_context)
  }
  for (const pair of [d.identity, d.incident])
    check(
      pair.incident_id === expected.incident_id &&
        pair.stream_id === expected.stream_id
    )
  check(
    m.authoritative_count === d.incident.evidence_count &&
      m.items.length <= m.limit
  )
  check(
    m.has_more === (m.next_cursor !== null) &&
      m.next_cursor === payload.meta.next_cursor
  )
  check(m.total_candidates === null || m.total_candidates >= m.items.length)
  check(
    m.available ||
      (!m.items.length && !m.has_more && m.membership === 'UNAVAILABLE')
  )
  const seen = new Set()
  for (const event of m.items) {
    check(
      event.event_ref.stream_id === expected.stream_id &&
        !seen.has(event.event_ref.event_id)
    )
    seen.add(event.event_ref.event_id)
    check(
      (event.canonical_availability === 'AVAILABLE') ===
        (event.canonical !== null)
    )
    if (event.canonical)
      check(
        event.canonical.stream_id === expected.stream_id &&
          event.canonical.event_id === event.event_ref.event_id &&
          (event.canonical.request_id === null ||
            event.canonical.request_id === event.event_ref.request_id)
      )
    if (event.canonical_availability === 'MISMATCH')
      check(event.join_state === 'MISMATCH')
  }
  for (const a of d.alerts.items)
    check(
      a.stream_id === expected.stream_id &&
        a.incident_id === expected.incident_id &&
        a.trigger_event.stream_id === expected.stream_id
    )
  if (d.analyst_case.overlay)
    check(
      d.analyst_case.availability === 'AVAILABLE' &&
        d.analyst_case.overlay.kind === 'incident' &&
        d.analyst_case.overlay.object_id === expected.incident_id &&
        d.analyst_case.overlay.stream_id === expected.stream_id
    )
  return structuredClone(payload)
}
