export const STAGES = Object.freeze([
  'SQL_PARSE',
  'P14_POLICY',
  'P15_RISK',
  'P16H_AUDIT',
  'P17_DETECTION',
  'P17_DECISION',
  'P17_5_RESPONSE',
])
export const TABS = Object.freeze([
  'Overview',
  'Parser',
  'Rules',
  'Risk',
  'Trace',
  'Evidence',
])
const string = (value) =>
  typeof value === 'string' ? value.slice(0, 16384) : null
const strings = (value) =>
  Array.isArray(value)
    ? value.filter((x) => typeof x === 'string').slice(0, 256)
    : []
const object = (value) =>
  value && typeof value === 'object' && !Array.isArray(value) ? value : {}
const finite = (value) =>
  typeof value === 'number' && Number.isFinite(value) ? value : null

export function eventModel(raw) {
  if (
    !raw ||
    !raw.event_id ||
    !raw.stream_id ||
    raw.view_kind !== 'P16H_CANONICAL_AUDIT'
  )
    throw new Error('CANONICAL_STREAM_EVENT_REQUIRED')
  const provenance = object(raw.source_provenance),
    risk = object(raw.risk)
  const validRisk = risk.status === 'OK'
  const score = finite(risk.score)
  return {
    event_id: string(raw.event_id),
    stream_id: string(raw.stream_id),
    request_id: string(raw.request_id),
    occurred_at: string(raw.occurred_at),
    request_received_at: string(raw.request_received_at),
    storage_recorded_at: string(raw.storage_recorded_at),
    imported_at: string(raw.imported_at),
    time_basis: Object.fromEntries(
      [
        'occurred_at',
        'request_received_at',
        'storage_recorded_at',
        'imported_at',
      ].map((k) => [k, string(object(raw.time_basis)[k])])
    ),
    source_ip: string(raw.source_ip),
    db_user: string(raw.db_user),
    database_name: string(raw.database_name),
    mysql_command: string(raw.mysql_command),
    policy_version: string(raw.policy_version),
    policy_config_hash: string(object(raw.source_metadata).policy_config_hash),
    policy_hash_basis: string(object(raw.source_metadata).config_hash_basis),
    decision: ['ALLOW', 'BLOCK'].includes(raw.decision)
      ? raw.decision
      : 'UNKNOWN',
    effective_action: ['ALLOW', 'BLOCK'].includes(raw.effective_action)
      ? raw.effective_action
      : 'UNKNOWN',
    decision_basis: string(raw.decision_basis),
    runtime_mode: string(raw.runtime_mode),
    would_block: typeof raw.would_block === 'boolean' ? raw.would_block : null,
    action_result: string(raw.action_result),
    matched_rules: strings(raw.matched_rules),
    blocking_rules: strings(raw.blocking_rules),
    monitor_rules: strings(raw.monitor_rules),
    reasons: strings(raw.reasons),
    masked_query:
      raw.sql_text_status === 'MASKED' ? string(raw.masked_query) : null,
    sql_text_status: raw.sql_text_status === 'MASKED' ? 'MASKED' : 'WITHHELD',
    risk: {
      status: string(risk.status),
      score:
        validRisk && score !== null && score >= 0 && score <= 100
          ? score
          : null,
      severity: validRisk ? string(risk.severity) : null,
    },
    raw_score: validRisk ? finite(raw.raw_score) : null,
    score_breakdown:
      validRisk && Array.isArray(raw.score_breakdown)
        ? raw.score_breakdown.slice(0, 256).map((c) => ({
            source: string(c?.source),
            rule_id: string(c?.rule_id),
            category: string(c?.category),
            score: finite(c?.score),
            reason: string(c?.reason),
          }))
        : null,
    source_provenance: Object.fromEntries(
      [
        'source_system',
        'source_schema',
        'source_ref',
        'context',
        'source_run_id',
        'collected_at',
        'imported_at',
        'payload_sha256',
        'payload_hash_basis',
        'artifact_sha256',
        'original_artifact_sha256',
        'verification',
        'human_review',
        'coverage_kind',
      ].map((k) => [k, string(provenance[k])])
    ),
  }
}

export function canonicalLink(event) {
  const params = new URLSearchParams({
    source: 'canonical',
    stream_id: event.stream_id,
  })
  return `#/events/${encodeURIComponent(event.event_id)}?${params}`
}

export function compareEvents(leftRaw, rightRaw) {
  const left = eventModel(leftRaw),
    right = eventModel(rightRaw)
  return {
    left,
    right,
    same_identity:
      left.stream_id === right.stream_id && left.event_id === right.event_id,
    same_request:
      left.stream_id === right.stream_id &&
      left.request_id !== null &&
      left.request_id === right.request_id,
    context_denial: right.blocking_rules.includes('CTX-006'),
    limitations: [
      'APP/Clone are selection labels; source roles require verified inventory.',
      'Masked query equality does not prove identical raw SQL.',
      'CTX-006 is a context denial; no SQL injection label is inferred.',
    ],
  }
}

export function traceModel(raw) {
  const input = Array.isArray(raw?.stages) ? raw.stages : []
  if (
    input.some((s) => !STAGES.includes(s?.stage)) ||
    new Set(input.map((s) => s.stage)).size !== input.length
  )
    throw new Error('TRACE_STAGE_INVALID')
  return STAGES.map((stage) => {
    const row = input.find((s) => s.stage === stage)
    if (!row)
      return {
        stage,
        status: 'UNAVAILABLE',
        outcome: null,
        facts: [],
        reason_codes: ['SOURCE_NOT_PROVIDED'],
        source_ref: null,
        verification: 'UNAVAILABLE',
      }
    if (
      ![
        'EVALUATED',
        'NOT_TRIGGERED',
        'NOT_APPLICABLE',
        'UNAVAILABLE',
        'HISTORICAL',
      ].includes(row.status)
    )
      throw new Error('TRACE_STATUS_INVALID')
    return {
      stage,
      status: row.status,
      outcome: string(row.outcome),
      source_ref: string(row.source_ref),
      verification: string(row.verification),
      reason_codes: strings(row.reason_codes),
      facts: Array.isArray(row.facts)
        ? row.facts.slice(0, 64).map((f) => ({
            name: string(f.name),
            status: string(f.status),
            value_summary:
              f.status === 'PRESENT' || f.status === 'RECONSTRUCTED'
                ? string(f.value_summary)
                : null,
            source_ref: string(f.source_ref),
          }))
        : [],
    }
  })
}

export function lifecycleState(data, now = Date.now()) {
  const current = data?.current
  if (
    !current ||
    current.source_system !== 'NEUTRON_LIVE' ||
    current.source?.freshness_state !== 'FRESH'
  )
    return { state: 'UNKNOWN', reason: 'NEUTRON_CURRENT_UNAVAILABLE' }
  const observed = Date.parse(current.observed_at),
    expires = Date.parse(current.expires_at)
  if (
    !Number.isFinite(observed) ||
    !Number.isFinite(expires) ||
    observed > now ||
    expires <= now ||
    expires <= observed
  )
    return { state: 'UNKNOWN', reason: 'NEUTRON_CURRENT_STALE' }
  if (
    !Array.isArray(current.security_group_ids) ||
    !['RESTORED', 'QUARANTINED', 'DRIFT', 'UNKNOWN'].includes(
      data.current_state
    )
  )
    return { state: 'UNKNOWN', reason: 'NEUTRON_CURRENT_INVALID' }
  return { state: data.current_state, reason: null }
}

export function metricValue(metric) {
  return metric?.unit === 'seconds' &&
    !metric?.unavailable_reason &&
    finite(metric?.seconds) !== null &&
    metric.seconds >= 0 &&
    metric.clock_id &&
    metric.time_basis
    ? `${metric.seconds} s`
    : `UNAVAILABLE · ${metric?.unavailable_reason || 'CLOCK_TIME_BASIS_REQUIRED'}`
}

export function policyDrift(rule, event) {
  if (!rule || !event) return false
  if (rule.policy_version !== event.policy_version) return true
  return (
    event.policy_hash_basis === 'FILE_BYTES_SHA256' &&
    Boolean(event.policy_config_hash) &&
    rule.policy_sha256 !== event.policy_config_hash
  )
}
