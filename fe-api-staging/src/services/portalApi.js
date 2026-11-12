const BASE = (import.meta.env?.VITE_PORTAL_API_BASE_URL || '/api/v1').replace(
  /\/$/,
  ''
)

export class PortalApiError extends Error {
  constructor(message, status = 0, code = 'NETWORK_ERROR', requestId = null) {
    super(message)
    Object.assign(this, { status, code, requestId })
  }
}

const messages = {
  400: 'Bộ lọc hoặc yêu cầu không hợp lệ.',
  401: 'Cần đăng nhập để xem dữ liệu này.',
  403: 'Tài khoản không có quyền thực hiện thao tác này.',
  404: 'Chưa có endpoint hoặc không tìm thấy dữ liệu trong phạm vi truy cập.',
  409: 'Dữ liệu đã thay đổi hoặc có yêu cầu đang xử lý. Hãy đọc lại.',
  412: 'Chưa đáp ứng điều kiện thực hiện yêu cầu.',
  422: 'Thông tin gửi lên chưa hợp lệ.',
  429: 'Quá nhiều yêu cầu. Vui lòng thử lại sau.',
  502: 'Nguồn dữ liệu trả về phản hồi không hợp lệ.',
  503: 'Nguồn dữ liệu chưa sẵn sàng.',
  504: 'Nguồn dữ liệu phản hồi quá thời gian chờ.',
}

export function queryString(params = {}) {
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (
      value !== undefined &&
      value !== null &&
      value !== '' &&
      value !== 'ALL'
    )
      query.set(key, String(value))
  })
  return query.size ? `?${query}` : ''
}

export async function portalRequest(
  path,
  {
    params,
    signal,
    method = 'GET',
    body,
    csrfToken,
    idempotencyKey,
    fetcher = globalThis.fetch,
    timeout = 10000,
  } = {}
) {
  const controller = new AbortController()
  const abort = () => controller.abort()
  if (signal?.aborted) controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, timeout)
  try {
    const headers = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
    const response = await fetcher(`${BASE}${path}${queryString(params)}`, {
      method,
      credentials: 'include',
      cache: 'no-store',
      signal: controller.signal,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
    let payload
    try {
      payload = await response.json()
    } catch {
      throw new PortalApiError(
        messages[response.status] ||
          'Phản hồi không đúng định dạng API Portal.',
        response.status,
        'INVALID_RESPONSE'
      )
    }
    if (!response.ok || payload?.error) {
      if (
        response.status === 401 &&
        !path.startsWith('/auth/') &&
        typeof window !== 'undefined'
      )
        window.dispatchEvent(new Event('portal-session-expired'))
      const code =
        typeof payload?.error?.code === 'string' &&
        /^[A-Z0-9_]{1,80}$/.test(payload.error.code)
          ? payload.error.code
          : 'API_ERROR'
      throw new PortalApiError(
        messages[response.status] || 'Không xử lý được yêu cầu.',
        response.status,
        code,
        payload?.meta?.request_id
      )
    }
    if (
      !payload ||
      !Object.hasOwn(payload, 'data') ||
      !payload.meta ||
      typeof payload.meta !== 'object'
    ) {
      throw new PortalApiError(
        'Phản hồi thiếu data hoặc meta của Portal v4.',
        response.status,
        'INVALID_RESPONSE'
      )
    }
    return payload
  } catch (error) {
    if (signal?.aborted) throw error
    if (error instanceof PortalApiError) throw error
    throw new PortalApiError(
      controller.signal.aborted
        ? 'Kết nối quá thời gian chờ.'
        : 'Chưa kết nối được Portal API v4.'
    )
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

const string = (value) => (typeof value === 'string' ? value : null)
const strings = (value) =>
  Array.isArray(value) ? value.filter((item) => typeof item === 'string') : []
const object = (value) =>
  value && typeof value === 'object' && !Array.isArray(value) ? value : {}
const number = (value) =>
  typeof value === 'number' && Number.isFinite(value) ? value : null
const boolean = (value) => (typeof value === 'boolean' ? value : null)
export const count = (value) =>
  Number.isInteger(value) && value >= 0 ? value : null

function requiredId(record, key) {
  if (!string(record?.[key]))
    throw new PortalApiError(
      'Dữ liệu chưa đúng schema Portal v4.',
      502,
      'UPSTREAM_INVALID'
    )
  return record[key]
}

export function readCollection(data, key) {
  if (Array.isArray(data)) return data
  if (Array.isArray(data?.items)) return data.items
  if (key && Array.isArray(data?.[key])) return data[key]
  throw new PortalApiError(
    'Nguồn chưa cung cấp danh sách đúng schema.',
    502,
    'UPSTREAM_INVALID'
  )
}

export function mapEvent(record) {
  requiredId(record, 'event_id')
  const risk = object(record.risk)
  const riskStatus = string(risk.status ?? record.risk_status)
  const riskScore = number(
    Object.hasOwn(risk, 'score') ? risk.score : record.risk_score
  )
  const validRisk =
    riskStatus && /^(OK|VALID|SUCCESS|SCORED)$/i.test(riskStatus)
  return {
    stream_id: string(record.stream_id),
    event_id: requiredId(record, 'event_id'),
    request_id: string(record.request_id),
    occurred_at: string(record.occurred_at),
    ingested_at: string(record.ingested_at),
    request_received_at: string(record.request_received_at),
    storage_recorded_at: string(record.storage_recorded_at),
    imported_at: string(record.imported_at),
    time_basis: Object.fromEntries(
      [
        'occurred_at',
        'request_received_at',
        'storage_recorded_at',
        'imported_at',
        'ingested_at',
      ].map((key) => [key, string(object(record.time_basis)[key])])
    ),
    identity_status: string(record.identity_status),
    missing_fields_reason: string(record.missing_fields_reason),
    source_ip: string(record.source_ip),
    db_user: string(record.db_user),
    database_name: string(record.database_name),
    mysql_command: string(record.mysql_command),
    decision: ['ALLOW', 'BLOCK'].includes(record.decision)
      ? record.decision
      : 'UNKNOWN',
    decision_basis: string(record.decision_basis),
    effective_action: string(record.effective_action),
    action_result: string(record.action_result),
    runtime_mode: string(record.runtime_mode),
    would_block: boolean(record.would_block),
    matched_rules: strings(record.matched_rules),
    blocking_rules: strings(record.blocking_rules),
    monitor_rules: strings(record.monitor_rules),
    policy_id: string(record.policy_id),
    reasons: strings(record.reasons),
    score_breakdown: Array.isArray(
      record.score_breakdown ?? risk.score_breakdown
    )
      ? (record.score_breakdown ?? risk.score_breakdown).map((component) => ({
          source: string(component?.source),
          rule_id: string(component?.rule_id),
          category: string(component?.category),
          score: validRisk ? count(component?.score) : null,
          reason: string(component?.reason),
        }))
      : null,
    raw_score: validRisk ? count(record.raw_score ?? risk.raw_score) : null,
    risk: {
      score:
        validRisk && riskScore !== null && riskScore >= 0 && riskScore <= 100
          ? riskScore
          : null,
      status: riskStatus,
      severity: validRisk ? string(risk.severity) : null,
    },
    masked_query:
      record.sql_text_status && record.sql_text_status !== 'MASKED'
        ? null
        : string(record.masked_query),
    sql_text_status: string(record.sql_text_status),
    policy_version: string(record.policy_version),
    p17_event_class: string(record.p17_event_class),
    stream_sequence: count(record.stream_sequence),
    incident_refs: strings(record.incident_refs),
    source_provenance: safeProvenance(record.source_provenance),
    source_metadata: {
      ...Object.fromEntries(
        [
          'request_id',
          'request_received_at',
          'received_time_basis',
          'producer_id',
          'producer_boot_id',
          'session_id',
          'policy_config_hash',
          'risk_config_hash',
          'config_hash_basis',
          'backend',
          'privacy',
          'backend_status',
          'privacy_status',
        ].map((key) => [key, string(object(record.source_metadata)[key])])
      ),
      request_sequence: count(record.source_metadata?.request_sequence),
      mysql_command_code: count(record.source_metadata?.mysql_command_code),
    },
    view_kind: string(record.view_kind),
    canonical_complete: boolean(record.canonical_complete),
  }
}

export function safeProvenance(value) {
  const source = object(value)
  return {
    ...Object.fromEntries(
      [
        'source_system',
        'source_schema',
        'source_ref',
        'observed_at',
        'generated_at_utc',
        'payload_sha256',
        'payload_hash_basis',
        'artifact_sha256',
        'original_artifact_sha256',
        'source_host',
        'source_run_id',
        'collected_at',
        'imported_at',
        'verification',
        'human_review',
        'context',
        'coverage_kind',
        'delivery_version',
        'event_role',
        'journal_stream_id',
      ].map((key) => [key, string(source[key])])
    ),
    journal_sequence: count(source.journal_sequence),
    segment_index: count(source.segment_index),
  }
}

export function mapMapping(value) {
  const mapping = object(value)
  return Object.fromEntries([
    ...[
      'source_ip',
      'server_id',
      'port_id',
      'project_id',
      'network_id',
      'observed_at',
      'reason',
      'verification',
    ].map((key) => [key, string(mapping[key])]),
    ['verified', boolean(mapping.verified)],
    ['ttl_seconds', number(mapping.ttl_seconds)],
    ['fixed_ips', mapIps(mapping.fixed_ips)],
    ['floating_ips', mapIps(mapping.floating_ips, 'floating_ip_address')],
  ])
}

export function mapIncident(record) {
  return {
    incident_id: requiredId(record, 'incident_id'),
    stream_id: string(record.stream_id),
    source_ip: string(record.source_ip),
    signal_rule: string(record.signal_rule),
    severity: string(record.severity),
    confidence: string(record.confidence),
    first_seen: string(record.first_seen),
    last_seen: string(record.last_seen),
    evidence_count: count(record.evidence_count),
    p15_peak_score: number(record.p15_peak_score ?? record.peak_p15),
    incident_status: string(record.incident_status),
    response_state: string(record.response_state ?? record.response?.state),
    review_state: string(record.review_state ?? record.review?.state),
    review_revision: string(record.review_revision ?? record.review?.revision),
    review_annotations: Array.isArray(record.review_annotations)
      ? record.review_annotations.map((row) => ({
          annotation_id: string(row?.annotation_id),
          review_state: string(row?.review_state),
          author: string(row?.author),
          created_at: string(row?.created_at),
          note: string(row?.note),
        }))
      : [],
    mapping: mapMapping(record.mapping ?? record.mapping_verification),
    current_mapping: mapCurrentMapping(record.current_mapping),
    evidence_membership: string(record.evidence_membership),
  }
}

export function mapCurrentMapping(value) {
  const row = object(value),
    source = object(row.source)
  return {
    ...mapMapping(row),
    state: string(row.state),
    server_name: string(row.server_name),
    observation_from: string(row.observation_from),
    candidate_count: number(row.candidate_count),
    matched_by: strings(row.matched_by),
    historical_identity_verified: boolean(row.historical_identity_verified),
    source: Object.fromEntries([
      ...[
        'source_mode',
        'source_system',
        'freshness_state',
        'read_at',
        'last_error_code',
        'project_id',
      ].map((key) => [key, string(source[key])]),
      ['stale_after_seconds', number(source.stale_after_seconds)],
    ]),
  }
}

export function currentMappingState(mapping, failed = false, now = Date.now()) {
  if (mapping?.source?.source_mode !== 'LIVE')
    return { state: 'UNKNOWN', freshness: 'UNKNOWN', href: null }
  const age = now - Date.parse(mapping?.observation_from)
  const ttl = mapping?.ttl_seconds
  const sourceState = freshness(mapping?.source, failed, now)
  const timed = Number.isFinite(age) && Number.isFinite(ttl) && ttl > 0
  if (sourceState === 'UNKNOWN' || !timed || age < -1000)
    return { state: 'UNKNOWN', freshness: 'UNKNOWN', href: null }
  if (sourceState !== 'FRESH' || age > ttl * 1000 || mapping?.state === 'STALE')
    return { state: 'STALE', freshness: 'STALE', href: null }
  const state = ['MATCHED', 'NO_MATCH', 'AMBIGUOUS'].includes(mapping?.state)
    ? mapping.state
    : 'UNKNOWN'
  const href =
    state === 'MATCHED' && mapping.server_id && mapping.port_id
      ? `#/workloads/${encodeURIComponent(mapping.server_id)}?port_id=${encodeURIComponent(mapping.port_id)}`
      : null
  return { state, freshness: 'FRESH', href }
}

export function mapWorkload(record) {
  return {
    server_id: requiredId(record, 'server_id'),
    name: string(record.name),
    nova_status: string(record.nova_status),
    project_id: string(record.project_id),
    role: string(record.role),
    compute_host: string(record.compute_host),
    observed_at: string(record.observed_at),
    network_state: string(record.network_state),
    network_observation: record.network_observation
      ? {
          state: string(record.network_observation.state),
          verification: string(record.network_observation.verification),
          observed_at: string(record.network_observation.observed_at),
          security_group_ids: strings(
            record.network_observation.security_group_ids
          ),
        }
      : null,
    incident_refs: strings(record.incident_refs),
    protected: boolean(record.protected),
    risk_exposure: mapRiskExposure(record.risk_exposure),
    ports: Array.isArray(record.ports) ? record.ports.map(mapPort) : [],
  }
}

export function freshness(meta, failed = false, now = Date.now()) {
  if (!meta) return 'UNKNOWN'
  if (failed) return 'STALE'
  if (meta.freshness_state !== 'FRESH')
    return ['STALE', 'UNKNOWN', 'PARTIAL'].includes(meta.freshness_state)
      ? meta.freshness_state
      : 'UNKNOWN'
  const observed = Date.parse(meta.read_at)
  if (!Number.isFinite(observed)) return 'UNKNOWN'
  if (observed - now > 1000) return 'UNKNOWN'
  if (now - observed > (number(meta.stale_after_seconds) ?? 30) * 1000)
    return 'STALE'
  return 'FRESH'
}

/**
 * Trạng thái hiển thị cho nguồn dữ liệu.
 *
 * Nguồn lịch sử (freshness_state=HISTORICAL) hoặc bản chụp
 * (source_mode=SNAPSHOT) đã đọc được nhưng không phải dữ liệu live, nên
 * hiển thị SNAPSHOT thay vì FRESH để không ám chỉ dữ liệu đang chạy.
 */
export function sourceState(meta, failed = false, now = Date.now()) {
  if (failed) return 'STALE'
  if (meta?.freshness_state === 'HISTORICAL') return 'SNAPSHOT'
  if (meta?.source_mode === 'SNAPSHOT') return 'SNAPSHOT'
  return freshness(meta, failed, now)
}

export function canWriteNotes(user, csrfToken) {
  return Boolean(
    csrfToken && ['Analyst', 'Operator', 'Approver'].includes(user?.role)
  )
}

export function isLocalSnapshotAccess(data) {
  const readonlySource =
    (data?.access_mode === 'LOCAL_SNAPSHOT_READONLY' &&
      data?.source_mode === 'SNAPSHOT') ||
    (data?.access_mode === 'LOCAL_REMOTE_READONLY' &&
      data?.source_mode === 'REMOTE_READONLY')
  return (
    readonlySource &&
    data?.user === null &&
    data?.write_enabled === false &&
    data?.session_supported === false &&
    Array.isArray(data?.capabilities) &&
    data.capabilities.includes('incidents:read')
  )
}

export function isFreshMapping(
  mapping,
  meta,
  failed = false,
  now = Date.now()
) {
  if (['SNAPSHOT', 'REMOTE_READONLY'].includes(meta?.source_mode)) return false
  const age = now - Date.parse(mapping?.observed_at)
  return (
    freshness(meta, failed, now) === 'FRESH' &&
    mapping?.verified === true &&
    typeof mapping?.ttl_seconds === 'number' &&
    mapping.ttl_seconds > 0 &&
    Number.isFinite(age) &&
    age >= -1000 &&
    age <= mapping.ttl_seconds * 1000
  )
}

function mapIps(value, key = 'ip_address') {
  return Array.isArray(value)
    ? value
        .map((ip) => (typeof ip === 'string' ? ip : string(ip?.[key])))
        .filter(Boolean)
    : []
}

export function mapSecurityGroups(value) {
  const row = object(value)
  const groups = Array.isArray(row.security_groups) ? row.security_groups : []
  const names = object(row.security_group_names)
  const ids = Array.isArray(row.security_group_ids)
    ? strings(row.security_group_ids)
    : groups.map((group) => string(group?.id)).filter(Boolean)
  return [...new Set(ids)].map((id) => ({
    id,
    name:
      string(groups.find((group) => group?.id === id)?.name) ??
      string(names[id]),
  }))
}

export function mapPort(value) {
  const port = object(value)
  return {
    port_id: string(port.port_id ?? port.id),
    network_id: string(port.network_id),
    project_id: string(port.project_id),
    device_id: string(port.device_id),
    device_owner: string(port.device_owner),
    mac_address: string(port.mac_address),
    status: string(port.status),
    fixed_ips: mapIps(port.fixed_ips),
    floating_ips: mapIps(port.floating_ips, 'floating_ip_address'),
    fixed_ip_details: Array.isArray(port.fixed_ips)
      ? port.fixed_ips.map((ip) => ({
          ip_address: typeof ip === 'string' ? ip : string(ip?.ip_address),
          subnet_id: string(ip?.subnet_id),
        }))
      : [],
    security_group_ids: mapSecurityGroups(port).map((group) => group.id),
    security_groups: mapSecurityGroups(port),
    security_groups_provided:
      Array.isArray(port.security_group_ids) ||
      Array.isArray(port.security_groups),
    port_security_enabled: boolean(port.port_security_enabled),
    observed_at: string(port.observed_at),
  }
}

export function mappingState(mapping, meta, failed = false, now = Date.now()) {
  const observed = Date.parse(mapping?.observed_at)
  const ttl = mapping?.ttl_seconds
  const timed = Number.isFinite(observed) && typeof ttl === 'number' && ttl > 0
  let ageState = 'UNKNOWN'
  if (timed && observed - now > 1000) ageState = 'UNKNOWN'
  else if (
    timed &&
    (now - observed > ttl * 1000 || freshness(meta, failed, now) !== 'FRESH')
  )
    ageState = 'STALE'
  else if (
    timed &&
    !['SNAPSHOT', 'REMOTE_READONLY'].includes(meta?.source_mode)
  )
    ageState = 'FRESH'
  return {
    verification: isFreshMapping(mapping, meta, failed, now)
      ? 'VERIFIED'
      : mapping?.verified === false
        ? 'UNVERIFIED'
        : 'UNKNOWN',
    freshness: ageState,
  }
}

export function mapRiskExposure(value) {
  const exposure = object(value)
  if (exposure.basis !== 'RECENT_INCIDENTS') return null
  return {
    basis: 'RECENT_INCIDENTS',
    incident_count: count(exposure.incident_count),
    severity: ['LOW', 'WARNING', 'HIGH', 'CRITICAL'].includes(exposure.severity)
      ? exposure.severity
      : null,
    window_from: string(exposure.window_from),
    window_to: string(exposure.window_to),
    observed_at: string(exposure.observed_at),
    ttl_seconds: number(exposure.ttl_seconds),
    incident_refs: strings(exposure.incident_refs),
    source_ref: string(exposure.source_ref),
  }
}

export function riskExposureState(
  exposure,
  meta,
  failed = false,
  now = Date.now()
) {
  if (!exposure || exposure.incident_count === null) return 'UNKNOWN'
  const start = Date.parse(exposure.window_from),
    end = Date.parse(exposure.window_to),
    observed = Date.parse(exposure.observed_at)
  if (
    ![exposure.window_from, exposure.window_to, exposure.observed_at].every(
      (value) =>
        typeof value === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    ) ||
    ![start, end, observed].every(Number.isFinite) ||
    start >= end ||
    end - now > 1000 ||
    observed - now > 1000
  )
    return 'UNKNOWN'
  if (meta?.source_mode === 'SNAPSHOT') return 'HISTORICAL'
  const ttl = exposure.ttl_seconds
  if (typeof ttl !== 'number' || ttl <= 0) return 'UNKNOWN'
  return freshness(meta, failed, now) === 'FRESH' &&
    now - observed <= ttl * 1000 &&
    now - end <= ttl * 1000
    ? 'FRESH'
    : 'STALE'
}

export function mapDecision(value) {
  const data = object(value)
  return {
    qualified: boolean(data.qualified),
    source_verified: boolean(data.source_verified),
    workload_allowed: boolean(data.workload_allowed ?? data.lab_workload),
    operator_approved: boolean(data.operator_approved),
    source_fresh: boolean(data.source_fresh),
    evaluated_at: string(data.evaluated_at),
    blocking_reasons: Array.isArray(data.blocking_reasons)
      ? data.blocking_reasons.map((reason) =>
          typeof reason === 'string'
            ? { code: reason, message: null }
            : { code: string(reason?.code), message: string(reason?.message) }
        )
      : [],
  }
}

export function mapSgHistory(value) {
  const data = object(value)
  const rows = Array.isArray(data.security_group_history)
    ? data.security_group_history
    : Array.isArray(data.security_group_history?.ports)
      ? data.security_group_history.ports
      : Array.isArray(data.actions)
        ? data.actions
        : [
              'original_security_group_ids',
              'quarantine_security_group_ids',
              'restored_security_group_ids',
            ].some((key) => Array.isArray(data[key]))
          ? [data]
          : []
  const stage = (row, name, idsKey, groupsKey, atKey) => {
    const nested = object(row[name])
    const input =
      Array.isArray(nested.security_group_ids) ||
      Array.isArray(nested.security_groups)
        ? nested
        : { security_group_ids: row[idsKey], security_groups: row[groupsKey] }
    return {
      provided:
        Array.isArray(input.security_group_ids) ||
        Array.isArray(input.security_groups),
      groups: mapSecurityGroups(input),
      observed_at: string(nested.observed_at ?? row[atKey]),
      source_ref: string(nested.source_ref ?? row.source_ref),
    }
  }
  return rows.map((row) => ({
    port_id: string(row?.port_id),
    action_id: string(row?.action_id),
    before: stage(
      object(row),
      'before',
      'original_security_group_ids',
      'original_security_groups',
      'before_observed_at'
    ),
    during: stage(
      object(row),
      'during',
      'quarantine_security_group_ids',
      'quarantine_security_groups',
      'during_observed_at'
    ),
    after: stage(
      object(row),
      'after',
      'restored_security_group_ids',
      'restored_security_groups',
      'after_observed_at'
    ),
  }))
}

export function isVerifiedNetwork(observation, meta, failed = false) {
  if (['SNAPSHOT', 'REMOTE_READONLY'].includes(meta?.source_mode)) return false
  const observed = Date.parse(observation?.observed_at)
  const ttl = number(meta?.network_stale_after_seconds) ?? 30
  const age = Date.now() - observed
  return (
    freshness(meta, failed) === 'FRESH' &&
    observation?.verification === 'LIVE_NEUTRON_READ' &&
    ['NORMAL', 'QUARANTINED'].includes(observation?.state) &&
    Number.isFinite(observed) &&
    age >= -1000 &&
    age <= ttl * 1000
  )
}
