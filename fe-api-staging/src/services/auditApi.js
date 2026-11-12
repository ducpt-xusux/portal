const API_BASE = (import.meta.env?.VITE_API_BASE_URL || '/api').replace(
  /\/$/,
  ''
)

export class AuditApiError extends Error {
  constructor(message, status = 0, code = 'NETWORK_ERROR') {
    super(message)
    this.status = status
    this.code = code
  }
}

export async function auditRequest(
  path,
  { params = {}, signal, fetcher = globalThis.fetch } = {}
) {
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
  const controller = new AbortController()
  const abort = () => controller.abort()
  if (signal?.aborted) controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, 10000)
  try {
    const result = await fetcher(
      `${API_BASE}${path}${query.size ? `?${query}` : ''}`,
      {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      }
    )
    let body
    try {
      body = await result.json()
    } catch {
      throw new AuditApiError(
        'Phản hồi API không phải JSON. Kiểm tra backend và cấu hình /api.',
        result.status,
        'INVALID_RESPONSE'
      )
    }
    if (!result.ok || body.error) {
      const message =
        result.status === 401
          ? 'API yêu cầu xác thực. Kiểm tra cấu hình PORTAL_API_KEY của backend.'
          : result.status === 503
            ? 'Nguồn audit hoặc SQLite chưa sẵn sàng. Kiểm tra backend.'
            : body.error?.message || 'Không đọc được dữ liệu audit.'
      throw new AuditApiError(message, result.status, body.error?.code)
    }
    if (body.data === undefined || !body.meta)
      throw new AuditApiError(
        'API thiếu dữ liệu hoặc metadata.',
        0,
        'INVALID_RESPONSE'
      )
    return body
  } catch (failure) {
    if (signal?.aborted) throw failure
    if (failure instanceof AuditApiError) throw failure
    throw new AuditApiError(
      controller.signal.aborted
        ? 'API phản hồi quá thời gian chờ. Dữ liệu cũ được giữ lại nếu có.'
        : 'Không kết nối được FastAPI. Kiểm tra backend tại cổng 8000.'
    )
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

export function mapAuditEvent(record) {
  return {
    id: record.event_id,
    timestamp: record.timestamp,
    source: 'audit_api',
    sourceIp: record.client_ip,
    user: record.db_user ?? '—',
    query: record.query_masked ?? 'Không có SQL đã mask',
    vm: 'Chưa ánh xạ VM',
    vmId: null,
    incidentId: null,
    decision: record.policy_decision,
    severity: record.severity ?? 'UNKNOWN',
    score: record.risk_score,
    rawScore: record.raw_score,
    rules: record.matched_rules,
    policyVersion: record.policy_version,
    ruleBreakdown: (record.score_breakdown || []).map((part, index) => ({
      id: part.rule_id,
      key: `${part.rule_id || part.source}-${index}`,
      name: part.reason,
      score: part.score,
      category: part.category,
      source: part.source,
    })),
    dominantRule: record.dominant_rule,
    reason:
      record.reasons.join(' · ') ||
      (record.defaulted
        ? 'P14 áp dụng default-deny vì query không thuộc workload được phép.'
        : 'Không có lý do bổ sung trong bản ghi.'),
    action: record.action,
    actionResult: record.action_result,
    recommendedAction: record.recommended_action,
    riskStatus: record.risk_status,
    riskError: record.risk_error,
    actionError: record.action_error,
    maskStatus: record.query_mask_status,
    raw: record,
  }
}

export const AUDIT_FILTERS = {
  query: '',
  minutes: 0,
  severity: 'ALL',
  decision: 'ALL',
  sourceIp: '',
  rule: '',
  dbUser: '',
  actionResult: 'ALL',
}

export function eventParams(filters = AUDIT_FILTERS, now = Date.now()) {
  return {
    q: filters.query.trim(),
    severity: filters.severity,
    decision: filters.decision,
    client_ip: filters.sourceIp.trim(),
    rule: filters.rule.trim(),
    db_user: filters.dbUser.trim(),
    action_result: filters.actionResult,
    ...(Number(filters.minutes) > 0
      ? {
          start: new Date(now - Number(filters.minutes) * 60000).toISOString(),
          end: new Date(now).toISOString(),
        }
      : {}),
  }
}

export async function getAuditEvents({
  filters = AUDIT_FILTERS,
  page = 1,
  pageSize = 50,
  signal,
} = {}) {
  const body = await auditRequest('/events', {
    signal,
    params: { ...eventParams(filters), page, page_size: pageSize },
  })
  return {
    events: body.data.events.map(mapAuditEvent),
    total: body.data.total,
    page: body.data.page,
    pageSize: body.data.page_size,
    pageCount: body.data.page_count,
    summary: { ...body.data.summary, highRisk: body.data.summary.high_risk },
    meta: body.meta,
    updatedAt: body.meta.timestamp,
  }
}

export async function getAuditEvent(id, { signal } = {}) {
  const body = await auditRequest(`/events/${encodeURIComponent(id)}`, {
    signal,
  })
  return { event: mapAuditEvent(body.data), meta: body.meta }
}

export async function getAuditDashboard({
  window = '1h',
  anchor = 'source',
  signal,
} = {}) {
  const health = await auditRequest('/system/health', { signal })
  const historical = health.data.audit_source.mode === 'snapshot'
  const end =
    anchor === 'source' && historical && health.data.last_event_at
      ? health.data.last_event_at
      : new Date().toISOString()
  const bucket = { '1h': '5m', '6h': '30m', '24h': '120m' }[window]
  const start = new Date(
    Date.parse(end) - { '1h': 60, '6h': 360, '24h': 1440 }[window] * 60000
  ).toISOString()
  const [summary, series, latest] = await Promise.all([
    auditRequest('/dashboard/summary', { signal, params: { window, end } }),
    auditRequest('/dashboard/event-series', {
      signal,
      params: { window, bucket, end },
    }),
    auditRequest('/events', { signal, params: { start, end, page_size: 6 } }),
  ])
  const counts = summary.data.events
  // If one API reports degradation, the entire dashboard keeps that state visible.
  const states = [health.meta, summary.meta, series.meta, latest.meta]
  const meta =
    states.find((m) => m.data_state === 'STALE') ||
    states.find((m) => m.data_state === 'DEGRADED') ||
    summary.meta
  return {
    counts,
    clients: summary.data.unique_client_ips,
    events: latest.data.events.map(mapAuditEvent),
    health: health.data,
    meta,
    end,
    start,
    window,
    historical,
    updatedAt: summary.meta.timestamp,
    activity: {
      total: counts.total,
      allowed: counts.allowed,
      blocked: counts.blocked,
      blockRate: counts.total ? (counts.blocked / counts.total) * 100 : 0,
      bucketMinutes: { '1h': 5, '6h': 30, '24h': 120 }[window],
      chart: series.data.points.map((p) => ({
        time: p.timestamp,
        allowed: p.allowed,
        blocked: p.blocked,
      })),
    },
  }
}

export function auditCsv(events) {
  const columns = [
    'event_id',
    'timestamp',
    'client_ip',
    'db_user',
    'query_masked',
    'matched_rules',
    'raw_score',
    'risk_score',
    'severity',
    'policy_decision',
    'policy_version',
    'action',
    'action_result',
    'source',
  ]
  const safeCell = (value) => {
    const text = String(value ?? '')
    const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
    return `"${safe.replaceAll('"', '""')}"`
  }
  const rows = events.map((e) => [
    e.id,
    e.timestamp,
    e.sourceIp,
    e.user,
    e.query,
    e.rules.join(';'),
    e.rawScore,
    e.score,
    e.severity,
    e.decision,
    e.policyVersion,
    e.action,
    e.actionResult,
    'P16_AUDIT_API',
  ])
  return (
    '\uFEFF' +
    [columns, ...rows].map((row) => row.map(safeCell).join(',')).join('\r\n')
  )
}

export function downloadAuditCsv(events) {
  const url = URL.createObjectURL(
    new Blob([auditCsv(events)], { type: 'text/csv;charset=utf-8;' })
  )
  const link = document.createElement('a')
  link.href = url
  link.download = 'dbsec-audit-current-page.csv'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
