import { PortalApiError, count } from './portalApi.js'

export const funnelStages = ['REQUEST','PARSE','POLICY','ALERT','INCIDENT','ACTION']
export const funnelTitles = { REQUEST: 'SQL requests / events', PARSE: 'SQL parse', POLICY: 'ALLOW / BLOCK', ALERT: 'Alerts', INCIDENT: 'Incidents', ACTION: 'Actions' }
export const metricTitles = { requests: 'request đã xác minh ID', audit_events: 'audit event', valid: 'parse valid', invalid: 'parse invalid', allow: 'ALLOW', block: 'BLOCK', alerts: 'alert', incidents: 'incident mới', actions: 'action' }
export const funnelReasons = { REQUEST_ID_NOT_PROVIDED: 'Nguồn canonical chưa cung cấp request_id; chỉ đếm audit event.', PARSER_FEATURES_NOT_PROVIDED: 'Chưa có kết quả parser từ P14.', IMPORTED_RECORDS_ONLY: 'Đếm event đã nhập, chưa xác nhận đủ traffic trong cửa sổ.', OUTBOX_RECORDS_ONLY: 'Đếm alert_id trong outbox đã thu thập.', P17_CREATED_RECORDS_ONLY: 'Đếm incident được tạo trong cửa sổ, không phải toàn bộ incident cần review.', P17_5_NOT_CONFIGURED: 'Chưa nối action evidence P17.5.', EVALUATION_FUNNEL_NOT_CAPTURED: 'Run chưa cung cấp counter cho bước này; số case PASS không thay số request.', SOURCE_NOT_CONFIGURED: 'Nguồn chưa được cấu hình.' }

export function dashboardHref(context, window = '15m', runId) {
  const query = new URLSearchParams({ context, window })
  if (context === 'EVALUATION' && runId) query.set('run_id', runId)
  return `#/dashboard?${query}`
}

export function readFunnel(data, context, runId) {
  const invalid = () => { throw new PortalApiError('Dữ liệu funnel chưa đúng phạm vi hoặc schema.', 502, 'FUNNEL_INVALID') }
  if (!data || data.context !== context || data.cohort_linked !== false || data.scope !== 'INDEPENDENT_SOURCE_COUNTERS' ||
      (context === 'EVALUATION' && data.run_id !== runId) || (context === 'LIVE' && data.run_id !== null) || !Array.isArray(data.stages) || data.stages.length !== 6) return invalid()
  const start = Date.parse(data.window_from), end = Date.parse(data.window_to)
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) return invalid()
  for (let i = 0; i < 6; i++) {
    const row = data.stages[i]
    if (row.stage !== funnelStages[i] || !['PARTIAL','UNAVAILABLE','STALE','HISTORICAL'].includes(row.status) ||
        row.window_from !== data.window_from || row.window_to !== data.window_to ||
        !row.source?.source_system || !row.source.coverage_kind || !Number.isFinite(Date.parse(row.source.read_at)) ||
        !Array.isArray(row.metrics) || row.metrics.some(m => (m.count !== null && count(m.count) === null) || !['AUDIT_EVENTS','REQUESTS','ALERTS','INCIDENTS','ACTIONS'].includes(m.unit)) ||
        (row.status === 'UNAVAILABLE' && row.metrics.some(m => m.count !== null))) return invalid()
  }
  return data
}

export function funnelLink(data, row, metric) {
  if (data.context !== 'LIVE' || row.status === 'UNAVAILABLE') return null
  if (row.stage === 'REQUEST' && metric.key === 'requests' && metric.count === null) return null
  const query = new URLSearchParams({ from: data.window_from, to: data.window_to })
  if (['REQUEST','POLICY'].includes(row.stage)) {
    query.set('source','canonical')
    if (['allow','block'].includes(metric.key)) query.set('decision',metric.key.toUpperCase())
    return `#/events?${query}`
  }
  // Incidents list filters last_seen, while funnel counts created_utc: do not imply equal filters.
  if (row.stage === 'INCIDENT') return '#/incidents'
  if (row.stage === 'ALERT') {
    const duration=Date.parse(data.window_to)-Date.parse(data.window_from)
    const window=duration===86400000 ? '24h' : duration===3600000 ? '1h' : '15m'
    return `#/dashboard?${new URLSearchParams({ context:'LIVE', window, alerts_from:data.window_from, alerts_to:data.window_to })}`
  }
  return null
}

export function readEvaluationRun(run) {
  const keys = ['pass','fail','incomplete','not_executed','unknown','na']
  if (!run || typeof run.run_id !== 'string' || !run.run_id || !run.provenance || !['LIVE','OFFLINE','HISTORICAL','MIXED'].includes(run.run_kind) ||
      count(run.case_count) === null || keys.some(k => count(run.counts?.[k]) === null) || keys.reduce((n,k) => n+run.counts[k],0) !== run.case_count ||
      (run.status === 'NOT_EXECUTED' && run.counts.not_executed !== run.case_count)) throw new PortalApiError('Run evaluation không hợp lệ.',502,'EVALUATION_RUN_INVALID')
  return run
}
