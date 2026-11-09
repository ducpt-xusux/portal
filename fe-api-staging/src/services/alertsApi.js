import { count, PortalApiError } from './portalApi.js'

const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(value)
const text = value => typeof value === 'string' ? value : null
const kinds = ['SINGLE_P15_HIGH', 'CORRELATED', 'OPERATIONAL', 'POLICY_VIOLATION', 'AUDIT_HEALTH', 'SYSTEM_HEALTH', 'OTHER']
function invalid() { throw new PortalApiError('Dữ liệu cảnh báo chưa đúng schema Portal.', 502, 'UPSTREAM_INVALID') }

export function mapAlert(row) {
  if (!id(row?.alert_id) || !Number.isFinite(Date.parse(row.created_at)) || !kinds.includes(row.kind) ||
      !text(row.signal_code) || !text(row.severity) || !text(row.title) || !text(row.summary) ||
      !Array.isArray(row.event_refs) || !row.event_refs.every(id) || new Set(row.event_refs).size !== row.event_refs.length ||
      (row.incident_id != null && !id(row.incident_id)) || !row.provenance || !text(row.provenance.source_system)) invalid()
  return {
    alert_id: row.alert_id, created_at: row.created_at, signal_code: row.signal_code, kind: row.kind,
    severity: row.severity, title: row.title, summary: row.summary, source_ip: text(row.source_ip),
    incident_id: row.incident_id ?? null, event_refs: [...row.event_refs], risk_peak: count(row.risk_peak) <= 100 ? count(row.risk_peak) : null,
    // Review/unread is not implemented by this read-only integration.
    source_record_ref: text(row.source_record_ref),
    provenance: Object.fromEntries(['source_system', 'source_schema', 'source_ref', 'read_at', 'data_as_of', 'observed_at', 'freshness_state', 'coverage_kind', 'error_code'].map(key => [key, text(row.provenance[key])])),
  }
}

export function readAlertsPage(data) {
  if (!data || !Array.isArray(data.items) || typeof data.has_more !== 'boolean' ||
      count(data.total_count) === null || data.total_count < data.items.length ||
      (data.next_cursor != null && !text(data.next_cursor)) || (data.has_more && !data.next_cursor)) invalid()
  const items = data.items.map(mapAlert)
  if (new Set(items.map(item => item.alert_id)).size !== items.length) invalid()
  return { items, total_count: data.total_count, has_more: data.has_more }
}

export function alertEventHref(eventId, streamId) {
  if (!id(eventId) || !id(streamId)) return null
  return `#/events/${encodeURIComponent(eventId)}?${new URLSearchParams({ source: 'p17', stream_id: streamId })}`
}

export function alertIncidentHref(incidentId) {
  return id(incidentId) ? `#/incidents/${encodeURIComponent(incidentId)}` : null
}

export function alertRequestFilters(draft, now = Date.now()) {
  const durations = { '15m': 900000, '1h': 3600000, '24h': 86400000 }
  const result = Object.fromEntries(['severity', 'signal_code', 'kind', 'source_ip'].flatMap(key => draft[key]?.trim() ? [[key, draft[key].trim()]] : []))
  if (durations[draft.window]) Object.assign(result, { from: new Date(now - durations[draft.window]).toISOString(), to: new Date(now).toISOString() })
  return result
}
