import { mapEvent, portalRequest, PortalApiError } from './portalApi.js'

// These two extension endpoints are capability-gated; the current read-only backend
// does not advertise them. See FRONTEND_V4_INTEGRATION.md for the proposed contract.
export const canReviewIncident = auth => auth?.status === 'authenticated' && auth.writeEnabled !== false && Boolean(auth.csrfToken) &&
  ['Analyst', 'Operator', 'Approver'].includes(auth.user?.role) && auth.capabilities?.includes('incidents:review') === true
export const canExportEvidence = auth => auth?.status === 'authenticated' && Boolean(auth.csrfToken) &&
  ['Viewer', 'Analyst', 'Operator', 'Approver', 'Auditor'].includes(auth.user?.role) && auth.capabilities?.includes('evidence:export') === true

function invalid(message = 'Phản hồi chưa đủ điều kiện xác nhận thao tác.') {
  throw new PortalApiError(message, 502, 'UPSTREAM_INVALID')
}
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(value)) invalid('ID chưa hợp lệ.')
  return value
}

export async function submitIncidentReview(auth, incidentId, { reviewState, note, revision, idempotencyKey }, fetcher) {
  if (!canReviewIncident(auth)) throw new PortalApiError('Phiên chưa được cấp quyền review incident.', 403, 'REVIEW_NOT_AVAILABLE')
  if (!['ACKNOWLEDGED', 'REVIEWED'].includes(reviewState) || typeof note !== 'string' || note.length > 1000 || !revision || !idempotencyKey) invalid('Thông tin review chưa hợp lệ.')
  identifier(incidentId); identifier(revision); identifier(idempotencyKey)
  const result = await portalRequest(`/incidents/${encodeURIComponent(incidentId)}/review`, {
    method: 'POST', body: { review_state: reviewState, note: note.trim(), expected_revision: revision },
    csrfToken: auth.csrfToken, idempotencyKey, ...(fetcher ? { fetcher } : {}),
  })
  const data = result.data
  if (data?.incident_id !== incidentId || data.review_state !== reviewState || !data.annotation_id || !data.review_revision) invalid()
  return { annotation_id: identifier(data.annotation_id), review_state: data.review_state, review_revision: identifier(data.review_revision) }
}

export function evidenceReference(row) {
  const event = mapEvent(row)
  return {
    stream_id: event.stream_id, event_id: event.event_id, request_id: event.request_id, occurred_at: event.occurred_at,
    source_ip: event.source_ip, decision: event.decision, risk_status: event.risk.status, risk_score: event.risk.score,
    matched_rules: event.matched_rules, source_system: event.source_provenance.source_system,
    source_ref: event.source_provenance.source_ref, payload_sha256: event.source_provenance.payload_sha256,
  }
}

export function csvCell(value) {
  let text = value === null || value === undefined ? '' : Array.isArray(value) ? value.join(' | ') : String(value)
  if (/^\s*[=+\-@]/.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text
  return '"' + text.replaceAll('"', '""') + '"'
}

export function prepareEvidenceFile(data, incidentId, format) {
  if (!['json', 'csv'].includes(format) || data?.incident_id !== incidentId || data.format !== format ||
      typeof data.complete !== 'boolean' || !Array.isArray(data.items) || data.items.length > 10000 ||
      (data.complete && data.has_more === true) || !Number.isFinite(Date.parse(data.generated_at))) invalid('Nguồn chưa cung cấp bản xuất có phạm vi rõ ràng.')
  const exportId = identifier(data.export_id), auditId = identifier(data.audit_id)
  const items = data.items.map(evidenceReference)
  if (new Set(items.map(row => `${row.stream_id}:${row.event_id}`)).size !== items.length) invalid('Bản xuất có event trùng ID.')
  const metadata = {
    export_id: exportId, audit_id: auditId, incident_id: identifier(incidentId), generated_at: data.generated_at,
    scope: 'EVIDENCE_REFERENCES', completeness: data.complete ? 'COMPLETE' : 'PARTIAL',
    evidence_membership: typeof data.evidence_membership === 'string' ? data.evidence_membership : 'UNAVAILABLE',
    recorded_evidence_count: Number.isInteger(data.recorded_evidence_count) && data.recorded_evidence_count >= 0 ? data.recorded_evidence_count : null,
    exported_event_count: items.length,
  }
  const stem = incidentId.replaceAll(':', '_').replace(/\.+$/, '')
  const filename = `${stem}-evidence${data.complete ? '' : '-partial'}.${format}`
  if (format === 'json') return { filename, content: JSON.stringify({ metadata, items }, null, 2), mime: 'application/json;charset=utf-8', ...metadata }
  const columns = ['record_type', 'incident_id', 'export_id', 'audit_id', 'scope', 'completeness', 'generated_at', 'evidence_membership', 'recorded_evidence_count', 'exported_event_count',
    'stream_id', 'event_id', 'request_id', 'occurred_at', 'source_ip', 'decision', 'risk_status', 'risk_score', 'matched_rules', 'source_system', 'source_ref', 'payload_sha256']
  const rows = [{ record_type: 'METADATA' }, ...items.map(row => ({ ...row, record_type: 'EVIDENCE' }))]
  const content = '\uFEFF' + [columns.map(csvCell).join(','), ...rows.map(row => columns.map(key => csvCell(Object.hasOwn(row, key) ? row[key] : metadata[key])).join(','))].join('\r\n')
  return { filename, content, mime: 'text/csv;charset=utf-8', ...metadata }
}

export async function requestEvidenceFile(auth, incidentId, format, idempotencyKey, fetcher) {
  if (!canExportEvidence(auth)) throw new PortalApiError('Phiên chưa được cấp quyền xuất evidence có audit.', 403, 'EXPORT_NOT_AVAILABLE')
  identifier(incidentId); identifier(idempotencyKey)
  if (!['json', 'csv'].includes(format)) invalid('Định dạng xuất chưa hợp lệ.')
  const { data } = await portalRequest(`/incidents/${encodeURIComponent(incidentId)}/evidence/exports`, {
    method: 'POST', body: { format, scope: 'EVIDENCE_REFERENCES' }, csrfToken: auth.csrfToken, idempotencyKey,
    ...(fetcher ? { fetcher } : {}),
  })
  return prepareEvidenceFile(data, incidentId, format)
}
