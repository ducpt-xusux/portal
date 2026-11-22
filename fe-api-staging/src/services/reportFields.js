// Required Event fields from report Table 3.6. Only source data is accepted.
export const REPORT_EVENT_FIELDS = Object.freeze([
  ['event_id', 'Mã sự kiện', event => event.event_id],
  ['stream_id', 'Mã luồng', event => event.stream_id],
  ['stream_sequence', 'Thứ tự trong luồng', event => event.stream_sequence],
  ['occurred_at', 'Thời điểm phát sinh', event => event.occurred_at],
  ['client_ip', 'IP nguồn', event => event.source_ip],
  ['db_user', 'Tài khoản CSDL', event => event.db_user],
  ['database', 'Cơ sở dữ liệu', event => event.database_name ?? (event.database_status === 'ABSENT' ? 'Chưa chọn CSDL (nguồn xác nhận)' : null)],
  ['policy_version', 'Phiên bản chính sách', event => event.policy_version],
  ['matched_rules', 'Quy tắc khớp', event => event.matched_rules],
  ['effective_action', 'Hành động áp dụng', event => event.effective_action],
  ['risk_status', 'Trạng thái tính điểm', event => event.risk?.status],
  ['risk_score', 'Điểm rủi ro', event => event.risk?.score],
  ['severity', 'Mức độ rủi ro', event => event.risk?.severity],
  ['payload_sha256', 'SHA-256 bản ghi nguồn', event => event.source_provenance?.payload_sha256],
  ['mask_status', 'Trạng thái che SQL', event => event.mask_status ?? event.sql_text_status],
])

export function hasSourceValue(value) {
  return value !== null && value !== undefined && value !== '' &&
    !(typeof value === 'string' && ['UNKNOWN', 'UNAVAILABLE', 'UNDEFINED', 'NULL'].includes(value.toUpperCase()))
}

export function reportEventCoverage(event) {
  const missing = REPORT_EVENT_FIELDS.filter(([, , read]) => !hasSourceValue(read(event))).map(([key]) => key)
  if (event.risk?.status === 'OK' && (!Array.isArray(event.score_breakdown) ||
      event.risk.score > 0 && event.score_breakdown.length === 0)) missing.push('breakdown')
  return { complete: missing.length === 0, missing }
}
