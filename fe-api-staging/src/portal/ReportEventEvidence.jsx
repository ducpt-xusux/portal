import { uiLabel } from '../services/uiLanguage'
import { hasSourceValue, reportEventCoverage, REPORT_EVENT_FIELDS } from '../services/reportFields'

export default function ReportEventEvidence({ event }) {
  const coverage = reportEventCoverage(event)
  return <section className="panel v4-panel n91-report-event" aria-label="Trường kiểm toán theo báo cáo">
    <div className="panel-heading"><div><h2>Thông tin kiểm toán đầy đủ</h2><p>Các trường theo Bảng 3.6 · đọc từ nhật ký kiểm toán chuẩn hóa</p></div></div>
    {!coverage.complete && <p className="v4-inline-warning" role="alert">Nguồn kiểm toán đang thiếu trường bắt buộc: {coverage.missing.map(uiLabel).join(', ')}. Cần bổ sung tại bộ ghi hoặc bộ đọc nguồn.</p>}
    <dl className="v4-fields">{REPORT_EVENT_FIELDS.map(([key, label, read]) => {
      const value = read(event)
      return <div key={key}><dt>{label}</dt><dd>{!hasSourceValue(value) ? <span className="n91-field-missing">Nguồn chưa cung cấp {label.toLowerCase()}</span>
        : Array.isArray(value) ? value.length ? value.join(' · ') : 'Không có (mảng rỗng từ nguồn)'
        : ['effective_action', 'severity', 'mask_status', 'risk_status'].includes(key) ? uiLabel(value)
        : String(value)}</dd></div>
    })}</dl>
    <h3 className="v4-subheading">Thành phần điểm rủi ro</h3>
    {Array.isArray(event.score_breakdown) ? event.score_breakdown.length ? <div className="table-scroll"><table className="v4-table"><thead><tr><th>QUY TẮC / NGUỒN</th><th>NHÓM</th><th>ĐIỂM</th><th>LÝ DO</th></tr></thead><tbody>{event.score_breakdown.map((part, index) => <tr key={index}><td>{part.rule_id || uiLabel(part.source)}</td><td>{uiLabel(part.category)}</td><td>{part.score}</td><td>{uiLabel(part.reason)}</td></tr>)}</tbody></table></div> : <p>Không có thành phần điểm (mảng rỗng từ nguồn).</p>
      : <p className="n91-field-missing">Nguồn chưa cung cấp thành phần điểm rủi ro.</p>}
  </section>
}
