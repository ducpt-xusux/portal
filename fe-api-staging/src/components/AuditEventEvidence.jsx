import { ShieldCheck } from 'lucide-react'

export default function AuditEventEvidence({ event }) {
  return <div className="event-explanation">
    <h4>Rule breakdown <span className="muted">· kết quả P15 được P16 ghi lại</span></h4>
    {event.riskStatus === 'ERROR' && <div className="audit-error" role="alert">Risk Engine báo lỗi. Điểm và severity chưa xác định; không suy diễn bằng 0.</div>}
    <div className="table-scroll"><table className="rule-breakdown"><thead><tr><th>Rule / thành phần</th><th>Điểm</th></tr></thead><tbody>
      {event.ruleBreakdown.map(part => <tr key={part.key}><td><code>{part.id ? <a href={`#/system/rules/${encodeURIComponent(part.id)}`}>{part.id}</a> : 'DEFAULT DENY'}</code><span>{part.name}</span></td><td>+{part.score}</td></tr>)}
      {!event.ruleBreakdown.length && <tr><td>Không có thành phần chấm điểm trong bản ghi</td><td>—</td></tr>}
    </tbody><tfoot><tr><td>Tổng trước giới hạn</td><td>{event.rawScore ?? 'UNKNOWN'}</td></tr><tr><td>Risk score · giới hạn 100</td><td>{event.score ?? 'UNKNOWN'}</td></tr></tfoot></table></div>
    <div className={`decision-explanation ${event.decision.toLowerCase()}`}><ShieldCheck size={17} /><div><strong>P14 quyết định {event.decision}</strong><p>{event.reason}</p><small>P15 đánh giá mức độ rủi ro; severity không thay thế quyết định ALLOW/BLOCK.</small></div></div>
    <h4>Hành động trên truy vấn</h4><div className="event-action-evidence">
      <div><span>Action</span><strong>{event.action}</strong></div><div><span>Action result</span><strong>{event.actionResult}</strong></div>
      <div><span>Dominant rule</span><strong>{event.dominantRule || 'Không có'}</strong></div><div><span>Khuyến nghị P15</span><strong>{event.recommendedAction || 'Chưa xác định'}</strong></div>
    </div>
    <p className="action-description">{event.actionResult === 'BLOCKED' ? 'Query bị chặn tại DB Firewall. Bản ghi này không xác nhận VM đã được isolate.' : event.actionResult === 'FORWARDED' ? 'Query đã được chuyển tiếp. Bản ghi này không chứng minh kết quả thực thi tại database.' : event.actionError || 'Proxy ghi nhận lỗi khi xử lý query.'}</p>
    <p className="event-no-incident">Chưa nối correlation và dữ liệu isolation. Không suy diễn incident hoặc trạng thái security group từ audit query.</p>
  </div>
}
