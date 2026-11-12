import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { ShieldCheck } from 'lucide-react'

export default function AuditEventEvidence({ event }) {
  return (
    <div className="event-explanation">
      <h4>
        Rule breakdown{' '}
        <span className="muted">· kết quả được ghi lại</span>
      </h4>
      {event.riskStatus === 'ERROR' && (
        <div className="audit-error" role="alert">
          Risk Engine báo lỗi. Điểm và mức độ chưa xác định; không suy diễn
          bằng 0.
        </div>
      )}
      <div className="table-scroll">
        <table className="rule-breakdown">
          <thead>
            <tr>
              <th>Quy tắc / thành phần</th>
              <th>Điểm</th>
            </tr>
          </thead>
          <tbody>
            {event.ruleBreakdown.map((part) => (
              <tr key={part.key}>
                <td>
                  <code>
                    {part.id ? (
                      <a href={`#/system/rules/${encodeURIComponent(part.id)}`}>
                        {part.id}
                      </a>
                    ) : (
                      'DEFAULT DENY'
                    )}
                  </code>
                  <span>{part.name}</span>
                </td>
                <td>+{part.score}</td>
              </tr>
            ))}
            {!event.ruleBreakdown.length && (
              <tr>
                <td>Không có thành phần chấm điểm trong bản ghi</td>
                <td>—</td>
              </tr>
            )}
          </tbody>
          <tfoot>
            <tr>
              <td>Tổng trước giới hạn</td>
              <td>{event.rawScore ?? 'UNKNOWN'}</td>
            </tr>
            <tr>
              <td>Risk score · giới hạn 100</td>
              <td>{event.score ?? 'UNKNOWN'}</td>
            </tr>
          </tfoot>
        </table>
      </div>
      <div className={`decision-explanation ${event.decision.toLowerCase()}`}>
        <ShieldCheck size={17} />
        <div>
          <strong>quyết định {uiLabel(event.decision)}</strong>
          <p>{event.reason}</p>
          <small>
            đánh giá mức độ rủi ro; mức độ không thay thế quyết định
            ALLOW/BLOCK.
          </small>
        </div>
      </div>
      <h4>Hành động trên truy vấn</h4>
      <div className="event-action-evidence">
        <div>
          <span>Hành động</span>
          <strong>{event.action}</strong>
        </div>
        <div>
          <span>Kết quả xử lý</span>
          <strong>{event.actionResult}</strong>
        </div>
        <div>
          <span>Dominant quy tắc</span>
          <strong>{event.dominantRule || 'Không có'}</strong>
        </div>
        <div>
          <span>Khuyến nghị </span>
          <strong>{event.recommendedAction || 'Chưa xác định'}</strong>
        </div>
      </div>
      <p className="action-description">
        {event.actionResult === 'BLOCKED'
          ? "Truy vấn bị chặn tại DB Firewall. Bản ghi này không xác nhận VM đã được isolate."
          : event.actionResult === 'FORWARDED'
            ? "Truy vấn đã được chuyển tiếp. Bản ghi này không chứng minh kết quả thực thi tại database."
            : event.actionError || "Proxy ghi nhận lỗi khi xử lý truy vấn."}
      </p>
      <p className="event-no-incident">
        Chưa nối correlation và dữ liệu isolation. Không suy diễn sự cố hoặc
        trạng thái security group từ audit truy vấn.
      </p>
    </div>
  )
}
