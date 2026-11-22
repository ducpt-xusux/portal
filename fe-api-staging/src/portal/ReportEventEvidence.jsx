import { uiLabel } from "../services/uiLanguage";
import { hasSourceValue, reportEventCoverage, REPORT_EVENT_FIELDS } from "../services/reportFields";
import { CopyId, useTime } from "./PortalUI";

const codes = new Set(["event_id", "stream_id", "payload_sha256"]);
const statusFields = new Set(["effective_action", "severity", "mask_status", "risk_status"]);

export default function ReportEventEvidence({ event }) {
  const { complete, missing } = reportEventCoverage(event);
  const parts = event.score_breakdown;
  const time = useTime();
  return (
    <section className="panel v4-panel n91-report-event" aria-label="Trường kiểm toán theo báo cáo">
      <div className="panel-heading">
        <h2>Chi tiết điểm rủi ro</h2>
        {Number.isFinite(event.risk?.score) && <strong className="n91-report-score">{event.risk.score}/100</strong>}
      </div>
      {Array.isArray(parts) && parts.length > 0 ? (
        <div className="table-scroll">
          <table className="v4-table n91-report-score-table">
            <thead>
              <tr><th>Quy tắc</th><th>Nhóm</th><th>Điểm</th><th>Lý do</th></tr>
            </thead>
            <tbody>
              {parts.map((part, index) => (
                <tr key={`${part.rule_id || part.source}:${index}`}>
                  <td>{part.rule_id ? <code>{part.rule_id}</code> : uiLabel(part.source)}</td>
                  <td>{uiLabel(part.category)}</td>
                  <td>{part.score ?? "—"}</td>
                  <td>{part.reason ? <span title={part.reason}>{uiLabel(part.reason)}</span> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="v4-panel-note">{Array.isArray(parts) ? "Bản ghi không có thành phần điểm." : "Nguồn chưa cung cấp thành phần điểm."}</p>
      )}
      <details className="n91-report-record">
        <summary>Trường kiểm toán theo báo cáo</summary>
        {!complete && (
          <p className="v4-inline-warning" role="status">
            Nguồn chưa cung cấp {missing.map(uiLabel).join(", ")}.
          </p>
        )}
        <dl>
          {REPORT_EVENT_FIELDS.map(([key, label, read]) => {
            const value = read(event);
            return (
              <div key={key}>
                <dt>{label}</dt>
                <dd>
                  {!hasSourceValue(value) ? "—"
                    : codes.has(key) ? <><code>{value}</code><CopyId value={value} /></>
                    : Array.isArray(value)
                      ? value.length ? <ul>{value.map((rule) => <li key={rule}><code>{rule}</code></li>)}</ul> : "Không có"
                    : key === "occurred_at" ? <time dateTime={value}>{time(value)}</time>
                    : key === "risk_status" && value === "OK" ? "Đã tính điểm"
                    : statusFields.has(key) ? uiLabel(value)
                    : String(value)}
                </dd>
              </div>
            );
          })}
        </dl>
      </details>
    </section>
  );
}
