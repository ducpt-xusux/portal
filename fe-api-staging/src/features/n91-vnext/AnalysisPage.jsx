import { useState } from "react";
import { useV4Resource } from "../../portal/IncidentPages";
import {
  Badge,
  FieldGrid,
  Panel,
  PageHeading,
  useTime,
} from "../../portal/PortalUI";
import { ShieldAlert, ScanSearch } from "lucide-react";
import { evidenceDecision } from "../../services/proxyPresentation";
import { uiLabel } from "../../services/uiLanguage";
import "./analysis.css";

const list = (value) => (Array.isArray(value) ? value : []);
const number = (value) =>
  typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString("vi-VN")
    : "—";
const href = (key, id) =>
  `#/incidents?analysis=1${key ? `&${key}=${encodeURIComponent(id)}` : ""}`;
const signals = {
  "CORR-001": "Vi phạm chính sách lặp lại",
  "CORR-002": "Thử chèn mã SQL nhiều lần",
  "CORR-003": "Truy cập dữ liệu nhạy cảm lặp lại",
  "CORR-004": "Kết hợp nhiều kỹ thuật",
  "CORR-005": "Lỗi tương thích giao thức lặp lại",
  "CORR-012": "Truy cập từ nguồn không được phép",
  "CORR-013": "Chèn mã SQL từ nguồn không được phép",
  "CORR-014": "Dò tìm cấu trúc lặp lại",
  "CORR-015": "Dò tìm rồi thử hành vi nguy hiểm",
  "CORR-022": "Chuỗi hành vi tăng mức nguy hiểm",
};
const signalTitle = (code) => signals[code] || code;
const caseTitle = (value) =>
  list(value.signals).includes("CORR-002")
    ? "Nghi vấn chèn mã SQL lặp lại"
    : "Hồ sơ hành vi cần xem xét";

export function IncidentNavigation({ analysis }) {
  return (
    <nav className="v4-system-tabs" aria-label="Chức năng sự cố">
      <a
        href="#/incidents"
        aria-current={!analysis ? "page" : undefined}
        className={!analysis ? "active" : ""}
      >
        <ShieldAlert size={16} />
        Danh sách sự cố
      </a>
      <a
        href={href()}
        aria-current={analysis ? "page" : undefined}
        className={analysis ? "active" : ""}
      >
        <ScanSearch size={16} />
        Phân tích hành vi
      </a>
    </nav>
  );
}

function Trace({ event }) {
  const trace = event.trace || {};
  const p14 = trace.p14 || {},
    p15 = trace.p15 || {},
    p17 = trace.p17 || {};
  const evaluations = Object.entries(p17.detector_evaluations || {});
  return (
    <>
      <div className="n91-analysis-trace">
        <section>
          <h3>Kiểm soát truy vấn</h3>
          <p>
            {list(p14.matched_rules).join(" · ") ||
              "Chưa có quy tắc trong bản xuất"}
          </p>
        </section>
        <section>
          <h3>Đánh giá rủi ro</h3>
          <p>
            {number(event.risk_score ?? p15.score)}/100 ·{" "}
            {p15.status ? uiLabel(p15.status) : "Chưa xác minh"}
          </p>
        </section>
        <section>
          <h3>Phát hiện hành vi</h3>
          <p>
            {list(p17.matched_signals).map(signalTitle).join(" · ") ||
              "Chưa có mẫu mới khớp"}
          </p>
        </section>
        <section>
          <h3>Phản ứng</h3>
          <p>Xem quyết định xử lý trong hồ sơ sự cố hoặc mục Ứng phó tự động.</p>
        </section>
      </div>
      {evaluations.length > 0 && (
        <details>
          <summary>Đánh giá {evaluations.length} mẫu hành vi</summary>
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>MẪU PHÁT HIỆN</th>
                  <th>ĐÁNH GIÁ</th>
                  <th>ĐÃ GHI NHẬN</th>
                  <th>MỐC THAM CHIẾU</th>
                </tr>
              </thead>
              <tbody>
                {evaluations.map(([code, result]) => (
                  <tr key={code}>
                    <td>{signalTitle(code)}</td>
                    <td>
                      {result.met === true
                        ? "Đủ điều kiện"
                        : result.met === false
                          ? "Chưa đủ điều kiện"
                          : "Chưa xác minh"}
                    </td>
                    <td>{number(result.actual)}</td>
                    <td>{number(result.required)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      <details>
        <summary>Thông tin kỹ thuật</summary>
        <p>
          Mã sự kiện: <code>{event.event_id}</code>
        </p>
        <p>Quy tắc: {list(p14.matched_rules).join(", ") || "—"}</p>
        <p>Mẫu: {list(p17.matched_signals).join(", ") || "—"}</p>
      </details>
    </>
  );
}

function CaseDetail({ data }) {
  const time = useTime();
  const evidence = [...list(data.evidence)].sort(
    (a, b) => a.event_ms - b.event_ms,
  );
  const span =
    evidence.length > 1 && evidence.every((e) => Number.isFinite(e.event_ms))
      ? (evidence.at(-1).event_ms - evidence[0].event_ms) / 1000
      : null;
  return (
    <>
      <a className="incident-back" href={href()}>
        ← Danh sách hồ sơ
      </a>
      <Panel title={caseTitle(data)} action={<Badge value={data.status} />}>
        <p className="n91-analysis-note">
          Hồ sơ dựa trên truy vấn đã ghi nhận; không chứng minh tấn công thành
          công và không cấp quyền cách ly.
        </p>
        <FieldGrid
          rows={[
            ["IP nguồn", data.source_ip],
            ["Mức độ", <Badge value={data.severity} />],
            ["Điểm rủi ro cao nhất", `${number(data.peak_p15)}/100`],
            ["Bằng chứng", number(data.evidence_count)],
          ]}
        />
      </Panel>
      <div className="n91-analysis-columns">
        <Panel title="Hành vi được nhận diện">
          {list(data.signals).map((signal) => (
            <p key={signal}>
              <Badge value="WARNING">{signalTitle(signal)}</Badge>
            </p>
          ))}
        </Panel>
        <Panel title="Kết luận và ứng phó">
          <FieldGrid
            rows={[
              ["Trạng thái", <Badge value={data.status} />],
              [
                "Biện pháp cách ly",
                data.response === "NO_ACTION"
                  ? "Chưa cách ly"
                  : "Chưa xác minh",
              ],
              [
                "Được phép tự động cách ly",
                data.isolation_authorized === false ? "Không" : "Chưa xác minh",
              ],
              [
                "Phạm vi bằng chứng",
                data.evidence_export_complete === true
                  ? "Đã xuất đủ thành viên hồ sơ"
                  : "Giới hạn, chưa đủ để kết luận toàn bộ",
              ],
            ]}
          />
        </Panel>
      </div>
      <Panel title="Truy vấn làm bằng chứng">
        {span !== null && (
          <p className="n91-analysis-note">
            Khoảng cách giữa các bằng chứng:{" "}
            <strong>
              {span.toLocaleString("vi-VN", {
                minimumFractionDigits: 3,
                maximumFractionDigits: 3,
              })}{" "}
              giây
            </strong>
            .
          </p>
        )}
        {evidence.length ? (
          evidence.map((event) => (
            <details className="n91-analysis-evidence" key={event.event_id}>
              <summary>
                <strong>Truy vấn thứ tự {event.stream_sequence ?? "—"}</strong>
                <span>
                  {time(event.trace?.event_time)} · {number(event.risk_score)}
                  /100 <Badge value={evidenceDecision(event)} />
                </span>
              </summary>
              <Trace event={event} />
              <a href={href("event_id", event.event_id)}>
                Mở chi tiết sự kiện →
              </a>
            </details>
          ))
        ) : (
          <p>Bản xuất chưa có bằng chứng để xem.</p>
        )}
      </Panel>
      <details>
        <summary>Thông tin kỹ thuật của hồ sơ</summary>
        <p>
          Mã hồ sơ: <code>{data.case_id}</code>
        </p>
        <p>{list(data.signals).join(", ")}</p>
      </details>
    </>
  );
}

function EventDetail({ event }) {
  const time = useTime();
  return (
    <>
      <a className="incident-back" href={href()}>
        ← Hồ sơ phân tích
      </a>
      <Panel
        title="Chi tiết sự kiện"
        action={<Badge value={evidenceDecision(event)} />}
      >
        <FieldGrid
          rows={[
            ["IP nguồn", event.trace?.source_ip],
            ["Thứ tự", event.stream_sequence],
            ["Điểm rủi ro", `${number(event.risk_score)}/100`],
            ["Thời gian", time(event.trace?.event_time)],
          ]}
        />
        <Trace event={event} />
      </Panel>
    </>
  );
}

export function AnalysisPage({ params }) {
  const [ip, setIp] = useState("");
  const key = params.case_id ? "cases" : params.event_id ? "events" : null;
  const id = params.case_id || params.event_id;
  const detail = useV4Resource(
    id ? `/p17-vnext/${key}/${encodeURIComponent(id)}` : "",
    { enabled: Boolean(id), interval: 10000 },
  );
  const cases = useV4Resource("/p17-vnext/cases", {
    enabled: !id,
    params: { limit: 50 },
    interval: 10000,
  });
  const resource = id ? detail : cases;
  const time = useTime();
  const rows = list(cases.data?.cases).filter(
    (value) => !ip || String(value.source_ip || "").includes(ip.trim()),
  );
  return (
    <div className="n91-analysis">
      <PageHeading
        eyebrow="PHÂN TÍCH VÀ ĐIỀU TRA"
        title="Phân tích hành vi"
        description="Đối chiếu chuỗi hành vi và các sự kiện làm bằng chứng cho từng hồ sơ."
        resource={resource}
      />
      <p className="n91-analysis-scope">
        <Badge
          value={resource.error ? "UNKNOWN" : resource.meta?.freshness_state}
        />{" "}
        Phạm vi: tối đa 50 hồ sơ, 100 sự kiện · Chỉ xem xét · Không tự động cách
        ly
        {resource.meta?.data_as_of && (
          <> · Nguồn: {time(resource.meta.data_as_of)}</>
        )}
      </p>
      {resource.loading && !resource.data && (
        <p role="status">Đang đọc hồ sơ đã ghi nhận…</p>
      )}
      {resource.error ? (
        <div className="n91-analysis-note" role="alert">
          {[401, 403].includes(resource.error.status)
            ? "Phiên đăng nhập chưa có quyền đọc phân tích. Hãy đăng nhập lại trên Portal."
            : `Không đọc được dữ liệu phân tích (${resource.error.code || "nguồn chưa khả dụng"}).`}{" "}
          <button className="button secondary" onClick={resource.refresh}>
            Thử lại
          </button>
        </div>
      ) : (
        resource.data &&
        (id ? (
          key === "cases" ? (
            <CaseDetail data={detail.data} />
          ) : (
            <EventDetail event={detail.data} />
          )
        ) : (
          <Panel
            title="Hồ sơ cần xem xét"
            action={<Badge value="UNKNOWN">Chỉ đọc</Badge>}
          >
            <label className="n91-analysis-filter">
              Lọc theo IP nguồn
              <input
                type="search"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="Ví dụ: 10.0.0.204"
              />
            </label>
            {rows.length ? (
              rows.map((value) => (
                <article className="n91-analysis-case" key={value.case_id}>
                  <div>
                    <h3>{caseTitle(value)}</h3>
                    <p>
                      IP nguồn {value.source_ip || "—"} ·{" "}
                      {number(value.evidence_count)} truy vấn làm bằng chứng ·
                      Điểm rủi ro cao nhất {number(value.peak_p15)}/100
                    </p>
                  </div>
                  <Badge value={value.severity} />
                  <a
                    className="button secondary"
                    href={href("case_id", value.case_id)}
                  >
                    Xem hồ sơ →
                  </a>
                </article>
              ))
            ) : (
              <p>Chưa có hồ sơ trong bản xuất và phạm vi lọc hiện tại.</p>
            )}
            <p className="muted">
              Hồ sơ phân tích không tự động cộng vào tổng số sự cố đã ghi nhận
              trước nâng cấp.
            </p>
          </Panel>
        ))
      )}
    </div>
  );
}
