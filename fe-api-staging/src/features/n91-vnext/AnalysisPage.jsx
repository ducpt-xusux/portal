import { useState } from "react";
import { useV4Resource } from "../../portal/IncidentPages";
import {
  Badge,
  FieldGrid,
  Panel,
  PageHeading,
  SourceStatus,
  useTime,
} from "../../portal/PortalUI";
import { ArrowLeft, ChevronDown, RefreshCw, ShieldAlert, ScanSearch } from "lucide-react";
import { evidenceDecision } from "../../services/proxyPresentation";
import { signalName, uiLabel } from "../../services/uiLanguage";
import { analysisCaseHref, analysisEventHref, incidentSectionHref, sameRequestEvent } from "../../services/incidentLinks";
import { eventHref } from "../n91-investigation/workbenchModel";
import { EventInvestigationLinks } from "../../portal/InvestigationFlow";
import { usePortal } from "../../portal/PortalContext";
import { AnalysisExecutions, useAnalysisExecutions } from "./AnalysisExecutions";
import "./analysis.css";

const list = (value) => (Array.isArray(value) ? value : []);
const number = (value) =>
  typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString("vi-VN")
    : "—";
const href = (key, id) =>
  `#/incidents?analysis=1${key ? `&${key}=${encodeURIComponent(id)}` : ""}`;
const signalTitle = (code) => signalName(code) || code;
const caseTitle = (value) =>
  list(value.signals).includes("CORR-002")
    ? "Nghi vấn chèn mã SQL lặp lại"
    : "Hồ sơ hành vi cần xem xét";

function AnalysisItems({ values, format = (value) => value, empty = "—" }) {
  const items = list(values);
  if (!items.length) return <p>{empty}</p>;
  return (
    <ul className="n91-analysis-items">
      {items.map((item) => <li key={item}>{format(item)}</li>)}
    </ul>
  );
}

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
  const riskScore = event.risk_score ?? p15.score;
  const riskStatus = p15.status || event.risk_status;
  const evaluations = Object.entries(p17.detector_evaluations || {});
  return (
    <>
      <div className="n91-analysis-trace">
        <section>
          <h3>Kiểm soát truy vấn</h3>
          <AnalysisItems values={p14.matched_rules} empty="Chưa có quy tắc trong bản xuất" />
        </section>
        <section>
          <h3>Điểm rủi ro</h3>
          <p>
            {Number.isFinite(riskScore) ? `${number(riskScore)}/100` : "Chưa có điểm"}
          </p>
        </section>
        <section>
          <h3>Phát hiện hành vi</h3>
          <AnalysisItems
            values={p17.matched_signals}
            format={signalTitle}
            empty="Chưa có mẫu mới khớp"
          />
        </section>
      </div>
      {evaluations.length > 0 && (
        <details>
          <summary>Đánh giá {evaluations.length} mẫu hành vi</summary>
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>Mẫu phát hiện</th>
                  <th>Đánh giá</th>
                  <th>Đã ghi nhận</th>
                  <th>Mốc tham chiếu</th>
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
        <div className="n91-analysis-technical-items">
          <div><strong>Mã quy tắc</strong><AnalysisItems values={p14.matched_rules} /></div>
          <div><strong>Mã mẫu hành vi</strong><AnalysisItems values={p17.matched_signals} /></div>
        </div>
        <p>Trạng thái tính điểm: {riskStatus === "OK" ? "Đã tính điểm" : uiLabel(riskStatus)}</p>
      </details>
    </>
  );
}

function RelatedResponseIncidents({ streamId, evidence }) {
  const { sessionAuthEnabled } = usePortal();
  const resource = useV4Resource("/system/automatic-response", {
    enabled: sessionAuthEnabled && evidence.length > 0,
    interval: 0,
  });
  if (resource.error) return null;
  const seen = new Set();
  const matches = [];
  for (const row of list(resource.data?.decisions)) {
    if (row.stream_id !== streamId || seen.has(row.incident_id)) continue;
    const href = incidentSectionHref(row.incident_id, row.stream_id, "response");
    if (!href) continue;
    const shared = new Set();
    for (const member of list(row.evidence?.incident?.evidence)) {
      if (evidence.some((event) => sameRequestEvent(event, { ...member, stream_id: row.stream_id }))) {
        shared.add(member.event_id);
      }
    }
    seen.add(row.incident_id);
    if (shared.size) matches.push({ row, href, count: shared.size });
  }
  if (!matches.length) return null;
  return (
    <details className="panel portal-provenance">
      <summary>Sự cố dùng chung truy vấn ({matches.length})</summary>
      <ul>
        {matches.map(({ row, href, count }) => (
          <li key={row.incident_id}>
            <a href={href}>{signalName(row.evidence?.incident?.correlation_rule) || row.incident_id}</a>
            {" · "}{count} truy vấn cùng nhóm · {uiLabel(row.state)}
          </li>
        ))}
      </ul>
    </details>
  );
}

function CaseDetail({ data, resource }) {
  const [shown, setShown] = useState(10);
  const time = useTime();
  const evidence = [...list(data.evidence)].sort((a, b) => b.event_ms - a.event_ms);
  const span = evidence.length > 1 && evidence.every((event) => Number.isFinite(event.event_ms))
    ? (evidence[0].event_ms - evidence.at(-1).event_ms) / 1000
    : null;
  return (
    <>
      <header className="n91-case-masthead">
        <a className="incident-back" href={href()}>
          <ArrowLeft size={15} aria-hidden="true" /> Hồ sơ phân tích
        </a>
        <div className="n91-case-heading">
          <div>
            <h1>{caseTitle(data)}</h1>
            <p>IP nguồn <strong>{data.source_ip || "—"}</strong> <Badge value={data.status} /></p>
          </div>
          <button className="button secondary" type="button" disabled={resource.loading} onClick={resource.refresh}>
            <RefreshCw size={15} className={resource.loading ? "spin" : ""} /> Làm mới
          </button>
        </div>
        <FieldGrid rows={[
          ["Số truy vấn", number(data.evidence_count)],
          ["Điểm rủi ro cao nhất", Number.isFinite(data.peak_p15) ? `${number(data.peak_p15)}/100` : "Chưa có điểm"],
          ["Mức độ", uiLabel(data.severity)],
          ["Cập nhật bằng chứng", time(data.updated_at)],
        ]} />
      </header>
      <Panel title="Truy vấn làm bằng chứng" className="n91-case-queries">
        {data.evidence_export_complete === false && (
          <p className="n91-analysis-note">Bản xuất có {evidence.length} truy vấn trong tổng số {number(data.evidence_count)} đã ghi nhận.</p>
        )}
        {evidence.length ? (
          <>
            <div className="n91-case-query-list">
              {evidence.slice(0, shown).map((event) => {
                const eventUrl = analysisEventHref(event);
                const stamp = event.trace?.event_time;
                return (
                  <details className="n91-case-query" key={event.event_id}>
                    <summary>
                      <strong>Truy vấn {event.stream_sequence ?? "—"}</strong>
                      <time dateTime={stamp}>{time(stamp)}</time>
                      <span>{Number.isFinite(event.risk_score) ? `${number(event.risk_score)}/100` : "Chưa có điểm"}</span>
                      <span className="n91-case-query-state">
                        <Badge value={evidenceDecision(event)} />
                        <ChevronDown size={15} aria-hidden="true" />
                      </span>
                    </summary>
                    <div className="n91-case-query-body">
                      <Trace event={event} />
                      {eventUrl && <a href={eventUrl}>Mở phân tích của truy vấn</a>}
                    </div>
                  </details>
                );
              })}
            </div>
            {evidence.length > shown && (
              <button className="button secondary n91-case-more" type="button" onClick={() => setShown(shown + 10)}>
                Xem thêm truy vấn
              </button>
            )}
          </>
        ) : <p>Bản xuất chưa có truy vấn để xem.</p>}
      </Panel>
      <Panel title="Mẫu hành vi trong hồ sơ">
        <AnalysisItems values={data.signals} format={signalTitle} empty="Hồ sơ chưa có mẫu hành vi được ghi nhận." />
      </Panel>
      <RelatedResponseIncidents streamId={data.stream_id} evidence={evidence} />
      <details className="panel portal-provenance">
        <summary>Thông tin nguồn và phạm vi</summary>
        <SourceStatus resource={resource} label="Bản xuất phân tích hành vi" />
        <FieldGrid rows={[
          ["Mã hồ sơ", data.case_id],
          ["Phạm vi bằng chứng", data.evidence_export_complete === true ? "Đã xuất đủ truy vấn của hồ sơ" : "Bản xuất giới hạn"],
          ["Khoảng thời gian của chuỗi", span === null ? null : `${span.toLocaleString("vi-VN", { maximumFractionDigits: 3 })} giây`],
          ["Hành động do hồ sơ phân tích ghi nhận", data.response === "NO_ACTION" ? "Không thực thi" : uiLabel(data.response)],
          ["Cờ cấp phép trong hồ sơ phân tích", uiLabel(data.isolation_authorized)],
        ]} />
        <strong>Mã mẫu hành vi</strong>
        <AnalysisItems values={data.signals} />
      </details>
    </>
  );
}

function EventDetail({ event }) {
  const time = useTime();
  const auditUrl = eventHref(event, "canonical");
  const caseUrl = analysisCaseHref(event.trace?.p17?.case_id, event.stream_id);
  return (
    <>
      <a className="incident-back" href={caseUrl || href()}>
        ← {caseUrl ? "Hồ sơ chứa truy vấn này" : "Danh sách hồ sơ phân tích"}
      </a>
      <Panel
        title="Phân tích một truy vấn"
        action={<Badge value={evidenceDecision(event)} />}
      >
        <FieldGrid
          rows={[
            ["IP nguồn", event.trace?.source_ip],
            ["Thứ tự", event.stream_sequence],
            ["Thời gian", time(event.trace?.event_time)],
          ]}
        />
        {auditUrl && <a href={auditUrl}>Đối chiếu cùng sự kiện trong nhật ký kiểm toán</a>}
        <Trace event={event} />
      </Panel>
      <EventInvestigationLinks event={event} analysis />
    </>
  );
}

function QueryList({ resource }) {
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const time = useTime();
  const events = list(resource.data?.events);
  const filtered = events.filter((event) =>
    event.source_ip?.includes(filter.trim()) || !filter.trim(),
  );
  const pageSize = 15;
  const activePage = Math.min(page, Math.max(0, Math.ceil(filtered.length / pageSize) - 1));
  const start = activePage * pageSize;
  return (
    <Panel
      title="Truy vấn đã phân tích"
      subtitle={resource.data?.source_total > events.length
        ? `Đang xem ${events.length} trong ${number(resource.data.source_total)} truy vấn ở nguồn.`
        : undefined}
    >
      <label className="n91-analysis-filter">
        Lọc theo IP nguồn
        <input type="search" value={filter} onChange={(event) => {
          setFilter(event.target.value);
          setPage(0);
        }} />
      </label>
      {filtered.length > 0 ? (
        <>
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>Truy vấn</th>
                  <th>Thời điểm</th>
                  <th>IP nguồn</th>
                  <th>Kết quả tường lửa</th>
                  <th>Rủi ro</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(start, start + pageSize).map((event) => (
                  <tr key={event.event_id}>
                    <td><a href={analysisEventHref(event)}>Truy vấn số {event.stream_sequence}</a></td>
                    <td>{time(event.event_time)}</td>
                    <td>{event.source_ip || "—"}</td>
                    <td><Badge value={evidenceDecision(event)} /></td>
                    <td>{number(event.risk_score)}/100</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <nav className="n91-analysis-pager" aria-label="Phân trang truy vấn">
            <button className="button secondary" disabled={activePage === 0} onClick={() => setPage(activePage - 1)}>Trang trước</button>
            <span>{start + 1}–{Math.min(start + pageSize, filtered.length)} / {filtered.length}</span>
            <button className="button secondary" disabled={start + pageSize >= filtered.length} onClick={() => setPage(activePage + 1)}>Trang sau</button>
          </nav>
        </>
      ) : <p>Chưa có truy vấn trong bản xuất và phạm vi lọc hiện tại.</p>}
    </Panel>
  );
}

export function AnalysisPage({ params, navigation }) {
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
  const showQueries = !id && params.view === "queries";
  const events = useV4Resource("/p17-vnext/events", {
    enabled: !id,
    params: { limit: 100 },
    interval: 10000,
  });
  const { sessionAuthEnabled } = usePortal();
  const executions = useAnalysisExecutions(sessionAuthEnabled && !id && !showQueries);
  const resource = id ? detail : showQueries ? events : cases;
  const refresh = () => {
    if (id) {
      detail.refresh();
    } else {
      cases.refresh();
      events.refresh();
      executions.response.refresh();
      executions.journal.refresh();
    }
  };
  const detailMismatch = id && detail.data && (
    detail.data[key === "cases" ? "case_id" : "event_id"] !== id ||
    (params.stream_id && detail.data.stream_id !== params.stream_id) ||
    (key === "events" && params.request_id && detail.data.request_id !== params.request_id)
  );
  const time = useTime();
  const rows = list(cases.data?.cases).filter(
    (value) => !ip || String(value.source_ip || "").includes(ip.trim()),
  );
  if (key === "cases" && detail.data && !detail.error && !detailMismatch) {
    return <div className="n91-analysis"><CaseDetail data={detail.data} resource={detail} /></div>;
  }
  return (
    <div className="n91-analysis">
      <PageHeading
        title="Phân tích hành vi"
        resource={{ loading: resource.loading && !resource.data, refresh }}
      />
      {navigation}
      {!id && (
        <nav className="v4-system-tabs v4-sub-tabs" aria-label="Danh sách phân tích">
          <a href={href()} className={!showQueries ? "active" : ""} aria-current={!showQueries ? "page" : undefined}>
            Hồ sơ tổng hợp{cases.data && !cases.error ? ` (${cases.data.shown})` : ""}
          </a>
          <a href={`${href()}&view=queries`} className={showQueries ? "active" : ""} aria-current={showQueries ? "page" : undefined}>
            Truy vấn đã phân tích{events.data && !events.error ? ` (${events.data.source_total})` : ""}
          </a>
        </nav>
      )}
      <SourceStatus resource={resource} label="Bản xuất phân tích hành vi" />
      {!id && !showQueries && sessionAuthEnabled && (
        <AnalysisExecutions
          {...executions}
          cases={cases.error ? [] : list(cases.data?.cases)}
          events={events.error ? [] : list(events.data?.events)}
        />
      )}
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
      ) : detailMismatch ? (
        <p className="n91-analysis-note" role="alert">
          Bản ghi trả về khác mã trong liên kết. Mở lại từ sự kiện hoặc hồ sơ gốc.
        </p>
      ) : (
        resource.data &&
        (id ? (
          <EventDetail event={detail.data} />
        ) : showQueries ? (
          <QueryList resource={events} />
        ) : (
          <Panel
            title="Hồ sơ hành vi theo nguồn"
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
                    {value.updated_at && <p>Ghi nhận gần nhất {time(value.updated_at)}</p>}
                  </div>
                  <Badge value={value.severity} />
                  <a
                    className="button secondary"
                    href={analysisCaseHref(value.case_id, value.stream_id) || href("case_id", value.case_id)}
                  >
                    Xem hồ sơ →
                  </a>
                </article>
              ))
            ) : (
              <p>Chưa có hồ sơ trong bản xuất và phạm vi lọc hiện tại.</p>
            )}
          </Panel>
        ))
      )}
    </div>
  );
}
