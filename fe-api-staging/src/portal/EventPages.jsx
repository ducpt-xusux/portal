import ReportEventEvidence from "./ReportEventEvidence";
import { uiLabel, uiRoleList } from "../services/uiLanguage.js";
import { useState } from "react";
import {
  EventComparePicker,
  EventInvestigation,
} from "../features/n91-investigation/Investigation";
import { auditEventQuery } from "../services/dashboardAudit";
import { ArrowLeft, ArrowUpRight, Search } from "lucide-react";
import { mapEvent, readCollection } from "../services/portalApi";
import { incidentHref } from "../services/incidentLinks";
import { useCursor, useV4Resource } from "./IncidentPages";
import {
  Badge,
  CopyId,
  CursorPager,
  Empty,
  FieldGrid,
  Filter,
  FilterHeading,
  PageHeading,
  Panel,
  ResourceNotice,
  SelectFilter,
  SourceStatus,
  display,
  useTime,
} from "./PortalUI";
import { usePortal } from "./PortalContext";
import { useDetailView } from "./DetailView";

const riskStatusLabel = (status) =>
  status === "OK" ? "Tính điểm thành công" : uiLabel(status);

// N91_EVENT_DETAIL_SOURCE_AWARE_V1: independent read-only cross-source comparison.
function auditIdentityConflicts(projection, canonical) {
  const problems = [];
  if (!canonical || canonical.view_kind !== "P16H_CANONICAL_AUDIT") {
    return ["Nguồn đối chiếu không phải bản ghi kiểm toán chuẩn."];
  }
  if (canonical.event_id !== projection.event_id) {
    problems.push("Mã sự kiện không trùng khớp.");
  }
  for (const [field, title] of [
    ["stream_id", "Mã luồng"],
    ["request_id", "Mã yêu cầu"],
    ["source_ip", "IP nguồn"],
    ["db_user", "Tài khoản CSDL"],
    ["decision", "Quyết định"],
  ]) {
    if (
      canonical[field] &&
      projection[field] &&
      canonical[field] !== projection[field]
    ) {
      problems.push(`${title} không trùng khớp.`);
    }
  }
  const a = Date.parse(canonical.occurred_at);
  const b = Date.parse(projection.occurred_at);
  if (!Number.isFinite(a) || !Number.isFinite(b)) {
    problems.push("Không xác minh được thời điểm phát sinh ở cả hai nguồn.");
  } else if (Math.abs(a - b) > 2000) {
    problems.push("Thời điểm phát sinh lệch quá 2 giây.");
  }
  return problems;
}

function EventAuditComparison({ event }) {
  // The projection remains intact: canonical values are NEVER copied into P17.
  // Only this read-only panel requests a separate canonical record.
  const canonical = useV4Resource(
    `/events/${encodeURIComponent(event.event_id)}`,
    {
      params: { source: "canonical" },
      interval: 0,
      transform: mapEvent,
    },
  );
  const matching = canonical.data;
  const problems = matching ? auditIdentityConflicts(event, matching) : [];
  const auditLink = `#/events/${encodeURIComponent(event.event_id)}?source=canonical`;
  const riskDisagrees =
    matching &&
    matching.risk.score !== null &&
    event.risk.score !== null &&
    matching.risk.score !== event.risk.score;

  return (
    <Panel
      title="Đối chiếu nhật ký kiểm toán"
      subtitle="Dữ liệu kiểm toán và bản chiếu phát hiện được đọc độc lập"
    >
      {canonical.loading && !matching && (
        <p className="v4-panel-note" role="status">
          Đang đối chiếu bản ghi kiểm toán…
        </p>
      )}
      {canonical.error && (
        <p className="v4-panel-note">
          {canonical.error.status === 404
            ? "Không có bản ghi kiểm toán tương ứng trong nguồn đang đọc."
            : canonical.error.status === 409
              ? "Định danh sự kiện không duy nhất; cần đối chiếu luồng tại nguồn."
              : [401, 403].includes(canonical.error.status)
                ? "Phiên đăng nhập không có quyền đọc bản ghi kiểm toán."
                : "Nguồn kiểm toán chưa khả dụng để đối chiếu."}
        </p>
      )}
      {matching && problems.length > 0 && (
        <div className="v4-inline-warning" role="status">
          <strong>Chưa xác minh được sự tương ứng giữa hai bản ghi.</strong>
          <ul>
            {problems.map((problem, index) => (
              <li key={index}>{problem}</li>
            ))}
          </ul>
          <p>
            Không ghép hoặc dùng trường từ nguồn kiểm toán thay cho bản chiếu
            phát hiện.
          </p>
        </div>
      )}
      {matching && problems.length === 0 && (
        <>
          <ReportEventEvidence event={matching} />
          <p className="v4-panel-note">
            Cùng mã sự kiện; các thuộc tính định danh chung phù hợp. Phần dưới
            là thông tin <strong>từ bản ghi kiểm toán chuẩn</strong>, không phải
            dữ liệu gốc của bản chiếu phát hiện.
          </p>
          <FieldGrid
            rows={[
              ["Hành động đã kiểm toán", uiLabel(matching.effective_action)],
              [
                "Kết quả thực thi đã kiểm toán",
                uiLabel(matching.action_result),
              ],
              ["Phiên bản chính sách", display(matching.policy_version)],
              [
                "Quy tắc chặn",
                matching.blocking_rules.join(" · ") || "Không có",
              ],
              [
                "Quy tắc giám sát",
                matching.monitor_rules.join(" · ") || "Không có",
              ],
              ["Điểm gốc", display(matching.raw_score)],
              ["Điểm rủi ro kiểm toán", matching.risk.score ?? "Không có"],
            ]}
          />
          {riskDisagrees && (
            <p className="v4-inline-warning" role="status">
              Điểm rủi ro khác nhau giữa nguồn kiểm toán và nguồn phát hiện. Cần
              kiểm tra thời điểm và chính sách xử lý, không tự hợp nhất.
            </p>
          )}
          {matching.score_breakdown?.length > 0 && (
            <details className="v4-json">
              <summary>Thành phần điểm rủi ro từ kiểm toán</summary>
              <ul className="v4-reasons">
                {matching.score_breakdown.map((part, index) => (
                  <li key={index}>
                    {part.rule_id || "Nguồn khác"}: {part.score ?? "N/A"} điểm
                    {part.reason ? ` — ${part.reason}` : ""}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {matching.masked_query && (
            <details className="v4-json">
              <summary>Truy vấn đã che từ nguồn kiểm toán</summary>
              <pre className="v4-code">{matching.masked_query}</pre>
            </details>
          )}
          <a className="incident-back" href={auditLink}>
            Xem bản ghi kiểm toán gốc <ArrowUpRight size={15} />
          </a>
        </>
      )}
    </Panel>
  );
}

export function EventTable({ events, compact = false }) {
  const time = useTime();
  return (
    <div className="table-scroll">
      <table className="v4-table">
        <thead>
          <tr>
            <th>SỰ KIỆN / THỜI GIAN</th>
            <th>NGUỒN</th>
            <th>QUYẾT ĐỊNH</th>
            <th>ĐIỂM RỦI RO</th>
            <th>QUY TẮC ÁP DỤNG</th>
            {!compact && <th>LOẠI / SỰ CỐ</th>}
            <th>
              <span className="sr-only">Chi tiết</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={`${event.stream_id}:${event.event_id}`}>
              <td>
                <a
                  className="v4-id-link"
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                >
                  {event.event_id}
                </a>
                <time>{time(event.occurred_at)}</time>
              </td>
              <td>
                <code>{display(event.source_ip)}</code>
                <small>{event.db_user || "Withheld / chưa cung cấp"}</small>
              </td>
              <td>
                <Badge value={event.decision} />
                {event.effective_action &&
                  !["UNKNOWN", "UNAVAILABLE"].includes(
                    event.effective_action,
                  ) && (
                    <small>Áp dụng: {uiLabel(event.effective_action)}</small>
                  )}
              </td>
              <td>
                <strong>{event.risk.score ?? "N/A"}</strong>
                {event.risk.status !== "OK" && (
                  <small>{riskStatusLabel(event.risk.status)}</small>
                )}
              </td>
              <td>
                <span className="v4-rule-list">
                  {event.matched_rules.map((rule) => (
                    <a
                      key={rule}
                      className="v4-rule"
                      href={`#/events?rule=${encodeURIComponent(rule)}${event.view_kind === "P16H_CANONICAL_AUDIT" ? "&source=canonical" : ""}`}
                    >
                      {rule}
                    </a>
                  ))}
                </span>
                {!event.matched_rules.length && "—"}
              </td>
              {!compact && (
                <td>
                  <Badge value={event.p17_event_class} />
                  {event.incident_refs.map((id) => (
                    <a
                      key={id}
                      className="v4-id-link"
                      href={incidentHref(id, event.stream_id)}
                    >
                      {id}
                    </a>
                  ))}
                </td>
              )}
              <td>
                <a
                  className="row-detail"
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                  aria-label={`Mở event ${event.event_id}`}
                >
                  <ArrowUpRight size={16} />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const localInput = (value, zone) =>
  value && Number.isFinite(Date.parse(value))
    ? new Date(Date.parse(value) + (zone === "UTC" ? 0 : 7 * 3600000))
        .toISOString()
        .slice(0, 16)
    : "";

export function EventsPage({ params }) {
  const { timezone } = usePortal();
  const [draft, setDraft] = useState(params);
  const [error, setError] = useState("");
  const pager = useCursor();
  const resource = useV4Resource("/events", {
    params: { ...params, limit: 25, cursor: pager.cursor },
    interval: 5000,
    transform: (data) => readCollection(data, "events").map(mapEvent),
  });
  const update = (key) => (value) =>
    setDraft((current) => ({ ...current, [key]: value }));
  return (
    <>
      <PageHeading
        eyebrow="SỰ KIỆN BẢO MẬT"
        title="Sự kiện bảo mật"
        description={
          params.source === "canonical"
            ? "Nhật ký kiểm toán đã nhập, phạm vi lịch sử có thể chưa đầy đủ."
            : undefined
        }
        resource={resource}
      />
      {["TEST", "EVALUATION"].includes(resource.meta?.import_context) && (
        <p className="v4-inline-warning" role="status">
          Dữ liệu {uiLabel(resource.meta.import_context).toLowerCase()} · bản
          chụp ngoại tuyến
        </p>
      )}
      <form
        className="panel v4-filters v4-event-filters"
        onSubmit={(event) => {
          event.preventDefault();
          if (
            draft.from &&
            draft.to &&
            Date.parse(draft.from) > Date.parse(draft.to)
          ) {
            setError("Thời điểm bắt đầu phải trước thời điểm kết thúc.");
            return;
          }
          if (
            draft.risk_min &&
            draft.risk_max &&
            Number(draft.risk_min) > Number(draft.risk_max)
          ) {
            setError("Điểm tối thiểu phải nhỏ hơn hoặc bằng điểm tối đa.");
            return;
          }
          setError("");
          const search = new URLSearchParams(
            Object.entries(draft).filter(
              ([, value]) => value && value !== "ALL",
            ),
          ).toString();
          window.location.hash = `/events${search ? `?${search}` : ""}`;
        }}
      >
        <FilterHeading />
        <Filter label={`Từ · ${timezone === "UTC" ? "UTC" : "UTC+7"}`}>
          <input
            type="datetime-local"
            value={localInput(draft.from, timezone)}
            onChange={(event) =>
              update("from")(
                event.target.value
                  ? new Date(
                      `${event.target.value}${timezone === "UTC" ? "Z" : "+07:00"}`,
                    ).toISOString()
                  : "",
              )
            }
          />
        </Filter>
        <Filter label={`Đến · ${timezone === "UTC" ? "UTC" : "UTC+7"}`}>
          <input
            type="datetime-local"
            value={localInput(draft.to, timezone)}
            onChange={(event) =>
              update("to")(
                event.target.value
                  ? new Date(
                      `${event.target.value}${timezone === "UTC" ? "Z" : "+07:00"}`,
                    ).toISOString()
                  : "",
              )
            }
          />
        </Filter>
        <SelectFilter
          label="Quyết định xử lý"
          value={draft.decision}
          onChange={update("decision")}
          options={[
            ["", "Tất cả"],
            ["ALLOW", "ALLOW"],
            ["BLOCK", "BLOCK"],
            ["UNKNOWN", "UNKNOWN"],
          ]}
        />
        <Filter label="IP nguồn">
          <input
            value={draft.source_ip || ""}
            maxLength={45}
            placeholder="10.0.0.204"
            onChange={(event) => update("source_ip")(event.target.value)}
          />
        </Filter>
        <Filter label="Mã quy tắc">
          <input
            value={draft.rule || ""}
            maxLength={80}
            placeholder="INJ-001"
            onChange={(event) => update("rule")(event.target.value)}
          />
        </Filter>
        <details className="n91-advanced-filters">
          <summary>Bộ lọc nâng cao</summary>
          <div>
            <Filter label="Mã sự cố">
              <input
                value={draft.incident_ref || ""}
                maxLength={128}
                placeholder="INC-…"
                onChange={(event) => update("incident_ref")(event.target.value)}
              />
            </Filter>
            <SelectFilter
              label="Loại sự kiện"
              value={draft.event_class}
              onChange={update("event_class")}
              options={[
                ["", "Tất cả"],
                ...[
                  "LIVE",
                  "STALE",
                  "HISTORICAL",
                  "OUT_OF_ORDER",
                  "FUTURE_SKEW",
                ].map((value) => [value, value]),
              ]}
            />
            <SelectFilter
              label="Trạng thái rủi ro"
              value={draft.risk_status}
              onChange={update("risk_status")}
              options={[
                ["", "Tất cả"],
                ["OK", "Tính điểm thành công"],
                ["ERROR", "ERROR"],
              ]}
            />
            <Filter label="Điểm rủi ro tối thiểu">
              <input
                type="number"
                min="0"
                max="100"
                value={draft.risk_min || ""}
                onChange={(event) => update("risk_min")(event.target.value)}
              />
            </Filter>
            <Filter label="Điểm rủi ro tối đa">
              <input
                type="number"
                min="0"
                max="100"
                value={draft.risk_max || ""}
                onChange={(event) => update("risk_max")(event.target.value)}
              />
            </Filter>
            <Filter label="Tài khoản cơ sở dữ liệu">
              <input
                maxLength={128}
                value={draft.db_user || ""}
                onChange={(event) => update("db_user")(event.target.value)}
                placeholder="Theo quyền xem dữ liệu"
              />
            </Filter>
          </div>
        </details>
        <button className="button primary">
          <Search size={14} />
          Áp dụng
        </button>
        <a
          className="text-button"
          href={
            params.source === "canonical"
              ? "#/events?source=canonical"
              : "#/events"
          }
        >
          Đặt lại
        </a>
        {error && (
          <p role="alert" className="v4-form-error">
            {error}
          </p>
        )}
      </form>
      <details className="n91-secondary-comparison">
        <summary>So sánh APP / Clone theo kiểm toán chuẩn IDs</summary>
        <EventComparePicker />
      </details>
      <Panel
        title="Sự kiện bảo mật"
        subtitle="Một dòng cho mỗi sự kiện · nguồn và phạm vi hiển thị bên dưới"
        resource={resource}
      >
        {resource.data &&
          (resource.data.length ? (
            <EventTable events={resource.data} />
          ) : (
            <Empty title="Không có sự kiện trong phạm vi lọc" />
          ))}
        <CursorPager resource={resource} {...pager} />
      </Panel>
    </>
  );
}

export function EventDetail({ id, params }) {
  if (params.source === "canonical" && params.stream_id) {
    return (
      <>
        <a href="#/events?source=canonical" className="incident-back">
          <ArrowLeft size={15} />
          Sự kiện bảo mật
        </a>
        <PageHeading
          eyebrow="CHI TIẾT SỰ KIỆN"
          title="Chi tiết sự kiện"
          description={id}
        />
        <EventInvestigation eventId={id} streamId={params.stream_id} />
      </>
    );
  }
  return <LegacyEventDetail id={id} params={params} />;
}

function LegacyEventDetail({ id, params }) {
  const { compact } = useDetailView();
  const time = useTime();
  const resource = useV4Resource(`/events/${encodeURIComponent(id)}`, {
    params: { stream_id: params.stream_id, source: params.source },
    interval: 0,
    transform: mapEvent,
  });
  const event = resource.data;
  return (
    <>
      <a
        href={
          params.source === "canonical"
            ? "#/events?source=canonical"
            : "#/events"
        }
        className="incident-back"
      >
        <ArrowLeft size={15} />
        Sự kiện bảo mật
      </a>
      <PageHeading
        eyebrow="CHI TIẾT SỰ KIỆN"
        title="Chi tiết sự kiện"
        description={id}
        resource={resource}
      >
        <CopyId value={id} />
      </PageHeading>
      <SourceStatus
        resource={resource}
        label={
          event?.view_kind === "P17_EVENT_PROJECTION"
            ? "Bản ghi sự kiện"
            : "Sự kiện nguồn"
        }
      />
      <ResourceNotice resource={resource} noun="event" />
      {event && (
        <>
          {["TEST", "EVALUATION"].includes(event.source_provenance.context) && (
            <p className="v4-inline-warning" role="status">
              Dữ liệu {uiLabel(event.source_provenance.context).toLowerCase()} ·
              bản chụp ngoại tuyến
            </p>
          )}
          <div className="v4-detail-statuses">
            <div>
              <span>QUYẾT ĐỊNH</span>
              <Badge value={event.decision} />
            </div>
            <div>
              <span>ĐIỂM RỦI RO</span>
              <strong>
                {event.risk.score ?? "N/A"}
                <small> / 100</small>
              </strong>
            </div>
            <div>
              <span>TRẠNG THÁI TÍNH ĐIỂM</span>
              <Badge value={event.risk.status}>
                {riskStatusLabel(event.risk.status)}
              </Badge>
            </div>
            {!compact && (
              <div>
                <span>LOẠI SỰ KIỆN</span>
                <Badge value={event.p17_event_class} />
              </div>
            )}
          </div>
          {event.view_kind === "P17_EVENT_PROJECTION" && (
            <EventAuditComparison event={event} />
          )}
          <div className="v4-detail-grid">
            <div className="v4-stack">
              <Panel
                title={
                  event.view_kind === "P17_EVENT_PROJECTION"
                    ? "Dữ liệu từ thành phần phát hiện"
                    : "Truy vấn và chính sách"
                }
                subtitle={
                  event.view_kind === "P17_EVENT_PROJECTION"
                    ? "Các trường do nguồn phát hiện trực tiếp cung cấp"
                    : "Thông tin thực thi lấy từ nhật ký kiểm toán chuẩn"
                }
              >
                {event.view_kind === "P17_EVENT_PROJECTION" ? (
                  <p className="v4-panel-note">
                    Nguồn phát hiện không lưu nội dung truy vấn SQL. Thông tin
                    kiểm toán có thể đối chiếu tại khung phía trên.
                  </p>
                ) : event.masked_query ? (
                  <pre className="v4-code">{event.masked_query}</pre>
                ) : !compact ? (
                  <div className="v4-privacy">
                    <ShieldPrivacy />
                    <strong>
                      {event.view_kind === "P17_EVENT_PROJECTION"
                        ? "Nguồn không lưu SQL"
                        : "SQL không khả dụng do chính sách riêng tư"}
                    </strong>
                    <p>
                      Dùng sự kiện ID, quy tắc và thông tin nguồn để truy vết.
                      Các trường kiểm toán chuẩn chưa cung cấp được giữ trống.
                    </p>
                  </div>
                ) : null}
                <FieldGrid
                  rows={
                    event.view_kind === "P17_EVENT_PROJECTION"
                      ? [
                          [
                            "Căn cứ quyết định",
                            "Cờ blocked của nguồn phát hiện",
                          ],
                          [
                            "Quy tắc khớp",
                            event.matched_rules.join(" · ") || "Không có",
                          ],
                          ["Phân loại sự kiện", display(event.p17_event_class)],
                        ]
                      : [
                          ["Căn cứ quyết định", display(event.decision_basis)],
                          [
                            "Hành động áp dụng",
                            uiLabel(event.effective_action),
                          ],
                          ["Kết quả xử lý", uiLabel(event.action_result)],
                          ["Chế độ vận hành", uiLabel(event.runtime_mode)],
                          ["Mã chính sách", display(event.policy_id)],
                          [
                            "Phiên bản chính sách",
                            display(event.policy_version),
                          ],
                          ["Lệnh MySQL", display(event.mysql_command)],
                          [
                            "Quy tắc khớp",
                            event.matched_rules.join(" · ") || "Không có",
                          ],
                          [
                            "Quy tắc chặn",
                            event.blocking_rules.join(" · ") ||
                              (event.canonical_complete
                                ? "Không có"
                                : "Chưa cung cấp"),
                          ],
                          [
                            "Quy tắc giám sát",
                            event.monitor_rules.join(" · ") ||
                              (event.canonical_complete
                                ? "Không có"
                                : "Chưa cung cấp"),
                          ],
                        ]
                  }
                />
                {event.view_kind === "P17_EVENT_PROJECTION" ? (
                  <p className="v4-panel-note">
                    Quyết định ALLOW/BLOCK ở đây được suy ra từ cờ blocked trong
                    bản ghi phát hiện. Kết quả thực thi và phiên bản chính sách
                    chỉ có thể xác nhận bằng nguồn kiểm toán tương ứng.
                  </p>
                ) : (
                  <>
                    <h3 className="v4-subheading">Lý do từ chính sách</h3>
                    {event.reasons.length ? (
                      <ul className="v4-reasons">
                        {event.reasons.map((reason, index) => (
                          <li key={index}>{reason}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="v4-panel-note">
                        Nguồn chưa cung cấp lý do chi tiết.
                      </p>
                    )}
                    <p className="v4-panel-note">
                      {event.view_kind === "P17_EVENT_PROJECTION"
                        ? "Quyết định được suy ra từ trạng thái chặn của bộ phát hiện. Chưa có quyết định trong nhật ký kiểm toán chuẩn hóa."
                        : "Hành động áp dụng và hành động result phản ánh thực thi. Monitor match không tự chứng minh đã chặn."}{" "}
                      Trạng thái cách ly VM cần bằng chứng hành động và quan sát
                      Neutron riêng.
                    </p>
                  </>
                )}
              </Panel>
              {(!compact || event.score_breakdown?.length > 0) && (
                <Panel title="Giải thích điểm">
                  <FieldGrid
                    rows={
                      event.view_kind === "P17_EVENT_PROJECTION"
                        ? [
                            [
                              "Điểm rủi ro",
                              event.risk.score ?? "Không khả dụng",
                            ],
                            [
                              "Trạng thái phép tính",
                              riskStatusLabel(event.risk.status),
                            ],
                          ]
                        : [
                            ["Điểm gốc", display(event.raw_score)],
                            ["Điểm sau giới hạn", event.risk.score ?? "N/A"],
                            [
                              "Trạng thái rủi ro",
                              riskStatusLabel(event.risk.status),
                            ],
                          ]
                    }
                  />
                  {event.score_breakdown?.length ? (
                    <div className="table-scroll">
                      <table className="v4-table v4-breakdown-table">
                        <thead>
                          <tr>
                            <th>NGUỒN / RULE</th>
                            <th>NHÓM</th>
                            <th>ĐIỂM</th>
                            <th>LÝ DO</th>
                          </tr>
                        </thead>
                        <tbody>
                          {event.score_breakdown.map((component, index) => (
                            <tr key={index}>
                              <td>
                                <strong>
                                  {component.rule_id ||
                                    "Component không gắn quy tắc"}
                                </strong>
                                <small>{display(component.source)}</small>
                              </td>
                              <td>{display(component.category)}</td>
                              <td>{display(component.score)}</td>
                              <td className="v4-text-cell">
                                {display(component.reason)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : event.view_kind === "P17_EVENT_PROJECTION" ? null : (
                    <p className="v4-panel-note">
                      Nguồn kiểm toán không cung cấp chi tiết thành phần điểm.
                    </p>
                  )}
                </Panel>
              )}
              {(!compact || event.incident_refs.length > 0) && (
                <Panel
                  title="Sự cố liên quan"
                  subtitle="Liên kết bằng chứng theo nguồn "
                >
                  {event.incident_refs.length ? (
                    <div className="v4-link-list">
                      {event.incident_refs.map((ref) => (
                        <a key={ref} href={incidentHref(ref, event.stream_id)}>
                          {ref}
                          <ArrowUpRight size={15} />
                        </a>
                      ))}
                    </div>
                  ) : (
                    <p className="v4-panel-note">
                      Chưa có liên kết sự cố được nguồn cung cấp.
                    </p>
                  )}
                </Panel>
              )}
            </div>
            <Panel title="Nguồn và định danh">
              <FieldGrid
                rows={
                  event.view_kind === "P17_EVENT_PROJECTION"
                    ? [
                        [
                          "Mã sự kiện",
                          <span className="v4-copy-row">
                            {event.event_id}
                            <CopyId value={event.event_id} />
                          </span>,
                        ],
                        ["Mã yêu cầu", display(event.request_id)],
                        ["Mã luồng", display(event.stream_id)],
                        ["Thứ tự", display(event.stream_sequence)],
                        ["Phát sinh lúc", time(event.occurred_at)],
                        ["Ghi nhận lúc", time(event.ingested_at)],
                        ["Nguồn IP", display(event.source_ip)],
                        ["Tài khoản cơ sở dữ liệu", display(event.db_user)],
                        [
                          "Nguồn dữ liệu",
                          uiLabel(event.source_provenance.source_system),
                        ],
                        [
                          "Tham chiếu nguồn",
                          display(event.source_provenance.source_ref),
                        ],
                        [
                          "SHA-256 do nguồn cung cấp",
                          display(event.source_provenance.payload_sha256),
                        ],
                      ]
                    : [
                        [
                          "Mã sự kiện",
                          <span className="v4-copy-row">
                            {event.event_id}
                            <CopyId value={event.event_id} />
                          </span>,
                        ],
                        ["Mã yêu cầu", display(event.request_id)],
                        ["Mã luồng", display(event.stream_id)],
                        ["Thứ tự", display(event.stream_sequence)],
                        ["Phát sinh lúc", time(event.occurred_at)],
                        ["received_utc / ingested_at", time(event.ingested_at)],
                        [
                          "Yêu cầu received · nguồn",
                          time(event.request_received_at),
                        ],
                        [
                          "Storage recorded · nguồn",
                          time(event.storage_recorded_at),
                        ],
                        [
                          "Portal imported · PORTAL_CLOCK",
                          time(event.imported_at),
                        ],
                        [
                          "Yêu cầu căn cứ thời gian",
                          display(event.time_basis.request_received_at),
                        ],
                        ["Identity status", display(event.identity_status)],
                        ["Thiếu trường", display(event.missing_fields_reason)],
                        ["Nguồn IP", display(event.source_ip)],
                        [
                          "Tài khoản cơ sở dữ liệu",
                          event.db_user || "Withheld / chưa cung cấp",
                        ],
                        ["Cơ sở dữ liệu", display(event.database_name)],
                        [
                          "Nguồn dữ liệu",
                          uiLabel(event.source_provenance.source_system),
                        ],
                        [
                          "Tham chiếu nguồn",
                          display(event.source_provenance.source_ref),
                        ],
                        [
                          "SHA-256 nội dung tại nguồn gốc",
                          display(event.source_provenance.payload_sha256),
                        ],
                        [
                          "Căn cứ tính mã băm",
                          display(event.source_provenance.payload_hash_basis),
                        ],
                        [
                          "Verification",
                          uiLabel(event.source_provenance.verification),
                        ],
                        [
                          "Phạm vi dữ liệu",
                          uiLabel(event.source_provenance.context),
                        ],
                        [
                          "Coverage",
                          display(event.source_provenance.coverage_kind),
                        ],
                        [
                          "Human rà soát",
                          display(event.source_provenance.human_review),
                        ],
                      ]
                }
              />
              {!compact && (
                <details className="v4-json">
                  <summary>Xem JSON đã giới hạn trường</summary>
                  <pre className="v4-code">
                    {JSON.stringify(event, null, 2)}
                  </pre>
                </details>
              )}
            </Panel>
          </div>
        </>
      )}
    </>
  );
}

function ShieldPrivacy() {
  return (
    <span className="v4-privacy-symbol" aria-hidden="true">
      SQL
    </span>
  );
}
