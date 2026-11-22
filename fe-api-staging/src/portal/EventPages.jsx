import ReportEventEvidence from "./ReportEventEvidence";
import { signalName, uiLabel, uiRoleList } from "../services/uiLanguage.js";
import { useState } from "react";
import {
  EventComparePicker,
  EventInvestigation,
} from "../features/n91-investigation/Investigation";
import { auditEventQuery } from "../services/dashboardAudit";
import { ArrowLeft, ArrowUpRight, Search } from "lucide-react";
import { mapEvent, mapIncident, readCollection } from "../services/portalApi";
import { analysisCaseHref, analysisEventHref, incidentEventsHref, incidentHref, incidentSectionHref } from "../services/incidentLinks";
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
          <details className="portal-provenance">
            <summary>Kết quả thực thi từ nhật ký</summary>
          <FieldGrid
            showAll
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
          </details>
          {riskDisagrees && (
            <p className="v4-inline-warning" role="status">
              Điểm rủi ro khác nhau giữa nguồn kiểm toán và nguồn phát hiện. Cần
              kiểm tra thời điểm và chính sách xử lý, không tự hợp nhất.
            </p>
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

function EventIncidentLinks({ event }) {
  const related = event.recorded_incidents ?? event.incident_refs.map((incident_id) => ({ incident_id }));
  if (related.length === 0) {
    return event.recorded_incidents
      ? <small>Chưa có liên kết</small>
      : <span title="Chưa đối chiếu được với hồ sơ phát hiện" aria-label="Chưa đối chiếu được với hồ sơ phát hiện">—</span>;
  }
  const verified = Boolean(event.recorded_incidents) || event.incident_membership === "DIRECT_PERSISTED";
  return (
    <ul className="v4-event-incident-links">
      {related.map(({ incident_id, signal_rule }) => {
        const href = incidentEventsHref(incident_id, event.stream_id)
          || incidentHref(incident_id, event.stream_id);
        const title = signalName(signal_rule);
        const label = `${verified ? "Nhóm" : "Dựng lại"} ${incident_id.slice(-8)}`;
        const tone = Array.from(incident_id).reduce((hash, char) => (hash * 31 + char.charCodeAt(0)) % 5, 0);
        return (
          <li key={incident_id}>
            {href ? (
              <a
                href={href}
                title={title ? `${title} · ${incident_id}` : incident_id}
                aria-label={title ? `${label} · ${title}` : label}
                data-tone={verified ? tone : "reconstructed"}
              >
                {label}
              </a>
            ) : label}
          </li>
        );
      })}
    </ul>
  );
}

export function EventTable({ events, compact = false }) {
  const time = useTime();
  return (
    <div className="table-scroll">
      <table className="v4-table v4-events-list-table">
        <thead>
          <tr>
            <th>Mã sự kiện / thời gian</th>
            <th>Nguồn</th>
            <th>Quyết định</th>
            <th>Điểm rủi ro</th>
            <th>Quy tắc áp dụng</th>
            {!compact && <th>Nhóm sự cố</th>}
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
                {event.db_user && <small>{event.db_user}</small>}
              </td>
              <td>
                <Badge value={event.decision} />
              </td>
              <td>
                <strong>{event.risk.score ?? "—"}</strong>
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
              {!compact && <td><EventIncidentLinks event={event} /></td>}
              <td>
                <a
                  className="row-detail"
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                  aria-label={`Mở sự kiện ${event.event_id}`}
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

const groupedEventsUrl = "#/events?view=incidents";
const timelineUrl = "#/events?view=timeline&source=canonical";
const groupSignalOptions = [
  ["", "Tất cả loại sự cố"],
  ...["CORR-001", "CORR-002", "CORR-003", "CORR-004", "CORR-005"]
    .map((code) => [code, signalName(code)]),
];

function EventViewNavigation({ grouped }) {
  return (
    <nav className="v4-system-tabs" aria-label="Chế độ xem sự kiện">
      <a href={groupedEventsUrl} className={grouped ? "active" : undefined} aria-current={grouped ? "page" : undefined}>
        Theo sự cố
      </a>
      <a href={timelineUrl} className={grouped ? undefined : "active"} aria-current={grouped ? undefined : "page"}>
        Theo thời gian
      </a>
    </nav>
  );
}

const incidentTitle = (incident) => signalName(incident.signal_rule) || incident.signal_rule || "Sự cố";

function IncidentEventMembers({ incident }) {
  const time = useTime();
  const pager = useCursor();
  const membership = incident.evidence_membership;
  const canReadMembers = Boolean(incidentEventsHref(incident.incident_id, incident.stream_id))
    && membership !== "UNAVAILABLE";
  const resource = useV4Resource("/events", {
    enabled: canReadMembers,
    params: { source: "p17", incident_ref: incident.incident_id, stream_id: incident.stream_id,
      limit: 25, cursor: pager.cursor },
    transform: (data) => readCollection(data, "events").map(mapEvent),
  });
  const detailsUrl = incidentSectionHref(incident.incident_id, incident.stream_id, "detection");
  const members = resource.data;
  const validMembers = members?.every((event) =>
    event.stream_id === incident.stream_id && event.incident_refs.includes(incident.incident_id));
  const total = validMembers ? resource.meta?.total_count ?? members.length : null;

  return (
    <section className="panel v4-panel event-group-members" aria-labelledby="event-group-heading">
      <header className="event-group-heading">
        <div>
          <h2 id="event-group-heading">{incidentTitle(incident)}</h2>
          <p>
            <code>{incident.incident_id}</code>
            {incident.source_ip && <span>IP nguồn <strong>{incident.source_ip}</strong></span>}
          </p>
        </div>
        {detailsUrl && <a className="button secondary" href={detailsUrl}>Mở hồ sơ sự cố <ArrowUpRight size={15} /></a>}
      </header>
      {canReadMembers ? (
        <>
          <ResourceNotice resource={resource} noun="sự kiện của hồ sơ" />
          {members && (validMembers ? (
            <>
              <div className="event-group-members-caption">
                <strong>{total} sự kiện</strong>
                <span>{membership === "DIRECT_PERSISTED"
                  ? "Bằng chứng do bộ phát hiện lưu"
                  : membership === "RECONSTRUCTED_WINDOW"
                    ? "Đối chiếu theo mốc thời gian"
                    : "Nguồn chưa xác nhận cách liên kết"}</span>
              </div>
              {members.length ? <EventTable events={members} compact />
                : <Empty title="Hồ sơ chưa có sự kiện để hiển thị" />}
              {(pager.history.length > 0 || resource.meta?.has_more) && <CursorPager resource={resource} {...pager} />}
            </>
          ) : <p role="alert">Chưa xác minh được sự kiện thuộc đúng hồ sơ này.</p>)}
        </>
      ) : <Empty title="Nguồn chưa cung cấp danh sách sự kiện của hồ sơ này" />}
    </section>
  );
}

function GroupedEvents({ incidentRef, streamId, signalRule }) {
  const time = useTime();
  const pager = useCursor();
  const [refreshCount, setRefreshCount] = useState(0);
  const resource = useV4Resource("/incidents", {
    params: { limit: 8, cursor: pager.cursor, signal_rule: signalRule || undefined },
    transform: (data) => readCollection(data, "incidents").map(mapIncident),
  });
  const incidents = resource.data ?? [];
  const showAnalysis = Boolean(signalRule && resource.data?.length === 0 && !resource.error);
  const analysis = useV4Resource("/p17-vnext/cases", {
    enabled: showAnalysis,
    params: { detector: signalRule, limit: 50 },
    transform: (data) => readCollection(data, "cases"),
  });
  const analysisLinks = showAnalysis && !analysis.error
    ? (analysis.data ?? [])
        .filter((item) => Array.isArray(item.signals) && item.signals.includes(signalRule))
        .map((item) => ({ ...item, href: analysisCaseHref(item.case_id, item.stream_id) }))
        .filter((item) => item.href)
    : [];
  const hasSelection = incidentRef !== undefined || streamId !== undefined;
  const validSelection = incidentEventsHref(incidentRef, streamId);
  const isSelected = (incident) => incident.incident_id === incidentRef && incident.stream_id === streamId;
  const listed = hasSelection ? incidents.find(isSelected) : incidents[0];
  const detail = useV4Resource(validSelection ? `/incidents/${encodeURIComponent(incidentRef)}` : null, {
    enabled: Boolean(validSelection && !listed && (resource.data || resource.error)),
    transform: mapIncident,
  });
  const selected = listed ?? (detail.data && isSelected(detail.data) ? detail.data : null);
  const visibleIncidents = selected && !listed ? [selected, ...incidents] : incidents;
  const refresh = () => {
    resource.refresh();
    detail.refresh();
    analysis.refresh();
    setRefreshCount((count) => count + 1);
  };

  return (
    <>
      <PageHeading title="Sự kiện bảo mật" resource={{ ...resource, refresh }} />
      <EventViewNavigation grouped />
      <div className="event-group-layout">
        <section className="panel v4-panel event-group-picker" aria-labelledby="event-group-list-heading">
          <h2 id="event-group-list-heading">Nhóm sự cố</h2>
          <SelectFilter
            label="Loại sự cố"
            value={signalRule}
            options={groupSignalOptions}
            onChange={(value) => {
              window.location.hash = value
                ? `${groupedEventsUrl}&signal_rule=${encodeURIComponent(value)}`
                : groupedEventsUrl;
            }}
          />
          <ResourceNotice resource={resource} noun="danh sách sự cố" />
          {resource.data && (visibleIncidents.length ? (
            <ul className="event-group-list">
              {visibleIncidents.map((incident) => {
                const key = `${incident.stream_id}:${incident.incident_id}`;
                const url = incidentEventsHref(incident.incident_id, incident.stream_id);
                const href = url && signalRule ? `${url}&signal_rule=${encodeURIComponent(signalRule)}` : url;
                const label = (
                  <>
                    <strong>{incidentTitle(incident)}</strong>
                    {incident.last_seen && <time dateTime={incident.last_seen}>{time(incident.last_seen)}</time>}
                    <span>
                      <code>{incident.incident_id}</code>
                      {incident.evidence_count !== null && <span>{incident.evidence_count} sự kiện</span>}
                    </span>
                  </>
                );
                return <li key={key}>{href
                  ? <a href={href} aria-current={incident === selected ? "true" : undefined}>{label}</a>
                  : <div className="event-group-list-item">{label}</div>}</li>;
              })}
            </ul>
          ) : <Empty title={signalRule ? "Chưa có hồ sơ sự cố loại này" : "Chưa có sự cố"}
            text={analysisLinks.length ? "Đã ghi nhận tín hiệu trong Phân tích hành vi." : ""}>
              {analysisLinks.length > 0 && (
                <ul className="event-group-analysis-links">
                  {analysisLinks.map((item) => (
                    <li key={item.href}>
                      <a className="v4-text-link" href={item.href}>
                        Mở phân tích{item.source_ip ? ` · ${item.source_ip}` : ""}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </Empty>)}
          {(pager.history.length > 0 || resource.meta?.has_more) && <CursorPager resource={resource} {...pager} />}
        </section>
        {selected ? (
          <IncidentEventMembers key={`${selected.stream_id}:${selected.incident_id}:${refreshCount}`} incident={selected} />
        ) : hasSelection ? (
          <section className="panel v4-panel">
            <ResourceNotice resource={detail} noun="hồ sơ sự cố" />
            {!resource.loading && !detail.loading && !detail.error && <Empty title="Không tìm thấy sự cố trong luồng dữ liệu này" />}
          </section>
        ) : null}
      </div>
    </>
  );
}

export function EventsPage({ params }) {
  const { view, ...query } = params;
  if (view === "incidents" || (!view && !Object.keys(query).length)) {
    const signalRule = groupSignalOptions.find(([code]) => code === query.signal_rule)?.[0];
    return <GroupedEvents incidentRef={query.incident_ref} streamId={query.stream_id} signalRule={signalRule} />;
  }
  return <ChronologicalEvents params={{ source: "canonical", ...query }} />;
}

function ChronologicalEvents({ params }) {
  const { timezone } = usePortal();
  const [draft, setDraft] = useState(params);
  const [error, setError] = useState("");
  const pager = useCursor();
  const resource = useV4Resource("/events", {
    params: {
      ...params,
      limit: 25,
      cursor: pager.cursor,
      include_incident_links: params.source === "canonical" ? "true" : undefined,
    },
    interval: 5000,
    transform: (data) => readCollection(data, "events").map(mapEvent),
  });
  const update = (key) => (value) =>
    setDraft((current) => ({ ...current, [key]: value }));
  return (
    <>
      <PageHeading
        title="Sự kiện bảo mật"
        resource={resource}
      />
      <EventViewNavigation />
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
              : `#/events?view=timeline&source=${encodeURIComponent(params.source)}`
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
        <summary>So sánh truy vấn của máy ứng dụng và máy thử nghiệm</summary>
        <EventComparePicker />
      </details>
      <Panel
        title="Nhật ký sự kiện"
        resource={resource}
      >
        {resource.meta?.incident_link_error && (
          <p className="v4-panel-note">Tạm thời chưa đọc được nguồn liên kết sự cố.</p>
        )}
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
  const analysisUrl = analysisEventHref(event);
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
      <ResourceNotice resource={resource} noun="sự kiện" />
      {analysisUrl && (
        <section className="investigation-related" aria-label="Liên kết điều tra sự kiện">
          <a href={analysisUrl}>Xem phân tích hành vi của truy vấn này</a>
        </section>
      )}
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
                          <li key={index}>{uiLabel(reason)}</li>
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
                            <th>Nguồn / quy tắc</th>
                            <th>Nhóm</th>
                            <th>Điểm</th>
                            <th>Lý do</th>
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
