import { DetailToggle, useDetailView } from "../../portal/DetailView";
import { signalName, uiLabel } from "../../services/uiLanguage.js";
import { useId, useRef } from "react";
import { ArrowLeft, ChevronDown, RefreshCw } from "lucide-react";
import { usePortal } from "../../portal/PortalContext";
import { EvidenceExports } from "../../portal/ReviewEvidence";
import {
  Badge,
  CopyId,
  FieldGrid,
  PageHeading,
  Panel,
  display,
  useTime,
} from "../../portal/PortalUI";
import { IncidentBusinessPanel } from "../n91-business";
import { analysisEventHref, incidentHref } from "../../services/incidentLinks.js";
import {
  WORKBENCH_TABS,
  canReadWorkbench,
  eventHref,
  workbenchTab,
} from "./workbenchModel.js";
import { useWorkbench } from "./useWorkbench.js";
import { ResponseHistoryView } from "./ResponseHistory.jsx";
import AutomaticResponsePanel from "../../portal/AutomaticResponsePanel";
import "./workbench.css";

const labels = {
  overview: "Tổng quan",
  timeline: "Dòng thời gian",
  detection: "Bằng chứng",
  response: "Ứng phó",
  notes: "Ghi chú xử lý",
};
function Reasons({ values }) {
  return values.length ? (
    <ul className="n91-wb-reasons">
      {values.map((v) => (
        <li key={v}>
          <code>{uiLabel(v)}</code>
        </li>
      ))}
    </ul>
  ) : null;
}
function Unavailable({ title, section }) {
  if (section.availability === "AVAILABLE")
    return (
      <section>
        <h3>{title}</h3>
        <dl className="v4-fields">
          <div>
            <dt>Phiên bản bộ phát hiện</dt>
            <dd>{uiLabel(section.detector_version)}</dd>
          </div>
          <div>
            <dt>SHA-256 mã nguồn bộ phát hiện</dt>
            <dd>{section.detector_sha256}</dd>
          </div>
          <div>
            <dt>Mã bản chụp bằng chứng</dt>
            <dd>{section.snapshot_id}</dd>
          </div>
          <div>
            <dt>Bộ phát hiện ghi nhận lúc</dt>
            <dd>{section.recorded_at}</dd>
          </div>
        </dl>
      </section>
    );
  return (
    <section className="n91-wb-unavailable">
      <h3>{title}</h3>
      <Badge value="UNAVAILABLE" />
      <p>Chưa có dữ liệu nguồn đủ ngữ nghĩa để kết luận.</p>
      <Reasons values={section.reason_codes} />
    </section>
  );
}
function ProcessingHistory({ section }) {
  if (section.schema_version === "portal-response-history-1")
    return <ResponseHistoryView history={section} />;
  return (
    <>
      <Unavailable title="Lịch sử xử lý" section={section} />
      <a href="#/incidents?response_history=1">
        Mở lịch sử xử lý từ bộ điều khiển
      </a>
    </>
  );
}

export function WorkbenchGate({ id, message }) {
  return (
    <div className="n91-workbench">
      <a href="#/incidents">← Sự cố</a>
      <PageHeading title="Điều tra sự cố" description={id} />
      <div className="n91-wb-notice" role="status">
        {message}
        <p>Bạn có thể mở trang sự cố cơ bản.</p>
        <a href={incidentHref(id)}>Xem thông tin sự cố cơ bản</a>
      </div>
    </div>
  );
}
function Sources({ meta }) {
  const time = useTime();
  return (
    <details className="panel portal-provenance">
      <summary>Nguồn và phạm vi của hồ sơ</summary>
      <FieldGrid showAll rows={[
        ["Phạm vi", uiLabel(meta.source_context)],
        ["Đọc lúc", time(meta.read_at)],
        ["Bộ phát hiện ghi nhận đến", time(meta.data_as_of)],
      ]} />
      <div className="n91-wb-sources">
        {meta.sources.map((s) => (
          <details key={s.source_system}>
            <summary>
              {uiLabel(s.source_system)} <Badge value={s.availability} />{" "}
              <Badge value={s.freshness_state} />
            </summary>
            <FieldGrid
              showAll
              rows={[
                ["Đọc lúc", time(s.read_at)],
                ["Nguồn quan sát lúc", time(s.observed_at)],
                ["Chụp lúc", time(s.captured_at)],
                ["Dữ liệu đến", time(s.data_as_of)],
                ["Phạm vi dữ liệu", uiLabel(s.context)],
                ["Cấu trúc dữ liệu", uiLabel(s.source_schema)],
                ["Tham chiếu nguồn", uiLabel(s.source_ref)],
                ["Phiên bản dữ liệu", display(s.generation)],
                ["Lỗi nguồn", display(s.error_code)],
              ]}
            />
            <Reasons values={s.reason_codes} />
          </details>
        ))}
      </div>
      <details>
        <summary>Giới hạn từng nguồn và trường thiếu</summary>
        <Reasons values={meta.missing_fields} />
        <ul>
          {meta.limitations.map((s) => (
            <li key={s}>{uiLabel(s)}</li>
          ))}
        </ul>
      </details>
    </details>
  );
}
function Counts({ data }) {
  const { compact } = useDetailView();
  const m = data.event_members;
  return (
    <div className="n91-wb-counts">
      <div>
        <span>Số bằng chứng bộ phát hiện ghi nhận</span>
        <strong>{m.authoritative_count}</strong>
      </div>
      {!compact && (
        <div>
          <span>Ứng viên tái dựng</span>
          <strong>{display(m.total_candidates)}</strong>
        </div>
      )}
      <div>
        <span>Liên kết trực tiếp</span>
        <strong>
          {display(
            m.direct_membership_supported ? m.verified_linked_count : null,
          )}
        </strong>
      </div>
      {!compact && (
        <div>
          <span>Khớp số lượng ghi nhận</span>
          <strong>{display(m.matches_recorded_count)}</strong>
        </div>
      )}
    </div>
  );
}
function EventCard({ member: e }) {
  const { compact } = useDetailView();
  const time = useTime(),
    p = e.projection,
    c = e.canonical;
  const analysisUrl = analysisEventHref(e.event_ref);
  return (
    <details className="n91-wb-event">
      <summary>
        <span>
          <strong>{Number.isInteger(p.stream_sequence) ? `Truy vấn ${p.stream_sequence}` : e.event_ref.event_id}</strong>
          <time dateTime={p.occurred_at}>{time(p.occurred_at)}</time>
        </span>
        <span className="n91-wb-event-state">
          <Badge value={p.blocked ? "BLOCK" : "ALLOW"} />
          <ChevronDown size={15} aria-hidden="true" />
        </span>
      </summary>
      <dl className="n91-wb-event-essential">
        <div>
          <dt>Điểm rủi ro</dt>
          <dd>{Number.isFinite(p.risk.score) ? `${p.risk.score}/100` : "Chưa có điểm"}</dd>
        </div>
        <div>
          <dt>Quy tắc khớp</dt>
          <dd>
            {p.matched_rules.length ? (
              <ul className="n91-wb-rule-list">
                {p.matched_rules.map((rule) => <li key={rule}><code>{rule}</code></li>)}
              </ul>
            ) : "Nguồn chưa ghi quy tắc"}
          </dd>
        </div>
      </dl>
      <div className="n91-wb-links">
        {e.canonical_availability === "AVAILABLE" && c && (
          <a href={eventHref(e.event_ref, "canonical")}>Mở nhật ký kiểm toán</a>
        )}
        {analysisUrl && <a href={analysisUrl}>Phân tích truy vấn</a>}
      </div>
      {!compact && (
        <>
          <details>
            <summary>Bản ghi phát hiện</summary>
            <FieldGrid showAll rows={[
              ["Mã sự kiện", e.event_ref.event_id],
              ["Mã yêu cầu", e.event_ref.request_id],
              ["Trạng thái bản ghi kiểm toán", uiLabel(e.canonical_availability)],
              ["Cách liên kết", uiLabel(e.join_state)],
              ["Tiếp nhận lúc", time(p.ingested_at)],
              ["Trạng thái tính điểm", p.risk.status === "OK" ? "Đã tính điểm" : uiLabel(p.risk.status)],
              ["Loại sự kiện", uiLabel(p.event_class)],
              ["Được nguồn phân loại để xử lý trực tiếp", display(p.live_eligible)],
            ]} />
            <a href={eventHref(e.event_ref, "p17")}>Mở bản ghi phát hiện</a>
          </details>
      {c && (
        <details>
          <summary>Bản ghi kiểm toán</summary>
          <FieldGrid
            showAll
            rows={[
              ["Yêu cầu kiểm toán chuẩn", display(c.request_id)],
              ["Phát sinh kiểm toán chuẩn", time(c.occurred_at)],
              ["Quyết định xử lý", uiLabel(c.decision)],
              ["Hành động áp dụng", uiLabel(c.effective_action)],
              ["Kết quả xử lý", uiLabel(c.action_result)],
              ["Chính sách", `${c.policy_id} · ${c.policy_version}`],
              ["Chế độ vận hành", uiLabel(c.runtime_mode)],
              [
                "Trạng thái / điểm rủi ro",
                `${uiLabel(c.risk.status)} / ${display(c.risk.score)}`,
              ],
              ["Quy tắc khớp", c.matched_rules.join(", ") || "—"],
              ["Quy tắc chặn", c.blocking_rules.join(", ") || "—"],
              ["Quy tắc giám sát", c.monitor_rules.join(", ") || "—"],
            ]}
          />
        </details>
      )}
      <details>
        <summary>Liên kết, đối chiếu và mã băm</summary>
        <p>
          {uiLabel(e.candidate_basis)} · Căn cứ đối chiếu mã băm:{" "}
          {uiLabel(e.hash_comparability)}.
          {e.hash_comparability !== "VERIFIED_EQUAL" &&
            " Chưa có bằng chứng mã băm khớp gói bản ghi nguồn."}
        </p>
        <FieldGrid
          showAll
          rows={[
            ["Mã băm ", p.payload_sha256],
            ["Căn cứ tính mã băm ", uiLabel(p.payload_hash_basis)],
            ["Mã băm kiểm toán chuẩn", display(c?.payload_sha256)],
            ["Căn cứ mã băm kiểm toán chuẩn", c?.payload_hash_basis ? uiLabel(c.payload_hash_basis) : "—"],
          ]}
        />
        <Reasons values={e.reason_codes} />
      </details>
        </>
      )}
    </details>
  );
}
function Members({ data, resource }) {
  const m = data.event_members;
  const direct = m.membership === "DIRECT_PERSISTED";
  return (
    <>
      {!direct && m.available && (
        <p className="n91-wb-notice">Các truy vấn dưới đây được đối chiếu theo thời gian trong lịch sử.</p>
      )}
      {!m.available ? (
        <p role="status">Nguồn chưa cung cấp danh sách sự kiện liên kết.</p>
      ) : !m.items.length ? (
        <p role="status">Trang này chưa có truy vấn liên quan.</p>
      ) : (
        m.items.map((e) => (
          <EventCard
            key={`${e.event_ref.stream_id}:${e.event_ref.event_id}`}
            member={e}
          />
        ))
      )}
      {(m.has_more || resource.history.length > 0) && (
        <nav className="n91-wb-pager" aria-label="Phân trang truy vấn">
          <button className="button secondary" disabled={!resource.history.length || resource.loading} onClick={resource.previous}>
            ← Trước
          </button>
          <span>Trang {resource.history.length + 1}</span>
          <button className="button secondary" disabled={!m.has_more || resource.loading || Boolean(resource.error)} onClick={resource.next}>
            Tiếp →
          </button>
        </nav>
      )}
    </>
  );
}
function Alerts({ alerts }) {
  const time = useTime();
  return (
    <section>
      <h3>Cảnh báo liên quan</h3>
      <p>
        Số cảnh báo nguồn ghi nhận {display(alerts.total_count)} · {uiLabel(alerts.availability)}
      </p>
      {!alerts.items.length ? (
        <p>Chưa có cảnh báo để hiển thị.</p>
      ) : (
        <ol className="n91-wb-alerts">
          {alerts.items.map((a) => (
            <li key={a.alert_id}>
              <strong>{a.alert_id}</strong>
              <p>
                <time>{time(a.created_at)}</time> · {a.signal_code} ·{" "}
                <Badge value={a.severity} />
              </p>
              <p>
                Sự kiện kích hoạt{" "}
                <a href={eventHref(a.trigger_event, "p17")}>
                  {a.trigger_event.event_id}
                </a>
              </p>
              <small>{uiLabel(a.link_basis)}</small>
            </li>
          ))}
        </ol>
      )}
      {alerts.has_more && (
        <p>Danh sách cảnh báo bị giới hạn ở nguồn; chưa hiển thị toàn bộ.</p>
      )}
      <Reasons values={alerts.reason_codes} />
    </section>
  );
}
function Timeline({ data, resource }) {
  const time = useTime();
  return (
    <div className="n91-wb-lanes">
      <section className="n91-wb-lane">
        <h2>1 · Phát hiện</h2>
        <p>
          Thời gian phát sinh / tiếp nhận của từng sự kiện nghi vấn ở dưới; các
          nguồn giữ căn cứ thời gian riêng.
        </p>
        <Members data={data} resource={resource} />
        <Alerts alerts={data.alerts} />
      </section>
      <section className="n91-wb-lane">
        <h2>2 · Đánh giá trong hồ sơ phát hiện</h2>
        <p>
          Sự cố được tạo lúc {time(data.incident.created_at)} ·{" "}
          <Badge value={data.incident.status} />
        </p>
        <Unavailable title="Thông tin đánh giá từ nguồn phát hiện" section={data.decision} />
      </section>
      <section className="n91-wb-lane">
        <h2>3 · Xử lý</h2>
        <ProcessingHistory section={data.response} />
      </section>
    </div>
  );
}
function Notes({ data, meta }) {
  const { sessionAuthEnabled } = usePortal();
  const overlay = data.analyst_case.overlay;
  const context = meta.source_context === "TEST" ? "TEST" : "HISTORICAL";
  if (
    sessionAuthEnabled &&
    data.analyst_case.availability === "AVAILABLE" &&
    overlay?.execution_mode === context
  )
    return (
      <IncidentBusinessPanel
        id={data.identity.incident_id}
        streamId={data.identity.stream_id}
      />
    );
  return (
    <Panel title="Ghi chú xử lý">
      <Badge value="UNAVAILABLE" />
      <p>
        {sessionAuthEnabled
          ? "Chưa thể mở hồ sơ xử lý của sự cố này."
          : "Chế độ quan sát chỉ đọc. Hồ sơ xử lý cần phiên Portal."}
      </p>
      <Reasons values={data.analyst_case.reason_codes} />
    </Panel>
  );
}
export function IncidentWorkbench({ id, streamId, params }) {
  const resource = useWorkbench({ incident_id: id, stream_id: streamId });
  return (
    <IncidentWorkbenchView
      id={id}
      streamId={streamId}
      params={params}
      resource={resource}
    />
  );
}
export function IncidentWorkbenchView({ id, streamId, params, resource }) {
  const { compact } = useDetailView();
  const portal = usePortal(),
    baseId = useId(),
    tabs = useRef([]);
  const active = workbenchTab(params.wb_tab),
    payload = resource.payload;
  const incident = payload?.data.incident;
  const time = useTime();
  const visibleTabs = WORKBENCH_TABS.filter(
    (tab) => !compact || !["timeline", "notes"].includes(tab) || active === tab,
  );
  const select = (tab) => {
    const query = new URLSearchParams({ stream_id: streamId, wb_tab: tab });
    window.location.hash = `/incidents/${encodeURIComponent(id)}?${query}`;
  };
  if (!canReadWorkbench(portal.auth, portal.sessionAuthEnabled))
    return (
      <WorkbenchGate
        id={id}
        message={
          portal.auth.status === "checking"
            ? "Đang kiểm tra phiên truy cập."
            : "Cần quyền đọc bằng chứng để mở hồ sơ điều tra."
        }
      />
    );
  const denied = [401, 403].includes(resource.error?.status);
  return (
    <div className="n91-workbench" aria-busy={resource.loading}>
      <header className="n91-incident-masthead">
        <a className="incident-back" href="#/incidents">
          <ArrowLeft size={15} aria-hidden="true" /> Danh sách sự cố
        </a>
        <div className="n91-incident-title-row">
          <div>
            <h1>{signalName(incident?.signal_rule) || "Hồ sơ sự cố"}</h1>
            <div className="n91-incident-context">
              <span className="n91-incident-code"><code>{id}</code><CopyId value={id} /></span>
              {incident?.source_ip && <span>IP nguồn <strong>{incident.source_ip}</strong></span>}
              {incident?.severity && <Badge value={incident.severity} />}
            </div>
          </div>
          <div className="page-actions">
            <DetailToggle />
            <button type="button" className="button secondary" disabled={resource.loading} onClick={resource.refresh}>
              <RefreshCw size={15} className={resource.loading ? "spin" : ""} /> Làm mới
            </button>
          </div>
        </div>
      </header>
      {resource.notice && (
        <div role="status" className="n91-wb-notice">
          {resource.notice}
        </div>
      )}
      {resource.error && (
        <div role="alert" className="n91-wb-notice">
          <strong>{resource.error.code}</strong>
          <p>{resource.error.message}</p>
          {payload && (
            <p>
              <Badge value="STALE" /> Đang giữ bản đọc thành công trước trong
              cùng phạm vi.
            </p>
          )}
          {denied && (
            <p>
              Dữ liệu điều tra đã được ẩn.{" "}
              <a href={incidentHref(id)}>Xem thông tin sự cố cơ bản</a>
            </p>
          )}
          {!payload && !denied && (
            <button className="button secondary" onClick={resource.first}>
              Về trang đầu
            </button>
          )}
        </div>
      )}
      {resource.loading && !payload && (
        <p role="status">Đang tải dữ liệu điều tra sự cố…</p>
      )}
      {payload && (
        <>
          <nav
            className="n91-wb-tabs"
            role="tablist"
            aria-label="Điều tra sự cố"
          >
            {visibleTabs.map((tab, i) => (
              <button
                key={tab}
                ref={(node) => {
                  tabs.current[i] = node;
                }}
                id={`${baseId}-${tab}`}
                role="tab"
                aria-selected={active === tab}
                aria-controls={`${baseId}-panel`}
                tabIndex={active === tab ? 0 : -1}
                onClick={() => select(tab)}
                onKeyDown={(event) => {
                  const next =
                    event.key === "ArrowRight"
                      ? (i + 1) % visibleTabs.length
                      : event.key === "ArrowLeft"
                        ? (i + visibleTabs.length - 1) % visibleTabs.length
                        : event.key === "Home"
                          ? 0
                          : event.key === "End"
                            ? visibleTabs.length - 1
                            : null;
                  if (next !== null) {
                    event.preventDefault();
                    tabs.current[next]?.focus();
                    select(visibleTabs[next]);
                  }
                }}
              >
                {labels[tab]}
              </button>
            ))}
          </nav>
          <div
            role="tabpanel"
            tabIndex={0}
            id={`${baseId}-panel`}
            aria-labelledby={`${baseId}-${active}`}
          >
            {active === "overview" && (
              <>
                <Panel title="Phát hiện ban đầu">
                  <FieldGrid
                    rows={[
                      ["Tín hiệu", incident.signal_rule],
                      ["Độ tin cậy", uiLabel(incident.confidence)],
                      ["Điểm rủi ro cao nhất", display(incident.peak_p15)],
                      ["Lần đầu", time(incident.first_seen)],
                      ["Lần cuối", time(incident.last_seen)],
                      ["Tạo lúc", time(incident.created_at)],
                      ["Cập nhật lúc", time(incident.updated_at)],
                    ]}
                  />
                </Panel>
                <Counts data={payload.data} />
                <AutomaticResponsePanel incidentId={id} streamId={streamId} summaryOnly />
                <EvidenceExports
                  incidentId={payload.data.identity.incident_id}
                  streamId={payload.data.identity.stream_id}
                  sessionEnabled={portal.sessionAuthEnabled}
                  available={
                    !resource.error && payload.meta.freshness_state !== "STALE"
                  }
                />
                <Panel title="Tình trạng dữ liệu xử lý">
                  <Unavailable
                    title="Đánh giá trong hồ sơ phát hiện"
                    section={payload.data.decision}
                  />
                  {payload.data.response.schema_version ? (
                    <p>
                      Bộ điều khiển ·{" "}
                      <Badge value={payload.data.response.availability} />
                    </p>
                  ) : (
                    <Unavailable
                      title="Bộ điều khiển"
                      section={payload.data.response}
                    />
                  )}
                </Panel>
                {payload.data.defense_registry && (
                  <Panel title="Kho bằng chứng">
                    <p>
                      {payload.data.defense_registry.run_id} ·{" "}
                      {uiLabel(payload.data.defense_registry.overall_status)} ·{" "}
                      {payload.data.defense_registry.artifact_count} tài liệu ·{" "}
                      {payload.data.defense_registry.archive_count} tệp lưu trữ.
                    </p>
                    <Reasons
                      values={payload.data.defense_registry.reason_codes}
                    />
                  </Panel>
                )}
              </>
            )}
            {active === "timeline" && (
              <>
                <Counts data={payload.data} />
                <Timeline data={payload.data} resource={resource} />
              </>
            )}
            {active === "detection" && (
              <Panel title="Truy vấn làm bằng chứng">
                <Counts data={payload.data} />
                <Members data={payload.data} resource={resource} />
              </Panel>
            )}
            {active === "response" && (
              <AutomaticResponsePanel incidentId={id} streamId={streamId}>
                <details className="panel portal-provenance auto-response-detail">
                  <summary>Hồ sơ phát hiện và xử lý đã lưu</summary>
                  <Unavailable title="Phiên bản dùng để phát hiện" section={payload.data.detection} />
                  <FieldGrid showAll rows={[
                    ["Xác minh nguồn trong hồ sơ phát hiện", display(incident.source_verified)],
                    ["Cờ cấp phép trong hồ sơ phát hiện", display(incident.isolation_authorized)],
                    ["Trạng thái do bộ phát hiện ghi", uiLabel(incident.status)],
                    ["Cách liên kết bằng chứng", uiLabel(payload.data.event_members.membership)],
                    ["Căn cứ liên kết", uiLabel(payload.data.event_members.candidate_basis)],
                  ]} />
                  <Unavailable
                    title="Đánh giá trong hồ sơ phát hiện"
                    section={payload.data.decision}
                  />
                  <ProcessingHistory section={payload.data.response} />
                </details>
                <Sources meta={payload.meta} />
              </AutomaticResponsePanel>
            )}
            {active === "notes" && (
              <Notes data={payload.data} meta={payload.meta} />
            )}
          </div>
        </>
      )}
    </div>
  );
}
