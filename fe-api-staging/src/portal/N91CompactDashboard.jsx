import {
  Activity,
  Database,
  RefreshCw,
  ShieldAlert,
  ShieldOff,
  ShieldCheck,
} from "lucide-react";
import { useV4Resource } from "./IncidentPages";
import { mapEvent, mapIncident, readCollection } from "../services/portalApi";
import { auditEventQuery } from "../services/dashboardAudit";
import { incidentHref } from "../services/incidentLinks";
import { Badge, useTime } from "./PortalUI";
import { uiLabel, uiErrorMessage } from "../services/uiLanguage";
import {
  dashboardMetrics,
  galeraNodeState,
} from "../services/proxyPresentation";

function Metric({ title, value, href, tone, icon: Icon }) {
  return (
    <a className={`n91-metric n91-metric-${tone}`} href={href}>
      <span className="n91-metric-top">
        <span className="n91-metric-label">{title}</span>
        <span className="n91-metric-icon">
          <Icon size={20} />
        </span>
      </span>
      <strong className="n91-metric-value">
        {value == null ? "—" : value.toLocaleString("vi-VN")}
      </strong>
    </a>
  );
}

function DashboardGalera() {
  const time = useTime();
  const resource = useV4Resource("/system/galera", { interval: 15000 });
  const nodes = resource.error ? [] : resource.data?.nodes || [];
  const current =
    !resource.error &&
    resource.meta?.collection_mode === "PERIODIC" &&
    resource.meta?.freshness_state === "FRESH"
      ? resource.data?.summary?.current_status
      : "UNKNOWN";
  return (
    <section
      className="n91-galera-summary n91-galera-exact"
      aria-label="Trạng thái cụm cơ sở dữ liệu Galera"
    >
      <div className="n91-galera-heading">
        <h2>
          <Database size={20} /> Cụm cơ sở dữ liệu Galera
        </h2>
        <div className="n91-galera-heading-right">
          <Badge value={current}>
            {current === "HEALTHY"
              ? "Đồng bộ"
              : current === "DEGRADED"
                ? "Cần kiểm tra"
                : "Chưa xác minh"}
          </Badge>
          <a href="#/system/galera">Chi tiết</a>
        </div>
      </div>
      <div
        className="n91-galera-table-wrap"
        role="region"
        aria-label="Bảng kiểm tra Galera"
        tabIndex={0}
      >
        <table className="n91-galera-exact-table">
          <thead>
            <tr>
              <th>NÚT CƠ SỞ DỮ LIỆU</th>
              <th>TRẠNG THÁI CỤM</th>
              <th>SỐ NÚT BÁO CÁO</th>
              <th>TRẠNG THÁI NÚT</th>
              <th>SẴN SÀNG / KẾT NỐI CỤM</th>
              <th>QUAN SÁT TRÊN NÚT</th>
              <th>ĐỘ MỚI</th>
            </tr>
          </thead>
          <tbody>
            {["galera-1", "galera-2", "galera-3"].map((name) => {
              const node =
                nodes.find((n) => n.node_id === name || n.name === name) || {};
              const state = galeraNodeState(node);
              return (
                <tr key={name}>
                  <td className="n91-galera-node-cell">
                    <strong>{name}</strong>
                    {!state.valid && (
                      <small>
                        {node.last_error_code || "Chưa có kết quả wsrep hợp lệ"}
                      </small>
                    )}
                  </td>
                  <td>
                    <Badge
                      value={
                        state.fresh &&
                        node.wsrep_cluster_status?.toUpperCase() === "PRIMARY"
                          ? "PRIMARY"
                          : "UNKNOWN"
                      }
                    >
                      {state.valid
                        ? uiLabel(node.wsrep_cluster_status)
                        : "Chưa xác định"}
                    </Badge>
                  </td>
                  <td>
                    {state.valid && Number.isInteger(node.wsrep_cluster_size)
                      ? node.wsrep_cluster_size
                      : "—"}
                  </td>
                  <td>
                    <Badge
                      value={
                        state.fresh &&
                        node.wsrep_local_state_comment?.toUpperCase() ===
                          "SYNCED"
                          ? "SYNCED"
                          : "UNKNOWN"
                      }
                    >
                      {state.valid
                        ? uiLabel(node.wsrep_local_state_comment)
                        : "Chưa xác định"}
                    </Badge>
                  </td>
                  <td>
                    {state.valid
                      ? `${uiLabel(node.wsrep_ready)} / ${uiLabel(node.wsrep_connected)}`
                      : "—"}
                  </td>
                  <td>
                    {state.valid
                      ? time(node.observed_at)
                      : node.attempted_at
                        ? `Lần thử ${time(node.attempted_at)}`
                        : "—"}
                  </td>
                  <td>
                    <Badge
                      value={
                        state.fresh
                          ? "FRESH"
                          : state.valid
                            ? "STALE"
                            : "UNKNOWN"
                      }
                    >
                      {state.fresh
                        ? "Trong thời hạn"
                        : state.valid
                          ? "Đã quá hạn"
                          : node.collection_freshness_state === "FRESH"
                            ? "Lần thử mới"
                            : "Chưa có quan sát"}
                    </Badge>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {resource.error && (
        <p className="n91-clean-notice" role="status">
          Chưa kết nối được API giám sát Galera.
        </p>
      )}
    </section>
  );
}

export default function N91CompactDashboard() {
  const time = useTime();
  const summary = useV4Resource("/dashboard/summary", {
    params: { window: "24h" },
    interval: 10000,
  });
  const canonical = summary.data?.view_kind === "P16H_CANONICAL_AUDIT";
  const events = useV4Resource("/events", {
    params: { limit: 3, source: canonical ? "canonical" : "p17" },
    enabled: Boolean(summary.data),
    interval: 10000,
    transform: (data) => readCollection(data, "events").map(mapEvent),
  });
  const incidents = useV4Resource("/incidents", {
    params: { limit: 3 },
    interval: 10000,
    transform: (data) => readCollection(data, "incidents").map(mapIncident),
  });
  const isolated = useV4Resource("/workloads", {
    params: { network_state: "QUARANTINED", limit: 1 },
    interval: 15000,
  });
  const metrics = dashboardMetrics(summary, isolated);
  const available = !summary.error && Boolean(summary.data);
  const label =
    summary.loading && !summary.data
      ? "Đang đọc nguồn dữ liệu"
      : !available
        ? "Không truy cập được nguồn"
        : summary.meta?.source_mode === "SNAPSHOT"
          ? "Dữ liệu bản chụp"
          : summary.meta?.freshness_state === "FRESH"
            ? "Nguồn dữ liệu bảo mật đã đọc"
            : "Chưa xác minh độ mới";
  return (
    <section
      id="n91-compact-overview"
      className="portal-dashboard"
      aria-label="Tổng quan bảo mật"
    >
      <header className="n91-hero">
        <div className="portal-dashboard-heading">
          <span className="portal-heading-icon">
            <ShieldCheck size={26} strokeWidth={1.7} />
          </span>
          <div className="n91-hero-main">
            <span className="n91-kicker">TRUNG TÂM GIÁM SÁT</span>
            <h1>Tổng quan bảo mật</h1>
            <p>Theo dõi truy vấn cơ sở dữ liệu và các sự cố cần điều tra.</p>
          </div>
        </div>
        <div className="n91-hero-actions">
          <span
            className="n91-data-indicator"
            data-state={
              summary.error
                ? "ERROR"
                : available
                  ? summary.meta?.freshness_state
                  : "UNKNOWN"
            }
          >
            {label}
          </span>
          <button
            id="n91-dash-refresh"
            onClick={() => {
              summary.refresh();
              events.refresh();
              incidents.refresh();
              isolated.refresh();
            }}
          >
            <RefreshCw size={16} />
            Làm mới
          </button>
        </div>
      </header>
      {!available && !summary.loading && (
        <p className="n91-clean-notice" role="status">
          Không đọc được nguồn dữ liệu. Số lượng chưa xác định không được hiểu
          là bằng 0.
        </p>
      )}
      <div className="n91-metric-grid">
        <Metric
          title="Sự kiện được ghi nhận"
          value={metrics.total}
          href={`#/events?source=${canonical ? "canonical" : "p17"}`}
          tone="neutral"
          icon={Activity}
        />
        <Metric
          title="Truy vấn bị chặn"
          value={metrics.blocked}
          href={`#/events?decision=BLOCK&source=${canonical ? "canonical" : "p17"}`}
          tone="danger"
          icon={ShieldOff}
        />
        <Metric
          title="Sự cố cần xem xét"
          value={metrics.review}
          href="#/incidents"
          tone="warn"
          icon={ShieldAlert}
        />
        <Metric
          title="Máy ảo đang cách ly"
          value={metrics.isolated}
          href={
            metrics.isolated == null
              ? "#/workloads"
              : "#/workloads?network_state=QUARANTINED"
          }
          tone="source"
          icon={Database}
        />
      </div>
      <div className="n91-clean-columns">
        <section className="n91-clean-section">
          <header className="n91-section-head">
            <div>
              <span className="n91-section-eyebrow">
                {canonical ? "NHẬT KÝ TRUY VẤN" : "DỮ LIỆU PHÁT HIỆN"}
              </span>
              <h2>Sự kiện gần đây</h2>
            </div>
            <a
              className="n91-section-action"
              href={`#/events?source=${canonical ? "canonical" : "p17"}`}
            >
              Xem tất cả
            </a>
          </header>
          <div className="n91-rows">
            {events.data?.length ? (
              events.data.map((event) => (
                <a
                  className="n91-item"
                  key={event.event_id}
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                >
                  <span
                    className={`n91-item-symbol ${event.decision === "BLOCK" ? "n91-symbol-block" : "n91-symbol-allow"}`}
                  >
                    {event.decision === "BLOCK"
                      ? "!"
                      : event.decision === "ALLOW"
                        ? "✓"
                        : "?"}
                  </span>
                  <span className="n91-item-content">
                    <strong>{event.source_ip || "Không rõ nguồn"}</strong>
                    <small>
                      {event.matched_rules.join(" · ") ||
                        "Không có quy tắc được công bố"}
                    </small>
                  </span>
                  <span className="n91-item-action">
                    <Badge value={event.decision} />
                    <b>{event.risk.score ?? "—"}</b>
                  </span>
                  <time className="n91-item-time">
                    {time(event.occurred_at)}
                  </time>
                </a>
              ))
            ) : (
              <p className="n91-empty">
                {events.loading
                  ? "Đang đọc dữ liệu sự kiện…"
                  : events.error
                  ? "Không đọc được nguồn sự kiện."
                  : "Chưa có sự kiện trong nguồn được chọn."}
              </p>
            )}
          </div>
        </section>
        <section className="n91-clean-section">
          <header className="n91-section-head">
            <div>
              <span className="n91-section-eyebrow">ĐIỀU TRA VÀ XỬ LÝ</span>
              <h2>Sự cố cần chú ý</h2>
            </div>
            <a className="n91-section-action" href="#/incidents">
              Xem tất cả
            </a>
          </header>
          <div className="n91-rows">
            {incidents.data?.length ? (
              incidents.data.map((incident) => (
                <a
                  className="n91-item"
                  key={incident.incident_id}
                  href={incidentHref(incident.incident_id, incident.stream_id)}
                >
                  <span className="n91-item-symbol n91-symbol-incident">
                    <ShieldAlert size={18} />
                  </span>
                  <span className="n91-item-content">
                    <strong>{incident.source_ip || "Không rõ nguồn"}</strong>
                    <small>
                      Hồ sơ điều tra · {incident.evidence_count ?? "—"} bằng
                      chứng
                    </small>
                  </span>
                  <Badge value={incident.severity} />
                  <time className="n91-item-time">
                    {time(incident.last_seen)}
                  </time>
                </a>
              ))
            ) : (
              <p className="n91-empty">
                {incidents.loading
                  ? "Đang đọc dữ liệu sự cố…"
                  : incidents.error
                  ? uiErrorMessage(incidents.error)
                  : "Chưa có hồ sơ sự cố từ nguồn trả về."}
              </p>
            )}
          </div>
        </section>
      </div>
      <DashboardGalera />
      <footer className="n91-clean-foot">
        <span>Nguồn đọc lúc {time(summary.meta?.read_at)}</span>
        <span>Độ đầy đủ lịch sử chưa được xác nhận</span>
        <a href="#/system/sources">Tình trạng nguồn</a>
      </footer>
    </section>
  );
}
