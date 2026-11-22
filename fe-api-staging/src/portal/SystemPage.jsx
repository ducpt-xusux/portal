import { useEffect } from "react";
import { sourceReadTimestamp } from "../services/proxyPresentation";
import { uiLabel, uiRoleList } from "../services/uiLanguage.js";
import { RulesExplorer } from "../features/n91-investigation/Investigation";
import { Activity, Database, Layers, Network, RefreshCw } from "lucide-react";
import { BusinessAdminPanel } from "../features/n91-business";
import EvaluationSystemTabs from "../features/n91-evaluation/EvaluationSystemTabs";
import { freshness, readCollection } from "../services/portalApi";
import { useV4Resource } from "./IncidentPages";
import ProxyServicesPanel from "./ProxyServicesPanel";
import GaleraPanel from "./GaleraPanel";
import ReportEvidencePanel from "./ReportEvidencePanel";
import AutomaticResponsePanel from "./AutomaticResponsePanel";
import DemoCoveragePage from "./DemoCoveragePage";
import { usePortal } from "./PortalContext";
import {
  Badge,
  Empty,
  FieldGrid,
  ObservationAgeBadge,
  PageHeading,
  ResourceNotice,
  SourceStatus,
  display,
  useTime,
} from "./PortalUI";

function PoliciesPanel() {
  return <RulesExplorer />;
}

function SourceCard({ source, reportStale }) {
  const time = useTime();
  const observation = source.observation_freshness_state;
  const coverage = source.coverage_state;
  const collection = source.freshness_state;
  const asOf = observation ? source.observation_to : source.data_as_of;
  let status = collection;
  if (reportStale) status = "STALE";
  else if (observation && (source.collection_mode !== "PERIODIC" || collection === "FRESH")) {
    status = coverage === "PARTIAL" && observation === "FRESH" ? coverage : observation;
  }
  const readAt = (field) => {
    const timestamp = sourceReadTimestamp(source, field);
    return timestamp === "NO_SEPARATE_TIMESTAMP" ? "Không có mốc riêng" : time(timestamp);
  };
  return (
    <article className="system-source-card">
      <header className="system-source-heading">
        <h3>{uiLabel(source.source_system)}</h3>
        {!reportStale && observation === status && observation
          ? <ObservationAgeBadge value={status} />
          : <Badge value={status} />}
      </header>
      <p className="system-source-observed">
        <span>Dữ liệu đến</span>
        {asOf ? <time dateTime={asOf}>{time(asOf)}</time> : <span>{time(null)}</span>}
      </p>
      <details className="system-source-diagnostics">
        <summary>Chi tiết nguồn</summary>
        <FieldGrid showAll rows={[
          ["Cấu trúc dữ liệu", uiLabel(source.source_schema)],
          ["Đọc thành công", readAt("last_success")],
          ["Lần thử đọc", readAt("last_attempt")],
          ...(observation ? [["Tình trạng đọc nguồn", uiLabel(collection)]] : []),
          ...(observation ? [["Hiệu lực quan sát", <ObservationAgeBadge value={observation} />]] : []),
          ...(coverage ? [["Mức độ bao phủ", uiLabel(coverage)]] : []),
          ...(source.last_error_code ? [["Mã lỗi", <code>{source.last_error_code}</code>]] : []),
        ]} />
      </details>
    </article>
  );
}

function SourcesPanel() {
  const time = useTime();
  const build = useV4Resource("/system/build");
  const resource = useV4Resource("/system/data-sources", {
    interval: 15000,
    transform: (data) => readCollection(data, "sources"),
  });
  const reportStale = freshness(resource.meta, Boolean(resource.error)) === "STALE";
  return (
    <section className="system-sources" aria-labelledby="system-sources-heading" aria-busy={resource.loading || undefined}>
      <header className="system-sources-header">
        <h2 id="system-sources-heading">Tình trạng nguồn dữ liệu</h2>
        <button type="button" className="button secondary" disabled={resource.loading} onClick={resource.refresh}>
          <RefreshCw size={15} /> Làm mới
        </button>
      </header>
      <ResourceNotice resource={resource} noun="tình trạng nguồn" />
      {resource.data && (resource.data.length ? (
        <div className="system-source-grid">
          {resource.data.map((source, index) => (
            <SourceCard key={source.source_system || index} source={source} reportStale={reportStale} />
          ))}
        </div>
      ) : (
        <Empty title="Chưa có quan sát nguồn" text="Nguồn chưa trả về danh sách." />
      ))}
      {(resource.meta || build.data) && (
        <footer className="system-source-footer">
          {build.data && (
            <details className="system-source-diagnostics">
              <summary>Phiên bản Portal</summary>
              <FieldGrid showAll rows={[
                ["Mã bản dựng", <code>{display(build.data.build_sha)}</code>],
                ["Thời điểm tạo bản dựng", time(build.data.build_utc)],
                ["Có chỉnh sửa chưa ghi vào Git", display(build.data.working_tree_dirty)],
              ]} />
            </details>
          )}
          <SourceStatus resource={resource} detailsOnly />
        </footer>
      )}
    </section>
  );
}

export default function SystemPage({ tab = "health" }) {
  const { sessionAuthEnabled, auth } = usePortal();
  useEffect(() => {
    if (["policies", "evaluation", "demo-coverage"].includes(tab))
      window.location.hash = "/system/health";
  }, [tab]);
  const tabs = [
    ["health", "Dịch vụ Proxy", Activity],
    ["galera", "Cụm Galera", Database],
    ["sources", "Nguồn dữ liệu", Network],
    ["report-evidence", "Bằng chứng báo cáo", Layers],
    ["automatic-response", "Ứng phó tự động", Activity],
  ];
  if (
    sessionAuthEnabled &&
    (auth.businessCapabilities?.portal_admin ||
      auth.user?.roles.includes("Auditor"))
  ) {
    tabs.push(["portal-business", "Quản trị Portal", Layers]);
  }
  const selected = tabs.some(([key]) => key === tab) ? tab : "health";
  const panels = {
    health: (
      <>
        <ProxyServicesPanel system />
      </>
    ),
    galera: <GaleraPanel standalone />,
    policies: <PoliciesPanel />,
    sources: <SourcesPanel />,
    "report-evidence": <ReportEvidencePanel />,
    "automatic-response": <AutomaticResponsePanel />,
    "demo-coverage": <DemoCoveragePage />,
    evaluation: sessionAuthEnabled ? (
      <EvaluationSystemTabs />
    ) : (
      <p role="status">Đăng nhập để xem dữ liệu đánh giá và khôi phục.</p>
    ),
    "portal-business": <BusinessAdminPanel />,
  };
  return (
    <>
      <PageHeading
        title="Hệ thống"
      />
      <nav className="v4-system-tabs" aria-label="Nội dung hệ thống">
        {tabs.map(([key, label, Icon]) => (
          <a
            key={key}
            href={`#/system/${key}`}
            className={selected === key ? "active" : ""}
            aria-current={selected === key ? "page" : undefined}
          >
            <Icon size={16} />
            {label}
          </a>
        ))}
      </nav>
      {panels[selected]}
    </>
  );
}
