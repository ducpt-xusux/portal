import { useEffect } from "react";
import { sourceReadTimestamp } from "../services/proxyPresentation";
import { uiLabel, uiRoleList } from "../services/uiLanguage.js";
import { RulesExplorer } from "../features/n91-investigation/Investigation";
import { Activity, Database, Layers, Network } from "lucide-react";
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
  Panel,
  display,
  useTime,
} from "./PortalUI";

function PoliciesPanel() {
  return <RulesExplorer />;
}

function SourcesPanel() {
  const time = useTime();
  const build = useV4Resource("/system/build");
  const resource = useV4Resource("/system/data-sources", {
    interval: 15000,
    transform: (data) => readCollection(data, "sources"),
  });
  return (
    <Panel
      title="Nguồn và tình trạng cập nhật"
      subtitle="Thời điểm Portal đọc nguồn và thời điểm thu được dữ liệu"
      resource={resource}
    >
      {build.data && (
        <p className="v4-proxy-snapshot">
          Bản Portal {build.data.build_sha?.slice(0, 12) || "chưa xác minh"}
          {build.data.working_tree_dirty && <> · Có chỉnh sửa chưa ghi vào Git</>}
          {build.data.build_utc && (
            <> · Tạo bản lúc {time(build.data.build_utc)}</>
          )}
        </p>
      )}
      {resource.data &&
        (resource.data.length ? (
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>NGUỒN / CẤU TRÚC DỮ LIỆU</th>
                  <th>TÌNH TRẠNG CẬP NHẬT</th>
                  <th>ĐỌC THÀNH CÔNG</th>
                  <th>LẦN THỬ ĐỌC</th>
                  <th>DỮ LIỆU ĐẾN</th>
                  <th>MÃ LỖI</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((source, index) => (
                  <tr key={source.source_system || index}>
                    <td>
                      {uiLabel(source.source_system)}
                      <small>{uiLabel(source.source_schema)}</small>
                    </td>
                    <td>
                      {source.observation_freshness_state ? (
                        <>
                          {source.collection_mode === "PERIODIC" && (
                            <Badge value={source.freshness_state} />
                          )}{" "}
                          <ObservationAgeBadge
                            value={source.observation_freshness_state}
                          />{" "}
                          <Badge value={source.coverage_state} />
                        </>
                      ) : (
                        <Badge
                          value={
                            freshness(
                              resource.meta,
                              Boolean(resource.error),
                            ) === "FRESH"
                              ? source.freshness_state
                              : "STALE"
                          }
                        />
                      )}
                    </td>
                    <td
                      title={
                        sourceReadTimestamp(source, "last_success") ===
                        "NO_SEPARATE_TIMESTAMP"
                          ? "Nguồn chỉ công bố dữ liệu đến; không cung cấp mốc đọc riêng."
                          : undefined
                      }
                    >
                      {sourceReadTimestamp(source, "last_success") ===
                      "NO_SEPARATE_TIMESTAMP"
                        ? "Không có mốc riêng"
                        : time(source.last_success)}
                    </td>
                    <td
                      title={
                        sourceReadTimestamp(source, "last_attempt") ===
                        "NO_SEPARATE_TIMESTAMP"
                          ? "Nguồn chỉ công bố dữ liệu đến; không cung cấp mốc đọc riêng."
                          : undefined
                      }
                    >
                      {sourceReadTimestamp(source, "last_attempt") ===
                      "NO_SEPARATE_TIMESTAMP"
                        ? "Không có mốc riêng"
                        : time(source.last_attempt)}
                    </td>
                    <td>
                      {time(
                        source.observation_freshness_state
                          ? source.observation_to
                          : source.data_as_of,
                      )}
                    </td>
                    <td>{display(source.last_error_code)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Chưa có quan sát nguồn" />
        ))}
    </Panel>
  );
}

export default function SystemPage({ tab = "health" }) {
  const { sessionAuthEnabled, auth } = usePortal();
  useEffect(() => {
    if (["policies", "evaluation", "demo-coverage"].includes(tab))
      window.location.hash = "/system/health";
  }, [tab]);
  const tabs = [
    ["health", "Tổng quan", Activity],
    ["galera", "Galera", Database],
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
        eyebrow="GIÁM SÁT HỆ THỐNG"
        title="Hệ thống"
        description="Theo dõi dịch vụ, cụm dữ liệu và bằng chứng vận hành từ các nguồn thực tế."
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
