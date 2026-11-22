import NetworkHistory from "./NetworkHistory";
import QuarantineJournal from "./QuarantineJournal";
import { uiLabel, uiRoleList } from "../services/uiLanguage.js";
import { incidentSectionHref } from "../services/incidentLinks";
import { LoadedSgLifecycle } from "../features/n91-investigation/Investigation";
import { useState } from "react";
import {
  ArrowLeft,
  ArrowUpRight,
  LayoutDashboard,
  LockKeyhole,
  Monitor,
  Server,
  Cpu,
  Network,
  ShieldCheck,
  RefreshCw,
  Plug2,
  CircleCheck,
} from "lucide-react";
import {
  freshness,
  isOpenStackInventoryExport,
  mapWorkload,
  portalRequest,
  readCollection,
  workloadNetworkStatus,
} from "../services/portalApi";
import { useCursor, useV4Resource } from "./IncidentPages";
import { RiskExposure, SecurityGroups } from "./InvestigationUI";
import {
  Badge,
  CopyId,
  CursorPager,
  Empty,
  FieldGrid,
  Filter,
  PageHeading,
  Panel,
  ResourceNotice,
  SelectFilter,
  SourceStatus,
  display,
  useTime,
} from "./PortalUI";
import WorkloadConsole from "./WorkloadConsole";
import { usePortal } from "./PortalContext";
import "./WorkloadConsole.css";
import "./WorkloadDetail.css";

const NETWORK_LABELS = {
  NORMAL: "Bình thường",
  QUARANTINED: "Đang bị cách ly",
  MISMATCH: "Cô lập không đồng nhất",
  UNKNOWN: "Chưa xác minh",
  STALE: "Dữ liệu cũ",
};

function NetworkStatusBadge({ state }) {
  return (
    <Badge value={state}>
      {NETWORK_LABELS[state] || NETWORK_LABELS.UNKNOWN}
    </Badge>
  );
}

const QUARANTINE_ERRORS = {
  RESTORE_PORT_CHANGED:
    "Cấu hình cổng đã thay đổi. Kiểm tra trực tiếp trong Neutron trước khi khôi phục.",
  RESTORE_PORT_SCOPE_CHANGED:
    "Danh sách Port đã thay đổi. Kiểm tra trực tiếp trong Neutron.",
  RESTORE_CONFIGURATION_CHANGED:
    "Dự án hoặc Security Group cô lập đã thay đổi.",
  RESTORE_OPERATION_CHANGED:
    "Lượt cô lập đã thay đổi. Hãy kiểm tra lại trạng thái.",
  RESTORE_HISTORY_UNAVAILABLE: "Đã khôi phục Security Group. Nhật ký chưa lưu đủ chi tiết.",
  QUARANTINE_RESTORE_UNVERIFIED:
    "Chưa xác minh được khôi phục Security Group cũ. Kiểm tra các cổng trong Neutron trước khi thử lại.",
  QUARANTINE_APPLIED_AUDIT_INCOMPLETE:
    "Neutron đã xác nhận cô lập. Chưa ghi được kết quả vào nhật ký Portal.",
  QUARANTINE_SG_NOT_EMPTY_OR_OUTSIDE_PROJECT:
    "Security Group cô lập phải thuộc dự án và không có luật cho phép.",
};

function WorkloadQuarantine({ vm, resource }) {
  const { auth, workloadQuarantineAvailable } = usePortal();
  const time = useTime();
  const [confirming, setConfirming] = useState(false);
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState(null);
  const name = vm.name ? uiLabel(vm.name) : vm.server_id;
  const path = `/workloads/${encodeURIComponent(vm.server_id)}`;
  const status = useV4Resource(`${path}/quarantine`, {
    enabled: workloadQuarantineAvailable,
    interval: 3000,
  });
  const operation = status.data;
  const responseUrl = incidentSectionHref(operation?.incident_id, operation?.stream_id, "response");
  const state = operation?.state;
  const restoring = state === "RESTORING" || state === "APPLYING";
  const canRestore = state === "QUARANTINED" || state === "RESTORE_FAILED";
  const networkState = workloadNetworkStatus(
    vm.network_observation,
    resource.meta,
    Boolean(resource.error),
  );
  const allowed =
    workloadQuarantineAvailable && operation?.allowed && !status.error;
  const executor = auth.csrfToken && auth.user?.roles?.includes("Executor");
  const unavailable = !workloadQuarantineAvailable
    ? "Portal chưa được cấu hình quyền cô lập."
    : status.error
      ? "Chưa đọc được trạng thái cô lập."
      : operation && !operation.allowed
        ? "Máy ảo này nằm ngoài danh sách được phép cô lập."
        : !executor
          ? "Cần đăng nhập bằng tài khoản được cấp quyền thực thi."
          : !canRestore && (vm.protected || networkState !== "NORMAL")
            ? "Cần xác minh máy ảo đủ điều kiện cô lập và mạng đang Bình thường."
            : null;

  async function change(restore = false) {
    if (!allowed || unavailable || pending || restoring) return;
    setPending(true);
    setNotice(null);
    try {
      const { data } = await portalRequest(
        `${path}/${restore ? "restore" : "quarantine"}`,
        {
          method: "POST",
          csrfToken: auth.csrfToken,
          body: restore
            ? { confirm: "RESTORE", operation_id: operation.operation_id }
            : { confirm: "QUARANTINE" },
          timeout: 90000,
        },
      );
      const message = restore
        ? `Neutron đã xác nhận khôi phục Security Group của ${name}.`
        : `Neutron đã xác nhận cô lập ${name}.`;
      setNotice(
        data?.history_saved === false
          ? {
              error: true,
              message: `${message} Chưa lưu được lịch sử trạng thái.`,
            }
          : { message },
      );
    } catch (error) {
      setNotice({
        error: true,
        message: QUARANTINE_ERRORS[error.code] || error.message,
      });
    } finally {
      setConfirming(false);
      await Promise.allSettled([status.refresh(), resource.refresh()]);
      setPending(false);
    }
  }

  return (
    <Panel
      title="Điều khiển bảo mật"
      subtitle="Cô lập kết nối hoặc khôi phục Security Group đã lưu."
      className="vm-control-panel"
      action={
        !confirming && (
          <button
            type="button"
            className={`button vm-security-action ${canRestore ? "vm-restore-action" : ""}`}
            disabled={!allowed || Boolean(unavailable) || pending || restoring}
            onClick={() => (canRestore ? change(true) : setConfirming(true))}
          >
            <LockKeyhole size={15} aria-hidden="true" />
            {pending || restoring
              ? "Đang xử lý…"
              : canRestore
                ? "Khôi phục"
                : "Cô lập"}
          </button>
        )
      }
    >
      {unavailable && !pending && (
        <p className="v4-panel-note">{unavailable}</p>
      )}
      {state === "QUARANTINED" && (
        <p role="status">
          {operation.restore_at
            ? `Khôi phục tự động lúc ${time(operation.restore_at)}.`
            : "Máy ảo sẽ giữ trạng thái cô lập cho đến khi bạn bấm Khôi phục."}
        </p>
      )}
      {restoring && <p role="status">Đang xử lý thay đổi Security Group.</p>}
      {state === "RESTORED" && (
        <p className="vm-action-success" role="status">
          <CircleCheck size={18} />
          <span>
            Security Group đã khôi phục
            <small>{time(operation.restored_at)}</small>
          </span>
        </p>
      )}
      {operation?.automatic_response && (
        <div className="v4-proxy-snapshot">
          <strong>Ứng phó tự động theo chính sách thử nghiệm</strong>
          <p>{operation.incident_id} · {uiLabel(operation.policy_version)}</p>
          <a href={responseUrl || "#/system/automatic-response"}>Xem quyết định, xác minh nguồn và bằng chứng</a>
        </div>
      )}
      {operation?.error_code && (
        <p role="alert">
          {QUARANTINE_ERRORS[operation.error_code] || operation.error_code}
        </p>
      )}
      {notice && (
        <p
          className={notice.error ? "vm-action-error" : "vm-action-notice"}
          role={notice.error ? "alert" : "status"}
        >
          {notice.message}
        </p>
      )}
      {confirming && (
        <div
          className="v4-inline-warning"
          role="group"
          aria-label="Xác nhận cô lập máy ảo"
        >
          <p>
            <strong>{name}</strong> có thể mất kết nối mạng sau khi cô lập.
          </p>
          <div className="v4-workload-quarantine-actions">
            <button
              type="button"
              className="button secondary"
              disabled={pending}
              onClick={() => setConfirming(false)}
            >
              Hủy
            </button>
            <button
              type="button"
              className="button primary"
              disabled={
                !allowed ||
                Boolean(unavailable) ||
                pending ||
                restoring ||
                canRestore
              }
              onClick={() => change()}
            >
              {pending ? "Đang cô lập…" : "Xác nhận cô lập"}
            </button>
          </div>
        </div>
      )}
    </Panel>
  );
}

export function WorkloadsPage({ params }) {
  const time = useTime();
  const [draft, setDraft] = useState(params);
  const pager = useCursor();
  const resource = useV4Resource("/workloads", {
    params: { ...params, limit: 25, cursor: pager.cursor },
    interval: 15000,
    transform: (data) => readCollection(data, "workloads").map(mapWorkload),
  });
  const classificationMissing = resource.meta?.network_classification === "NOT_CONFIGURED";
  const hasOpenStackObservation = resource.meta?.source_mode === "LIVE" || isOpenStackInventoryExport(resource.meta);
  const stale = hasOpenStackObservation && freshness(resource.meta, Boolean(resource.error)) !== "FRESH";
  const applyFilters = (event) => {
    event.preventDefault();
    const query = new URLSearchParams(Object.entries(draft).filter(([, value]) => value)).toString();
    window.location.hash = `/workloads${query ? `?${query}` : ""}`;
  };

  return (
    <>
      <PageHeading title="Máy ảo" resource={resource} />
      <section className="panel v4-panel workload-inventory" aria-label="Danh sách máy ảo">
        <form className="v4-filters workload-list-filters" onSubmit={applyFilters}>
          <Filter label="Tên máy ảo">
            <input
              type="search"
              placeholder="Nhập tên máy ảo"
              value={draft.name || ""}
              maxLength={128}
              onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
            />
          </Filter>
          <SelectFilter
            label="Kết nối mạng"
            value={draft.network_state}
            onChange={(value) => setDraft((current) => ({ ...current, network_state: value }))}
            options={[
              ["", "Tất cả"],
              ...Object.entries(NETWORK_LABELS)
                .filter(([value]) => value !== "STALE")
                .map(([value, label]) => [value, label, value !== "UNKNOWN" && classificationMissing]),
            ]}
          />
          <button className="button primary">Lọc</button>
          {(draft.name || draft.network_state || params.name || params.network_state) && (
            <a className="button secondary" href="#/workloads" onClick={() => setDraft({})}>Đặt lại</a>
          )}
        </form>
        <ResourceNotice resource={resource} noun="danh sách máy ảo" />
        {stale && !resource.error && <p className="v4-panel-note" role="status">Đang xem lần quan sát gần nhất.</p>}
        {classificationMissing && <p className="v4-panel-note">Dự án chưa cung cấp cấu hình Security Group cách ly.</p>}
        {resource.meta?.network_history_error && <p className="v4-panel-note" role="status">Tạm thời chưa đọc được lịch sử mạng.</p>}
        {resource.data && (resource.data.length ? (
          <div className="table-scroll">
            <table className="v4-table workload-list-table">
              <thead>
                <tr>
                  <th>Máy ảo</th>
                  <th>Trạng thái Nova</th>
                  <th>Kết nối mạng</th>
                  <th>Địa chỉ IP</th>
                  <th>Security Group</th>
                  <th>Quan sát lúc</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((vm) => {
                  const state = workloadNetworkStatus(vm.network_observation, resource.meta, Boolean(resource.error));
                  const nova = hasOpenStackObservation ? vm.nova_status : null;
                  const name = vm.name ? uiLabel(vm.name) : vm.server_id;
                  const vmUrl = `#/workloads/${encodeURIComponent(vm.server_id)}`;
                  const fixedIps = [...new Set(vm.ports.flatMap((port) => port.fixed_ips))];
                  const externalIps = [...new Set(vm.ports.flatMap((port) => port.floating_ips))];
                  const groupsById = new Map();
                  for (const port of vm.ports) {
                    for (const group of port.security_groups) {
                      if (group.name || !groupsById.has(group.id)) groupsById.set(group.id, group);
                    }
                  }
                  const groups = [...groupsById.values()];
                  const groupsProvided = groups.length > 0 ||
                    (vm.ports.length > 0 && vm.ports.every((port) => port.security_groups_provided));
                  return (
                    <tr key={vm.server_id}>
                      <td><a className="workload-list-name" href={vmUrl}><Server size={16} aria-hidden="true" /> {name}</a></td>
                      <td><Badge value={stale ? "STALE" : nova || "UNKNOWN"}>
                        {stale ? "Dữ liệu cũ" : nova ? uiLabel(nova) : "Chưa xác minh"}
                      </Badge></td>
                      <td>
                        <NetworkStatusBadge state={state} />
                        <NetworkHistory entries={vm.network_history} serverId={vm.server_id} name={name} />
                      </td>
                      <td>
                        {fixedIps.length ? fixedIps.map((ip) => <code key={ip}>{ip}</code>) : "—"}
                        {externalIps.map((ip) => <small key={ip}>Floating IP <code>{ip}</code></small>)}
                      </td>
                      <td><SecurityGroups groups={groups} provided={groupsProvided} namesOnly /></td>
                      <td><time dateTime={vm.network_observed_at}>{time(vm.network_observed_at)}</time></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <Empty title="Không có máy ảo trong phạm vi lọc" />)}
        <CursorPager resource={resource} {...pager} />
        {hasOpenStackObservation && (
          <details className="portal-provenance workload-source-details">
            <summary>Nguồn OpenStack</summary>
            <FieldGrid rows={[
              ["Project", display(resource.meta.project_id)],
              ["Quan sát gần nhất", time(resource.meta.data_as_of)],
              ["Chu kỳ đọc", resource.meta.refresh_seconds ? `${resource.meta.refresh_seconds} giây` : null],
            ]} />
          </details>
        )}
      </section>
    </>
  );
}

function PortsPanel({ vmId, selectedPort }) {
  const time = useTime();
  const resource = useV4Resource(
    `/workloads/${encodeURIComponent(vmId)}/ports`,
    {
      interval: 15000,
      transform: (data) =>
        mapWorkload({ server_id: vmId, ports: readCollection(data, "ports") })
          .ports,
    },
  );
  return (
    <Panel
      title="Port và Security Group"
      resource={resource}
      className="vm-ports-panel"
    >
      {selectedPort &&
        resource.data &&
        !resource.data.some((port) => port.port_id === selectedPort) && (
          <p className="v4-panel-note" role="status">
            Port từ hồ sơ sự cố không còn thuộc máy ảo này trong danh sách hiện
            tại. Hãy đọc lại đối chiếu tại sự cố.
          </p>
        )}
      {resource.data &&
        (resource.data.length ? (
          <div className="v4-port-grid">
            {resource.data.map((port, index) => (
              <article
                className="v4-port-card"
                style={
                  selectedPort === port.port_id
                    ? { outline: "2px solid var(--accent, #38bdf8)" }
                    : undefined
                }
                key={port.port_id || index}
              >
                {selectedPort === port.port_id && (
                  <p className="v4-panel-note">
                    <strong>
                      Port được mở từ đối chiếu IP nguồn của sự cố
                    </strong>
                  </p>
                )}
                <div className="vm-port-heading">
                  <span className="vm-port-heading-icon">
                    <Plug2 size={19} />
                  </span>
                  <div>
                    <h3>Port {index + 1}</h3>
                    <div className="v4-copy-row">
                      <span>{port.port_id || "Port chưa có mã"}</span>
                      <CopyId value={port.port_id} />
                    </div>
                  </div>
                  <Badge
                    value={workloadNetworkStatus(
                      {
                        state: port.network_state,
                        observed_at: port.observed_at,
                        verification: ["LIVE", "REMOTE_READONLY"].includes(
                          resource.meta?.source_mode,
                        )
                          ? "LIVE_NEUTRON_READ"
                          : null,
                      },
                      resource.meta,
                      Boolean(resource.error),
                    )}
                  />
                </div>
                <div className="vm-port-fields">
                  <FieldGrid
                    rows={[
                      ["IP nội bộ", port.fixed_ips.join(" · ") || "—"],
                      ["Floating IP", port.floating_ips.join(" · ") || "—"],
                      ["MAC", display(port.mac_address)],
                      ["Revision Neutron", display(port.revision_number)],
                      ["Port Security", display(port.port_security_enabled)],
                      ["Port status", uiLabel(port.status)],
                    ]}
                  />
                </div>
                <h3 className="v4-subheading">Security Group đang áp dụng</h3>
                <SecurityGroups
                  groups={port.security_groups}
                  provided={port.security_groups_provided}
                />
                <details className="vm-port-technical">
                  <summary>Thông tin định danh và subnet</summary>
                  <FieldGrid
                    rows={[
                      ["Project", display(port.project_id)],
                      ["Device ID", display(port.device_id)],
                      ["Device owner", display(port.device_owner)],
                      ["Network", display(port.network_id)],
                      ["Quan sát lúc", time(port.observed_at)],
                      [
                        "Subnet / fixed IP",
                        port.fixed_ip_details
                          .map(
                            (ip) =>
                              `${ip.ip_address || "—"} / ${ip.subnet_id || "Chưa có subnet"}`,
                          )
                          .join(" · ") || "Chưa cung cấp",
                      ],
                    ]}
                  />
                </details>
              </article>
            ))}
          </div>
        ) : (
          <Empty title="Không có Port trong phạm vi truy cập" />
        ))}
    </Panel>
  );
}

export function ActionHistory({ serverId, incidentId }) {
  const time = useTime();
  const resource = useV4Resource("/actions", {
    params: { server_id: serverId, incident_id: incidentId, limit: 25 },
    interval: 5000,
    transform: (data) => readCollection(data, "actions"),
  });
  if (
    serverId &&
    (resource.data?.length === 0 ||
      (!resource.data?.length &&
        resource.error?.code === "CONTROLLER_EVIDENCE_UNAVAILABLE"))
  )
    return null;
  return (
    <Panel
      title="Lịch sử xử lý"
      subtitle="Bản ghi hành động · trạng thái hiện tại cần Neutron trực tiếp"
      resource={resource}
    >
      {resource.data &&
        (resource.data.length ? (
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>Hành động / sự cố</th>
                  <th>Kết quả ghi nhận</th>
                  <th>Thời điểm</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((action, index) => (
                  <tr key={action.action_id || index}>
                    <td>
                      {typeof action.action_id === "string" ? (
                        <a
                          className="v4-id-link"
                          href={`#/actions/${encodeURIComponent(action.action_id)}`}
                        >
                          {action.action_id}
                        </a>
                      ) : (
                        "Chưa có hành động ID"
                      )}
                      {typeof action.incident_id === "string" && (
                        <a
                          className="v4-id-link"
                          href={`#/incidents/${encodeURIComponent(action.incident_id)}`}
                        >
                          {action.incident_id}
                        </a>
                      )}
                    </td>
                    <td>
                      <Badge value={action.action_state} />
                    </td>
                    <td>{time(action.started_at || action.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="Chưa có bản ghi hành động"
            text="Không suy ra hành động cách ly từ điểm rủi ro hoặc trạng thái sự cố."
          />
        ))}
    </Panel>
  );
}

export function WorkloadDetail({ id, params = {} }) {
  const { sessionAuthEnabled, controllerActionHistoryConfigured } = usePortal();
  const time = useTime();
  const resource = useV4Resource(`/workloads/${encodeURIComponent(id)}`, {
    interval: 15000,
    transform: mapWorkload,
  });
  const vm = resource.data;
  const activeTab = params.tab === "console" ? "console" : "overview";
  const tabHref = (tab) =>
    `#/workloads/${encodeURIComponent(id)}?${new URLSearchParams({ tab, ...(params.port_id ? { port_id: params.port_id } : {}) })}`;
  const networkState = vm
    ? workloadNetworkStatus(
        vm.network_observation,
        resource.meta,
        Boolean(resource.error),
      )
    : "UNKNOWN";
  const fresh = freshness(resource.meta, Boolean(resource.error)) === "FRESH";
  const addresses = vm
    ? [...new Set(vm.ports.flatMap((port) => port.fixed_ips))]
    : [];
  return (
    <div className="vm-detail-page">
      <a className="vm-back-link" href="#/workloads">
        <Server size={15} />
        Máy ảo<span>/</span>
        <span>Chi tiết máy ảo</span>
      </a>
      <header className="vm-hero">
        <div className="vm-hero-top">
          <div className="vm-hero-identity">
            <div className="vm-hero-icon">
              <Server size={27} strokeWidth={1.7} />
            </div>
            <div>
              <h1>{vm?.name ? uiLabel(vm.name) : "Chi tiết máy ảo"}</h1>
            </div>
          </div>
          <button
            className="button secondary vm-refresh"
            disabled={resource.loading}
            onClick={resource.refresh}
          >
            <RefreshCw size={16} className={resource.loading ? "spin" : ""} />
            Làm mới
          </button>
        </div>
        <div className="vm-hero-id">
          <span>VM ID</span>
          <code>{id}</code>
          <CopyId value={id} />
        </div>
        <div className="vm-hero-bottom">
          <div className="vm-hero-badges">
            {vm && (
              <>
                <Badge value={fresh ? vm.nova_status : "STALE"} />
                <NetworkStatusBadge state={networkState} />
              </>
            )}
          </div>
          <SourceStatus resource={resource} label="Nova / Neutron" />
        </div>
      </header>
      <ResourceNotice resource={resource} noun="máy ảo" />
      {vm && (
        <div
          className="vm-summary-grid"
          aria-label="Thông tin nhanh của máy ảo"
        >
          <div className="vm-stat">
            <span className="vm-stat-icon">
              <Network size={19} />
            </span>
            <div>
              <span>Trạng thái mạng</span>
              <strong>
                {NETWORK_LABELS[networkState] || NETWORK_LABELS.UNKNOWN}
              </strong>
              <small>Neutron · {time(vm.network_observed_at)}</small>
            </div>
          </div>
          <div className="vm-stat">
            <span className="vm-stat-icon">
              <Cpu size={19} />
            </span>
            <div>
              <span>Compute host</span>
              <strong>{display(vm.compute_host)}</strong>
              <small>Vị trí triển khai VM</small>
            </div>
          </div>
          <div className="vm-stat">
            <span className="vm-stat-icon">
              <Server size={19} />
            </span>
            <div>
              <span>IP nội bộ</span>
              <strong className="vm-address">
                {addresses.join(" · ") || "Chưa có fixed IP"}
              </strong>
              <small>Địa chỉ từ các port hiện tại</small>
            </div>
          </div>
          <div className="vm-stat">
            <span className="vm-stat-icon">
              <Plug2 size={19} />
            </span>
            <div>
              <span>Kết nối mạng</span>
              <strong>{vm.ports.length} port</strong>
              <small>Theo OpenStack</small>
            </div>
          </div>
        </div>
      )}
      <nav className="vm-page-tabs" aria-label="Chi tiết máy ảo">
        <a
          className={activeTab === "overview" ? "active" : ""}
          aria-current={activeTab === "overview" ? "page" : undefined}
          href={tabHref("overview")}
        >
          <LayoutDashboard size={17} />
          Tổng quan
        </a>
        <a
          className={activeTab === "console" ? "active" : ""}
          aria-current={activeTab === "console" ? "page" : undefined}
          href={tabHref("console")}
        >
          <Monitor size={17} />
          Console
        </a>
      </nav>
      {activeTab === "console" &&
        (sessionAuthEnabled ? (
          <Panel title="Console">
            <p role="status">Console đang tắt trong chế độ phiên đăng nhập.</p>
          </Panel>
        ) : (
          vm && (
            <WorkloadConsole
              vm={vm}
              meta={resource.meta}
              error={resource.error}
            />
          )
        ))}
      {vm && activeTab === "overview" && (
        <section className="vm-overview-layout" aria-label="Overview máy ảo">
          <div className="vm-main-column">
            <PortsPanel vmId={id} selectedPort={params.port_id} />
            <QuarantineJournal serverId={id} selectedOperationId={params.operation_id} />
            {controllerActionHistoryConfigured !== false && <ActionHistory serverId={id} />}
          </div>
          <aside className="vm-side-column">
            <WorkloadQuarantine
              key={vm.server_id}
              vm={vm}
              resource={resource}
            />
            <Panel title="Thông tin định danh" className="vm-identity-panel">
              <FieldGrid
                rows={[
                  ["Project", display(vm.project_id)],
                  ["Mã máy ảo", vm.server_id],
                  ["Compute host", display(vm.compute_host)],
                  ["Quan sát lúc", time(vm.observed_at)],
                ]}
              />
            </Panel>
            <Panel title="Theo dõi bảo mật" className="vm-security-panel">
              <div className="vm-security-heading">
                <ShieldCheck size={20} />
                <NetworkStatusBadge state={networkState} />
              </div>
              <p>
                Trạng thái mạng được xác minh bằng Security Group trên Neutron.
              </p>
              <NetworkHistory
                entries={vm.network_history}
                serverId={vm.server_id}
                name={vm.name ? uiLabel(vm.name) : vm.server_id}
              />
              {vm.incident_refs.length > 0 && (
                <div className="v4-link-list">
                  {vm.incident_refs.map((incident) => (
                    <a
                      key={incident}
                      href={`#/incidents/${encodeURIComponent(incident)}`}
                    >
                      {incident}
                    </a>
                  ))}
                </div>
              )}
            </Panel>
            {vm.risk_exposure && (
              <Panel title="Rủi ro từ sự cố gần đây">
                <RiskExposure
                  exposure={vm.risk_exposure}
                  meta={resource.meta}
                  error={resource.error}
                />
              </Panel>
            )}
          </aside>
        </section>
      )}
    </div>
  );
}

export function ActionDetail({ id }) {
  const time = useTime();
  const resource = useV4Resource(`/actions/${encodeURIComponent(id)}`, {
    interval: 5000,
  });
  const action = resource.data;
  const groups = (value) =>
    Array.isArray(value)
      ? value.filter((item) => typeof item === "string").join(" · ") ||
        "Không có Security Group"
      : "Chưa có bằng chứng";
  return (
    <>
      <a className="incident-back" href="#/workloads">
        <ArrowLeft size={15} />
        Máy ảo
      </a>
      <PageHeading
        title="Chi tiết hành động"
        description={id}
        resource={resource}
      />
      <SourceStatus resource={resource} label="bằng chứng + Neutron" />
      <ResourceNotice resource={resource} noun="action" />
      {action && (
        <div className="v4-detail-grid">
          <Panel title="Bản ghi xử lý">
            <Badge value={action.action_state} />
            <FieldGrid
              rows={[
                ["Mã hành động", display(action.action_id)],
                [
                  "Incident",
                  typeof action.incident_id === "string" ? (
                    <a
                      className="v4-id-link"
                      href={`#/incidents/${encodeURIComponent(action.incident_id)}`}
                    >
                      {action.incident_id}
                    </a>
                  ) : (
                    "—"
                  ),
                ],
                ["Mã port", display(action.target?.port_id)],
                ["Tạo lúc", time(action.started_at)],
                ["Verify lúc", time(action.finished_at)],
                ["Original SGs", groups(action.before_sgs)],
                ["During SGs", groups(action.during_sgs)],
                ["After SGs", groups(action.after_sgs)],
              ]}
            />
          </Panel>
          <Panel title="Security Group theo từng giai đoạn">
            <LoadedSgLifecycle actionId={id} />
          </Panel>
        </div>
      )}
    </>
  );
}
