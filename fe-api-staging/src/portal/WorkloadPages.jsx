import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { LoadedSgLifecycle } from '../features/n91-investigation/Investigation'
import { useState } from 'react'
import {
  ArrowLeft,
  ArrowUpRight,
  LayoutDashboard,
  LockKeyhole,
  Monitor,
  Server,
} from 'lucide-react'
import {
  freshness,
  isVerifiedNetwork,
  mapWorkload,
  portalRequest,
  readCollection,
} from '../services/portalApi'
import { useCursor, useV4Resource, NetworkObservation } from './IncidentPages'
import { RiskExposure, SecurityGroups } from './InvestigationUI'
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
} from './PortalUI'
import WorkloadConsole from './WorkloadConsole'
import { usePortal } from './PortalContext'
import './WorkloadConsole.css'

const ACTIVITY_LABELS = {
  NORMAL: 'Bình thường',
  QUARANTINED: 'Đã cô lập',
}

const QUARANTINE_ERRORS = {
  QUARANTINE_RESTORE_UNVERIFIED: 'Chưa xác minh được khôi phục nhóm bảo mật cũ. Kiểm tra các cổng trong Neutron trước khi thử lại.',
  QUARANTINE_APPLIED_AUDIT_INCOMPLETE: 'Neutron đã xác nhận cô lập. Chưa ghi được kết quả vào nhật ký Portal.',
  QUARANTINE_SG_NOT_EMPTY_OR_OUTSIDE_PROJECT: 'Security Group cô lập phải thuộc project và không có luật cho phép.',
}

export function WorkloadsPage({ params }) {
  const { auth, workloadQuarantineAvailable } = usePortal()
  const time = useTime()
  const [draft, setDraft] = useState(params)
  const [quarantineTarget, setQuarantineTarget] = useState(null)
  const [quarantining, setQuarantining] = useState(false)
  const [quarantineNotice, setQuarantineNotice] = useState(null)
  const pager = useCursor()
  const resource = useV4Resource('/workloads', {
    params: { ...params, limit: 25, cursor: pager.cursor },
    interval: 15000,
    transform: (data) => readCollection(data, 'workloads').map(mapWorkload),
  })
  const classificationMissing =
    resource.meta?.network_classification === 'NOT_CONFIGURED'
  const staleLive =
    resource.meta?.source_mode === 'LIVE' &&
    freshness(resource.meta, Boolean(resource.error)) !== 'FRESH'
  const canQuarantine = workloadQuarantineAvailable && auth.csrfToken &&
    auth.user?.roles?.includes('Executor')

  async function quarantine() {
    setQuarantining(true)
    setQuarantineNotice(null)
    try {
      await portalRequest(`/workloads/${encodeURIComponent(quarantineTarget.server_id)}/quarantine`, {
        method: 'POST',
        csrfToken: auth.csrfToken,
        body: { confirm: 'QUARANTINE' },
        timeout: 90000,
      })
      setQuarantineNotice({ message: `Neutron đã xác nhận cô lập ${quarantineTarget.name || quarantineTarget.server_id}.` })
    } catch (error) {
      setQuarantineNotice({ error: true, message: QUARANTINE_ERRORS[error.code] || error.message })
    } finally {
      setQuarantining(false)
      setQuarantineTarget(null)
      resource.refresh()
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="NOVA / NEUTRON INVENTORY"
        title="Máy ảo"
        resource={resource}
      />
      {resource.meta?.source_mode === 'LIVE' && (
        <div className="v4-snapshot-notice">
          <strong>
            Nova / Neutron · inventory thật · cập nhật theo chu kỳ{' '}
            {resource.meta.refresh_seconds || 15} giây khi mở trang
          </strong>
          <p>
            Project: {display(resource.meta.project_id)} · Quan sát gần nhất{' '}
            {time(resource.meta.data_as_of)}.
          </p>
          {staleLive && (
            <p role="status">
              Chưa đọc được kết quả mới; đang giữ dữ liệu lần thành công trước
              với nhãn STALE. {resource.meta.last_error_code || ''}
            </p>
          )}
          {classificationMissing && (
            <p>Chưa xác định được Security Group cô lập cho project này.</p>
          )}
        </div>
      )}
      <form
        className="panel v4-filters"
        onSubmit={(event) => {
          event.preventDefault()
          const query = new URLSearchParams(
            Object.entries(draft).filter(([, value]) => value)
          ).toString()
          window.location.hash = `/workloads${query ? `?${query}` : ''}`
        }}
      >
        <Filter label="Tên máy ảo">
          <input
            placeholder="Tìm tên VM"
            value={draft.name || ''}
            maxLength={128}
            onChange={(event) =>
              setDraft((current) => ({ ...current, name: event.target.value }))
            }
          />
        </Filter>
        <Filter label="Mã project">
          <input
            value={draft.project_id || ''}
            maxLength={64}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                project_id: event.target.value,
              }))
            }
            placeholder="UUID project"
          />
        </Filter>
        <SelectFilter
          label="Trạng thái hoạt động"
          value={draft.network_state}
          onChange={(value) =>
            setDraft((current) => ({ ...current, network_state: value }))
          }
          options={[
            ['', 'Tất cả'],
            ...Object.entries(ACTIVITY_LABELS).map(([value, label]) => [
              value,
              label,
              classificationMissing,
            ]),
          ]}
        />
        <button className="button primary">Áp dụng</button>
        <a className="text-button" href="#/workloads">
          Đặt lại
        </a>
      </form>
      <Panel
        title="Danh sách máy ảo"
        subtitle="Số VM và port được đọc động từ OpenStack"
        resource={resource}
      >
        <p className="muted">Nhãn Bình thường cho biết các cổng của VM chưa gắn Security Group cô lập.</p>
        {quarantineNotice && (
          <p role={quarantineNotice.error ? 'alert' : 'status'}>{quarantineNotice.message}</p>
        )}
        {quarantineTarget && (
          <div className="v4-inline-warning" role="group" aria-label="Xác nhận cô lập máy ảo">
            <p>
              Thay Security Group trên mọi cổng mạng của <strong>{quarantineTarget.name || quarantineTarget.server_id}</strong>{' '}
              bằng Security Group cô lập. Máy có thể mất kết nối mạng.
            </p>
            <button type="button" className="button primary" disabled={quarantining || !canQuarantine} onClick={quarantine}>
              {quarantining ? 'Đang cô lập…' : 'Xác nhận cô lập'}
            </button>{' '}
            <button type="button" className="button secondary" disabled={quarantining} onClick={() => setQuarantineTarget(null)}>
              Hủy
            </button>
          </div>
        )}
        {resource.data &&
          (resource.data.length ? (
            <div className="table-scroll">
              <table className="v4-table">
                <thead>
                  <tr>
                    <th>MÁY ẢO / PROJECT</th>
                    <th>STATUS</th>
                    <th>IP NỘI BỘ / FLOATING IP</th>
                    <th>SECURITY GROUP</th>
                    <th>RỦI RO LIÊN QUAN</th>
                    <th>QUAN SÁT</th>
                    <th>
                      Thao tác
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {resource.data.map((vm) => (
                    <tr key={vm.server_id}>
                      <td>
                        <a
                          className="v4-id-link"
                          href={`#/workloads/${encodeURIComponent(vm.server_id)}`}
                        >
                          {vm.name || vm.server_id}
                        </a>
                        <small>{display(vm.project_id)}</small>
                      </td>
                      <td>
                        {isVerifiedNetwork(
                          vm.network_observation,
                          resource.meta,
                          Boolean(resource.error)
                        ) ? (
                          <Badge value={vm.network_observation.state}>
                            {ACTIVITY_LABELS[vm.network_observation.state]}
                          </Badge>
                        ) : (
                          <Badge value={staleLive ? 'STALE' : vm.network_state === 'MISMATCH' ? 'MISMATCH' : 'UNKNOWN'}>
                            {staleLive ? 'Dữ liệu cũ' : vm.network_state === 'MISMATCH' ? 'Cô lập một phần' : 'Chưa xác minh'}
                          </Badge>
                        )}
                      </td>
                      <td>
                        {vm.ports.length
                          ? vm.ports.map((port, index) => (
                              <div
                                className="v4-port-brief"
                                key={port.port_id || index}
                              >
                                <code>
                                  {port.fixed_ips.join(', ') ||
                                    'Chưa có fixed IP'}
                                </code>
                                <small>
                                  FIP: {port.floating_ips.join(', ') || '—'}
                                </small>
                              </div>
                            ))
                          : 'Chưa có thông tin port'}
                      </td>
                      <td>
                        {vm.ports.map((port, index) => (
                          <div
                            className="v4-port-brief"
                            key={port.port_id || index}
                          >
                            <small>Port {port.port_id || 'Chưa có ID'}</small>
                            <SecurityGroups
                              groups={port.security_groups}
                              provided={port.security_groups_provided}
                            />
                          </div>
                        ))}
                      </td>
                      <td>
                        <RiskExposure
                          compact
                          exposure={vm.risk_exposure}
                          meta={resource.meta}
                          error={resource.error}
                        />
                      </td>
                      <td>{time(vm.observed_at)}</td>
                      <td>
                        <button
                          type="button"
                          className="button secondary"
                          aria-label={`Cô lập ${vm.name || vm.server_id}`}
                          disabled={!canQuarantine || Boolean(quarantineTarget) ||
                            !isVerifiedNetwork(vm.network_observation, resource.meta, Boolean(resource.error)) ||
                            vm.network_observation.state !== 'NORMAL'}
                          title={!canQuarantine ? 'Cần phiên Executor và quyền ghi Neutron đã cấu hình' : undefined}
                          onClick={() => { setQuarantineNotice(null); setQuarantineTarget(vm) }}
                        >
                          Cô lập
                        </button>{' '}
                        <a
                          className="row-detail"
                          href={`#/workloads/${encodeURIComponent(vm.server_id)}`}
                          aria-label={`Xem workload ${vm.name || vm.server_id}`}
                        >
                          <ArrowUpRight size={16} />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              title="Không có máy ảo trong phạm vi truy cập"
              text="Inventory phụ thuộc quyền đọc Nova/Neutron của Portal."
            />
          ))}
        <CursorPager resource={resource} {...pager} />
      </Panel>
    </>
  )
}

function PortsPanel({ vmId, selectedPort }) {
  const time = useTime()
  const resource = useV4Resource(
    `/workloads/${encodeURIComponent(vmId)}/ports`,
    {
      interval: 15000,
      transform: (data) =>
        mapWorkload({ server_id: vmId, ports: readCollection(data, 'ports') })
          .ports,
    }
  )
  return (
    <Panel
      title="Port mạng và Security Group"
      subtitle="Mỗi port được hiển thị riêng, không tự chọn port đầu tiên"
      resource={resource}
    >
      {selectedPort &&
        resource.data &&
        !resource.data.some((port) => port.port_id === selectedPort) && (
          <p className="v4-panel-note" role="status">
            Port từ liên kết sự cố không còn thuộc VM này trong inventory
            hiện tại. Hãy đọc lại đối chiếu tại sự cố.
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
                    ? { outline: '2px solid var(--accent, #38bdf8)' }
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
                <div className="v4-copy-row">
                  <Server size={17} />
                  <strong>{port.port_id || 'Port chưa có ID'}</strong>
                  <CopyId value={port.port_id} />
                </div>
                <FieldGrid
                  rows={[
                    ['Project', display(port.project_id)],
                    ['Device ID', display(port.device_id)],
                    ['Device owner', display(port.device_owner)],
                    ['Port status', uiLabel(port.status)],
                    ['MAC', display(port.mac_address)],
                    ['Network', display(port.network_id)],
                    ["IP nội bộ", port.fixed_ips.join(' · ') || '—'],
                    ['Floating IP', port.floating_ips.join(' · ') || '—'],
                    ['Port Security', display(port.port_security_enabled)],
                    ['Quan sát lúc', time(port.observed_at)],
                    [
                      'Subnet / fixed IP',
                      port.fixed_ip_details
                        .map(
                          (ip) =>
                            `${ip.ip_address || '—'} / ${ip.subnet_id || 'Chưa có subnet'}`
                        )
                        .join(' · ') || 'Chưa cung cấp',
                    ],
                  ]}
                />
                <h3 className="v4-subheading">Security Group theo nguồn</h3>
                <SecurityGroups
                  groups={port.security_groups}
                  provided={port.security_groups_provided}
                />
              </article>
            ))}
          </div>
        ) : (
          <Empty title="Không có port trong phạm vi truy cập" />
        ))}
    </Panel>
  )
}

export function ActionHistory({ serverId, incidentId }) {
  const time = useTime()
  const resource = useV4Resource('/actions', {
    params: { server_id: serverId, incident_id: incidentId, limit: 25 },
    interval: 5000,
    transform: (data) => readCollection(data, 'actions'),
  })
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
                  <th>HÀNH ĐỘNG / SỰ CỐ</th>
                  <th>KẾT QUẢ GHI NHẬN</th>
                  <th>THỜI ĐIỂM</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((action, index) => (
                  <tr key={action.action_id || index}>
                    <td>
                      {typeof action.action_id === 'string' ? (
                        <a
                          className="v4-id-link"
                          href={`#/actions/${encodeURIComponent(action.action_id)}`}
                        >
                          {action.action_id}
                        </a>
                      ) : (
                        "Chưa có hành động ID"
                      )}
                      {typeof action.incident_id === 'string' && (
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
            text="Không suy ra hành động cách ly từ điểm rủi ro hoặc trạng thái incident."
          />
        ))}
    </Panel>
  )
}

export function WorkloadDetail({ id, params = {} }) {
  const { sessionAuthEnabled } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/workloads/${encodeURIComponent(id)}`, {
    interval: 15000,
    transform: mapWorkload,
  })
  const vm = resource.data
  const activeTab = params.tab === 'console' ? 'console' : 'overview'
  const tabHref = (tab) =>
    `#/workloads/${encodeURIComponent(id)}?${new URLSearchParams({ tab, ...(params.port_id ? { port_id: params.port_id } : {}) })}`
  return (
    <>
      <a className="incident-back" href="#/workloads">
        <ArrowLeft size={15} />
        Máy ảo
      </a>
      <PageHeading
        eyebrow="WORKLOAD SECURITY CONTEXT"
        title={vm?.name || "Chi tiết máy ảo"}
        description={id}
        resource={resource}
      >
        <CopyId value={id} />
      </PageHeading>
      <SourceStatus resource={resource} label="Nova / Neutron" />
      <ResourceNotice resource={resource} noun="workload" />
      <nav className="v4-system-tabs" aria-label="Chi tiết máy ảo">
        <a
          className={activeTab === 'overview' ? 'active' : ''}
          aria-current={activeTab === 'overview' ? 'page' : undefined}
          href={tabHref('overview')}
        >
          <LayoutDashboard size={15} />Tổng quan</a>
        <a
          className={activeTab === 'console' ? 'active' : ''}
          aria-current={activeTab === 'console' ? 'page' : undefined}
          href={tabHref('console')}
        >
          <Monitor size={15} />
          Console
        </a>
      </nav>
      {activeTab === 'console' &&
        (sessionAuthEnabled ? (
          <p role="status">Console đang tắt trong chế độ phiên đăng nhập.</p>
        ) : (
          vm && (
            <WorkloadConsole
              vm={vm}
              meta={resource.meta}
              error={resource.error}
            />
          )
        ))}
      {vm && activeTab === 'overview' && (
        <section aria-label="Overview máy ảo">
          <div className="v4-detail-grid">
            <Panel title="Thông tin định danh">
              <Badge
                value={
                  freshness(resource.meta, Boolean(resource.error)) === 'FRESH'
                    ? vm.nova_status
                    : 'UNKNOWN'
                }
              />
              <FieldGrid
                rows={[
                  ["Mã máy ảo", vm.server_id],
                  ['Project', display(vm.project_id)],
                  ['Compute host', display(vm.compute_host)],
                  ['Vai trò', uiLabel(vm.role)],
                  ["Protected máy ảo", display(vm.protected)],
                  ['Quan sát lúc', time(vm.observed_at)],
                ]}
              />
            </Panel>
            <Panel title="Thông tin bảo mật">
              <NetworkObservation
                observation={vm.network_observation}
                meta={resource.meta}
                error={resource.error}
              />
              <p className="v4-panel-note">
                Nova ACTIVE thể hiện trạng thái VM. Trạng thái mạng và cách ly
                cần được xác minh riêng bằng Neutron.
              </p>
              {vm.incident_refs.length ? (
                <div className="v4-link-list">
                  {vm.incident_refs.map((incident) => (
                    <a
                      key={incident}
                      href={`#/incidents/${encodeURIComponent(incident)}`}
                    >
                      {incident}
                      <ArrowUpRight size={15} />
                    </a>
                  ))}
                </div>
              ) : (
                <p className="v4-panel-note">
                  Chưa có sự cố liên quan được nguồn cung cấp.
                </p>
              )}
              <div className="v4-action-boundary">
                <button className="button secondary" disabled>
                  <LockKeyhole size={14} />
                  Cách ly / khôi phục · Chưa bật
                </button>
                {vm.protected && <p>Máy ảo được bảo vệ, không được phép cách ly.</p>}
              </div>
            </Panel>
          </div>
          <Panel
            title="Mức rủi ro liên quan từ sự cố gần đây"
            subtitle="Theo cửa sổ và nguồn không suy từ trạng thái Nova"
          >
            <RiskExposure
              exposure={vm.risk_exposure}
              meta={resource.meta}
              error={resource.error}
            />
          </Panel>
          <PortsPanel vmId={id} selectedPort={params.port_id} />
          <ActionHistory serverId={id} />
        </section>
      )}
    </>
  )
}

export function ActionDetail({ id }) {
  const time = useTime()
  const resource = useV4Resource(`/actions/${encodeURIComponent(id)}`, {
    interval: 5000,
  })
  const action = resource.data
  const groups = (value) =>
    Array.isArray(value)
      ? value.filter((item) => typeof item === 'string').join(' · ') ||
        'Không có SG'
      : "Chưa có bằng chứng"
  return (
    <>
      <a className="incident-back" href="#/workloads">
        <ArrowLeft size={15} />
        Máy ảo
      </a>
      <PageHeading
        eyebrow="CHI TIẾT XỬ LÝ"
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
                  'Incident',
                  typeof action.incident_id === 'string' ? (
                    <a
                      className="v4-id-link"
                      href={`#/incidents/${encodeURIComponent(action.incident_id)}`}
                    >
                      {action.incident_id}
                    </a>
                  ) : (
                    '—'
                  ),
                ],
                ["Mã port", display(action.target?.port_id)],
                ['Tạo lúc', time(action.started_at)],
                ['Verify lúc', time(action.finished_at)],
                ['Original SGs', groups(action.before_sgs)],
                ['During SGs', groups(action.during_sgs)],
                ['After SGs', groups(action.after_sgs)],
              ]}
            />
          </Panel>
          <Panel title="SG lifecycle">
            <LoadedSgLifecycle actionId={id} />
          </Panel>
        </div>
      )}
    </>
  )
}
