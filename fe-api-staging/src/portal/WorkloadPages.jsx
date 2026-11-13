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
  mapWorkload,
  portalRequest,
  readCollection,
  workloadNetworkStatus,
} from '../services/portalApi'
import { useCursor, useV4Resource } from './IncidentPages'
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

const NETWORK_LABELS = {
  NORMAL: 'Bình thường',
  QUARANTINED: 'Đã cô lập',
  MISMATCH: 'Cô lập không đồng nhất',
  UNKNOWN: 'Chưa xác minh',
  STALE: 'Dữ liệu cũ',
}

function NetworkStatusBadge({ state }) {
  return <Badge value={state}>{NETWORK_LABELS[state] || NETWORK_LABELS.UNKNOWN}</Badge>
}

function NetworkHistory({ entries }) {
  const time = useTime()
  const changes = entries.filter((entry) => entry.previous_state)
  const lastIsolation = entries.find((entry) => entry.state === 'QUARANTINED')
  if (!changes.length && !lastIsolation) return null
  return (
    <details>
      <summary>
        {lastIsolation ? `Cô lập gần nhất · ${time(lastIsolation.observed_at)}` : 'Lịch sử trạng thái mạng'}
      </summary>
      <ul>
        {entries.map((entry) => (
          <li key={`${entry.observed_at}:${entry.state}`}>
            {time(entry.observed_at)} · {entry.previous_state && `${NETWORK_LABELS[entry.previous_state]} → `}
            {NETWORK_LABELS[entry.state] || NETWORK_LABELS.UNKNOWN}
          </li>
        ))}
      </ul>
    </details>
  )
}

const QUARANTINE_ERRORS = {
  QUARANTINE_RESTORE_UNVERIFIED: 'Chưa xác minh được khôi phục nhóm bảo mật cũ. Kiểm tra các cổng trong Neutron trước khi thử lại.',
  QUARANTINE_APPLIED_AUDIT_INCOMPLETE: 'Neutron đã xác nhận cô lập. Chưa ghi được kết quả vào nhật ký Portal.',
  QUARANTINE_SG_NOT_EMPTY_OR_OUTSIDE_PROJECT: 'Security Group cô lập phải thuộc project và không có luật cho phép.',
}

function WorkloadQuarantine({ vm, resource }) {
  const { auth, workloadQuarantineAvailable } = usePortal()
  const [confirming, setConfirming] = useState(false)
  const [quarantining, setQuarantining] = useState(false)
  const [quarantineNotice, setQuarantineNotice] = useState(null)
  const name = vm.name || vm.server_id
  const networkState = workloadNetworkStatus(vm.network_observation, resource.meta, Boolean(resource.error))
  const unavailable = vm.protected
    ? 'Máy ảo này được bảo vệ.'
    : networkState === 'QUARANTINED'
      ? 'Máy ảo đã được cô lập.'
      : !workloadQuarantineAvailable
        ? 'Portal chưa được cấu hình quyền cô lập.'
        : !auth.csrfToken || !auth.user?.roles?.includes('Executor')
          ? 'Cần đăng nhập bằng tài khoản có vai trò Executor.'
          : networkState !== 'NORMAL'
            ? 'Cần xác minh trạng thái mạng Bình thường trước khi cô lập.'
            : null

  async function quarantine() {
    if (unavailable || quarantining) return
    setQuarantining(true)
    setQuarantineNotice(null)
    try {
      const { data } = await portalRequest(`/workloads/${encodeURIComponent(vm.server_id)}/quarantine`, {
        method: 'POST',
        csrfToken: auth.csrfToken,
        body: { confirm: 'QUARANTINE' },
        timeout: 90000,
      })
      const message = `Neutron đã xác nhận cô lập ${name}.`
      setQuarantineNotice(data?.history_saved === false
        ? { error: true, message: `${message} Chưa lưu được lịch sử trạng thái.` }
        : { message })
    } catch (error) {
      setQuarantineNotice({ error: true, message: QUARANTINE_ERRORS[error.code] || error.message })
    } finally {
      setQuarantining(false)
      setConfirming(false)
      resource.refresh()
    }
  }

  return (
    <Panel
      title="Cô lập máy ảo"
      subtitle="Áp dụng Security Group cô lập cho tất cả cổng mạng của máy ảo."
      action={!confirming && (
        <button
          type="button"
          className="button secondary"
          disabled={Boolean(unavailable) || resource.loading}
          onClick={() => { setQuarantineNotice(null); setConfirming(true) }}
        >
          <LockKeyhole size={15} aria-hidden="true" />
          Cô lập
        </button>
      )}
    >
      {unavailable && !quarantining && <p className="v4-panel-note">{unavailable}</p>}
      {quarantineNotice && (
        <p className="v4-panel-note" role={quarantineNotice.error ? 'alert' : 'status'}>
          {quarantineNotice.message}
        </p>
      )}
      {confirming && (
        <div className="v4-inline-warning" role="group" aria-label="Xác nhận cô lập máy ảo">
          <p><strong>{name}</strong> có thể mất kết nối mạng sau khi cô lập.</p>
          <div className="v4-workload-quarantine-actions">
            <button type="button" className="button secondary" disabled={quarantining} onClick={() => setConfirming(false)}>
              Hủy
            </button>
            <button type="button" className="button primary" disabled={Boolean(unavailable) || quarantining || resource.loading} onClick={quarantine}>
              {quarantining ? 'Đang cô lập…' : 'Xác nhận cô lập'}
            </button>
          </div>
        </div>
      )}
    </Panel>
  )
}

export function WorkloadsPage({ params }) {
  const time = useTime()
  const [draft, setDraft] = useState(params)
  const pager = useCursor()
  const resource = useV4Resource('/workloads', {
    params: { ...params, limit: 25, cursor: pager.cursor },
    interval: 15000,
    transform: (data) => readCollection(data, 'workloads').map(mapWorkload),
  })
  const classificationMissing =
    resource.meta?.network_classification === 'NOT_CONFIGURED'
  const live = resource.meta?.source_mode === 'LIVE'
  const staleLive = live && freshness(resource.meta, Boolean(resource.error)) !== 'FRESH'
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
            {resource.meta.refresh_seconds || 15} giây
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
          {resource.meta.network_history_error && (
            <p role="status">Lịch sử trạng thái mạng tạm thời không truy cập được.</p>
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
          label="Trạng thái mạng"
          value={draft.network_state}
          onChange={(value) =>
            setDraft((current) => ({ ...current, network_state: value }))
          }
          options={[
            ['', 'Tất cả'],
            ...Object.entries(NETWORK_LABELS).filter(([value]) => value !== 'STALE').map(([value, label]) => [
              value,
              label,
              value !== 'UNKNOWN' && classificationMissing,
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
        {resource.data &&
          (resource.data.length ? (
            <div className="table-scroll">
              <table className="v4-table">
                <thead>
                  <tr>
                    <th>MÁY ẢO / PROJECT</th>
                    <th>TRẠNG THÁI NOVA</th>
                    <th>TRẠNG THÁI MẠNG</th>
                    <th>IP NỘI BỘ / FLOATING IP</th>
                    <th>SECURITY GROUP</th>
                    <th>RỦI RO LIÊN QUAN</th>
                    <th>QUAN SÁT</th>
                    <th>
                      <span className="sr-only">Chi tiết</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {resource.data.map((vm) => {
                    const state = workloadNetworkStatus(
                      vm.network_observation, resource.meta, Boolean(resource.error)
                    )
                    const nova = live ? vm.nova_status : null
                    return (
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
                        <Badge value={staleLive ? 'STALE' : nova || 'UNKNOWN'}>
                          {staleLive ? 'Dữ liệu cũ' : nova || 'Chưa xác minh'}
                        </Badge>
                      </td>
                      <td>
                        <NetworkStatusBadge state={state} />
                        <NetworkHistory entries={vm.network_history} />
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
                            <NetworkStatusBadge state={workloadNetworkStatus({
                              state: port.network_state,
                              observed_at: port.observed_at,
                              verification: live ? 'LIVE_NEUTRON_READ' : null,
                            }, resource.meta, Boolean(resource.error))} />
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
                      <td>{time(vm.network_observed_at)}</td>
                      <td>
                        <a
                          className="row-detail"
                          href={`#/workloads/${encodeURIComponent(vm.server_id)}`}
                          aria-label={`Xem workload ${vm.name || vm.server_id}`}
                        >
                          <ArrowUpRight size={16} />
                        </a>
                      </td>
                    </tr>
                    )
                  })}
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
                    ['Trạng thái mạng', <NetworkStatusBadge state={workloadNetworkStatus({
                      state: port.network_state,
                      observed_at: port.observed_at,
                      verification: resource.meta?.source_mode === 'LIVE' ? 'LIVE_NEUTRON_READ' : null,
                    }, resource.meta, Boolean(resource.error))} />],
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
              <FieldGrid rows={[
                ['Trạng thái mạng', <NetworkStatusBadge state={
                  workloadNetworkStatus(vm.network_observation, resource.meta, Boolean(resource.error))
                } />],
                ['Quan sát Neutron lúc', time(vm.network_observed_at)],
              ]} />
              <NetworkHistory entries={vm.network_history} />
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
          <WorkloadQuarantine key={vm.server_id} vm={vm} resource={resource} />
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
