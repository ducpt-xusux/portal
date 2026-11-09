import { LoadedSgLifecycle } from '../features/n91-investigation/Investigation'
import { useState } from 'react'
import { ArrowLeft, ArrowUpRight, LayoutDashboard, LockKeyhole, Monitor, Server } from 'lucide-react'
import { freshness, isVerifiedNetwork, mapWorkload, readCollection } from '../services/portalApi'
import { useCursor, useV4Resource, NetworkObservation } from './IncidentPages'
import { RiskExposure, SecurityGroups } from './InvestigationUI'
import { Badge, CopyId, CursorPager, Empty, FieldGrid, Filter, PageHeading, Panel, ResourceNotice, SelectFilter, SourceStatus, display, useTime } from './PortalUI'
import WorkloadConsole from './WorkloadConsole'
import { usePortal } from './PortalContext'
import './WorkloadConsole.css'

export function WorkloadsPage({ params }) {
  const time = useTime()
  const [draft, setDraft] = useState(params)
  const pager = useCursor()
  const resource = useV4Resource('/workloads', { params: { ...params, limit: 25, cursor: pager.cursor }, interval: 15000, transform: data => readCollection(data, 'workloads').map(mapWorkload) })
  const classificationMissing = resource.meta?.network_classification === 'NOT_CONFIGURED'
  const staleLive = resource.meta?.source_mode === 'LIVE' && freshness(resource.meta, Boolean(resource.error)) !== 'FRESH'
  return <><PageHeading eyebrow="NOVA / NEUTRON INVENTORY" title="Workloads" description="Đối chiếu nguồn sự kiện với VM, network port và Security Groups." resource={resource} />
    {resource.meta?.source_mode === 'LIVE' && <div className="v4-snapshot-notice"><strong>Nova / Neutron · inventory thật · cập nhật theo chu kỳ {resource.meta.refresh_seconds || 15} giây khi mở trang</strong><p>Project: {display(resource.meta.project_id)} · Quan sát gần nhất {time(resource.meta.data_as_of)}.</p>{staleLive && <p role="status">Chưa đọc được kết quả mới; đang giữ dữ liệu lần thành công trước với nhãn STALE. {resource.meta.last_error_code || ''}</p>}<p>Trạng thái VM, IP và SG là quan sát từ OpenStack. Phân loại vai trò, incident exposure và xác minh cách ly cần nguồn riêng.</p></div>}
    <form className="panel v4-filters" onSubmit={event => { event.preventDefault(); const query = new URLSearchParams(Object.entries(draft).filter(([, value]) => value)).toString(); window.location.hash = `/workloads${query ? `?${query}` : ''}` }}><Filter label="Tên workload"><input placeholder="Tìm tên VM" value={draft.name || ''} maxLength={128} onChange={event => setDraft(current => ({ ...current, name: event.target.value }))} /></Filter><Filter label="Project ID"><input value={draft.project_id || ''} maxLength={64} onChange={event => setDraft(current => ({ ...current, project_id: event.target.value }))} placeholder="Project UUID" /></Filter><SelectFilter label="Network state" value={draft.network_state} onChange={value => setDraft(current => ({ ...current, network_state: value }))} options={[['', 'Tất cả'], ...['NORMAL', 'QUARANTINED', 'MISMATCH', 'UNKNOWN'].map(value => [value, value, classificationMissing && value !== 'UNKNOWN'])]} /><button className="button primary">Áp dụng</button><a className="text-button" href="#/workloads">Đặt lại</a></form>
    <Panel title="Workload inventory" subtitle="Số VM và port được đọc động từ OpenStack" resource={resource}>{resource.data && (resource.data.length ? <div className="table-scroll"><table className="v4-table"><thead><tr><th>WORKLOAD / PROJECT</th><th>VAI TRÒ</th><th>NOVA / NETWORK</th><th>FIXED / FLOATING IP</th><th>SECURITY GROUPS</th><th>INCIDENT EXPOSURE</th><th>QUAN SÁT</th><th><span className="sr-only">Chi tiết</span></th></tr></thead><tbody>{resource.data.map(vm => <tr key={vm.server_id}><td><a className="v4-id-link" href={`#/workloads/${encodeURIComponent(vm.server_id)}`}>{vm.name || vm.server_id}</a><small>{display(vm.project_id)}</small></td><td><span className="v4-role-label">{vm.protected === true && <LockKeyhole size={13} />}{vm.protected === true ? 'PROTECTED' : vm.role || 'Chưa phân loại'}</span></td><td><Badge value={freshness(resource.meta, Boolean(resource.error)) === 'FRESH' ? vm.nova_status : 'UNKNOWN'} /><small><Badge value={isVerifiedNetwork(vm.network_observation, resource.meta, Boolean(resource.error)) ? vm.network_observation.state : 'UNKNOWN'} /></small></td><td>{vm.ports.length ? vm.ports.map((port, index) => <div className="v4-port-brief" key={port.port_id || index}><code>{port.fixed_ips.join(', ') || 'Chưa có fixed IP'}</code><small>FIP: {port.floating_ips.join(', ') || '—'}</small></div>) : 'Chưa có thông tin port'}</td><td>{vm.ports.map((port, index) => <div className="v4-port-brief" key={port.port_id || index}><small>Port {port.port_id || 'Chưa có ID'}</small><SecurityGroups groups={port.security_groups} provided={port.security_groups_provided} /></div>)}</td><td><RiskExposure compact exposure={vm.risk_exposure} meta={resource.meta} error={resource.error} /></td><td>{time(vm.observed_at)}</td><td><a className="row-detail" href={`#/workloads/${encodeURIComponent(vm.server_id)}`} aria-label={`Xem workload ${vm.name || vm.server_id}`}><ArrowUpRight size={16} /></a></td></tr>)}</tbody></table></div> : <Empty title="Không có workload trong phạm vi truy cập" text="Inventory phụ thuộc quyền đọc Nova/Neutron của Portal." />)}<CursorPager resource={resource} {...pager} /></Panel>
  </>
}

function PortsPanel({ vmId, selectedPort }) {
  const time = useTime()
  const resource = useV4Resource(`/workloads/${encodeURIComponent(vmId)}/ports`, { interval: 15000, transform: data => mapWorkload({ server_id: vmId, ports: readCollection(data, 'ports') }).ports })
  return <Panel title="Network ports & Security Groups" subtitle="Mỗi port được hiển thị riêng, không tự chọn port đầu tiên" resource={resource}>{selectedPort && resource.data && !resource.data.some(port => port.port_id === selectedPort) && <p className="v4-panel-note" role="status">Port từ liên kết incident không còn thuộc VM này trong inventory hiện tại. Hãy đọc lại mapping tại incident.</p>}{resource.data && (resource.data.length ? <div className="v4-port-grid">{resource.data.map((port, index) => <article className="v4-port-card" style={selectedPort === port.port_id ? { outline: '2px solid var(--accent, #38bdf8)' } : undefined} key={port.port_id || index}>{selectedPort === port.port_id && <p className="v4-panel-note"><strong>Port được mở từ đối chiếu Source IP của incident</strong></p>}<div className="v4-copy-row"><Server size={17} /><strong>{port.port_id || 'Port chưa có ID'}</strong><CopyId value={port.port_id} /></div><FieldGrid rows={[
    ['Project', display(port.project_id)], ['Device ID', display(port.device_id)], ['Device owner', display(port.device_owner)], ['Port status', display(port.status)], ['MAC', display(port.mac_address)], ['Network', display(port.network_id)], ['Fixed IP', port.fixed_ips.join(' · ') || '—'], ['Floating IP', port.floating_ips.join(' · ') || '—'],
    ['Port Security', display(port.port_security_enabled)], ['Quan sát lúc', time(port.observed_at)], ['Subnet / fixed IP', port.fixed_ip_details.map(ip => `${ip.ip_address || '—'} / ${ip.subnet_id || 'Chưa có subnet'}`).join(' · ') || 'Chưa cung cấp'],
  ]} /><h3 className="v4-subheading">Security Groups theo nguồn</h3><SecurityGroups groups={port.security_groups} provided={port.security_groups_provided} /></article>)}</div> : <Empty title="Không có port trong phạm vi truy cập" />)}</Panel>
}

export function ActionHistory({ serverId, incidentId }) {
  const time = useTime()
  const resource = useV4Resource('/actions', { params: { server_id: serverId, incident_id: incidentId, limit: 25 }, interval: 5000, transform: data => readCollection(data, 'actions') })
  return <Panel title="Action history" subtitle="Bản ghi hành động · trạng thái hiện tại cần Neutron live" resource={resource}>{resource.data && (resource.data.length ? <div className="table-scroll"><table className="v4-table"><thead><tr><th>ACTION / INCIDENT</th><th>KẾT QUẢ GHI NHẬN</th><th>THỜI ĐIỂM</th></tr></thead><tbody>{resource.data.map((action, index) => <tr key={action.action_id || index}><td>{typeof action.action_id === 'string' ? <a className="v4-id-link" href={`#/actions/${encodeURIComponent(action.action_id)}`}>{action.action_id}</a> : 'Chưa có action ID'}{typeof action.incident_id === 'string' && <a className="v4-id-link" href={`#/incidents/${encodeURIComponent(action.incident_id)}`}>{action.incident_id}</a>}</td><td><Badge value={action.action_state} /></td><td>{time(action.started_at || action.finished_at)}</td></tr>)}</tbody></table></div> : <Empty title="Chưa có bản ghi hành động" text="Không suy ra hành động cách ly từ điểm rủi ro hoặc trạng thái incident." />)}</Panel>
}

export function WorkloadDetail({ id, params = {} }) {
  const { sessionAuthEnabled } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/workloads/${encodeURIComponent(id)}`, { interval: 15000, transform: mapWorkload })
  const vm = resource.data
  const activeTab = params.tab === 'console' ? 'console' : 'overview'
  const tabHref = tab => `#/workloads/${encodeURIComponent(id)}?${new URLSearchParams({ tab, ...(params.port_id ? { port_id: params.port_id } : {}) })}`
  return <><a className="incident-back" href="#/workloads"><ArrowLeft size={15} />Workloads</a><PageHeading eyebrow="WORKLOAD SECURITY CONTEXT" title={vm?.name || 'Chi tiết workload'} description={id} resource={resource}><CopyId value={id} /></PageHeading><SourceStatus resource={resource} label="Nova / Neutron" /><ResourceNotice resource={resource} noun="workload" />
    <nav className="v4-system-tabs" aria-label="Chi tiết workload"><a className={activeTab === 'overview' ? 'active' : ''} aria-current={activeTab === 'overview' ? 'page' : undefined} href={tabHref('overview')}><LayoutDashboard size={15} />Overview</a><a className={activeTab === 'console' ? 'active' : ''} aria-current={activeTab === 'console' ? 'page' : undefined} href={tabHref('console')}><Monitor size={15} />Console</a></nav>
    {activeTab === 'console' && (sessionAuthEnabled
      ? <p role="status">Console đang tắt trong chế độ session.</p>
      : vm && <WorkloadConsole vm={vm} meta={resource.meta} error={resource.error} />)}
    {vm && activeTab === 'overview' && <section aria-label="Overview workload"><div className="v4-detail-grid"><Panel title="Identity"><Badge value={freshness(resource.meta, Boolean(resource.error)) === 'FRESH' ? vm.nova_status : 'UNKNOWN'} /><FieldGrid rows={[
      ['Server ID', vm.server_id], ['Project', display(vm.project_id)], ['Compute host', display(vm.compute_host)], ['Vai trò', display(vm.role)],
      ['Protected workload', display(vm.protected)], ['Quan sát lúc', time(vm.observed_at)],
    ]} /></Panel><Panel title="Security context"><NetworkObservation observation={vm.network_observation} meta={resource.meta} error={resource.error} /><p className="v4-panel-note">Nova ACTIVE thể hiện trạng thái VM. Trạng thái mạng và cách ly cần được xác minh riêng bằng Neutron.</p>{vm.incident_refs.length ? <div className="v4-link-list">{vm.incident_refs.map(incident => <a key={incident} href={`#/incidents/${encodeURIComponent(incident)}`}>{incident}<ArrowUpRight size={15} /></a>)}</div> : <p className="v4-panel-note">Chưa có incident liên quan được nguồn cung cấp.</p>}<div className="v4-action-boundary"><button className="button secondary" disabled><LockKeyhole size={14} />Isolate / Restore · Phase 2</button><p>{vm.protected ? 'Workload được bảo vệ, không được phép cách ly trong demo.' : 'Phản ứng qua Portal chỉ bật sau khi Broker, allowlist, phê duyệt và rollback đã được nghiệm thu.'}</p></div></Panel></div><Panel title="Risk exposure từ incident gần đây" subtitle="Theo cửa sổ và nguồn P17 · không suy từ trạng thái Nova"><RiskExposure exposure={vm.risk_exposure} meta={resource.meta} error={resource.error} /></Panel><PortsPanel vmId={id} selectedPort={params.port_id} /><ActionHistory serverId={id} /></section>}
  </>
}

export function ActionDetail({ id }) {
  const time = useTime()
  const resource = useV4Resource(`/actions/${encodeURIComponent(id)}`, { interval: 5000 })
  const action = resource.data
  const groups = value => Array.isArray(value) ? value.filter(item => typeof item === 'string').join(' · ') || 'Không có SG' : 'Chưa có evidence'
  return <><a className="incident-back" href="#/workloads"><ArrowLeft size={15} />Workloads</a><PageHeading eyebrow="RESPONSE EVIDENCE" title="Chi tiết action" description={id} resource={resource} /><SourceStatus resource={resource} label="P17.5 evidence + Neutron" /><ResourceNotice resource={resource} noun="action" />{action && <div className="v4-detail-grid"><Panel title="Action record"><Badge value={action.action_state} /><FieldGrid rows={[
    ['Action ID', display(action.action_id)], ['Incident', typeof action.incident_id === 'string' ? <a className="v4-id-link" href={`#/incidents/${encodeURIComponent(action.incident_id)}`}>{action.incident_id}</a> : '—'],
    ['Port ID', display(action.target?.port_id)], ['Tạo lúc', time(action.started_at)], ['Verify lúc', time(action.finished_at)], ['Original SGs', groups(action.before_sgs)], ['During SGs', groups(action.during_sgs)], ['After SGs', groups(action.after_sgs)],
  ]} /></Panel><Panel title="SG lifecycle"><LoadedSgLifecycle actionId={id} /></Panel></div>}</>
}
