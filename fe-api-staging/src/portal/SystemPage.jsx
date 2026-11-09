import { RulesExplorer } from '../features/n91-investigation/Investigation'
import { Activity, Database, Layers, Network } from 'lucide-react'
import { BusinessAdminPanel } from '../features/n91-business'
import EvaluationSystemTabs from '../features/n91-evaluation/EvaluationSystemTabs'
import { freshness, readCollection } from '../services/portalApi'
import { useV4Resource } from './IncidentPages'
import ProxyServicesPanel from './ProxyServicesPanel'
import GaleraPanel from './GaleraPanel'
import DemoCoveragePage from './DemoCoveragePage'
import { usePortal } from './PortalContext'
import { Badge, Empty, FieldGrid, PageHeading, Panel, display, useTime } from './PortalUI'

function ComponentsPanel() {
  const time = useTime()
  const resource = useV4Resource('/system/health', { interval: 15000, transform: data => readCollection(data, 'components').filter(row => row.scope !== 'SYSTEMD_STATUS_ONLY') })
  return <Panel title="Service health" subtitle="Trạng thái từng thành phần theo nguồn quan sát" resource={resource}>{resource.data && (resource.data.length ? <div className="v4-service-grid">{resource.data.map((item, index) => <article className="v4-service-card" key={item.component_id || index}><div><Activity size={17} /><h3>{display(item.name || item.component_id)}</h3><Badge value={freshness(resource.meta, Boolean(resource.error)) === 'FRESH' ? item.status : 'UNKNOWN'} /></div><FieldGrid rows={[
    ['Quan sát', time(item.observed_at)], ['Thành công gần nhất', time(item.last_success)], ['Lần thử gần nhất', time(item.last_attempt)],
    ['Source ref', display(item.source_ref)],
  ]} /></article>)}</div> : <Empty title="Chưa có kết quả probe" />)}</Panel>
}

function PoliciesPanel() { return <RulesExplorer /> }

function SourcesPanel() {
  const time = useTime()
  const resource = useV4Resource('/system/data-sources', { interval: 15000, transform: data => readCollection(data, 'sources') })
  return <Panel title="Data sources & freshness" subtitle="Tách thời điểm kiểm tra nguồn khỏi thời điểm event cuối" resource={resource}>{resource.data && (resource.data.length ? <div className="table-scroll"><table className="v4-table"><thead><tr><th>NGUỒN / SCHEMA</th><th>FRESHNESS</th><th>THÀNH CÔNG GẦN NHẤT</th><th>LẦN THỬ GẦN NHẤT</th><th>DỮ LIỆU ĐẾN</th><th>MÃ LỖI</th></tr></thead><tbody>{resource.data.map((source, index) => <tr key={source.source_system || index}><td>{display(source.source_system)}<small>{display(source.source_schema)}</small></td><td><Badge value={freshness(resource.meta, Boolean(resource.error)) === 'FRESH' ? source.freshness_state : 'STALE'} /></td><td>{time(source.last_success)}</td><td>{time(source.last_attempt)}</td><td>{time(source.data_as_of)}</td><td>{display(source.last_error_code)}</td></tr>)}</tbody></table></div> : <Empty title="Chưa có quan sát nguồn" />)}</Panel>
}

export default function SystemPage({ tab = 'health' }) {
  const { sessionAuthEnabled, auth } = usePortal()
  const tabs = [
    ['health', 'Overview', Activity], ['galera', 'Galera', Database],
    ['policies', 'Policies & rules', Layers], ['sources', 'Data sources', Network],
    ['demo-coverage', 'Demo Coverage', Layers], ['evaluation', 'Evaluation & recovery', Layers],
  ]
  if (sessionAuthEnabled && (auth.businessCapabilities?.portal_admin || auth.user?.roles.includes('Auditor'))) {
    tabs.push(['portal-business', 'Portal administration', Layers])
  }
  const selected = tabs.some(([key]) => key === tab) ? tab : 'health'
  const panels = {
    health: <><ProxyServicesPanel system /><ComponentsPanel /><GaleraPanel /></>,
    galera: <GaleraPanel />,
    policies: <PoliciesPanel />,
    sources: <SourcesPanel />,
    'demo-coverage': <DemoCoveragePage />,
    evaluation: sessionAuthEnabled ? <EvaluationSystemTabs />
      : <p role="status">Evaluation và dữ liệu Recovery yêu cầu phiên đăng nhập. Người vận hành cần bật chế độ session cho Portal này.</p>,
    'portal-business': <BusinessAdminPanel />,
  }
  return <>
    <PageHeading eyebrow="PLATFORM OBSERVABILITY" title="System" description="Health, nguồn dữ liệu, Galera và policy snapshot của hệ thống." />
    <nav className="v4-system-tabs" aria-label="Nội dung System">{tabs.map(([key, label, Icon]) =>
      <a key={key} href={`#/system/${key}`} className={selected === key ? 'active' : ''} aria-current={selected === key ? 'page' : undefined}><Icon size={16} />{label}</a>)}</nav>
    {panels[selected]}
  </>
}
