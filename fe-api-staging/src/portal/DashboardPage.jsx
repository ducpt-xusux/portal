import { useState } from 'react'
import { Activity, ArrowRight, ArrowUpRight, Database, Layers, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react'
import { count, freshness, mapEvent, mapIncident, readCollection } from '../services/portalApi'
import { dashboardEventCounts, dashboardSeriesPoints, readIncidentBreakdown } from '../services/dashboardAudit'
import { useV4Resource, IncidentTable } from './IncidentPages'
import { EventTable } from './EventPages'
import ProxyServicesPanel from './ProxyServicesPanel'
import GaleraPanel from './GaleraPanel'
import AlertCenter from './AlertCenter'
import { DecisionFunnel, EvaluationDashboard } from './DashboardFunnel'
import { dashboardHref } from '../services/dashboardFunnel'
import { Badge, Empty, PageHeading, Panel, ResourceNotice, SourceStatus, display, useTime } from './PortalUI'

function Metric({ label, value, icon: Icon, tone = 'blue', href, detail, resource }) {
  const state = freshness(resource.meta, Boolean(resource.error))
  const content = <><div className="stat-top"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={18} /></span></div><div className="stat-value">{count(value) ?? '—'}</div><div className="stat-note">{state === 'FRESH' ? `${resource.meta?.source_mode === 'SNAPSHOT' ? 'HISTORICAL · ' : ''}${detail}` : `${state} · ${detail}`}<ArrowUpRight size={13} /></div></>
  return href ? <a className="stat-card v4-stat-link" href={href}>{content}</a> : <article className="stat-card">{content}</article>
}

function SeriesChart({ resource }) {
  const time = useTime()
  const points = dashboardSeriesPoints(resource.data, resource.meta, Boolean(resource.error))
  if (!points?.some(point => !point.gap)) return resource.data ? <Empty title="Chưa đủ dữ liệu cho biểu đồ trong khoảng này" text="Khoảng chưa có bản ghi được giữ là chưa xác định, không chuyển thành đường biểu đồ bằng 0." /> : null
  const width = 760, height = 210, left = 38, top = 18, bottom = 36
  const max = Math.max(1, ...points.flatMap(point => [point.allow, point.block]))
  const x = index => left + index / Math.max(points.length - 1, 1) * (width - left - 16)
  const y = value => top + (1 - value / max) * (height - top - bottom)
  const line = key => points.map((point, index) => point.gap ? '' : `${index && !points[index - 1].gap ? 'L' : 'M'}${x(index)},${y(point[key])}`).join(' ')
  return <><div className="v4-chart-legend"><span><i className="v4-dot good" />ALLOW</span><span><i className="v4-dot danger" />BLOCK</span><span>{points.length} buckets · khoảng trống: chưa xác nhận dữ liệu</span></div><svg className="v4-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Biểu đồ ALLOW và BLOCK theo thời gian"><title>Số bản ghi audit theo khoảng đã chọn; khoảng thiếu dữ liệu không biểu diễn bằng 0</title>{[0, .5, 1].map(ratio => <g key={ratio}><line x1={left} y1={y(max * ratio)} x2={width - 16} y2={y(max * ratio)} stroke="#e4ebef" strokeDasharray="4 4" /><text x={left - 8} y={y(max * ratio) + 4} textAnchor="end">{Math.round(max * ratio)}</text></g>)}<path d={line('allow')} fill="none" stroke="#087e85" strokeWidth="3" /><path d={line('block')} fill="none" stroke="#c44242" strokeWidth="2.5" />{points.map((point, index) => <g key={`${point.occurred_at}:${index}`}>
    {!point.gap && <>{['allow', 'block'].map(key => <circle key={key} cx={x(index)} cy={y(point[key])} r="3.5" fill={key === 'allow' ? '#087e85' : '#c44242'}><title>{time(point.occurred_at)} · ALLOW {point.allow} · BLOCK {point.block} · bản ghi đã nhập</title></circle>)}</>}
    {(index === 0 || index === points.length - 1) && <text x={x(index)} y={height - 10} textAnchor={index === 0 ? 'start' : 'end'}>{time(point.occurred_at)}</text>}
  </g>)}</svg></>
}

function IncidentBreakdown({ resource }) {
  const breakdown = resource.data
  return <Panel title="Thống kê incidents" subtitle="Severity và signal P17 · toàn bộ lịch sử trong nguồn đã đọc" resource={resource}
    action={breakdown && <a className="v4-text-link" href="#/incidents">Tất cả {breakdown.total} incidents<ArrowUpRight size={14} /></a>}>
    {breakdown && <><p className="v4-panel-note">Mỗi incident được đếm một lần trong từng nhóm. Khoảng 15 phút/1 giờ/24 giờ của audit phía trên không thay đổi thống kê này.</p>
      <div className="v4-incident-breakdown-grid">{[['by_severity', 'Severity P17'], ['by_signal', 'Signal P17']].map(([key, label]) => <section key={key} aria-label={label}>
        <h3 className="v4-subheading">{label}</h3><ul className="v4-incident-breakdown-list">{breakdown[key].map(row => <li key={row.value}>
          <a href={row.href} aria-label={`${label} ${row.value}: ${row.count} incidents`}>
            <span className="v4-breakdown-row"><span>{key === 'by_severity' ? <Badge value={row.value} /> : <span className="v4-rule">{row.value}</span>}</span><strong>{row.count}</strong><ArrowUpRight size={14} /></span>
            <span className="v4-breakdown-track" aria-hidden="true"><span style={{ width: `${breakdown.total ? row.count / breakdown.total * 100 : 0}%` }} /></span>
          </a>
        </li>)}</ul>
      </section>)}</div>
    </>}
  </Panel>
}

export default function DashboardPage({ params = {} }) {
  if (params.context && !['LIVE','EVALUATION'].includes(params.context)) return <Empty title="Chế độ Dashboard không hợp lệ" text="Chọn LIVE hoặc EVALUATION trên thanh đầu trang." />
  return params.context === 'EVALUATION' ? <EvaluationDashboard params={params}/> : <LiveDashboard params={params}/>
}

function LiveDashboard({ params }) {
  const time = useTime()
  const [window] = useState(['15m','1h','24h'].includes(params.window) ? params.window : '15m')
  const [anchor, setAnchor] = useState(() => new Date().toISOString())
  const summary = useV4Resource('/dashboard/summary', { params: { window }, interval: 10000 })
  const series = useV4Resource('/dashboard/event-series', { params: { window, end: summary.data?.window_to, bucket: window === '15m' ? '1m' : window === '1h' ? '5m' : '1h' }, enabled: Boolean(summary.data?.window_to), interval: 10000 })
  const incidents = useV4Resource('/incidents', { params: { limit: 5 }, interval: 5000, transform: data => readCollection(data, 'incidents').map(mapIncident) })
  const data = summary.data
  const canonical = data?.view_kind === 'P16H_CANONICAL_AUDIT'
  const events = useV4Resource('/events', { params: { limit: 5, source: canonical ? 'canonical' : 'p17' }, enabled: Boolean(data), interval: 5000, transform: data => readCollection(data, 'events').map(mapEvent) })
  const eventCounts = dashboardEventCounts(data, summary.meta, Boolean(summary.error))
  const incidentResource = { meta: data?.sources?.p17 || summary.meta, error: summary.error }
  const breakdownResource = { ...incidentResource, data: readIncidentBreakdown(data?.incident_breakdown), loading: summary.loading }
  const eventScope = canonical ? 'Bản ghi audit · chưa xác nhận đủ cửa sổ' : `Trong ${window}`
  const refresh = () => { setAnchor(new Date().toISOString()); [summary, series, incidents, events].forEach(resource => resource.refresh()) }
  const duration = { '15m': 900000, '1h': 3600000, '24h': 86400000 }[window]
  const observedEnd = Number.isFinite(Date.parse(data?.window_to)) ? data.window_to : summary.meta?.read_at || anchor
  const from = Number.isFinite(Date.parse(data?.window_from)) ? data.window_from : new Date(Date.parse(observedEnd) - duration).toISOString()
  const eventLink = decision => `#/events?${new URLSearchParams({ decision, from, to: observedEnd, ...(canonical ? { source: 'canonical' } : {}) })}`
  const historical = summary.meta?.source_mode === 'SNAPSHOT'
  const remote = summary.meta?.source_mode === 'REMOTE_READONLY'
  return <><PageHeading eyebrow="OPENSTACK DATABASE SECURITY" title="Protection Overview" description="Trạng thái bảo vệ, sự cố và bằng chứng trên cùng một góc nhìn." resource={{ ...summary, refresh }}><div className="segmented" role="group" aria-label="Khoảng thống kê">{[['15m', '15 phút'], ['1h', '1 giờ'], ['24h', '24 giờ']].map(([value, label]) => <button key={value} className={window === value ? 'selected' : ''} aria-pressed={window === value} onClick={() => { globalThis.window.location.hash = dashboardHref('LIVE',value) }}>{label}</button>)}</div></PageHeading>
    {canonical && <div className="v4-snapshot-notice"><strong>P16H canonical · {historical ? 'bản xuất lịch sử' : 'nguồn audit chỉ đọc'} · {display(summary.meta?.available_records)} events đã nhập</strong><p>KPI và biểu đồ đếm bản ghi audit, không dùng event projection P17. Bản ghi có từ {time(summary.meta?.first_event_at)} đến {time(summary.meta?.last_event_at)}.</p><p>Khoảng đang xem: {time(data.window_from)} → {time(data.window_to)}. {historical && 'Mốc mặc định là event cuối bản xuất. '}Chưa xác nhận lịch sử đầy đủ; không coi khoảng trống là không có truy vấn. Incidents dùng nguồn P17 riêng.</p></div>}
    {!canonical && historical && <div className="v4-snapshot-notice"><strong>Bản chụp P17 · {display(data?.projection_counts?.processed_events)} events / {display(data?.projection_counts?.incidents)} incidents</strong><p>Khoảng biểu đồ: {time(data?.window_from)} → {time(data?.window_to)}. Mốc mặc định là event cuối của bản chụp; số liệu không đại diện thời gian hiện tại hoặc toàn bộ canonical audit P16H.</p></div>}
    {!canonical && remote && <div className="v4-snapshot-notice"><strong>Proxy P17 · {display(data?.projection_counts?.processed_events)} events / {display(data?.projection_counts?.incidents)} incidents</strong><p>Đang hiển thị projection P17 theo lần đọc gần nhất; chưa phải toàn bộ lịch sử canonical P16H.</p></div>}
    <div className="v4-context-banner"><strong>LIVE · nguồn vận hành</strong><p>Chỉ đọc dữ liệu runtime hoặc cache của nguồn vận hành. Nhãn LIVE không xác nhận dữ liệu còn mới; xem FRESH/STALE, timestamp và coverage của từng nguồn. Dữ liệu evaluation không được nhập vào KPI này.</p></div>
    <div className="v4-protection-strip"><div className="v4-protection-title"><ShieldCheck size={20} /><div><strong>SQL protection path</strong><span>Health chức năng · kiểm tra độc lập với systemd</span></div></div><div className="v4-path-nodes">{['SQL clients', 'DB Firewall', 'Galera Cluster'].map((name, index) => {
      const node = Array.isArray(data?.protection_path) ? data.protection_path[index] : null
      return <div className="v4-path-node-wrap" key={name}>{index > 0 && <ArrowRight size={18} />}<div className="v4-path-node"><span>{name}</span><Badge value={freshness(summary.meta, Boolean(summary.error)) === 'FRESH' && Number.isFinite(Date.parse(node?.observed_at)) ? node?.status : 'UNKNOWN'} /></div></div>
    })}</div></div>
    <ProxyServicesPanel />
    <SourceStatus resource={summary} label={canonical ? 'KPI audit P16H' : 'Dashboard aggregates'} /><ResourceNotice resource={summary} noun="thống kê bảo vệ" />
    <section className="incident-kpis v4-kpis" aria-label="Chỉ số bảo vệ"><Metric label="Queries blocked" value={eventCounts.block} icon={ShieldOff} tone="coral" href={eventLink('BLOCK')} detail={eventScope} resource={summary} /><Metric label="Queries allowed" value={eventCounts.allow} icon={ShieldCheck} tone="green" href={eventLink('ALLOW')} detail={eventScope} resource={summary} /><Metric label="Incidents cần xem" value={data?.incident_counts?.review_required} icon={ShieldAlert} tone="blue" href="#/incidents?status=REVIEW_REQUIRED" detail="Theo trạng thái P17" resource={incidentResource} /><Metric label="Đang quarantine" value={freshness(data?.sources?.neutron, Boolean(summary.error)) === 'FRESH' ? data?.quarantined_workloads : null} icon={Layers} tone="purple" href="#/workloads?network_state=QUARANTINED" detail="Theo quan sát Neutron live" resource={{ meta: data?.sources?.neutron, error: summary.error }} /></section>
    <div className="v4-dashboard-grid"><Panel title="Security activity" subtitle={canonical ? 'ALLOW / BLOCK từ bản ghi canonical · khoảng trống chưa xác nhận' : 'ALLOW / BLOCK theo thời điểm event'} resource={series}><SeriesChart resource={series} /></Panel><Panel title="Chất lượng dữ liệu" subtitle="Số liệu theo bản ghi đã đọc, không xác nhận toàn bộ feed"><div className="v4-quality-list"><div><span><Activity size={16} />P15 score errors</span><strong>{display(eventCounts.risk_errors)}</strong></div><div><span><Database size={16} />Unknown decisions</span><strong>{display(eventCounts.unknown)}</strong></div><div><span><ShieldAlert size={16} />Critical incidents</span><strong>{display(data?.incident_counts?.critical)}</strong></div></div><SourceStatus resource={incidentResource} label="P17 incidents" /><p className="v4-panel-note">Health của audit không tự chứng minh Firewall hoặc Galera đang khỏe. Mỗi nguồn được kiểm tra riêng trong System.</p><a className="v4-text-link" href="#/system">Kiểm tra các nguồn<ArrowUpRight size={15} /></a></Panel></div>
    <DecisionFunnel window={window} end={data?.window_to} />
    <AlertCenter initialRange={params.alerts_from && params.alerts_to ? { from:params.alerts_from,to:params.alerts_to } : null} />
    <IncidentBreakdown resource={breakdownResource} />
    <GaleraPanel compact />
    <Panel title="Incidents gần đây" subtitle="P17.2 authoritative incidents" resource={incidents} action={<a className="v4-text-link" href="#/incidents">Incident Center<ArrowUpRight size={14} /></a>}>{incidents.data && (incidents.data.length ? <IncidentTable compact incidents={incidents.data} /> : <Empty title="Chưa có incident trong phạm vi truy vấn" />)}</Panel>
    <Panel title="Security events gần đây" subtitle={canonical ? 'Canonical P16H · bản ghi audit đã nhập' : 'P17 event projection · click event để xem evidence'} resource={events} action={<a className="v4-text-link" href={canonical ? '#/events?source=canonical' : '#/events'}>Tất cả events<ArrowUpRight size={14} /></a>}>{events.data && (events.data.length ? <EventTable compact events={events.data} /> : <Empty title="Chưa có event trong phạm vi truy vấn" />)}</Panel>
  </>
}
