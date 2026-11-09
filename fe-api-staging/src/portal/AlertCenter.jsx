import { useState } from 'react'
import { IncidentBusinessPanel } from '../features/n91-business'
import { usePortal } from './PortalContext'
import { ArrowUpRight, RefreshCw } from 'lucide-react'
import { alertEventHref, alertIncidentHref, alertRequestFilters, mapAlert, readAlertsPage } from '../services/alertsApi'
import { useCursor, useV4Resource } from './IncidentPages'
import { Badge, CopyId, CursorPager, Dialog, Empty, FieldGrid, Filter, Panel, ResourceNotice, SelectFilter, SourceStatus, display, useTime } from './PortalUI'
import './AlertCenter.css'

function IncidentLink({ id }) {
  const href = alertIncidentHref(id)
  return href ? <a className="v4-id-link" href={href}>{id}<ArrowUpRight size={13} /></a> : <span className="v4-muted">Không có incident gắn trong alert</span>
}

function AlertDetail({ id, onClose }) {
  const { sessionAuthEnabled } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/alerts/${encodeURIComponent(id)}`, { interval: 5000, transform: mapAlert })
  const alert = resource.data
  return <Dialog title="Chi tiết cảnh báo P17" onClose={onClose}><div className="v4-alert-detail">
    <SourceStatus resource={resource} label="P17 outbox" /><ResourceNotice resource={resource} noun="cảnh báo" />
    {alert && <><div className="v4-copy-row"><strong>{alert.alert_id}</strong><CopyId value={alert.alert_id} /></div>
      <div className="v4-alert-badges"><Badge value={alert.severity} /><span className="v4-rule">{alert.signal_code}</span></div>
      <h3>{alert.title}</h3><p>{alert.summary}</p>
      <FieldGrid rows={[
        ['Tạo lúc', time(alert.created_at)], ['Loại cảnh báo', alert.kind], ['Source IP', alert.source_ip || 'Nguồn không công bố danh tính đầy đủ'],
        ['Peak P15 theo alert', alert.risk_peak === null ? 'Chưa có điểm hợp lệ' : `${alert.risk_peak}/100`],
        ['Incident được nguồn liên kết', <IncidentLink id={alert.incident_id} />],
        ['Nguồn', alert.provenance.source_system], ['Schema', display(alert.provenance.source_schema)],
        ['Dữ liệu thu thập đến', time(alert.provenance.data_as_of)], ['Source ref', display(alert.source_record_ref)],
      ]} />
      <h3 className="v4-subheading">Event evidence được outbox tham chiếu</h3>
      {alert.event_refs.length ? <ul className="v4-alert-refs">{alert.event_refs.map(eventId => {
        const href = alertEventHref(eventId, resource.meta?.stream_id)
        return <li key={eventId}>{href ? <a className="v4-id-link" href={href}>{eventId}<ArrowUpRight size={13} /></a> : <code>{eventId}</code>}</li>
      })}</ul> : <p className="v4-panel-note">Outbox không cung cấp event ref.</p>}
      <p className="v4-panel-note">Các ref trên được ghi trong outbox. Danh sách đầy đủ của incident, nếu có, nằm tại Incident → Evidence và được gắn phương pháp xác định membership.</p>
      {sessionAuthEnabled
        ? <IncidentBusinessPanel id={id} streamId={resource.meta?.stream_id} kind="alerts" />
        : <p className="v4-panel-note">Review cảnh báo cần phiên Portal.</p>}
    </>}
  </div></Dialog>
}

function AlertFeed({ filters, onRestart }) {
  const time = useTime(), pager = useCursor()
  const [selected, setSelected] = useState(null)
  const resource = useV4Resource('/alerts', { params: { ...filters, limit: 10, cursor: pager.cursor }, interval: 5000, transform: readAlertsPage })
  const data = resource.data
  return <Panel title="Alert Center" subtitle="Cảnh báo riêng từ outbox P17 · đọc lại mỗi 5 giây khi trang đang hiển thị" resource={resource}
    action={<button type="button" className="button secondary" onClick={onRestart}><RefreshCw size={14} />Đọc lại cảnh báo</button>}>
    <p className="v4-panel-note">{data ? <strong>{data.total_count} alert trong phạm vi lọc của outbox đã thu thập. </strong> : 'Chưa xác định số alert. '}Một incident có thể có nhiều alert; một alert có thể chưa có incident. Nguồn chưa xác nhận toàn bộ lịch sử cảnh báo.</p>
    {resource.error?.status === 412 && <p className="v4-panel-note">Nguồn đã thay đổi khi phân trang. Bấm “Đọc lại cảnh báo” để bắt đầu từ trang đầu.</p>}
    {data && (data.items.length ? <div className="table-scroll"><table className="v4-table v4-alert-table"><thead><tr>
      <th>THỜI GIAN</th><th>CẢNH BÁO / SIGNAL</th><th>SEVERITY / P15</th><th>SOURCE IP</th><th>INCIDENT</th><th>CHI TIẾT</th>
    </tr></thead><tbody>{data.items.map(alert => <tr key={alert.alert_id}>
      <td><time>{time(alert.created_at)}</time></td><td><strong>{alert.title}</strong><small>{alert.signal_code} · {alert.kind}</small><small>{alert.alert_id}</small></td>
      <td><Badge value={alert.severity} /><small>P15: {display(alert.risk_peak)}</small></td><td>{alert.source_ip || 'Chưa công bố'}</td>
      <td><IncidentLink id={alert.incident_id} /></td><td><button type="button" className="button secondary" aria-label={`Xem cảnh báo ${alert.alert_id}`} onClick={() => setSelected(alert.alert_id)}>Xem<ArrowUpRight size={14} /></button></td>
    </tr>)}</tbody></table></div> : <Empty title="Không có alert trong phạm vi lọc của outbox đã thu thập" text="Kết quả này không xác nhận toàn bộ lịch sử cảnh báo trên Proxy." />)}
    <CursorPager resource={resource} {...pager} />
    {selected && <AlertDetail key={selected} id={selected} onClose={() => setSelected(null)} />}
  </Panel>
}

export default function AlertCenter({ initialRange = null }) {
  const [draft, setDraft] = useState({ window: 'all', severity: '', signal_code: '', source_ip: '', kind: '' })
  const [filters, setFilters] = useState(initialRange || {}), [revision, setRevision] = useState(0)
  const update = key => value => setDraft(current => ({ ...current, [key]: value }))
  return <section className="v4-alert-center" aria-label="Alert Center">
    {filters.from && filters.to && <p className="v4-panel-note">Alert Center đang lọc theo cửa sổ đã chọn: {filters.from} → {filters.to}. Reset để xem toàn bộ outbox.</p>}
    <details className="panel v4-alert-filter-panel"><summary>Lọc cảnh báo P17</summary>
      <form className="v4-filters" onSubmit={event => { event.preventDefault(); setFilters(alertRequestFilters(draft)); setRevision(value => value + 1) }}>
        <SelectFilter label="Thời gian cảnh báo" value={draft.window} onChange={update('window')} options={[["all", "Toàn bộ outbox đã thu thập"], ["15m", "15 phút gần nhất"], ["1h", "1 giờ gần nhất"], ["24h", "24 giờ gần nhất"]]} />
        <SelectFilter label="Severity cảnh báo" value={draft.severity} onChange={update('severity')} options={[["", "Tất cả"], ...['CRITICAL', 'HIGH', 'WARNING', 'LOW', 'INFO'].map(value => [value, value])]} />
        <Filter label="Signal cảnh báo"><input value={draft.signal_code} maxLength={64} placeholder="SINGLE_P15_HIGH / CORR-002" onChange={event => update('signal_code')(event.target.value)} /></Filter>
        <Filter label="Source IP cảnh báo"><input value={draft.source_ip} maxLength={45} placeholder="10.0.0.204" onChange={event => update('source_ip')(event.target.value)} /></Filter>
        <SelectFilter label="Loại cảnh báo" value={draft.kind} onChange={update('kind')} options={[["", "Tất cả"], ...['SINGLE_P15_HIGH', 'CORRELATED', 'OPERATIONAL', 'POLICY_VIOLATION', 'AUDIT_HEALTH', 'SYSTEM_HEALTH', 'OTHER'].map(value => [value, value])]} />
        <button className="button primary">Lọc cảnh báo</button><button type="button" className="button secondary" onClick={() => { setDraft({ window: 'all', severity: '', signal_code: '', source_ip: '', kind: '' }); setFilters({}); setRevision(value => value + 1) }}>Đặt lại cảnh báo</button>
        <p className="v4-filter-support">Bộ lọc riêng của Alert Center; không dùng cửa sổ KPI audit phía trên. Khoảng gần nhất được chốt khi bấm Lọc.</p>
      </form>
    </details>
    <AlertFeed key={`${revision}:${JSON.stringify(filters)}`} filters={filters} onRestart={() => setRevision(value => value + 1)} />
  </section>
}
