import { useEffect, useState } from 'react'
import { ArrowUpRight, Database, FileCheck2, RefreshCw, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react'
import ActivityChart from '../components/ActivityChart'
import AuditSourceNotice from '../components/AuditSourceNotice'
import { getAuditDashboard } from '../services/auditApi'
import { dateTimeLabel } from '../utils/format'

export default function ApiDashboardPage() {
  const [window, setWindow] = useState('1h')
  const [anchor, setAnchor] = useState('source')
  const [payload, setPayload] = useState(null)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [reload, setReload] = useState(0)
  const [auto, setAuto] = useState(true)
  useEffect(() => {
    const controller = new AbortController()
    setBusy(true)
    getAuditDashboard({ window, anchor, signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) { setPayload(data); setError('') }
    }).catch(failure => { if (!controller.signal.aborted) setError(failure.message) })
      .finally(() => { if (!controller.signal.aborted) setBusy(false) })
    return () => controller.abort()
  }, [window, anchor, reload])
  useEffect(() => {
    if (!auto) return
    const timer = setInterval(() => setReload(n => n + 1), 10000)
    return () => clearInterval(timer)
  }, [auto])
  const stale = Boolean(error) || payload?.meta.data_state === 'STALE'
  return <div className="api-audit-page api-dashboard">
    <div className="page-heading"><div><div className="eyebrow">DATABASE SECURITY · AUDIT API</div><h1>Tổng quan bảo mật<span className="title-dot">.</span></h1><p>Thống kê các sự kiện P16 được FastAPI cung cấp.</p></div><button className="button primary" disabled={busy} onClick={() => setReload(n => n + 1)}><RefreshCw size={15} className={busy ? 'spin' : ''} />Làm mới</button></div>
    <AuditSourceNotice meta={payload?.meta} error={error} hasCache={Boolean(payload)} />
    <div className="api-time-controls"><label>Mốc thời gian<select aria-label="Mốc thời gian dashboard" value={anchor} onChange={e => setAnchor(e.target.value)}><option value="source">{payload?.historical ? 'Bản ghi cuối của bản chụp' : 'Theo nguồn audit'}</option><option value="now">Thời gian hiện tại</option></select></label><label className="api-auto-control"><input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} />Tự cập nhật mỗi 10 giây</label></div>
    {payload && <p className="api-range">Khoảng dữ liệu{error ? ' đã lưu' : ''}: {dateTimeLabel(payload.start)} → {dateTimeLabel(payload.end)} · UTC+7{payload.historical && anchor === 'source' ? ' · mốc lịch sử, không đổi timestamp của sự kiện' : ''}</p>}
    <section className="incident-kpis" aria-label="Thống kê sự kiện từ API" aria-busy={busy}>{[
      ['Tổng events', payload?.counts.total, FileCheck2, 'blue'], ['Được cho phép', payload?.counts.allowed, ShieldCheck, 'green'], ['Queries Blocked', payload?.counts.blocked, ShieldOff, 'coral'], ['Mức HIGH / CRITICAL', payload?.counts.high_risk, ShieldAlert, 'purple'],
    ].map(([label, value, Icon, tone]) => <article className="stat-card" key={label}><div className="stat-top"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={17} /></span></div><div className="stat-value">{value ?? '—'}</div><div className="stat-note">{stale ? payload ? 'STALE · số liệu đã lưu' : 'UNKNOWN · chưa có dữ liệu' : 'Theo khoảng thời gian đã chọn'}</div></article>)}</section>
    {payload ? <div className="main-panels api-overview-panels"><ActivityChart activity={payload.activity} window={payload.window} onWindowChange={setWindow} busy={busy} /><section className="panel api-context-panel"><div className="panel-heading"><h2>Phạm vi dữ liệu</h2><Database size={18} /></div><dl><div><dt>Client IP trong khoảng</dt><dd>{payload.clients}</dd></div><div><dt>Audit source</dt><dd>{stale ? 'STALE · cần đọc lại' : payload.health.audit_source.state}</dd></div><div><dt>SQLite</dt><dd>{stale ? 'Chưa xác nhận lại' : payload.health.sqlite}</dd></div><div><dt>Incident / isolation</dt><dd>Chưa kết nối</dd></div><div><dt>OpenStack / Galera</dt><dd>Chưa có probe</dd></div></dl><p>Thống kê audit không xác nhận hệ thống đang được bảo vệ hoặc VM đã cô lập.</p></section></div>
      : <section className="panel api-context-panel"><p>{busy ? 'Đang đọc Dashboard từ FastAPI...' : 'Chưa có thống kê từ API. Không dùng số liệu demo thay thế.'}</p></section>}
    <section className="panel events-panel"><div className="panel-heading"><div><h2>Security events gần đây</h2><p>Trong cùng khoảng thời gian với biểu đồ</p></div><a className="text-button" href="#/events">Nhật ký đầy đủ <ArrowUpRight size={15} /></a></div>
      <div className="table-scroll"><table className="events-table"><thead><tr><th>THỜI GIAN</th><th>NGUỒN / DB USER</th><th>QUERY · MASKED</th><th>SEVERITY / SCORE</th><th>DECISION</th><th>CHI TIẾT</th></tr></thead><tbody>{payload?.events.map(event => <tr key={event.id}><td><time>{dateTimeLabel(event.timestamp)}</time><span className="event-id api-event-id">{event.id}</span></td><td><code>{event.sourceIp}</code><small className="api-block">{event.user}</small></td><td className="query-cell"><code title={event.query}>{event.query}</code></td><td><span className={`severity ${event.severity.toLowerCase()}`}><i />{event.severity}</span><span className="api-block">{event.score ?? 'UNKNOWN'} / 100</span></td><td><span className={`decision ${event.decision.toLowerCase()}`}>{event.decision}</span></td><td><a className="row-detail" href={`#/events/${event.id}`} aria-label={`Mở event ${event.id}`}><ArrowUpRight size={16} /></a></td></tr>)}</tbody></table></div>
      {payload && !payload.events.length && <div className="table-empty"><strong>Không có sự kiện trong khoảng này</strong><p>Bạn có thể chọn mốc bản ghi cuối để xem bản chụp lịch sử.</p></div>}
    </section>
    <footer className="dashboard-footer"><span>Phạm vi P16 · Dashboard, Events và System audit dùng FastAPI</span><span>{payload && `Đọc API lúc ${dateTimeLabel(payload.updatedAt)}`}</span></footer>
  </div>
}
