import { useState } from 'react'
import { EventComparePicker, EventInvestigation } from '../features/n91-investigation/Investigation'
import { auditEventQuery } from '../services/dashboardAudit'
import { ArrowLeft, ArrowUpRight, Search } from 'lucide-react'
import { mapEvent, readCollection } from '../services/portalApi'
import { useCursor, useV4Resource } from './IncidentPages'
import { Badge, CopyId, CursorPager, Empty, FieldGrid, Filter, PageHeading, Panel, ResourceNotice, SelectFilter, SourceStatus, display, useTime } from './PortalUI'
import { usePortal } from './PortalContext'

export function EventTable({ events, compact = false }) {
  const time = useTime()
  return <div className="table-scroll"><table className="v4-table"><thead><tr><th>EVENT / THỜI GIAN</th><th>NGUỒN</th><th>DECISION</th><th>P15 SCORE / STATUS</th><th>P14 RULES</th>{!compact && <th>CLASS / INCIDENTS</th>}<th><span className="sr-only">Chi tiết</span></th></tr></thead><tbody>{events.map(event => <tr key={`${event.stream_id}:${event.event_id}`}><td><a className="v4-id-link" href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}>{event.event_id}</a><time>{time(event.occurred_at)}</time></td><td><code>{display(event.source_ip)}</code><small>{event.db_user || 'Withheld / chưa cung cấp'}</small></td><td><Badge value={event.decision} /><small>{event.view_kind === 'P17_EVENT_PROJECTION' ? 'P17 blocked projection' : 'P14 policy decision'}</small><small>Effective: {display(event.effective_action)}</small></td><td><strong>{event.risk.score ?? 'N/A'}</strong><small>{display(event.risk.status)}</small></td><td><span className="v4-rule-list">{event.matched_rules.map(rule => <a key={rule} className="v4-rule" href={`#/events?rule=${encodeURIComponent(rule)}${event.view_kind === 'P16H_CANONICAL_AUDIT' ? '&source=canonical' : ''}`}>{rule}</a>)}</span>{!event.matched_rules.length && '—'}</td>{!compact && <td><Badge value={event.p17_event_class} />{event.incident_refs.map(id => <a key={id} className="v4-id-link" href={`#/incidents/${encodeURIComponent(id)}`}>{id}</a>)}</td>}<td><a className="row-detail" href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`} aria-label={`Mở event ${event.event_id}`}><ArrowUpRight size={16} /></a></td></tr>)}</tbody></table></div>
}

const localInput = (value, zone) => value && Number.isFinite(Date.parse(value)) ? new Date(Date.parse(value) + (zone === 'UTC' ? 0 : 7 * 3600000)).toISOString().slice(0, 16) : ''

export function EventsPage({ params }) {
  const { timezone } = usePortal()
  const [draft, setDraft] = useState(params)
  const [error, setError] = useState('')
  const pager = useCursor()
  const resource = useV4Resource('/events', { params: { ...params, limit: 25, cursor: pager.cursor }, interval: 5000, transform: data => readCollection(data, 'events').map(mapEvent) })
  const update = key => value => setDraft(current => ({ ...current, [key]: value }))
  return <><PageHeading eyebrow="SECURITY EVENT EVIDENCE" title="Security Events" description={params.source === 'canonical' ? 'Bản ghi audit canonical đã nhập · chưa xác nhận lịch sử đầy đủ.' : 'Truy vết rule và điểm rủi ro từ nguồn đã cung cấp. Nguồn P17 chỉ chứa event projection.'} resource={resource} />
    {['TEST', 'EVALUATION'].includes(resource.meta?.import_context) && <p className="v4-inline-warning" role="status">{resource.meta.import_context} · Offline fixture / evaluation store · không phải nguồn LIVE.</p>}<form className="panel v4-filters v4-event-filters" onSubmit={event => {
      event.preventDefault()
      if (draft.from && draft.to && Date.parse(draft.from) > Date.parse(draft.to)) { setError('Thời điểm bắt đầu phải trước thời điểm kết thúc.'); return }
      if (draft.risk_min && draft.risk_max && Number(draft.risk_min) > Number(draft.risk_max)) { setError('Điểm tối thiểu phải nhỏ hơn hoặc bằng điểm tối đa.'); return }
      setError('')
      const search = new URLSearchParams(Object.entries(draft).filter(([, value]) => value && value !== 'ALL')).toString()
      window.location.hash = `/events${search ? `?${search}` : ''}`
    }}><Filter label={`Từ · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}><input type="datetime-local" value={localInput(draft.from, timezone)} onChange={event => update('from')(event.target.value ? new Date(`${event.target.value}${timezone === 'UTC' ? 'Z' : '+07:00'}`).toISOString() : '')} /></Filter><Filter label={`Đến · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}><input type="datetime-local" value={localInput(draft.to, timezone)} onChange={event => update('to')(event.target.value ? new Date(`${event.target.value}${timezone === 'UTC' ? 'Z' : '+07:00'}`).toISOString() : '')} /></Filter><SelectFilter label="Decision" value={draft.decision} onChange={update('decision')} options={[['', 'Tất cả'], ['ALLOW', 'ALLOW'], ['BLOCK', 'BLOCK'], ['UNKNOWN', 'UNKNOWN']]} /><Filter label="Source IP"><input value={draft.source_ip || ''} maxLength={45} placeholder="10.0.0.204" onChange={event => update('source_ip')(event.target.value)} /></Filter><Filter label="Rule ID"><input value={draft.rule || ''} maxLength={80} placeholder="INJ-001" onChange={event => update('rule')(event.target.value)} /></Filter><Filter label="Incident ID"><input value={draft.incident_ref || ''} maxLength={128} placeholder="INC-…" onChange={event => update('incident_ref')(event.target.value)} /></Filter><SelectFilter label="P17 event class" value={draft.event_class} onChange={update('event_class')} options={[['', 'Tất cả'], ...['LIVE', 'STALE', 'HISTORICAL', 'OUT_OF_ORDER', 'FUTURE_SKEW'].map(value => [value, value])]} /><SelectFilter label="Risk status" value={draft.risk_status} onChange={update('risk_status')} options={[['', 'Tất cả'], ['OK', 'OK'], ['ERROR', 'ERROR']]} /><Filter label="P15 tối thiểu"><input type="number" min="0" max="100" value={draft.risk_min || ''} onChange={event => update('risk_min')(event.target.value)} /></Filter><Filter label="P15 tối đa"><input type="number" min="0" max="100" value={draft.risk_max || ''} onChange={event => update('risk_max')(event.target.value)} /></Filter><Filter label="DB user"><input maxLength={128} value={draft.db_user || ''} onChange={event => update('db_user')(event.target.value)} placeholder="Theo quyền xem dữ liệu" /></Filter><button className="button primary"><Search size={14} />Áp dụng</button><a className="text-button" href={params.source === 'canonical' ? '#/events?source=canonical' : '#/events'}>Đặt lại</a>{error && <p role="alert" className="v4-form-error">{error}</p>}</form>
    <details><summary>So sánh APP / Clone theo canonical IDs</summary><EventComparePicker /></details>
    <Panel title="Security events" subtitle="Một dòng cho mỗi event · nguồn và phạm vi hiển thị bên dưới" resource={resource}>{resource.data && (resource.data.length ? <EventTable events={resource.data} /> : <Empty title="Không có event trong phạm vi lọc" />)}<CursorPager resource={resource} {...pager} /></Panel>
  </>
}

export function EventDetail({ id, params }) {
  if (params.source === 'canonical' && params.stream_id) {
    return <><a href="#/events?source=canonical" className="incident-back"><ArrowLeft size={15} />Security Events</a><PageHeading eyebrow="EVENT EVIDENCE" title="Chi tiết event" description={id} /><EventInvestigation eventId={id} streamId={params.stream_id} /></>
  }
  return <LegacyEventDetail id={id} params={params} />
}

function LegacyEventDetail({ id, params }) {
  const time = useTime()
  const resource = useV4Resource(`/events/${encodeURIComponent(id)}`, { params: { stream_id: params.stream_id, source: params.source }, interval: 0, transform: mapEvent })
  const event = resource.data
  return <><a href={params.source === 'canonical' ? '#/events?source=canonical' : '#/events'} className="incident-back"><ArrowLeft size={15} />Security Events</a><PageHeading eyebrow="EVENT EVIDENCE" title="Chi tiết event" description={id} resource={resource}><CopyId value={id} /></PageHeading><SourceStatus resource={resource} label={event?.view_kind === 'P17_EVENT_PROJECTION' ? 'P17 event projection' : 'Event source'} /><ResourceNotice resource={resource} noun="event" />
    {event && <>{['TEST', 'EVALUATION'].includes(event.source_provenance.context) && <p className="v4-inline-warning" role="status">{event.source_provenance.context} · Offline fixture / evaluation store · không phải nguồn LIVE.</p>}<div className="v4-detail-statuses"><div><span>{event.view_kind === 'P17_EVENT_PROJECTION' ? 'P17 BLOCKED PROJECTION' : 'P14 POLICY DECISION'}</span><Badge value={event.decision} /></div><div><span>P15 SCORE</span><strong>{event.risk.score ?? 'N/A'}<small> / 100</small></strong></div><div><span>RISK STATUS</span><Badge value={event.risk.status} /></div><div><span>P17 CLASS TẠI LÚC XỬ LÝ</span><Badge value={event.p17_event_class} /></div></div>
      <div className="v4-detail-grid"><div className="v4-stack"><Panel title={event.view_kind === 'P17_EVENT_PROJECTION' ? 'P17 event projection' : 'SQL & policy decision'} subtitle="Chỉ hiển thị SQL đã được canonical source cho phép">{event.masked_query ? <pre className="v4-code">{event.masked_query}</pre> : <div className="v4-privacy"><ShieldPrivacy /><strong>{event.view_kind === 'P17_EVENT_PROJECTION' ? 'Nguồn P17 không lưu SQL' : 'SQL không khả dụng do chính sách riêng tư'}</strong><p>Dùng event ID, rule và metadata để truy vết. Các trường canonical chưa cung cấp được giữ trống.</p></div>}<FieldGrid rows={[
        ['Decision basis', display(event.decision_basis)], ['Effective action', display(event.effective_action)], ['Action result', display(event.action_result)], ['Runtime mode', display(event.runtime_mode)], ['Policy ID', display(event.policy_id)], ['Policy version', display(event.policy_version)], ['MySQL command', display(event.mysql_command)],
        ['Matched rules', event.matched_rules.join(' · ') || 'Không có'], ['Blocking rules', event.blocking_rules.join(' · ') || (event.canonical_complete ? 'Không có' : 'Chưa cung cấp')],
        ['Monitor rules', event.monitor_rules.join(' · ') || (event.canonical_complete ? 'Không có' : 'Chưa cung cấp')],
      ]} /><h3 className="v4-subheading">Lý do từ policy</h3>{event.reasons.length ? <ul className="v4-reasons">{event.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul> : <p className="v4-panel-note">Nguồn chưa cung cấp lý do chi tiết.</p>}<p className="v4-panel-note">{event.view_kind === 'P17_EVENT_PROJECTION' ? 'Decision ở đây dựa trên cờ blocked của P17; chưa có canonical P14 decision.' : 'Effective action và action result phản ánh thực thi. Monitor match không tự chứng minh đã chặn.'} Trạng thái cách ly VM cần evidence hành động và quan sát Neutron riêng.</p></Panel>
      <Panel title="Giải thích điểm P15" subtitle="Score breakdown từ nguồn canonical · không tính lại risk"><FieldGrid rows={[
        ['Raw score', display(event.raw_score)], ['Điểm sau giới hạn', event.risk.score ?? 'N/A'], ['Risk status', display(event.risk.status)],
      ]} />{event.score_breakdown?.length ? <div className="table-scroll"><table className="v4-table v4-breakdown-table"><thead><tr><th>NGUỒN / RULE</th><th>CATEGORY</th><th>ĐIỂM</th><th>LÝ DO</th></tr></thead><tbody>{event.score_breakdown.map((component, index) => <tr key={index}><td><strong>{component.rule_id || 'Component không gắn rule'}</strong><small>{display(component.source)}</small></td><td>{display(component.category)}</td><td>{display(component.score)}</td><td className="v4-text-cell">{display(component.reason)}</td></tr>)}</tbody></table></div> : <p className="v4-panel-note">Chưa có score breakdown từ nguồn. Điểm tổng không được dùng để tự dựng các component.</p>}</Panel>
      <Panel title="Incidents liên quan" subtitle="Liên kết evidence theo nguồn P17">{event.incident_refs.length ? <div className="v4-link-list">{event.incident_refs.map(ref => <a key={ref} href={`#/incidents/${encodeURIComponent(ref)}`}>{ref}<ArrowUpRight size={15} /></a>)}</div> : <p className="v4-panel-note">Chưa có liên kết incident được nguồn cung cấp.</p>}</Panel></div>
      <Panel title="Identity & provenance"><FieldGrid rows={[
        ['Event ID', <span className="v4-copy-row">{event.event_id}<CopyId value={event.event_id} /></span>], ['Request ID', display(event.request_id)], ['Stream ID', display(event.stream_id)],
        ['Sequence', display(event.stream_sequence)], ['Phát sinh lúc', time(event.occurred_at)], ['P17 received_utc / ingested_at', time(event.ingested_at)], ['Request received · source', time(event.request_received_at)], ['Storage recorded · source', time(event.storage_recorded_at)], ['Portal imported · PORTAL_CLOCK', time(event.imported_at)], ['Request time basis', display(event.time_basis.request_received_at)], ['Identity status', display(event.identity_status)], ['Thiếu trường', display(event.missing_fields_reason)],
        ['Nguồn IP', display(event.source_ip)], ['DB user', event.db_user || 'Withheld / chưa cung cấp'], ['Database', display(event.database_name)],
        ['Source system', display(event.source_provenance.source_system)], ['Source ref', display(event.source_provenance.source_ref)], ['Payload SHA256 · upstream', display(event.source_provenance.payload_sha256)], ['Hash basis', display(event.source_provenance.payload_hash_basis)], ['Verification', display(event.source_provenance.verification)], ['Context', display(event.source_provenance.context)], ['Coverage', display(event.source_provenance.coverage_kind)], ['Human review', display(event.source_provenance.human_review)],
      ]} /><details className="v4-json"><summary>Xem JSON đã giới hạn trường</summary><pre className="v4-code">{JSON.stringify(event, null, 2)}</pre></details></Panel></div>
    </>}
  </>
}

function ShieldPrivacy() { return <span className="v4-privacy-symbol" aria-hidden="true">SQL</span> }
