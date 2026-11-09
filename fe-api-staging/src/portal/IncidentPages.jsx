import { IncidentInvestigation } from '../features/n91-investigation/Investigation'
import { IncidentBusinessPanel } from '../features/n91-business'
import { useId, useRef, useState } from 'react'
import { ArrowLeft, ArrowUpRight, FileText, RefreshCw, ShieldCheck } from 'lucide-react'
import usePortalResource from '../hooks/usePortalResource'
import { canWriteNotes, isVerifiedNetwork, mapEvent, mapIncident, readCollection, portalRequest } from '../services/portalApi'
import { usePortal } from './PortalContext'
import { CurrentMapping, DecisionChecklist, VerifiedSource } from './InvestigationUI'
import { EvidenceExportButtons, ReviewPanel } from './ReviewEvidence'
import { initialIncidentDraft, incidentFilterSearch, incidentLocalTime, incidentRequestFilters, incidentUtcTime, readIncidentFilterSupport, withoutUnsupportedIncidentFilters } from '../services/incidentFilters'
import { Badge, CopyId, CursorPager, Empty, FieldGrid, Filter, PageHeading, Panel, ResourceNotice, SelectFilter, SourceStatus, display, useTime } from './PortalUI'

export function useV4Resource(path, options = {}) {
  const { sessionVersion, auth, mode } = usePortal()
  return usePortalResource(path, { scope: `${sessionVersion}:${auth.status}:${auth.user?.user_id || ''}`, ...options, enabled: mode === 'v4' && auth.status !== 'checking' && options.enabled !== false })
}

export function useCursor() {
  const [cursor, setCursor] = useState(null)
  const [history, setHistory] = useState([])
  return { cursor, history, onNext: next => { setHistory(items => [...items, cursor]); setCursor(next) }, onPrevious: () => { setCursor(history.at(-1) || null); setHistory(items => items.slice(0, -1)) } }
}

export function IncidentTable({ incidents, compact = false, meta, error }) {
  const time = useTime()
  return <div className="table-scroll"><table className={`v4-table ${compact ? '' : 'v4-investigation-table'}`}><thead><tr><th>INCIDENT / NGUỒN</th><th>SIGNAL</th><th>SEVERITY / CONFIDENCE</th><th>EVIDENCE</th>{!compact && <><th>PHÁT HIỆN / PHẢN ỨNG</th><th>XÁC MINH NGUỒN / MAPPING</th></>}<th>LẦN CUỐI</th><th><span className="sr-only">Chi tiết</span></th></tr></thead><tbody>{incidents.map(incident => <tr key={`${incident.stream_id}:${incident.incident_id}`}><td><a className="v4-id-link" href={`#/incidents/${encodeURIComponent(incident.incident_id)}`}>{incident.incident_id}</a><small>{display(incident.source_ip)}</small></td><td><span className="v4-rule">{display(incident.signal_rule)}</span></td><td><Badge value={incident.severity} /><small>{display(incident.confidence)}</small></td><td><strong>{display(incident.evidence_count)}</strong><small>Peak P15: {display(incident.p15_peak_score)}</small></td>{!compact && <td><Badge value={incident.incident_status} /><small><Badge value={incident.response_state} /></small></td>}{!compact && <td><CurrentMapping compact mapping={incident.current_mapping} error={error} /></td>}<td><time>{time(incident.last_seen)}</time></td><td><a className="row-detail" href={`#/incidents/${encodeURIComponent(incident.incident_id)}`} aria-label={`Xem ${incident.incident_id}`}><ArrowUpRight size={16} /></a></td></tr>)}</tbody></table></div>
}

export function IncidentsPage({ params }) {
  const { auth, timezone } = usePortal()
  const time = useTime(), supportId = useId()
  const [draft, setDraft] = useState(() => initialIncidentDraft(params))
  const [formError, setFormError] = useState('')
  const support = readIncidentFilterSupport(auth.incidentFilters)
  const query = incidentRequestFilters(params, support)
  const pager = useCursor()
  const resource = useV4Resource('/incidents', { params: { ...query.filters, limit: 25, cursor: pager.cursor }, enabled: !query.error, interval: 5000, transform: data => readCollection(data, 'incidents').map(mapIncident) })
  const apply = event => {
    event.preventDefault()
    const result = incidentFilterSearch(draft, support)
    setFormError(result.error)
    if (!result.error) window.location.hash = `/incidents${result.search ? `?${result.search}` : ''}`
  }
  const update = key => value => { setDraft(current => ({ ...current, [key]: value })); setFormError('') }
  const updateTime = key => value => {
    const utc = incidentUtcTime(value, timezone)
    if (utc === null) { setFormError('Mốc thời gian chưa hợp lệ.'); return }
    setDraft(current => ({ ...current, [key]: utc, window: 'custom' })); setFormError('')
  }
  const supportedResponse = support.response_states
  return <>
    <PageHeading title="Incident Center" description="Điều tra sự cố theo evidence và kết quả phát hiện của P17." resource={query.error ? undefined : resource} />
    <div className="v4-explainer"><ShieldCheck size={18} /><span>Một request có nhiều rule vẫn chỉ là một request. Severity/confidence P17 và Peak P15 là các thông tin riêng.</span></div>
    <form className="panel v4-filters v4-incident-filters" onSubmit={apply}>
      <Filter label="Source IP"><input placeholder="Ví dụ 10.0.0.204" value={draft.source_ip || ''} onChange={event => update('source_ip')(event.target.value)} maxLength={45} /></Filter>
      <SelectFilter label="Signal" value={draft.signal_rule} onChange={update('signal_rule')} options={[['', 'Tất cả signal'], ...[1, 2, 3, 4, 5].map(n => [`CORR-00${n}`, `CORR-00${n}`])]} />
      <SelectFilter label="Severity P17" value={draft.severity} onChange={update('severity')} options={[['', 'Tất cả severity'], ...['LOW', 'WARNING', 'HIGH', 'CRITICAL'].map(value => [value, value]), ...(draft.severity && draft.severity !== 'ALL' && !['LOW', 'WARNING', 'HIGH', 'CRITICAL'].includes(draft.severity) ? [[draft.severity, `${draft.severity} (nguồn P17)`]] : [])]} />
      <SelectFilter label="Trạng thái phát hiện" value={draft.status} onChange={update('status')} options={[['', 'Tất cả trạng thái'], ['REVIEW_REQUIRED', 'REVIEW_REQUIRED'], ['OPERATIONAL_REVIEW', 'OPERATIONAL_REVIEW']]} />
      <SelectFilter label="Khoảng thời gian" value={draft.window} onChange={update('window')} options={[["all", "Toàn bộ lịch sử nguồn"], ["custom", "Tùy chọn từ–đến"], ["15", "15 phút gần nhất"], ["60", "1 giờ gần nhất"], ["1440", "24 giờ gần nhất"], ["10080", "7 ngày gần nhất"]]} />
      {draft.window === 'custom' && <>
        <Filter label={`Từ · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}><input type="datetime-local" step="1" value={incidentLocalTime(draft.from, timezone)} onInput={event => updateTime('from')(event.target.value)} onChange={event => updateTime('from')(event.target.value)} /></Filter>
        <Filter label={`Đến · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}><input type="datetime-local" step="1" value={incidentLocalTime(draft.to, timezone)} onInput={event => updateTime('to')(event.target.value)} onChange={event => updateTime('to')(event.target.value)} /></Filter>
      </>}
      <SelectFilter label="Portal review" value={draft.review_state} onChange={update('review_state')} disabled={!support.review_state} describedBy={supportId} options={[["", "Tất cả review"], ...['UNREVIEWED', 'ACKNOWLEDGED', 'REVIEWED'].map(value => [value, value])]} />
      <SelectFilter label="Response state" value={draft.response_state} onChange={update('response_state')} disabled={!supportedResponse.length} describedBy={supportId} options={[["", "Tất cả response"], ...['NONE', 'QUARANTINED', 'RESTORED', 'UNKNOWN'].map(value => [value, value, !supportedResponse.includes(value)])]} />
      <button className="button primary" disabled={auth.status === 'checking'}>Áp dụng</button><a className="text-button" href="#/incidents">Đặt lại</a>
      <p id={supportId} className="v4-filter-support">{!support.review_state && 'Nguồn hiện chưa hỗ trợ lọc Portal review. '}{supportedResponse.length === 1 && supportedResponse[0] === 'UNKNOWN' ? 'Phản ứng hiện chỉ lọc được UNKNOWN; chưa có dữ liệu P17.5 để xác nhận các trạng thái còn lại.' : !supportedResponse.length ? 'Nguồn chưa công bố khả năng lọc trạng thái phản ứng.' : `Trạng thái phản ứng có thể lọc: ${supportedResponse.join(', ')}.`}</p>
      <p className="v4-filter-support">Khoảng gần nhất tính tại lúc Áp dụng và được giữ trên URL. Chọn từ–đến để xem sự cố lịch sử; khoảng có đủ hai mốc tối đa 30 ngày.</p>
      {formError && <p className="v4-form-error v4-filter-support" role="alert">{formError}</p>}
    </form>
    {query.error && auth.status !== 'checking' && <div className="v4-notice warn" role="alert"><div><strong>Chưa áp dụng được bộ lọc trên đường dẫn</strong><p>{query.error}</p>{query.unsupported && <a className="v4-text-link" href={`#/incidents?${withoutUnsupportedIncidentFilters(params, support)}`}>Bỏ bộ lọc chưa hỗ trợ</a>}</div></div>}
    {!query.error && <p className="v4-filter-scope">{params.from || params.to ? `Đang lọc Last Seen: ${params.from ? time(params.from) : 'từ đầu lịch sử'} → ${params.to ? time(params.to) : 'đến cuối lịch sử'}.` : 'Đang xem toàn bộ lịch sử trong nguồn P17.'} Sắp xếp lần xuất hiện cuối mới nhất trước.</p>}
    <Panel title="Incidents" subtitle="P17.2 · dữ liệu theo lần thu thập gần nhất; giao diện đọc lại mỗi 5 giây" resource={query.error ? undefined : resource}>
      {resource.data && (resource.data.length ? <IncidentTable incidents={resource.data} meta={resource.meta} error={resource.error} /> : <Empty title="Không có incident trong phạm vi lọc" />)}
      {!query.error && <CursorPager resource={resource} {...pager} />}
    </Panel>
  </>
}

function EvidencePanel({ id }) {
  const time = useTime()
  const resource = useV4Resource(`/incidents/${encodeURIComponent(id)}/evidence`, { interval: 5000, transform: data => ({
    items: readCollection(data, 'events').map(mapEvent), membership: data?.evidence_membership || data?.membership_type || null,
    hasMore: data?.has_more === true, recordedCount: data?.recorded_evidence_count, reconstructedCount: data?.reconstructed_request_count, countsMatch: data?.matches_recorded_count,
  }) })
  return <Panel title="Evidence requests" subtitle="Liên kết sự kiện và phương pháp xác định membership" resource={resource}>
    <EvidenceExportButtons incidentId={id} available={Boolean(resource.data)} />
    {resource.data && <><p className="v4-panel-note">Membership: <strong>{display(resource.data.membership)}</strong>. Tập tái dựng theo cửa sổ không phải membership bất biến.</p><p className="v4-panel-note">P17 ghi nhận {display(resource.data.recordedCount)} request; tái dựng được {display(resource.data.reconstructedCount)} request.{resource.data.countsMatch === false && <strong> Hai số khác nhau; không sửa evidence_count gốc.</strong>}</p><div className="table-scroll"><table className="v4-table"><thead><tr><th>EVENT / REQUEST ID</th><th>THỜI ĐIỂM</th><th>RULES</th><th>P15</th><th>DECISION</th></tr></thead><tbody>{resource.data.items.map(event => <tr key={`${event.stream_id}:${event.event_id}`}><td><a className="v4-id-link" href={`#/events/${encodeURIComponent(event.event_id)}?stream_id=${encodeURIComponent(event.stream_id || '')}`}>{event.event_id}</a><small>{display(event.request_id)}</small></td><td>{time(event.occurred_at)}</td><td>{event.matched_rules.join(', ') || '—'}</td><td>{display(event.risk.score)}<small>{display(event.risk.status)}</small></td><td><Badge value={event.decision} /></td></tr>)}</tbody></table></div>{!resource.data.items.length && <Empty title="Chưa có evidence có thể đọc" text="Không suy ra nội dung request từ evidence_count." />}{resource.data.hasMore && <p className="v4-panel-note">Đang hiển thị một phần evidence. Không dùng số dòng này làm tổng số request.</p>}</>}
  </Panel>
}

export function NetworkObservation({ observation, meta, error }) {
  const time = useTime()
  const verified = isVerifiedNetwork(observation, meta, Boolean(error))
  return <div className="v4-network-observation"><div><span className="v4-label">MẠNG HIỆN TẠI</span><Badge value={verified ? observation.state : 'UNKNOWN'} /></div><p>{verified ? 'Đã đọc trạng thái từ Neutron.' : 'Chưa có quan sát Neutron live đủ mới để kết luận.'}</p><FieldGrid rows={[
    ['Quan sát lúc', time(observation?.observed_at)], ['Phương pháp', display(observation?.verification)],
    [verified ? 'Security groups hiện tại' : 'Security groups lần quan sát trước', Array.isArray(observation?.security_group_ids) ? observation.security_group_ids.join(' · ') || 'Không có SG' : 'Chưa xác minh'],
  ]} /></div>
}

function TimelinePanel({ id }) { return <IncidentInvestigation incidentId={id} /> }

function DecisionPanel({ id }) {
  const time = useTime()
  const { auth } = usePortal()
  const allowed = auth.status === 'local_snapshot' || ['Analyst', 'Operator', 'Approver', 'Executor'].includes(auth.user?.role)
  const resource = useV4Resource(`/incidents/${encodeURIComponent(id)}/decision`, { interval: 0, enabled: allowed })
  return <Panel title="Đánh giá phản ứng" subtitle="Dry-run P17.3 · không thay đổi mạng" resource={resource} action={<button type="button" className="button secondary v4-decision-refresh" disabled={!allowed || resource.loading} onClick={resource.refresh}><RefreshCw size={14} className={resource.loading ? 'spin' : ''} />{resource.loading ? 'Đang đọc…' : 'Làm mới dry-run'}</button>}>
    {!allowed && <p className="v4-panel-note">Cần đăng nhập với quyền Analyst hoặc quyền đánh giá phản ứng tương ứng.</p>}
    <FieldGrid rows={[["Đánh giá lúc", time(resource.data?.evaluated_at)]]} />
    <DecisionChecklist data={resource.data} />
    <div className="v4-action-boundary"><button className="button secondary" disabled>Cách ly qua Portal · Phase 2</button><p>Thao tác thay đổi mạng cần Broker, phê duyệt và đường khôi phục đã nghiệm thu.</p></div>
  </Panel>
}

function NotesPanel({ id }) {
  const { auth, sessionVersion } = usePortal()
  const [text, setText] = useState('')
  const [state, setState] = useState({ busy: false, error: '', saved: false })
  const pending = useRef(false)
  const key = useRef(null)
  const allowed = canWriteNotes(auth.user, auth.csrfToken)
  return <Panel title="Ghi chú review" subtitle="Ghi vào Portal · không thay đổi trạng thái phát hiện P17">
    <form key={sessionVersion} onSubmit={async event => {
      event.preventDefault()
      if (!allowed || !text.trim() || pending.current) return
      pending.current = true
      key.current ||= crypto.randomUUID()
      setState({ busy: true, error: '', saved: false })
      try { await portalRequest(`/incidents/${encodeURIComponent(id)}/notes`, { method: 'POST', body: { note: text.trim() }, csrfToken: auth.csrfToken, idempotencyKey: key.current }); setText(''); key.current = null; setState({ busy: false, error: '', saved: true }) }
      catch (error) { setState({ busy: false, error: error.message, saved: false }) }
      finally { pending.current = false }
    }}><label className="v4-filter"><span>Nội dung ghi chú</span><textarea rows={4} maxLength={1000} value={text} disabled={!allowed || state.busy} onChange={event => { setText(event.target.value); key.current = null; setState(current => ({ ...current, saved: false })) }} placeholder="Kết quả kiểm tra và hướng xử lý…" /></label>{!allowed && <p className="v4-panel-note">{auth.status === 'local_snapshot' ? (auth.remote ? 'Nguồn SSH hiện chỉ đọc; chưa bật lưu ghi chú hoặc review.' : 'Bản chụp hiện chỉ đọc; chưa bật lưu ghi chú hoặc review.') : 'Cần phiên đăng nhập hợp lệ có quyền Analyst, Operator hoặc Approver để ghi chú.'}</p>}{state.error && <p className="v4-form-error" role="alert">{state.error}</p>}{state.saved && <p className="v4-success" role="status">Đã lưu ghi chú vào Portal.</p>}<button className="button primary" disabled={!allowed || !text.trim() || state.busy}><FileText size={14} />{state.busy ? 'Đang lưu…' : 'Lưu ghi chú'}</button></form>
  </Panel>
}

export function IncidentDetail({ id }) {
  const { sessionAuthEnabled } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/incidents/${encodeURIComponent(id)}`, { interval: 5000, transform: mapIncident })
  const incident = resource.data
  return <><a className="incident-back" href="#/incidents"><ArrowLeft size={15} />Incident Center</a><PageHeading eyebrow="INCIDENT INVESTIGATION" title="Chi tiết incident" description={id} resource={resource}><CopyId value={id} /></PageHeading><SourceStatus resource={resource} label="P17.2 Incident" /><ResourceNotice resource={resource} noun="incident" />
    {incident && <><section className="v4-incident-identity" aria-label="Nhận diện incident"><div><span className="v4-label">SIGNAL P17</span><strong>{display(incident.signal_rule)}</strong></div><div><span className="v4-label">SOURCE IP</span><strong>{display(incident.source_ip)}</strong></div><div><span className="v4-label">CONFIDENCE P17</span><strong>{display(incident.confidence)}</strong></div></section><div className="v4-detail-statuses"><div><span>SEVERITY P17</span><Badge value={incident.severity} /></div><div><span>PHÁT HIỆN</span><Badge value={incident.incident_status} /></div><div><span>PHẢN ỨNG ĐÃ GHI NHẬN</span><Badge value={incident.response_state} /></div><div><span>PEAK P15</span><strong>{display(incident.p15_peak_score)}<small> / 100</small></strong></div></div>
      <div className="v4-detail-grid"><Panel title="Detection & source"><FieldGrid rows={[
        ['Signal rule', display(incident.signal_rule)], ['Nguồn', display(incident.source_ip)], ['Confidence', display(incident.confidence)],
        ['Evidence count P17', display(incident.evidence_count)], ['Lần đầu', time(incident.first_seen)], ['Lần cuối', time(incident.last_seen)],
        ['Stream ID', display(incident.stream_id)], ['Membership', display(incident.evidence_membership)], ['Portal review', display(incident.review_state)],
      ]} /><p className="v4-panel-note">{incident.signal_rule === 'CORR-003' ? 'CORR-003: truy cập dữ liệu nhạy cảm lặp lại trong cửa sổ 120 giây. Signal này không tự cho phép cách ly.' : incident.signal_rule === 'CORR-002' ? 'CORR-002: tối thiểu 3 request BLOCK injection riêng biệt trong cửa sổ 60 giây của cùng nhóm nguồn. P15=100 đơn lẻ chưa đủ để tự cách ly.' : 'Signal và evidence_count được giữ nguyên theo P17; Portal không tự tương quan hoặc tạo incident mới.'}</p></Panel>
      <Panel title="Cloud mapping" subtitle="Đối chiếu IP hiện tại · danh tính lịch sử được đánh giá riêng"><CurrentMapping mapping={incident.current_mapping} error={resource.error} /><h3 className="v4-subheading">Xác minh danh tính trong evidence P17</h3><VerifiedSource mapping={incident.mapping} meta={resource.meta} error={resource.error} /></Panel></div>
      <EvidencePanel id={id} /><div className="v4-detail-grid"><TimelinePanel id={id} /><div className="v4-stack"><DecisionPanel id={id} />{sessionAuthEnabled
        ? <IncidentBusinessPanel id={id} streamId={incident.stream_id} />
        : <><ReviewPanel incident={incident} onSaved={resource.refresh} /><NotesPanel id={id} /></>}</div></div>
    </>}
  </>
}
