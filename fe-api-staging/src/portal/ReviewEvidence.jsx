import { useEffect, useRef, useState } from 'react'
import { Download, FileCheck2 } from 'lucide-react'
import { canExportEvidence, canReviewIncident, requestEvidenceFile, submitIncidentReview } from '../services/incidentActions'
import { usePortal } from './PortalContext'
import { Badge, display, Panel, useTime } from './PortalUI'

export function EvidenceExportButtons({ incidentId, available }) {
  const { auth } = usePortal()
  const alive = useRef(true), latestAuth = useRef(auth)
  latestAuth.current = auth
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const pending = useRef(false), keys = useRef({})
  const [state, setState] = useState({ busy: false, error: '', message: '' })
  const allowed = canExportEvidence(auth)
  const download = async format => {
    if (!allowed || !available || pending.current) return
    pending.current = true
    keys.current[format] ||= crypto.randomUUID()
    setState({ busy: true, error: '', message: '' })
    try {
      const file = await requestEvidenceFile(auth, incidentId, format, keys.current[format])
      if (!alive.current || !canExportEvidence(latestAuth.current) || latestAuth.current.user?.user_id !== auth.user?.user_id || latestAuth.current.csrfToken !== auth.csrfToken) return
      const url = URL.createObjectURL(new Blob([file.content], { type: file.mime }))
      const anchor = document.createElement('a')
      anchor.href = url; anchor.download = file.filename; document.body.append(anchor); anchor.click(); anchor.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      keys.current[format] = null
      setState({ busy: false, error: '', message: `${file.exported_event_count} event · ${file.completeness === 'COMPLETE' ? 'đủ tập được nguồn cấp' : 'tập con PARTIAL'} · Audit ${file.audit_id}` })
    } catch (error) { setState({ busy: false, error: error.message, message: '' }) }
    finally { pending.current = false }
  }
  return <div className="v4-evidence-export"><div className="v4-inline-actions">{['json', 'csv'].map(format => <button key={format} type="button" className="button secondary" disabled={!allowed || !available || state.busy} onClick={() => download(format)}><Download size={14} />Xuất {format.toUpperCase()}</button>)}</div>
    <p className="v4-panel-note">Xuất tham chiếu evidence: ID, thời gian, rule, điểm và provenance; không kèm SQL, DB user hoặc nội dung ghi chú. Bản xuất phải được dịch vụ cấp quyền và ghi audit.</p>
    {!allowed && <p className="v4-panel-note">Phiên này chưa được cấp chức năng xuất evidence có audit.</p>}
    {state.error && <p role="alert" className="v4-form-error">{state.error}</p>}{state.message && <p role="status" className="v4-success">{state.message}</p>}
  </div>
}

export function ReviewPanel({ incident, onSaved }) {
  const { auth } = usePortal(), time = useTime()
  const [reviewState, setReviewState] = useState('ACKNOWLEDGED')
  const [note, setNote] = useState('')
  const [state, setState] = useState({ busy: false, error: '', saved: false })
  const pending = useRef(false), key = useRef(null)
  const allowed = canReviewIncident(auth) && Boolean(incident.review_revision)
  const change = callback => value => { callback(value); key.current = null; setState(previous => ({ ...previous, saved: false, error: '' })) }
  return <Panel title="ACK / review annotation" subtitle="Trạng thái xử lý của Portal · độc lập với phát hiện P17 và cách ly VM"><div className="v4-review-current"><span>Review hiện tại</span><Badge value={incident.review_state} /></div>
    <form onSubmit={async event => {
      event.preventDefault()
      if (!allowed || pending.current) return
      pending.current = true; key.current ||= crypto.randomUUID()
      setState({ busy: true, error: '', saved: false })
      try {
        await submitIncidentReview(auth, incident.incident_id, { reviewState, note, revision: incident.review_revision, idempotencyKey: key.current })
        key.current = null; setNote(''); setState({ busy: false, error: '', saved: true }); onSaved()
      } catch (error) { if ([409, 412].includes(error.status)) { key.current = null; onSaved() } setState({ busy: false, error: error.message, saved: false }) }
      finally { pending.current = false }
    }}><label className="v4-filter"><span>Annotation review</span><select value={reviewState} disabled={!allowed || state.busy} onChange={event => change(setReviewState)(event.target.value)}><option value="ACKNOWLEDGED">ACK · đã tiếp nhận</option><option value="REVIEWED">REVIEWED · đã rà soát</option></select></label>
      <label className="v4-filter"><span>Lý do / ghi chú review</span><textarea rows={3} maxLength={1000} value={note} disabled={!allowed || state.busy} onChange={event => change(setNote)(event.target.value)} /></label>
      {!allowed && <p className="v4-panel-note">Nguồn review chưa sẵn sàng hoặc phiên này chưa có quyền ghi. Trạng thái phát hiện P17 được giữ nguyên.</p>}
      <button className="button primary" disabled={!allowed || state.busy}><FileCheck2 size={14} />{state.busy ? 'Đang lưu…' : 'Lưu ACK / review'}</button>
      {state.error && <p role="alert" className="v4-form-error">{state.error}</p>}{state.saved && <p role="status" className="v4-success">Đã lưu annotation do dịch vụ xác nhận.</p>}
    </form>
    <h3 className="v4-subheading">Lịch sử annotation</h3>{incident.review_annotations.length ? <ol className="v4-review-history">{incident.review_annotations.map((row, index) => <li key={row.annotation_id || index}><Badge value={row.review_state} /><strong>{display(row.author)}</strong><time>{time(row.created_at)}</time>{row.note && <p>{row.note}</p>}</li>)}</ol> : <p className="v4-panel-note">Chưa có lịch sử annotation được nguồn cung cấp.</p>}
  </Panel>
}
