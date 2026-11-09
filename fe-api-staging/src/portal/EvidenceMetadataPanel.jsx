import { useEffect, useRef, useState } from 'react'
import { useV4Resource } from './IncidentPages'
import { readEvidence } from '../services/demoCoverageApi'

export default function EvidenceMetadataPanel({ evidenceId, onClose }) {
  const resource = useV4Resource(`/evidence/${encodeURIComponent(evidenceId)}`, { interval: 0, transform: data => readEvidence(data, evidenceId) })
  const ref = useRef(null), [copyState, setCopyState] = useState('')
  const data = resource.error ? null : resource.data
  useEffect(() => {
    const previous = document.activeElement
    ref.current?.showModal()
    return () => { ref.current?.close(); previous?.focus() }
  }, [])
  async function copy(value) {
    try { await navigator.clipboard.writeText(value); setCopyState('Đã sao chép') }
    catch { setCopyState('Clipboard chưa khả dụng; chọn và sao chép giá trị bên dưới.') }
  }
  return <dialog className="demo-evidence-dialog" ref={ref} onCancel={onClose} aria-labelledby="demo-evidence-title">
    <div className="demo-dialog-heading"><h2 id="demo-evidence-title">Evidence metadata</h2><button onClick={onClose} autoFocus>Đóng</button></div>
    <p>Analyst contract · local owner read-only khi chưa có session adapter. Metadata đã sanitize.</p>
    {resource.loading && <p role="status">LOADING · Đang đọc metadata…</p>}
    {resource.error && <p role="alert">UNAVAILABLE · {resource.error.code || 'NETWORK_ERROR'}. <button onClick={resource.refresh}>Thử lại</button></p>}
    {data && <><dl>{[
      ['Evidence ID', data.evidence_id], ['Kind', data.evidence_kind], ['Entity', `${data.related_entity_type}: ${data.related_entity_id}`],
      ['SHA256 sanitized/imported bytes', data.sha256], ['Size (bytes)', data.size_bytes], ['Source', data.source_system],
      ['Captured at (UTC)', data.captured_at], ['Data as of (UTC)', data.provenance.data_as_of],
      ['Read at (UTC)', data.provenance.read_at], ['Freshness', data.provenance.freshness_state], ['Sanitization', data.sanitization_state],
    ].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? 'UNKNOWN'}</dd></div>)}</dl>
      <div className="demo-actions"><button onClick={() => copy(data.evidence_id)}>Copy ID</button><button onClick={() => copy(data.sha256)}>Copy SHA256</button></div>
      <p role="status">{copyState}</p><h3>Provenance & limitations</h3><ul>{data.notes.map(note => <li key={note}>{note}</li>)}</ul>
      <p>Hash match tại import không chứng minh testcase PASS hoặc human signoff. Source bytes không được phục vụ.</p></>}
  </dialog>
}
