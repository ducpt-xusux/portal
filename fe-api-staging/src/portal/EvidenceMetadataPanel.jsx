import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { useEffect, useRef, useState } from 'react'
import { useV4Resource } from './IncidentPages'
import { readEvidence } from '../services/demoCoverageApi'

export default function EvidenceMetadataPanel({ evidenceId, onClose }) {
  const resource = useV4Resource(
    `/evidence/${encodeURIComponent(evidenceId)}`,
    { interval: 0, transform: (data) => readEvidence(data, evidenceId) }
  )
  const ref = useRef(null),
    [copyState, setCopyState] = useState('')
  const data = resource.error ? null : resource.data
  useEffect(() => {
    const previous = document.activeElement
    ref.current?.showModal()
    return () => {
      ref.current?.close()
      previous?.focus()
    }
  }, [])
  async function copy(value) {
    try {
      await navigator.clipboard.writeText(value)
      setCopyState('Đã sao chép')
    } catch {
      setCopyState(
        'Clipboard chưa khả dụng; chọn và sao chép giá trị bên dưới.'
      )
    }
  }
  return (
    <dialog
      className="demo-evidence-dialog"
      ref={ref}
      onCancel={onClose}
      aria-labelledby="demo-evidence-title"
    >
      <div className="demo-dialog-heading">
        <h2 id="demo-evidence-title">Thông tin bằng chứng</h2>
        <button onClick={onClose} autoFocus>
          Đóng
        </button>
      </div>
      <p>
        Thông tin bằng chứng đã được ẩn dữ liệu nhạy cảm.
      </p>
      {resource.loading && <p role="status">Đang tải · Đang đọc thông tin nguồn…</p>}
      {resource.error && (
        <p role="alert">
          Chưa có dữ liệu · {resource.error.code || 'NETWORK_ERROR'}.{' '}
          <button onClick={resource.refresh}>Thử lại</button>
        </p>
      )}
      {data && (
        <>
          <dl>
            {[
              ["Bằng chứng ID", data.evidence_id],
              ["Loại", data.evidence_kind],
              [
                "Đối tượng",
                `${data.related_entity_type}: ${data.related_entity_id}`,
              ],
              ["SHA256 dữ liệu đã ẩn / nhập", data.sha256],
              ["Kích thước (byte)", data.size_bytes],
              ["Nguồn", uiLabel(data.source_system)],
              ["Chụp lúc (UTC)", data.captured_at],
              ["Dữ liệu đến (UTC)", data.provenance.data_as_of],
              ["Đọc lúc (UTC)", data.provenance.read_at],
              ['Tình trạng cập nhật', uiLabel(data.provenance.freshness_state)],
              ["Tình trạng ẩn dữ liệu", data.sanitization_state],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value ?? 'UNKNOWN'}</dd>
              </div>
            ))}
          </dl>
          <div className="demo-actions">
            <button onClick={() => copy(data.evidence_id)}>Sao chép ID</button>
            <button onClick={() => copy(data.sha256)}>Sao chép SHA256</button>
          </div>
          <p role="status">{copyState}</p>
          <h3>Nguồn gốc và giới hạn</h3>
          <ul>
            {data.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
          <p>
            Mã băm khớp xác nhận tính toàn vẹn, không thay thế kết quả kiểm thử hoặc nghiệm thu.
          </p>
        </>
      )}
    </dialog>
  )
}
