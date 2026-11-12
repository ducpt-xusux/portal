import { useEffect, useRef, useState } from 'react'
import { Download } from 'lucide-react'
import { useBusinessSession } from '../features/n91-business'
import { newIntent } from '../features/n91-business/businessApi'
import { Panel } from './PortalUI'

const errors = {
  SESSION_REQUIRED: 'Phiên đã hết hạn. Hãy đăng nhập lại để xuất bằng chứng.',
  ROLE_REQUIRED: 'Phiên hiện tại chưa được cấp quyền xuất bằng chứng.',
  SOURCE_OBJECT_NOT_FOUND: 'Không tìm thấy sự cố trong luồng dữ liệu này.',
  EVIDENCE_SOURCE_UNAVAILABLE: 'Nguồn bằng chứng chưa sẵn sàng. Hãy đọc lại dữ liệu rồi thử lại.',
  INVALID_EVIDENCE_EXPORT: 'Tệp phản hồi chưa có xác nhận phạm vi và mã kiểm toán hợp lệ.',
}

export function EvidenceExports({ incidentId, streamId, sessionEnabled, available }) {
  return (
    <Panel title="Xuất bằng chứng">
      {sessionEnabled ? (
        <SessionExport incidentId={incidentId} streamId={streamId} available={available} />
      ) : (
        <p>Chế độ quan sát chỉ đọc. Cần phiên Portal được cấp quyền để xuất bằng chứng.</p>
      )}
    </Panel>
  )
}

function SessionExport({ incidentId, streamId, available }) {
  const { status, canExportEvidence, capabilities, client, session } = useBusinessSession()
  if (status !== 'authenticated' || !session?.csrf_token || !canExportEvidence)
    return <p>Phiên hiện tại chưa được cấp quyền xuất bằng chứng.</p>
  const scope = JSON.stringify([incidentId, streamId, capabilities?.user_id, session.csrf_token])
  return <ExportButtons key={scope} client={client} incidentId={incidentId} streamId={streamId} available={available} />
}

function ExportButtons({ client, incidentId, streamId, available }) {
  const [state, setState] = useState({ busy: false, error: '', message: '' })
  const pending = useRef(null)
  const intents = useRef({})
  useEffect(() => () => pending.current?.abort(), [])

  const download = async (format) => {
    if (!available || pending.current) return
    const controller = new AbortController()
    pending.current = controller
    intents.current[format] ||= newIntent()
    setState({ busy: true, error: '', message: '' })
    try {
      const file = await client.exportEvidence(incidentId, streamId, format, intents.current[format], controller.signal)
      if (controller.signal.aborted) return
      const url = URL.createObjectURL(file.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = file.filename
      document.body.append(anchor)
      anchor.click()
      anchor.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      delete intents.current[format]
      setState({ busy: false, error: '',
        message: 'Đã xuất ' + file.eventCount + ' sự kiện. Phạm vi một phần. Mã kiểm toán ' + file.auditId + '.' })
    } catch (error) {
      if (controller.signal.aborted) return
      if (error.status === 409) delete intents.current[format]
      setState({ busy: false, message: '',
        error: errors[error.code] || 'Chưa thể tải tệp bằng chứng. Hãy thử lại.' })
    } finally {
      pending.current = null
    }
  }
  return (
    <div className="v4-evidence-export">
      <p>
        Tệp chứa các tham chiếu P17 theo luồng của sự cố. Các liên kết tái dựng
        có phạm vi một phần. Nội dung ghi chú xử lý nằm riêng trong hồ sơ Portal.
      </p>
      <div className="v4-inline-actions">
        {['json', 'csv'].map((format) => (
          <button key={format} type="button" className="button secondary"
            disabled={!available || state.busy} onClick={() => download(format)}>
            <Download size={14} aria-hidden="true" /> Tải {format.toUpperCase()}
          </button>
        ))}
      </div>
      {!available && <p role="status">Hãy đọc lại dữ liệu nguồn để bật chức năng xuất.</p>}
      {state.busy && <p role="status">Đang chuẩn bị tệp bằng chứng…</p>}
      {state.error && <p role="alert" className="v4-form-error">{state.error}</p>}
      {state.message && <p role="status" className="v4-success">{state.message}</p>}
    </div>
  )
}
