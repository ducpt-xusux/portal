import { useEffect, useId, useRef, useState } from 'react'
import { useV4Resource } from './IncidentPages'
import { useTime, Badge } from './PortalUI'
import { isolationEpisodes } from '../services/proxyPresentation'

export default function NetworkHistory({ entries = [], serverId, name }) {
  const [open, setOpen] = useState(false)
  const dialog = useRef(null)
  const heading = useId()
  const time = useTime()
  const resource = useV4Resource(`/workloads/${encodeURIComponent(serverId)}`, { enabled: open, interval: 0 })
  const hasHistory = entries.some(entry => entry.state === 'QUARANTINED' || entry.previous_state === 'QUARANTINED')
  useEffect(() => {
    if (open) dialog.current?.showModal()
    else dialog.current?.close()
  }, [open])
  const rows = resource.data?.server_id === serverId ? isolationEpisodes(resource.data.network_history) : []
  if (!hasHistory && !open) return null
  return <>
    <button className="n91-workload-history-button" type="button" onClick={() => setOpen(true)} aria-label={`Xem lịch sử cách ly của ${name || serverId}`}>Lịch sử cách ly</button>
    <dialog ref={dialog} className="n91-network-history-dialog" aria-labelledby={heading} onCancel={() => setOpen(false)} onClose={() => setOpen(false)}>
      <header><div><h2 id={heading}>Lịch sử cách ly</h2><p>{name || serverId}</p></div><button type="button" className="button secondary" onClick={() => setOpen(false)}>Đóng ✕</button></header>
      {resource.loading && <p role="status">Đang đọc lịch sử…</p>}
      {resource.error || resource.meta?.network_history_error ? <div role="alert">Chưa đọc được lịch sử cách ly. <button type="button" onClick={resource.refresh}>Thử lại</button></div> : resource.data && <>
        {rows.length ? <div className="table-scroll"><table className="v4-table"><thead><tr><th>Lần</th><th>Bắt đầu cách ly</th><th>Khôi phục</th><th>Kết quả ghi nhận</th></tr></thead><tbody>
          {rows.map((row, index) => <tr key={`${row.started}:${row.restored}:${index}`}><td>{index + 1}</td><td>{row.started ? time(row.started) : 'Ngoài phạm vi lịch sử'}</td><td>{row.restored ? time(row.restored) : '—'}</td><td><Badge value={row.restored ? 'NORMAL' : 'UNKNOWN'}>{row.restored ? 'Đã khôi phục' : 'Chưa có mốc khôi phục'}</Badge></td></tr>)}
        </tbody></table></div> : <p>Chưa có lần cách ly được xác minh trong phạm vi lịch sử hiện có.</p>}
        <p className="muted">Tối đa 10 mốc thay đổi mạng gần nhất. Đây là lịch sử quan sát mạng, chưa phải toàn bộ hành động của bộ điều khiển.</p>
      </>}
    </dialog>
  </>
}
