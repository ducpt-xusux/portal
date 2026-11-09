import { CircleAlert, Database } from 'lucide-react'
import { dateTimeLabel } from '../utils/format'

export default function AuditSourceNotice({ meta, error, hasCache = false }) {
  const source = meta?.audit_source
  const stale = Boolean(error) || meta?.data_state === 'STALE'
  const degraded = meta?.data_state === 'DEGRADED'
  return <div className={`audit-source-notice ${stale || degraded ? 'is-stale' : ''}`} role={stale || degraded ? 'alert' : 'status'}>
    {stale || degraded ? <CircleAlert size={20} /> : <Database size={20} />}
    <div><strong>{stale ? hasCache ? 'STALE · đang giữ kết quả lần đọc trước' : 'UNKNOWN · chưa tải được audit'
      : degraded ? 'DEGRADED · nguồn audit có bản ghi lỗi'
        : source?.mode === 'snapshot' ? 'Bản chụp audit thật · dữ liệu lịch sử'
          : source ? 'Audit từ API · nguồn log trực tiếp' : 'Đang kết nối FastAPI'}</strong>
      <p>{error || (degraded ? `${source?.invalid_records || 0} bản ghi lỗi, ${source?.conflicting_records || 0} ID xung đột. Chỉ hiển thị các bản ghi hợp lệ.`
        : source?.mode === 'snapshot' ? 'Nguồn local là log P16 bạn cung cấp. Chưa theo dõi log trên Proxy.'
          : source ? 'Backend đọc file audit được cấu hình; trạng thái này chưa xác nhận sức khỏe Firewall hoặc Galera.' : 'Không sử dụng dữ liệu demo làm phương án thay thế.')}</p>
      {meta?.timestamp && <small>Lần đọc API: {dateTimeLabel(meta.timestamp)} · UTC+7{source?.pending_bytes > 0 ? ' · còn dữ liệu đang chờ nhập' : ''}</small>}
    </div>
  </div>
}
