import { createContext, useContext, useState } from 'react'

const DetailContext = createContext({ kind: null, compact: false })
export function DetailView({ kind, children }) {
  const [compact, setCompact] = useState(true)
  return <DetailContext.Provider value={{ kind, compact: Boolean(kind && compact), setCompact }}>
    {children}
  </DetailContext.Provider>
}
export const useDetailView = () => useContext(DetailContext)

export function DetailToggle() {
  const { kind, compact, setCompact } = useDetailView()
  return kind ? <button type="button" className="button secondary" aria-pressed={!compact}
    onClick={() => setCompact(!compact)}>{compact ? 'Xem đầy đủ' : 'Xem gọn'}</button> : null
}

export const meaningful = value => value !== null && value !== undefined &&
  !['', '—', '-', 'n/a', 'unknown', 'unavailable', 'null', 'chưa xác định', 'chưa cung cấp', 'chưa có thời điểm']
    .includes(String(value).trim().toLowerCase())

const normalize = text => String(text).trim().toLowerCase()
const keptFields = new Set([
  'hành động đã kiểm toán', 'kết quả thực thi đã kiểm toán', 'điểm rủi ro kiểm toán', 'quy tắc chặn đã kiểm toán',
  'phát sinh lúc (utc)', 'khớp', 'chặn', 'điểm từ nguồn',
  'mã sự kiện', 'thứ tự', 'phát sinh lúc', 'phát sinh', 'ip nguồn', 'nguồn ip',
  'tài khoản cơ sở dữ liệu', 'cơ sở dữ liệu', 'quyết định', 'quyết định ·',
  'hành động áp dụng', 'kết quả xử lý', 'quy tắc khớp', 'quy tắc chặn',
  'phiên bản chính sách', 'điểm gốc', 'điểm sau giới hạn', 'trạng thái rủi ro',
  'điểm rủi ro', 'trạng thái đánh giá rủi ro', 'ip nguồn', 'tín hiệu', 'tín hiệu quy tắc',
  'mức độ', 'độ tin cậy', 'status', 'trạng thái phát hiện', 'điểm rủi ro cao nhất score',
  'điểm rủi ro cao nhất', 'nguồn đã xác minh', 'được phép cách ly', 'lần đầu', 'lần cuối',
  'phát hiện', 'số bằng chứng', 'phản ứng', 'mã luồng', 'mã yêu cầu', 'trạng thái',
  'nguồn đã xác minh (bộ phát hiện)', 'được phép cách ly (bộ phát hiện)',
])
export function compactFields(rows) {
  return rows.filter(([name, value]) => keptFields.has(normalize(name)) && meaningful(value))
}
