// Presentation helpers shared by the P16 API views. No sample data or incident logic.
export function dateTimeLabel(value) {
  return new Intl.DateTimeFormat('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(value))
}

export function timeLabel(value, includeSeconds = false) {
  return new Intl.DateTimeFormat('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', hour: '2-digit', minute: '2-digit', ...(includeSeconds ? { second: '2-digit' } : {}), hour12: false }).format(new Date(value))
}

export const numberLabel = value => new Intl.NumberFormat('vi-VN').format(value)
