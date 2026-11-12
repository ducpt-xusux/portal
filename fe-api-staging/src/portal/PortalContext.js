import { createContext, useContext } from 'react'

export const PortalContext = createContext(null)
export const usePortal = () => useContext(PortalContext)

/**
 * Dashboard Portal v4 hiển thị gọn: ẩn tên nguồn kỹ thuật (source_system) và
 * nhãn HISTORICAL trên thanh trạng thái nguồn. Các trang khác giữ nguyên.
 */
export const SourceDisplayContext = createContext({ hideSourceSystem: false })
export const useSourceDisplay = () => useContext(SourceDisplayContext)
