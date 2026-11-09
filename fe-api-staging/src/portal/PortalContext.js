import { createContext, useContext } from 'react'

export const PortalContext = createContext(null)
export const usePortal = () => useContext(PortalContext)
