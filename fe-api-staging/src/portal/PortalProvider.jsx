import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BusinessSessionBridge,
  createBusinessClient,
} from '../features/n91-business'
import { isLocalSnapshotAccess, portalRequest } from '../services/portalApi'
import { readIncidentFilterSupport } from '../services/incidentFilters'
import { PortalContext } from './PortalContext'

function stored(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback
  } catch {
    return fallback
  }
}

const emptyAuth = (status) => ({
  status,
  user: null,
  csrfToken: null,
  error: null,
})

export function PortalProvider({ children }) {
  const [mode, setModeState] = useState(() =>
    stored('dbsec-source', 'v4') === 'p16' ? 'p16' : 'v4'
  )
  const [timezone, setTimezoneState] = useState(() =>
    stored('dbsec-timezone', 'Asia/Ho_Chi_Minh') === 'UTC'
      ? 'UTC'
      : 'Asia/Ho_Chi_Minh'
  )
  const [auth, setAuth] = useState(() => emptyAuth('checking'))
  const [access, setAccess] = useState('checking')
  const [accessAttempt, setAccessAttempt] = useState(0)
  const sessionAuthEnabled = access === 'SESSION'
  const [sessionVersion, setSessionVersion] = useState(0)
  const [loginOpen, setLoginOpen] = useState(false)
  const changePreference = (key, value) => {
    try {
      localStorage.setItem(key, value)
    } catch {
      /* Preference is optional. */
    }
  }
  const setMode = (mode) => {
    setModeState(mode)
    changePreference('dbsec-source', mode)
  }
  const setTimezone = (zone) => {
    setTimezoneState(zone)
    changePreference('dbsec-timezone', zone)
  }
  const sessionChanged = useCallback(
    () => setSessionVersion((value) => value + 1),
    []
  )
  const expire = useCallback(
    () =>
      setAuth((previous) =>
        previous.status === 'authenticated' ? emptyAuth('anonymous') : previous
      ),
    []
  )
  const businessClient = useMemo(
    () => createBusinessClient({ onExpired: expire }),
    [expire]
  )
  const retryAccess = () => setAccessAttempt((value) => value + 1)
  useEffect(() => {
    const controller = new AbortController()
    setAccess('checking')
    portalRequest('/portal/access-mode', { signal: controller.signal })
      .then(({ data }) => {
        if (!['SESSION', 'OBSERVATION'].includes(data?.mode))
          throw new Error('INVALID_ACCESS_MODE')
        if (!controller.signal.aborted) setAccess(data.mode)
      })
      .catch(() => {
        if (!controller.signal.aborted) setAccess('unavailable')
      })
    return () => controller.abort()
  }, [accessAttempt])
  useEffect(() => {
    window.addEventListener('portal-session-expired', expire)
    return () => window.removeEventListener('portal-session-expired', expire)
  }, [expire])
  useEffect(() => {
    if (!['SESSION', 'OBSERVATION'].includes(access)) return
    const controller = new AbortController()
    setAuth(emptyAuth('checking'))
    portalRequest('/auth/me', { signal: controller.signal })
      .then(async ({ data }) => {
        const capabilities = Array.isArray(data?.capabilities)
          ? data.capabilities
              .filter(
                (value) => typeof value === 'string' && value.length <= 80
              )
              .slice(0, 32)
          : []
        const incidentFilters = readIncidentFilterSupport(
          data?.incident_filters
        )
        if (!sessionAuthEnabled && isLocalSnapshotAccess(data)) {
          if (!controller.signal.aborted)
            setAuth({
              status: 'local_snapshot',
              remote: data.source_mode === 'REMOTE_READONLY',
              capabilities,
              incidentFilters,
              writeEnabled: false,
              user: null,
              csrfToken: null,
              error: null,
            })
          return
        }
        if (!sessionAuthEnabled)
          throw new Error('INVALID_OBSERVATION_CAPABILITIES')
        if (
          !Array.isArray(data?.roles) ||
          !data.roles.length ||
          typeof data.username !== 'string' ||
          typeof data.csrf_token !== 'string' ||
          !(Date.parse(data.expires_at) > Date.now())
        ) {
          throw new Error('INVALID_SESSION')
        }
        const { data: businessCapabilities } = await portalRequest(
          '/portal/session/capabilities',
          { signal: controller.signal }
        )
        if (typeof businessCapabilities?.user_id !== 'string')
          throw new Error('INVALID_SESSION_CAPABILITIES')
        if (!controller.signal.aborted)
          setAuth({
            status: 'authenticated',
            sessionData: data,
            businessCapabilities,
            capabilities,
            incidentFilters,
            writeEnabled: false,
            csrfToken: data.csrf_token,
            error: null,
            user: {
              user_id: businessCapabilities.user_id,
              login: data.username,
              role: data.roles.join(', '),
              roles: data.roles,
            },
          })
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setAuth({
            status: error.status === 401 ? 'anonymous' : 'unavailable',
            user: null,
            csrfToken: null,
            error,
          })
      })
    return () => controller.abort()
  }, [access, sessionAuthEnabled, sessionVersion])
  const login = async (username, password) => {
    await portalRequest('/auth/login', {
      method: 'POST',
      body: { username, password },
    })
    sessionChanged()
    setLoginOpen(false)
  }
  const logout = async () => {
    if (!auth.csrfToken)
      throw new Error(
        'Phiên chưa cung cấp CSRF token để đăng xuất an toàn. Hãy kiểm tra dịch vụ đăng nhập.'
      )
    await portalRequest('/auth/logout', {
      method: 'POST',
      csrfToken: auth.csrfToken,
      body: {},
    })
    setAuth({ status: 'anonymous', user: null, csrfToken: null, error: null })
    sessionChanged()
  }
  return (
    <PortalContext.Provider
      value={{
        access,
        retryAccess,
        sessionAuthEnabled,
        mode,
        setMode,
        timezone,
        setTimezone,
        auth,
        login,
        logout,
        loginOpen,
        setLoginOpen,
        sessionVersion,
        sessionChanged,
      }}
    >
      {sessionAuthEnabled ? (
        <BusinessSessionBridge
          status={auth.status}
          session={auth.sessionData}
          capabilities={auth.businessCapabilities}
          client={businessClient}
          login={login}
          logout={logout}
          refresh={sessionChanged}
        >
          {children}
        </BusinessSessionBridge>
      ) : (
        children
      )}
    </PortalContext.Provider>
  )
}
