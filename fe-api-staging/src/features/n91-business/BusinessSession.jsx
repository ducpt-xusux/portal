import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import { createBusinessClient, permissions } from './businessApi'
import './business.css'
const Context = createContext(null)
export const useBusinessSession = () => {
  const value = useContext(Context)
  if (!value) throw new Error('BusinessSessionProvider required')
  return value
}
export function BusinessSessionProvider({ children, client: injectedClient }) {
  const [state, setState] = useState({
    status: 'checking',
    session: null,
    capabilities: null,
    error: null,
  })
  const client = useMemo(
    () =>
      injectedClient ||
      createBusinessClient({
        onExpired: () =>
          setState({
            status: 'anonymous',
            session: null,
            capabilities: null,
            error: null,
          }),
      }),
    [injectedClient]
  )
  const refresh = useCallback(async () => {
    try {
      const session = await client.me(),
        capabilities = await client.capabilities()
      setState({ status: 'authenticated', session, capabilities, error: null })
    } catch (error) {
      setState({
        status: error.status === 401 ? 'anonymous' : 'unavailable',
        session: null,
        capabilities: null,
        error,
      })
    }
  }, [client])
  useEffect(() => {
    refresh()
  }, [refresh])
  useEffect(() => {
    if (!state.session) return
    const timeout = setTimeout(
      () => {
        setState({
          status: 'anonymous',
          session: null,
          capabilities: null,
          error: null,
        })
      },
      Math.max(0, Date.parse(state.session.expires_at) - Date.now())
    )
    return () => clearTimeout(timeout)
  }, [state.session])
  const login = async (username, password) => {
    await client.login(username, password)
    await refresh()
  }
  const logout = async () => {
    try {
      await client.logout()
    } finally {
      setState({
        status: 'anonymous',
        session: null,
        capabilities: null,
        error: null,
      })
    }
  }
  const value = {
    ...state,
    client,
    refresh,
    login,
    logout,
    ...permissions(state.session, state.capabilities),
  }
  return <Context.Provider value={value}>{children}</Context.Provider>
}
export function BusinessSessionBridge({
  children,
  status,
  session,
  capabilities,
  client,
  login,
  logout,
  refresh,
}) {
  // Integrates an existing server-session store without a second me/login lifecycle.
  useEffect(() => {
    client.adoptSession(status === 'authenticated' ? session : null)
  }, [client, status, session])
  useEffect(() => {
    if (status !== 'authenticated' || !session) return
    const timer = setTimeout(
      () => {
        client.adoptSession(null)
        refresh()
      },
      Math.max(0, Date.parse(session.expires_at) - Date.now())
    )
    return () => clearTimeout(timer)
  }, [client, status, session, refresh])
  const value = {
    status,
    session,
    capabilities,
    client,
    login,
    logout,
    refresh,
    ...permissions(session, capabilities),
  }
  return <Context.Provider value={value}>{children}</Context.Provider>
}
export function BusinessLoginPanel() {
  const { status, session, capabilities, login, logout, refresh } =
    useBusinessSession()
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState(''),
    [busy, setBusy] = useState(false),
    [error, setError] = useState('')
  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(username, password)
      setPassword('')
    } catch (error) {
      setError(error.code || 'BUSINESS_UNAVAILABLE')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }
  if (status === 'checking')
    return (
      <section className="n91-business" aria-live="polite">
        Đang kiểm tra phiên…
      </section>
    )
  if (status === 'authenticated')
    return (
      <section className="n91-business n91-business-session">
        <div>
          <strong>{session.username}</strong>
          <span> · {session.roles.join(', ')}</span>
          <small>
            Hết hạn {session.expires_at} ·{' '}
            {capabilities.context === 'TEST'
              ? 'Phiên thử nghiệm'
              : 'Phiên đăng nhập Portal'}
          </small>
        </div>
        <button
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            setError('')
            try {
              await logout()
            } catch (e) {
              setError(e.code || 'BUSINESS_UNAVAILABLE')
            } finally {
              setBusy(false)
            }
          }}
        >
          Đăng xuất
        </button>
        {error && <p role="alert">{error}</p>}
      </section>
    )
  return (
    <section className="n91-business">
      <h2>Đăng nhập Portal</h2>
      <p>Phiên người dùng quản lý ghi chú và rà soát trong Portal DB.</p>
      {status === 'unavailable' && (
        <p role="status">
          Dịch vụ phiên UNAVAILABLE. <button onClick={refresh}>Thử lại</button>
        </p>
      )}
      <form onSubmit={submit}>
        <label>
          Tài khoản
          <input
            name="username"
            autoComplete="username"
            required
            minLength={3}
            maxLength={64}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label>
          Mật khẩu
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={128}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <button disabled={busy}>
          {busy ? 'Đang đăng nhập…' : 'Đăng nhập'}
        </button>
        {error && <p role="alert">{error}</p>}
      </form>
    </section>
  )
}
