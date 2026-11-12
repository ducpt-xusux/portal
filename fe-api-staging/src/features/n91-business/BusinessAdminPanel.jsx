import { uiLabel, uiRoleList } from '../../services/uiLanguage.js'
import { useCallback, useEffect, useState } from 'react'
import { useBusinessSession } from './BusinessSession'
import { newIntent } from './businessApi'
const ROLES = [
  'Viewer',
  'Analyst',
  'Operator',
  'Approver',
  'Executor',
  'Auditor',
]
export function BusinessAdminPanel() {
  const auth = useBusinessSession(),
    [users, setUsers] = useState([]),
    [audit, setAudit] = useState([]),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false)
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState(''),
    [role, setRole] = useState('Viewer')
  const load = useCallback(async () => {
    if (!auth.canAudit && !auth.canAdmin) return
    try {
      const [u, a] = await Promise.all([
        auth.canAdmin ? auth.client.users() : { items: [] },
        auth.client.audit(),
      ])
      setUsers(u.items)
      setAudit(a.items)
    } catch (e) {
      setError(e.code || 'BUSINESS_UNAVAILABLE')
    }
  }, [auth.client, auth.canAdmin, auth.canAudit])
  useEffect(() => {
    setUsers([])
    setAudit([])
    load()
  }, [load])
  async function provision(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await auth.client.createUser(
        { username, password, roles: [role] },
        newIntent()
      )
      setPassword('')
      setUsername('')
      await load()
    } catch (e) {
      setError(e.code || 'BUSINESS_UNAVAILABLE')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }
  async function change(user, roles, active) {
    setBusy(true)
    setError('')
    try {
      await auth.client.updateUser(
        user.user_id,
        { version: user.version, roles, active },
        newIntent()
      )
      await load()
    } catch (e) {
      setError(e.code || 'BUSINESS_UNAVAILABLE')
      if (e.status === 409) await load()
    } finally {
      setBusy(false)
    }
  }
  if (!auth.canAudit && !auth.canAdmin)
    return (
      <section className="n91-business">
        Cần quyền Auditor hoặc Portal admin để xem thông tin nguồn quản trị.
      </section>
    )
  return (
    <section className="n91-business">
      <h2>Quản trị Portal</h2>
      <p>
        Quyền quản trị do operator bootstrap riêng. Role Operator không tự có
        quyền quản lý user.
      </p>
      {error && <p role="alert">{error}</p>}
      {auth.canAdmin && (
        <>
          <form onSubmit={provision}>
            <label>
              User mới
              <input
                required
                minLength={3}
                maxLength={64}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Mật khẩu mới
              <input
                type="password"
                required
                minLength={12}
                maxLength={128}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            <label>
              Role
              <select
                aria-label="Vai trò"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>{uiLabel(r)}</option>
                ))}
              </select>
            </label>
            <button disabled={busy}>Tạo user Portal</button>
          </form>
          <div className="n91-business-scroll">
            <table>
              <caption>Users · tối đa 100 bản ghi/trang</caption>
              <thead>
                <tr>
                  <th>Người dùng</th>
                  <th>Vai trò hiện tại</th>
                  <th>Trạng thái</th>
                  <th>Thay đổi</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.user_id}>
                    <td>{u.username}</td>
                    <td>{u.roles.join(', ')}</td>
                    <td>
                      {u.active ? 'ACTIVE' : 'INACTIVE'} · v{u.version}
                    </td>
                    <td>
                      <select
                        aria-label={`Đổi role ${u.username}`}
                        disabled={busy}
                        value=""
                        onChange={(e) =>
                          e.target.value &&
                          change(u, [e.target.value], u.active)
                        }
                      >
                        <option value="">Chọn vai trò…</option>
                        {ROLES.map((r) => (
                          <option key={r} value={r}>{uiLabel(r)}</option>
                        ))}
                      </select>
                      <button
                        disabled={busy}
                        onClick={() => change(u, u.roles, !u.active)}
                      >
                        {u.active ? 'Vô hiệu hóa' : 'Kích hoạt'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <h3>Nhật ký thao tác</h3>
      <div className="n91-business-scroll">
        <table>
          <caption>
            Portal audit · 100 thao tác đầu; không chứa mật khẩu/hash phiên
          </caption>
          <thead>
            <tr>
              <th>UTC</th>
              <th>Người thực hiện</th>
              <th>Hành động</th>
              <th>Kết quả</th>
              <th>Trước / sau</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((a) => (
              <tr key={a.audit_id}>
                <td>{a.timestamp}</td>
                <td>{a.actor_id}</td>
                <td>{a.action}</td>
                <td>{uiLabel(a.outcome)}</td>
                <td>
                  <details>
                    <summary>Thông tin nguồn thay đổi</summary>
                    <pre>
                      {JSON.stringify(
                        { before: a.before, after: a.after },
                        null,
                        2
                      )}
                    </pre>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
