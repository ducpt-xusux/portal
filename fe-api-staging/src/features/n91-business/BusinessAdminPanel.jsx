import { uiLabel, uiRoleList } from "../../services/uiLanguage.js";
import { useCallback, useEffect, useState } from "react";
import { useBusinessSession } from "./BusinessSession";
import { newIntent } from "./businessApi";
import { usePortal } from "../../portal/PortalContext";
const ROLES = [
  "Viewer",
  "Analyst",
  "Operator",
  "Approver",
  "Executor",
  "Auditor",
];
export function BusinessAdminPanel() {
  const { singleAccount = false } = usePortal() || {};
  const auth = useBusinessSession(),
    [users, setUsers] = useState([]),
    [audit, setAudit] = useState([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [role, setRole] = useState("Viewer");
  const load = useCallback(async () => {
    if (!auth.canAudit && !auth.canAdmin) return;
    try {
      const [u, a] = await Promise.all([
        auth.canAdmin ? auth.client.users() : { items: [] },
        auth.client.audit(),
      ]);
      setUsers(u.items);
      setAudit(a.items);
      setError("");
    } catch (e) {
      setError(e.code || "BUSINESS_UNAVAILABLE");
    }
  }, [auth.client, auth.canAdmin, auth.canAudit]);
  useEffect(() => {
    setUsers([]);
    setAudit([]);
    load();
  }, [load]);
  async function provision(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await auth.client.createUser(
        { username, password, roles: [role] },
        newIntent(),
      );
      setPassword("");
      setUsername("");
      await load();
    } catch (e) {
      setError(e.code || "BUSINESS_UNAVAILABLE");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }
  async function change(user, roles, active) {
    setBusy(true);
    setError("");
    try {
      await auth.client.updateUser(
        user.user_id,
        { version: user.version, roles, active },
        newIntent(),
      );
      await load();
    } catch (e) {
      setError(e.code || "BUSINESS_UNAVAILABLE");
      if (e.status === 409) await load();
    } finally {
      setBusy(false);
    }
  }
  if (!auth.canAudit && !auth.canAdmin)
    return (
      <section className="n91-business">
        Cần quyền Auditor hoặc Portal admin để xem thông tin nguồn quản trị.
      </section>
    );
  return (
    <section className="n91-business">
      <h2>Quản trị Portal</h2>
      <p>
        {singleAccount
          ? "Thông tin tài khoản quản trị và nhật ký thao tác trên bản local."
          : "Quản lý tài khoản, vai trò và xem nhật ký thao tác trong Portal. Quyền quản trị được cấp riêng với các vai trò vận hành."}
      </p>
      {error && <p role="alert">{error}</p>}
      {singleAccount && (
        <div className="v4-proxy-snapshot">
          <strong>Một tài khoản quản trị</strong>
          <p>
            Quản lý Portal, rà soát sự cố, xuất bằng chứng và cô lập/khôi phục
            máy ảo bằng cùng một tài khoản.
          </p>
          <p>
            Hai tài khoản LAB cũ đã vô hiệu hóa. Lịch sử thao tác vẫn được giữ
            lại.
          </p>
        </div>
      )}
      {auth.canAdmin && !singleAccount && (
        <>
          <form onSubmit={provision}>
            <label>
              Tài khoản mới
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
              Vai trò
              <select
                aria-label="Vai trò"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {uiLabel(r)}
                  </option>
                ))}
              </select>
            </label>
            <button disabled={busy}>Tạo tài khoản</button>
          </form>
          <div className="n91-business-scroll">
            <table>
              <caption>Người dùng · tối đa 100 bản ghi/trang</caption>
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
                    <td>{u.roles.join(", ")}</td>
                    <td>
                      {u.active ? "ACTIVE" : "INACTIVE"} · v{u.version}
                    </td>
                    <td>
                      <select
                        aria-label={`Đổi vai trò ${u.username}`}
                        disabled={busy}
                        value=""
                        onChange={(e) =>
                          e.target.value &&
                          change(u, [e.target.value], u.active)
                        }
                      >
                        <option value="">Chọn vai trò…</option>
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {uiLabel(r)}
                          </option>
                        ))}
                      </select>
                      <button
                        disabled={busy}
                        onClick={() => change(u, u.roles, !u.active)}
                      >
                        {u.active ? "Vô hiệu hóa" : "Kích hoạt"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {singleAccount && users.length > 0 && (
        <div className="n91-business-scroll">
          <table>
            <caption>Tài khoản trên bản local</caption>
            <thead>
              <tr>
                <th>Tài khoản</th>
                <th>Loại tài khoản</th>
                <th>Trạng thái</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.user_id}>
                  <td>{u.username}</td>
                  <td>{u.active ? "Quản trị viên" : "Tài khoản thử nghiệm cũ"}</td>
                  <td>{u.active ? "Đang hoạt động" : "Đã vô hiệu hóa"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
                        2,
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
  );
}
