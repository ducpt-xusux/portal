import { Component, useEffect, useState } from 'react'
import { ChevronRight, Clock3, LogOut, Menu } from 'lucide-react'
import Sidebar from './components/Sidebar'
import useHashRoute from './hooks/useHashRoute'
import ApiDashboardPage from './pages/ApiDashboardPage'
import ApiSecurityEventsPage from './pages/ApiSecurityEventsPage'
import ApiAuditSystemPage from './pages/ApiAuditSystemPage'
import DashboardPage from './portal/DashboardPage'
import { dashboardHref } from './services/dashboardFunnel'
import { IncidentDetail, IncidentsPage } from './portal/IncidentPages'
import { EventDetail, EventsPage } from './portal/EventPages'
import { ActionDetail, WorkloadDetail, WorkloadsPage } from './portal/WorkloadPages'
import SystemPage from './portal/SystemPage'
import { usePortal } from './portal/PortalContext'
import { PortalProvider } from './portal/PortalProvider'
import { Empty } from './portal/PortalUI'
import { BusinessLoginPanel } from './features/n91-business'

class PageBoundary extends Component {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() {
    return this.state.failed ? <section className="panel"><Empty title="Chưa hiển thị được dữ liệu nguồn" text="Phản hồi chưa tương thích với giao diện. Hãy kiểm tra contract API rồi tải lại."><button className="button secondary" onClick={() => window.location.reload()}>Tải lại giao diện</button></Empty></section> : this.props.children
  }
}

function PortalClock() {
  const { timezone } = usePortal()
  const [now, setNow] = useState(() => new Date())
  useEffect(() => { const timer = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(timer) }, [])
  return <span className="v4-clock"><Clock3 size={13} /><time>{new Intl.DateTimeFormat('vi-VN', { timeZone: timezone, hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(now)}</time></span>
}

function Shell() {
  const [route] = useHashRoute()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [logoutError, setLogoutError] = useState('')
  const [loggingOut, setLoggingOut] = useState(false)
  const { mode, setMode, timezone, setTimezone, auth, logout, sessionVersion, access, retryAccess, sessionAuthEnabled } = usePortal()
  const labels = { dashboard: 'Dashboard', incidents: 'Incidents', events: 'Security Events', workloads: 'Workloads', system: 'System', actions: 'Action detail' }
  const routeLabel = labels[route.page]
  useEffect(() => { document.title = `${routeLabel} · DBSEC Portal v4`; setMobileOpen(false) }, [route.page, route.id, routeLabel])
  const pageKey = `${mode}:${route.page}:${route.id || ''}:${JSON.stringify(route.params)}:${sessionVersion}`
  let page
  if (mode === 'p16') {
    page = route.page === 'dashboard' ? <ApiDashboardPage /> : route.page === 'events' ? <ApiSecurityEventsPage eventId={route.id} /> : route.page === 'system' ? <ApiAuditSystemPage tab={route.systemTab} ruleId={route.ruleId} /> : <section className="panel"><Empty title="Màn hình này cần nguồn Portal v4" text="Nguồn audit P16 hiện chỉ cung cấp Dashboard, Security Events và System audit."><button className="button primary" onClick={() => setMode('v4')}>Chuyển sang Portal v4</button></Empty></section>
  } else {
    page = route.page === 'incidents' ? route.id ? <IncidentDetail id={route.id} /> : <IncidentsPage params={route.params} />
      : route.page === 'events' ? route.id ? <EventDetail id={route.id} params={route.params} /> : <EventsPage params={route.params} />
        : route.page === 'workloads' ? route.id ? <WorkloadDetail id={route.id} params={route.params} /> : <WorkloadsPage params={route.params} />
          : route.page === 'actions' ? <ActionDetail id={route.id || ''} />
            : route.page === 'system' ? <SystemPage tab={route.systemTab} /> : <DashboardPage params={route.params}/>
  }
  return <div className="app-layout v4-app"><a className="skip-link" href="#main" onClick={event => { event.preventDefault(); document.getElementById('main')?.focus() }}>Đến nội dung chính</a><Sidebar activePage={route.page === 'actions' ? 'workloads' : route.page} mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} mode={mode} user={auth.user} />
    <div className="main-shell"><header className="topbar v4-topbar"><div className="topbar-start"><button className="icon-button menu-button" aria-label="Mở menu" onClick={() => setMobileOpen(true)}><Menu size={21} /></button><span className="breadcrumb">Workspace<ChevronRight size={14} /><strong>{routeLabel}</strong></span></div><div className="topbar-end"><PortalClock />{mode === 'v4' && route.page === 'dashboard' && <label className="v4-top-select"><span className="sr-only">Chế độ Dashboard</span><select aria-label="Chế độ Dashboard" value={route.params.context || 'LIVE'} onChange={event => { window.location.hash=dashboardHref(event.target.value,route.params.window || '15m') }}><option value="LIVE">LIVE</option><option value="EVALUATION">EVALUATION</option></select></label>}<label className="v4-top-select"><span className="sr-only">Múi giờ</span><select aria-label="Múi giờ" value={timezone} onChange={event => setTimezone(event.target.value)}><option value="Asia/Ho_Chi_Minh">UTC+7</option><option value="UTC">UTC</option></select></label><label className="v4-top-select v4-source-select"><span className="sr-only">Nguồn dữ liệu</span><select aria-label="Nguồn dữ liệu" value={mode} onChange={event => { setMode(event.target.value); setLogoutError('') }}><option value="v4">Portal v4</option><option value="p16">Audit P16</option></select></label>{auth.user ? <><span className="v4-account"><strong>{auth.user.login}</strong><small>{auth.user.role}</small></span><button className="icon-button" aria-label="Đăng xuất" title="Đăng xuất" disabled={loggingOut} onClick={async () => { setLoggingOut(true); setLogoutError(''); try { await logout() } catch (error) { setLogoutError(error.message) } finally { setLoggingOut(false) } }}><LogOut size={17} /></button></> : access === 'OBSERVATION' && <span className="v4-local-account">Quan sát local · chỉ đọc</span>}</div></header>
      <main id="main" className="dashboard v4-main" tabIndex={-1}>
        <div className="v4-workspace-line"><span className="v4-workspace-project">{mode === 'v4' && auth.user?.project_name || 'OpenStack Database Security'}</span><span className="v4-mode-label"><i />{mode === 'v4' ? 'PORTAL V4 · OBSERVATION' : 'AUDIT P16 · NGUỒN RIÊNG'}</span></div>
        {mode === 'p16' && <p className="v4-source-mode-notice">Đang dùng nguồn audit P16. Các trạng thái hiển thị theo metadata của nguồn; không xác nhận health hoặc cách ly của OpenStack.</p>}
        {mode === 'v4' && auth.status === 'local_snapshot' && !(route.page === 'dashboard' && route.params.context === 'EVALUATION') && <div className="v4-snapshot-notice" role="status"><strong>{auth.remote ? 'Dữ liệu P17 từ Proxy · chỉ đọc' : 'Đang xem bản chụp lịch sử P17'}</strong><p>{auth.remote ? 'Portal đang chạy local và hiển thị dữ liệu P17 theo lần thu thập gần nhất. Trạng thái cập nhật nằm ở từng bảng; audit P16H có nguồn riêng. Chưa bật ghi chú hoặc thao tác mạng.' : 'Đọc dữ liệu đã xuất từ Proxy. Đây không phải kết nối live hoặc phiên đăng nhập; ghi chú và thao tác mạng chưa bật.'}</p></div>}
        {access === 'OBSERVATION' && mode === 'v4' && auth.status === 'unavailable' && <p className="v4-session-notice" role="status">Nguồn quan sát P17 chưa sẵn sàng.</p>}
        {logoutError && <p className="v4-form-error" role="alert">{logoutError}</p>}
        <div key={pageKey} className="v4-page-content">
          {access === 'checking' ? <p role="status">Đang kiểm tra chế độ truy cập…</p>
            : access === 'unavailable' ? <div role="alert">Chưa xác định được chế độ truy cập Portal. <button onClick={retryAccess}>Thử lại</button></div>
            : sessionAuthEnabled && auth.status !== 'authenticated' ? <BusinessLoginPanel />
            : <PageBoundary>{page}</PageBoundary>}
        </div>
        <footer className="dashboard-footer v4-footer"><span>DBSEC Portal v4 · Management workspace</span><a href="#/system">Nguồn dữ liệu & trạng thái</a></footer>
      </main>
    </div>
  </div>
}

export default function App() { return <PortalProvider><Shell /></PortalProvider> }
