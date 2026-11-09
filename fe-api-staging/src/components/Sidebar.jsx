import { Activity, ArrowUpRight, Blocks, ChevronRight, CircleHelp, FileClock, LayoutDashboard, LockKeyhole, Server, ShieldCheck, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard, page: 'dashboard', href: '#/dashboard' },
  { label: 'Incidents', icon: ShieldCheck, page: 'incidents', href: '#/incidents' },
  { label: 'Security Events', icon: FileClock, page: 'events', href: '#/events' },
  { label: 'Workloads', icon: Server, page: 'workloads', href: '#/workloads' },
  { label: 'System', icon: Activity, page: 'system', href: '#/system' },
]

export default function Sidebar({ mobileOpen, onClose, activePage = 'dashboard', mode, user }) {
  const [compact, setCompact] = useState(() => window.matchMedia('(max-width:760px)').matches)
  const sidebar = useRef(null)
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    const media = window.matchMedia('(max-width:760px)')
    const update = () => setCompact(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => {
    if (!mobileOpen || !compact) return
    const previous = document.activeElement
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const items = () => [...sidebar.current.querySelectorAll('a[href],button:not(:disabled)')].filter(element => element.getClientRects().length)
    items()[0]?.focus()
    const key = event => {
      if (event.key === 'Escape') close.current()
      if (event.key !== 'Tab') return
      const targets = items(), first = targets[0], last = targets.at(-1)
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    document.addEventListener('keydown', key)
    return () => { document.body.style.overflow = overflow; document.removeEventListener('keydown', key); previous?.focus?.() }
  }, [mobileOpen, compact])
  return <>
    {mobileOpen && <button className="sidebar-backdrop" aria-label="Đóng menu" onClick={onClose} />}
    <aside ref={sidebar} inert={compact && !mobileOpen} className={`sidebar ${mobileOpen ? 'is-open' : ''}`} aria-label="Điều hướng chính">
      <a className="brand" href="#/dashboard" onClick={onClose} aria-label="DBSEC Dashboard">
        <span className="brand-mark"><ShieldCheck size={25} strokeWidth={1.8} /></span>
        <span className="brand-word">DBSEC<span>SECURITY PORTAL</span></span>
      </a>
      <button className="mobile-sidebar-close icon-button" onClick={onClose} aria-label="Đóng menu"><X size={20} /></button>
      <div className="workspace-label"><Blocks size={15} /><span>OpenStack Private Cloud</span></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav className="navigation">
        {navigation.map(({ label, icon: Icon, page, href }) => <a key={label} href={href} className={`nav-item ${activePage === page ? 'active' : ''}`} aria-current={activePage === page ? 'page' : undefined} onClick={onClose}>
          <Icon size={19} strokeWidth={1.8} /><span>{label}</span>{activePage === page && <span className="nav-active-dot" />}
        </a>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="environment-card"><div><span className="status-dot blue" />{mode === 'v4' ? 'PORTAL V4' : 'AUDIT P16'}</div><p>{mode === 'v4' ? <>P16H / P17 evidence<br />Nova / Neutron observations</> : <>Nguồn audit hiện có<br />Lịch sử và trạng thái đồng bộ</>}</p><a href="#/system" onClick={onClose}>Kiểm tra nguồn <ArrowUpRight size={15} /></a></div>
        <a className="sidebar-help" href="#/system/sources" onClick={onClose}><Activity size={17} /><span>Data source health</span><ChevronRight size={15} /></a>
        <div className="user-card"><span className="avatar">{mode === 'v4' && user ? user.login?.charAt(0).toUpperCase() : 'V'}</span><div><strong>{mode === 'v4' && user ? user.login : 'Management workspace'}</strong><span>{mode === 'v4' && user ? user.role : 'Quyền được xác minh qua API'}</span></div><LockKeyhole size={15} /></div>
      </div>
    </aside>
  </>
}
