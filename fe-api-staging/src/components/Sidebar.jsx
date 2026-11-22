import {
  Activity,
  Blocks,
  ChevronRight,
  FileClock,
  LayoutDashboard,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

const navigation = [
  {
    label: "Trang chủ",
    icon: LayoutDashboard,
    page: "dashboard",
    href: "#/dashboard",
  },
  {
    label: "Sự kiện bảo mật",
    icon: FileClock,
    page: "events",
    href: "#/events",
  },
  {
    label: "Sự cố",
    icon: ShieldCheck,
    page: "incidents",
    href: "#/incidents",
  },
  { label: "Máy ảo", icon: Server, page: "workloads", href: "#/workloads" },
  { label: "Hệ thống", icon: Activity, page: "system", href: "#/system" },
];

export default function Sidebar({
  mobileOpen,
  onClose,
  activePage = "dashboard",
}) {
  const [compact, setCompact] = useState(
    () => window.matchMedia("(max-width:760px)").matches,
  );
  const sidebar = useRef(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const media = window.matchMedia("(max-width:760px)");
    const update = () => setCompact(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!mobileOpen || !compact) return;
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const items = () =>
      [
        ...sidebar.current.querySelectorAll("a[href],button:not(:disabled)"),
      ].filter((element) => element.getClientRects().length);
    items()[0]?.focus();
    const key = (event) => {
      if (event.key === "Escape") close.current();
      if (event.key !== "Tab") return;
      const targets = items(),
        first = targets[0],
        last = targets.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.body.style.overflow = overflow;
      document.removeEventListener("keydown", key);
      previous?.focus?.();
    };
  }, [mobileOpen, compact]);
  return (
    <>
      {mobileOpen && (
        <button
          className="sidebar-backdrop"
          aria-label="Đóng menu"
          onClick={onClose}
        />
      )}
      <aside
        ref={sidebar}
        inert={compact && !mobileOpen}
        className={`sidebar ${mobileOpen ? "is-open" : ""}`}
        aria-label="Điều hướng chính"
      >
        <a
          className="brand"
          href="#/dashboard"
          onClick={onClose}
          aria-label="DBSEC Trang chủ"
        >
          <span className="brand-mark">
            <ShieldCheck size={25} strokeWidth={1.8} />
          </span>
          <span className="brand-word">
            DBSEC<span>Cổng quản trị bảo mật</span>
          </span>
        </a>
        <button
          className="mobile-sidebar-close icon-button"
          onClick={onClose}
          aria-label="Đóng menu"
        >
          <X size={20} />
        </button>
        <div className="workspace-label">
          <Blocks size={15} />
          <span>Đám mây riêng OpenStack</span>
        </div>
        <nav className="navigation" aria-label="Các trang của Portal">
          {navigation.map(({ label, icon: Icon, page, href }) => (
            <a
              key={label}
              href={href}
              className={`nav-item ${activePage === page ? "active" : ""}`}
              aria-current={activePage === page ? "page" : undefined}
              onClick={onClose}
            >
              <Icon size={19} strokeWidth={1.8} />
              <span>{label}</span>
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <a className="sidebar-help" href="#/system/sources" onClick={onClose}>
            <Activity size={17} />
            <span>Nguồn dữ liệu</span>
            <ChevronRight size={15} />
          </a>
        </div>
      </aside>
    </>
  );
}
