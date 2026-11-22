import { uiLabel, uiRoleList } from "./services/uiLanguage.js";
import { Component, useEffect, useState } from "react";
import { Clock3, LogOut, Menu } from "lucide-react";
import Sidebar from "./components/Sidebar";
import useHashRoute from "./hooks/useHashRoute";
import ApiDashboardPage from "./pages/ApiDashboardPage";
import ApiSecurityEventsPage from "./pages/ApiSecurityEventsPage";
import ApiAuditSystemPage from "./pages/ApiAuditSystemPage";
import DashboardPage from "./portal/N91CompactDashboard";
import "./portal/n91Typography.css";
import { IncidentDetail, IncidentsPage } from "./portal/IncidentPages";
import { EventDetail, EventsPage } from "./portal/EventPages";
import {
  ActionDetail,
  WorkloadDetail,
  WorkloadsPage,
} from "./portal/WorkloadPages";
import SystemPage from "./portal/SystemPage";
import { usePortal } from "./portal/PortalContext";
import { PortalProvider } from "./portal/PortalProvider";
import { Empty } from "./portal/PortalUI";
import { DetailView } from "./portal/DetailView";
import {
  AnalysisPage,
  IncidentNavigation,
} from "./features/n91-vnext/AnalysisPage";
import "./portal/proxySource.css";
import { BusinessLoginPanel } from "./features/n91-business";

class PageBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <section className="panel">
        <Empty
          title="Chưa hiển thị được dữ liệu nguồn"
          text="Dữ liệu trả về chưa đúng cấu trúc giao diện hỗ trợ. Hãy tải lại để kiểm tra kết nối nguồn."
        >
          <button
            className="button secondary"
            onClick={() => window.location.reload()}
          >
            Tải lại giao diện
          </button>
        </Empty>
      </section>
    ) : (
      this.props.children
    );
  }
}

function PortalClock() {
  const { timezone } = usePortal();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <span className="v4-clock">
      <Clock3 size={13} />
      <time>
        {new Intl.DateTimeFormat("vi-VN", {
          timeZone: timezone,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }).format(now)}
      </time>
    </span>
  );
}

function Shell() {
  const [route] = useHashRoute();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);
  const {
    mode,
    setMode,
    timezone,
    setTimezone,
    auth,
    logout,
    sessionVersion,
    access,
    retryAccess,
    sessionAuthEnabled,
  } = usePortal();
  const labels = {
    dashboard: "Trang chủ",
    incidents: "Sự cố",
    events: "Sự kiện bảo mật",
    workloads: "Máy ảo",
    system: "Hệ thống",
    actions: "Chi tiết xử lý",
  };
  const routeLabel = labels[route.page];
  useEffect(() => {
    document.title = `${routeLabel} · DBSEC Portal`;
    setMobileOpen(false);
  }, [route.page, route.id, routeLabel]);
  const remountParams = { ...route.params };
  if (route.page === "incidents" && route.id) delete remountParams.wb_tab;
  if (route.page === "events" && !route.id && route.params.view === "incidents") {
    delete remountParams.incident_ref;
    delete remountParams.stream_id;
  }
  const pageKey = `${mode}:${route.page}:${route.id || ""}:${JSON.stringify(remountParams)}:${sessionVersion}`;
  let page;
  if (mode === "p16") {
    page =
      route.page === "dashboard" ? (
        <ApiDashboardPage />
      ) : route.page === "events" ? (
        <ApiSecurityEventsPage eventId={route.id} />
      ) : route.page === "system" ? (
        <ApiAuditSystemPage tab={route.systemTab} ruleId={route.ruleId} />
      ) : (
        <section className="panel">
          <Empty
            title="Màn hình này cần nguồn Portal"
            text="Nhật ký kiểm toán cung cấp dữ liệu cho Trang chủ, Sự kiện bảo mật và Hệ thống."
          >
            <button className="button primary" onClick={() => setMode("v4")}>
              Chuyển sang Portal
            </button>
          </Empty>
        </section>
      );
  } else {
    page =
      route.page === "incidents" ? (
        route.id ? (
          <IncidentDetail id={route.id} params={route.params} />
        ) : (
          route.params.analysis === "1" ? (
            <AnalysisPage params={route.params} navigation={<IncidentNavigation analysis />} />
          ) : (
            <IncidentsPage params={route.params} navigation={<IncidentNavigation />} />
          )
        )
      ) : route.page === "events" ? (
        route.id ? (
          <EventDetail id={route.id} params={route.params} />
        ) : (
          <EventsPage params={route.params} />
        )
      ) : route.page === "workloads" ? (
        route.id ? (
          <WorkloadDetail id={route.id} params={route.params} />
        ) : (
          <WorkloadsPage params={route.params} />
        )
      ) : route.page === "actions" ? (
        <ActionDetail id={route.id || ""} />
      ) : route.page === "system" ? (
        <SystemPage tab={route.systemTab} />
      ) : (
        <DashboardPage params={route.params} />
      );
  }
  return (
    <div className="app-layout v4-app">
      <a
        className="skip-link"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        Đến nội dung chính
      </a>
      <Sidebar
        activePage={route.page === "actions" ? "workloads" : route.page}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />
      <div className="main-shell">
        <header className="topbar v4-topbar">
          <div className="topbar-start">
            <button
              className="icon-button menu-button"
              aria-label="Mở menu"
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={21} />
            </button>
            <span className="breadcrumb">
              <strong>{routeLabel}</strong>
            </span>
          </div>
          <div className="topbar-end">
            <PortalClock />
            <label className="v4-top-select">
              <span className="sr-only">Múi giờ</span>
              <select
                aria-label="Múi giờ"
                value={timezone}
                onChange={(event) => setTimezone(event.target.value)}
              >
                <option value="Asia/Ho_Chi_Minh">UTC+7</option>
                <option value="UTC">UTC</option>
              </select>
            </label>
            {auth.user ? (
              <>
                <span className="v4-account">
                  <strong>{auth.user.login}</strong>
                  <small>{uiRoleList(auth.user.role)}</small>
                </span>
                <button
                  className="icon-button"
                  aria-label="Đăng xuất"
                  title="Đăng xuất"
                  disabled={loggingOut}
                  onClick={async () => {
                    setLoggingOut(true);
                    setLogoutError("");
                    try {
                      await logout();
                    } catch (error) {
                      setLogoutError(error.message);
                    } finally {
                      setLoggingOut(false);
                    }
                  }}
                >
                  <LogOut size={17} />
                </button>
              </>
            ) : (
              access === "OBSERVATION" && (
                <span className="v4-local-account">
                  Quan sát nội bộ · chỉ đọc
                </span>
              )
            )}
          </div>
        </header>
        <main id="main" className="dashboard v4-main" tabIndex={-1}>
          {mode === "p16" && (
            <p className="v4-source-mode-notice">
              Đang xem nhật ký kiểm toán. Trạng thái máy ảo và cách ly nằm trong
              chế độ Portal.
            </p>
          )}
          {access === "OBSERVATION" &&
            mode === "v4" &&
            auth.status === "unavailable" && (
              <p className="v4-session-notice" role="status">
                Chưa kết nối được nguồn sự cố.
              </p>
            )}
          {logoutError && (
            <p className="v4-form-error" role="alert">
              {logoutError}
            </p>
          )}
          <div
            key={pageKey}
            className={`v4-page-content portal-page portal-page-${route.page} ${route.id ? "portal-detail" : "portal-list"} ${route.page === "workloads" && route.id ? "portal-vm-detail" : ""} ${sessionAuthEnabled && auth.status !== "authenticated" ? "portal-auth-page" : ""}`}
          >
            {access === "checking" ? (
              <p role="status">Đang kiểm tra chế độ truy cập…</p>
            ) : access === "unavailable" ? (
              <div role="alert">
                Chưa xác định được chế độ truy cập Portal.{" "}
                <button onClick={retryAccess}>Thử lại</button>
              </div>
            ) : sessionAuthEnabled && auth.status !== "authenticated" ? (
              <BusinessLoginPanel />
            ) : (
              <PageBoundary>
                <DetailView
                  key={`${route.page}:${route.id}`}
                  kind={
                    route.id && ["events", "incidents"].includes(route.page)
                      ? route.page
                      : null
                  }
                >
                  {page}
                </DetailView>
              </PageBoundary>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <PortalProvider>
      <Shell />
    </PortalProvider>
  );
}
