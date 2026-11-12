import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { useEffect, useState } from 'react'
import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  FileCheck2,
  Filter,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  X,
} from 'lucide-react'
import {
  AUDIT_FILTERS,
  downloadAuditCsv,
  getAuditEvent,
  getAuditEvents,
} from '../services/auditApi'
import { dateTimeLabel } from '../utils/format'
import AuditSourceNotice from '../components/AuditSourceNotice'
import AuditEventEvidence from '../components/AuditEventEvidence'

function Select({ label, value, options, onChange }) {
  return (
    <label className="audit-filter">
      <span>{label}</span>
      <div>
        <select
          aria-label={label}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        >
          {options.map(([id, text]) => (
            <option key={id} value={id}>
              {uiLabel(text)}
            </option>
          ))}
        </select>
        <ChevronDown size={13} />
      </div>
    </label>
  )
}

function TextFilter({ label, value, onChange, placeholder }) {
  return (
    <label className="audit-filter">
      <span>{label}</span>
      <input
        aria-label={label}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  )
}

function ApiEventDetail({ eventId }) {
  const [payload, setPayload] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(true)
  const [reload, setReload] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setError('')
    setBusy(true)
    getAuditEvent(eventId, { signal: controller.signal })
      .then(setPayload)
      .catch((failure) => {
        if (!controller.signal.aborted)
          setError(
            failure.status === 404
              ? 'API không có sự kiện với ID này.'
              : failure.message
          )
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false)
      })
    return () => controller.abort()
  }, [eventId, reload])
  const event = payload?.event
  return (
    <div className="security-events-page api-audit-page">
      <a href="#/events" className="incident-back">
        <ArrowLeft size={15} />
        Danh sách sự kiện bảo mật
      </a>
      <div className="page-heading">
        <div>
          <div className="eyebrow">EVENT DETAIL · AUDIT API</div>
          <h1>
            Chi tiết security sự kiện
          </h1>
          <p className="api-event-id">{eventId}</p>
        </div>
        <button
          className="button primary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          <RefreshCw size={15} className={busy ? 'spin' : ''} />
          Đọc lại API
        </button>
      </div>
      <AuditSourceNotice
        meta={payload?.meta}
        error={error}
        hasCache={Boolean(payload)}
      />
      {busy && (
        <div className="audit-loading" role="status">
          <RefreshCw size={15} className="spin" />
          Đang đọc chi tiết từ API...
        </div>
      )}
      {event && (
        <>
          <div className="incident-heading-badges api-detail-badges">
            <span className={`severity-pill ${event.severity.toLowerCase()}`}>
              {uiLabel(event.severity)}
            </span>
            <span className={`decision ${event.decision.toLowerCase()}`}>
              {uiLabel(event.decision)}
            </span>
            <span>{dateTimeLabel(event.timestamp)} · UTC+7</span>
          </div>
          <div className="audit-detail-grid">
            <section className="panel audit-evidence-panel">
              <div className="incident-section-heading">
                <span className="section-icon blue">
                  <FileCheck2 size={18} />
                </span>
                <div>
                  <h2>Truy vấn & decision bằng chứng</h2>
                  <p>Dữ liệu đọc từ bản ghi qua FastAPI</p>
                </div>
              </div>
              <h4>Truy vấn đã mask</h4>
              <pre className="query-code">{event.query}</pre>
              <AuditEventEvidence event={event} />
              <details className="api-raw-evidence">
                <summary>
                  Xem đầy đủ bản ghi JSON · {Object.keys(event.raw).length}{' '}
                  trường
                </summary>
                <pre className="query-code">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              </details>
            </section>
            <aside className="panel incident-section audit-metadata">
              <h2>Nguồn & ngữ cảnh</h2>
              <dl className="incident-definition-grid single-column">
                {[
                  ["Mã sự kiện", event.id],
                  ['Timestamp gốc · UTC', event.timestamp],
                  ['Client IP', event.sourceIp],
                  ['Client port', event.raw.client_port],
                  ["Tài khoản cơ sở dữ liệu", event.user],
                  ["Cơ sở dữ liệu", event.raw.session_database || '—'],
                  ["Lệnh MySQL", event.raw.mysql_command],
                  ["Phiên bản chính sách", event.policyVersion],
                  ["Risk phiên bản", event.raw.risk_version || 'UNKNOWN'],
                  ['Mask status', event.maskStatus],
                  ["Máy ảo / VM", 'Chưa nối ánh xạ OpenStack'],
                  ['Incident', 'Chưa nối correlation'],
                  ['Nguồn', "→ FastAPI"],
                ].map(([label, value]) => (
                  <div className="incident-field" key={label}>
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
              </dl>
            </aside>
          </div>
        </>
      )}
      {!busy && !event && (
        <section className="panel incident-not-found">
          <Search size={32} />
          <h2>{error || 'Không có dữ liệu'}</h2>
          <a className="button secondary" href="#/events">
            Về danh sách events
          </a>
        </section>
      )}
    </div>
  )
}

export default function ApiSecurityEventsPage({ eventId }) {
  return eventId ? (
    <ApiEventDetail key={eventId} eventId={eventId} />
  ) : (
    <ApiEventList />
  )
}

function ApiEventList() {
  const [filters, setFilters] = useState(AUDIT_FILTERS)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [payload, setPayload] = useState(null)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [reload, setReload] = useState(0)
  const [auto, setAuto] = useState(true)
  useEffect(() => {
    const controller = new AbortController()
    setBusy(true)
    const timer = setTimeout(() => {
      getAuditEvents({ filters, page, pageSize, signal: controller.signal })
        .then((data) => {
          if (!controller.signal.aborted) {
            setPayload(data)
            setError('')
          }
        })
        .catch((failure) => {
          if (!controller.signal.aborted) setError(failure.message)
        })
        .finally(() => {
          if (!controller.signal.aborted) setBusy(false)
        })
    }, 250)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [filters, page, pageSize, reload])
  useEffect(() => {
    if (!auto) return
    const timer = setInterval(() => setReload((n) => n + 1), 10000)
    return () => clearInterval(timer)
  }, [auto])
  const update = (key, value) => {
    setFilters((f) => ({ ...f, [key]: value }))
    setPage(1)
  }
  const reset = () => {
    setFilters(AUDIT_FILTERS)
    setPage(1)
  }
  const stale = Boolean(error) || payload?.meta.data_state === 'STALE'
  const versions = [
    ...new Set(payload?.events.map((e) => e.policyVersion) || []),
  ]
  return (
    <div className="security-events-page api-audit-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SỰ KIỆN BẢO MẬT</div>
          <h1>
            Nhật ký bảo mật
          </h1>
          <p>Đọc audit : truy vấn, quy tắc, điểm và quyết định thực tế.</p>
        </div>
        <div className="page-actions">
          <button
            className="button secondary"
            onClick={() => downloadAuditCsv(payload.events)}
            disabled={busy || stale || !payload?.events.length}
          >
            <ArrowDownToLine size={15} />
            Xuất CSV trang này
          </button>
          <button
            className="button primary"
            disabled={busy}
            onClick={() => setReload((n) => n + 1)}
          >
            <RefreshCw size={15} className={busy ? 'spin' : ''} />
            Làm mới
          </button>
        </div>
      </div>
      <AuditSourceNotice
        meta={payload?.meta}
        error={error}
        hasCache={Boolean(payload)}
      />
      {error && payload && (
        <p className="api-filter-warning">
          Đang giữ kết quả trước đó; bộ lọc hoặc trang mới chưa được áp dụng.
        </p>
      )}
      <section
        className="incident-kpis"
        aria-label="Thống kê audit theo bộ lọc"
        aria-busy={busy}
      >
        {[
          ['Tổng events', 'total', FileCheck2, 'blue'],
          ['Được cho phép', 'allowed', ShieldCheck, 'green'],
          ['Đã chặn', 'blocked', ShieldOff, 'coral'],
          ['Mức HIGH / CRITICAL', 'highRisk', ShieldAlert, 'purple'],
        ].map(([label, key, Icon, tone]) => (
          <article className="stat-card" key={key}>
            <div className="stat-top">
              <span>{label}</span>
              <span className={`stat-icon ${tone}`}>
                <Icon size={17} />
              </span>
            </div>
            <div className="stat-value">{payload?.summary[key] ?? '—'}</div>
            <div className="stat-note">
              {stale
                ? payload
                  ? 'STALE · dữ liệu đã lưu'
                  : "Chưa xác định · chưa có dữ liệu"
                : 'Theo bộ lọc · toàn bộ các trang'}
            </div>
          </article>
        ))}
      </section>

      <section className="panel audit-filter-panel">
        <div className="audit-filter-heading">
          <span>
            <Filter size={16} />
            Bộ lọc audit
          </span>
          <button className="text-button" onClick={reset}>
            <X size={13} />
            Đặt lại bộ lọc
          </button>
        </div>
        <div className="audit-search-row">
          <label className="search-field">
            <Search size={16} />
            <input
              aria-label="Tìm kiếm audit sự kiện"
              placeholder="Tìm Mã sự kiện hoặc SQL đã mask..."
              value={filters.query}
              onChange={(e) => update('query', e.target.value)}
            />
          </label>
          <Select
            label="Khoảng thời gian events"
            value={filters.minutes}
            onChange={(v) => update('minutes', Number(v))}
            options={[
              [0, 'Toàn bộ lịch sử'],
              [60, '1 giờ gần nhất'],
              [1440, '24 giờ gần nhất'],
              [10080, '7 ngày gần nhất'],
              [43200, '30 ngày gần nhất'],
            ]}
          />
        </div>
        <div className="audit-filter-grid">
          <Select
            label="Mức độ"
            value={filters.severity}
            onChange={(v) => update('severity', v)}
            options={[
              ['ALL', "Mọi mức độ"],
              ...['LOW', 'WARNING', 'HIGH', 'CRITICAL'].map((s) => [s, s]),
            ]}
          />
          <Select
            label="Quyết định xử lý"
            value={filters.decision}
            onChange={(v) => update('decision', v)}
            options={[
              ['ALL', 'ALLOW & BLOCK'],
              ['ALLOW', 'ALLOW'],
              ['BLOCK', 'BLOCK'],
            ]}
          />
          <TextFilter
            label="Client IP"
            value={filters.sourceIp}
            onChange={(v) => update('sourceIp', v)}
            placeholder="Ví dụ 10.0.0.30"
          />
          <TextFilter
            label="Mã quy tắc"
            value={filters.rule}
            onChange={(v) => update('rule', v)}
            placeholder="Ví dụ INJ-001"
          />
          <TextFilter
            label="Tài khoản cơ sở dữ liệu"
            value={filters.dbUser}
            onChange={(v) => update('dbUser', v)}
            placeholder="Ví dụ app_reader"
          />
          <Select
            label="Kết quả xử lý"
            value={filters.actionResult}
            onChange={(v) => update('actionResult', v)}
            options={[
              ['ALL', 'Mọi kết quả'],
              ['FORWARDED', 'FORWARDED'],
              ['BLOCKED', 'BLOCKED'],
              ['ERROR', 'ERROR'],
            ]}
          />
        </div>
      </section>

      <section
        className="panel audit-table-panel"
        aria-label="Danh sách sự kiện bảo mật"
        aria-busy={busy}
      >
        <div className="panel-heading">
          <div>
            <div className="inline-heading">
              <h2>Sự kiện bảo mật</h2>
              <span className="count-badge">{payload?.total ?? '—'}</span>
              {stale && (
                <span className="incident-status status-stale">Chưa cập nhật</span>
              )}
            </div>
            <p>
              Newest-first ·{' '}
              {versions.length
                ? `policy ${versions.join(', ')}`
                : 'Phiên bản lấy từ từng bản ghi'}
            </p>
          </div>
          <span className="audit-store-label">
            <LockKeyhole size={13} />
            READ ONLY · UTC+7
          </span>
        </div>
        {busy && (
          <div className="audit-loading" role="status">
            <RefreshCw size={14} className="spin" />
            Đang đọc FastAPI...
          </div>
        )}
        <div className={`table-scroll ${busy ? 'audit-is-updating' : ''}`}>
          <table className="audit-table">
            <thead>
              <tr>
                <th>SỰ KIỆN / THỜI GIAN</th>
                <th>NGUỒN / DB USER</th>
                <th>QUERY · MASKED</th>
                <th>MATCHED RULES</th>
                <th>SEVERITY / SCORE</th>
                <th>QUYẾT ĐỊNH</th>
                <th>ACTION / RESULT</th>
                <th>
                  <span className="sr-only">Chi tiết</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {payload?.events.map((event) => (
                <tr key={event.id}>
                  <td>
                    <a
                      className="event-link api-event-id"
                      href={`#/events/${event.id}`}
                    >
                      {event.id}
                    </a>
                    <time dateTime={event.timestamp}>
                      {dateTimeLabel(event.timestamp)}
                    </time>
                  </td>
                  <td>
                    <span className="api-source-cell">
                      <code>{event.sourceIp}</code>
                      <small>{event.user}</small>
                      <small>Chưa ánh xạ VM</small>
                    </span>
                  </td>
                  <td>
                    <code className="audit-query" title={event.query}>
                      {event.query}
                    </code>
                  </td>
                  <td>
                    <span className="audit-rule-tags">
                      {event.rules.length ? (
                        event.rules.map((rule) => (
                          <button
                            key={rule}
                            onClick={() => update('rule', rule)}
                          >
                            {rule}
                          </button>
                        ))
                      ) : (
                        <span className="muted">Không match quy tắc</span>
                      )}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`severity ${event.severity.toLowerCase()}`}
                    >
                      <i />
                      {uiLabel(event.severity)}
                    </span>
                    <strong
                      className={`score-value ${event.severity === 'CRITICAL' ? 'critical' : ''}`}
                    >
                      {event.score ?? '—'}
                      <small>/ 100</small>
                    </strong>
                  </td>
                  <td>
                    <span
                      className={`decision ${event.decision.toLowerCase()}`}
                    >
                      {event.decision === 'BLOCK' ? (
                        <ShieldOff size={12} />
                      ) : (
                        <Check size={12} />
                      )}
                      {uiLabel(event.decision)}
                    </span>
                  </td>
                  <td>
                    <span className="audit-action-name">{event.action}</span>
                    <span className="audit-result">{event.actionResult}</span>
                  </td>
                  <td>
                    <a
                      className="row-detail"
                      href={`#/events/${event.id}`}
                      aria-label={`Mở event ${event.id}`}
                    >
                      <ArrowUpRight size={16} />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!busy && !error && payload?.total === 0 && (
          <div className="table-empty">
            <Search size={30} />
            <strong>Không có sự kiện phù hợp</strong>
            <p>Bản chụp cũ có thể nằm ngoài khoảng thời gian đang chọn.</p>
            <button className="text-button" onClick={reset}>
              Xem toàn bộ lịch sử
            </button>
          </div>
        )}
        {!busy && error && !payload && (
          <div className="table-empty">
            <Search size={30} />
            <strong>Chưa có dữ liệu từ API</strong>
            <p>Không thay thế bằng sự kiện demo.</p>
          </div>
        )}
        <div className="audit-pagination">
          <span>
            {payload?.events.length
              ? `${(payload.page - 1) * payload.pageSize + 1}–${(payload.page - 1) * payload.pageSize + payload.events.length} / ${payload.total} events`
              : payload
                ? `0 / ${payload.total} events`
                : 'Chưa có dữ liệu'}
          </span>
          <div>
            <label>
              Số dòng
              <select
                aria-label="Số dòng mỗi trang events"
                value={pageSize}
                disabled={busy || Boolean(error)}
                onChange={(e) => {
                  setPageSize(Number(e.target.value))
                  setPage(1)
                }}
              >
                {[10, 25, 50].map((n) => (
                  <option key={n} value={n}>
                    {uiLabel(n)}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="icon-button"
              aria-label="Trang events trước"
              disabled={busy || Boolean(error) || !payload || payload.page <= 1}
              onClick={() => setPage(page - 1)}
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              Trang {payload?.page ?? 1} / {payload?.pageCount ?? 1}
            </span>
            <button
              className="icon-button"
              aria-label="Trang events tiếp"
              disabled={
                busy ||
                Boolean(error) ||
                !payload ||
                payload.page >= payload.pageCount
              }
              onClick={() => setPage(page + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>
      <footer className="audit-footer">
        <span>FastAPI · audit · không có dữ liệu isolation</span>
        <label className="api-auto-control">
          <input
            type="checkbox"
            checked={auto}
            onChange={(e) => setAuto(e.target.checked)}
          />
          Tự cập nhật mỗi 10 giây
        </label>
      </footer>
    </div>
  )
}
