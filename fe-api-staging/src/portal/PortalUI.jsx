import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  Database,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react'
import { freshness, sourceState } from '../services/portalApi'
import { usePortal, useSourceDisplay } from './PortalContext'

export const display = (value) =>
  value === null || value === undefined || value === ''
    ? '—'
    : typeof value === 'boolean'
      ? value
        ? 'Có'
        : 'Không'
      : String(value)

export function useTime() {
  const { timezone } = usePortal()
  return (value) => {
    if (!value || !Number.isFinite(Date.parse(value)))
      return 'Chưa có thời điểm'
    return new Intl.DateTimeFormat('vi-VN', {
      dateStyle: 'short',
      timeStyle: 'medium',
      timeZone: timezone,
    }).format(new Date(value))
  }
}

const green = [
  'FRESH',
  'HEALTHY',
  'ONLINE',
  'NORMAL',
  'ALLOW',
  'ACTIVE',
  'SYNCED',
  'PRIMARY',
  'VERIFIED',
]
const red = [
  'BLOCK',
  'CRITICAL',
  'FAILED',
  'ERROR',
  'DOWN',
  'UNREACHABLE',
  'MISMATCH',
]
const amber = [
  'STALE',
  'PARTIAL',
  'DEGRADED',
  'WARNING',
  'HIGH',
  'DRIFT',
  'REVIEW_REQUIRED',
  'RECOVERY_REQUIRED',
]
export function Badge({ value, children, className = '' }) {
  const state = typeof value === 'string' ? value.toUpperCase() : 'UNKNOWN'
  const tone = green.includes(state)
    ? 'good'
    : red.includes(state)
      ? 'danger'
      : amber.includes(state)
        ? 'warn'
        : state === 'QUARANTINED'
          ? 'quarantine'
          : 'neutral'
  return (
    <span className={`v4-badge ${tone} ${className}`}>
      <i />
      {children || uiLabel(value || 'UNKNOWN')}
    </span>
  )
}

export function ObservationAgeBadge({ value }) {
  return (
    <Badge value={value}>
      {value === 'FRESH' ? 'Trong thời hạn' : value === 'STALE' ? 'Đã quá hạn' : 'Chưa có quan sát'}
    </Badge>
  )
}

export function PageHeading({
  eyebrow = "GIÁM SÁT BẢO MẬT",
  title,
  description,
  resource,
  children,
}) {
  return (
    <div className="page-heading v4-page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      <div className="page-actions">
        {children}
        {resource && (
          <button
            className="button secondary"
            disabled={resource.loading}
            onClick={resource.refresh}
          >
            <RefreshCw size={15} className={resource.loading ? 'spin' : ''} />
            Làm mới
          </button>
        )}
      </div>
    </div>
  )
}

export function SourceStatus({ resource, label }) {
  const time = useTime()
  const { hideSourceSystem } = useSourceDisplay()
  const [, tick] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => tick((value) => value + 1), 5000)
    return () => clearInterval(timer)
  }, [])
  const state = freshness(resource.meta, Boolean(resource.error))
  const snapshot = resource.meta?.source_mode === 'SNAPSHOT'
  if (hideSourceSystem) {
    // Dashboard gọn: bỏ tên nguồn kỹ thuật (source_system) và nhãn
    // HISTORICAL, chỉ giữ trạng thái đọc được và mốc thời gian nguồn.
    const value =
      resource.data === null
        ? 'UNKNOWN'
        : sourceState(resource.meta, Boolean(resource.error))
    return (
      <div className="v4-source-status">
        <span>
          <Database size={14} />
          <Badge value={value} />
        </span>
        <span>
          {resource.meta?.read_at
            ? `Đọc ${snapshot ? 'tệp ' : ''}lúc ${time(resource.meta.read_at)}`
            : 'Chưa đọc được nguồn'}
          {resource.meta?.data_as_of &&
            ` · ${snapshot ? 'Chốt bản chụp' : 'Dữ liệu đến'} ${time(resource.meta.data_as_of)}`}
        </span>
      </div>
    )
  }
  return (
    <div className="v4-source-status">
      <span>
        <Database size={14} />
        <strong>
          {label || uiLabel(resource.meta?.source_system || 'UNKNOWN')}
        </strong>
        <Badge
          value={
            resource.data === null ? 'UNKNOWN' : snapshot ? 'HISTORICAL' : state
          }
        />
        {snapshot && state !== 'FRESH' && <Badge value={state} />}
      </span>
      <span>
        {resource.meta?.read_at
          ? `Đọc ${snapshot ? 'tệp ' : ''}lúc ${time(resource.meta.read_at)}`
          : 'Chưa đọc được nguồn'}
        {resource.meta?.data_as_of &&
          ` · ${snapshot ? 'Chốt bản chụp' : 'Dữ liệu đến'} ${time(resource.meta.data_as_of)}`}
      </span>
    </div>
  )
}

export function ResourceNotice({ resource, noun = 'dữ liệu' }) {
  const { setLoginOpen } = usePortal()
  if (resource.loading && resource.data === null)
    return (
      <div
        className="v4-skeleton"
        role="status"
        aria-label={`Đang đọc ${noun}`}
      >
        <div />
        <div />
        <div />
      </div>
    )
  if (resource.error)
    return (
      <div
        className={`v4-notice ${resource.data !== null ? 'warn' : ''}`}
        role="status"
      >
        <ShieldAlert size={19} />
        <div>
          <strong>
            {resource.error.status === 401
              ? 'Phiên đăng nhập chưa hợp lệ'
              : resource.data !== null
                ? 'Đang hiển thị dữ liệu lần đọc trước'
                : `Chưa đọc được ${noun}`}
          </strong>
          <p>{resource.error.message}</p>
          <small>
            {resource.error.code}
            {resource.error.requestId
              ? ` · Mã yêu cầu ${resource.error.requestId}`
              : ''}
          </small>
        </div>
        {resource.error.status === 401 && (
          <button
            className="button secondary"
            onClick={() => setLoginOpen(true)}
          >
            Đăng nhập
          </button>
        )}
      </div>
    )
  if (
    resource.meta?.source_mode === 'REMOTE_READONLY' &&
    resource.data !== null &&
    freshness(resource.meta) !== 'FRESH'
  )
    return (
      <div className="v4-notice warn" role="status">
        <ShieldAlert size={19} />
        <div>
          <strong>Chưa đồng bộ được dữ liệu mới từ Proxy</strong>
          <p>
            Đang hiển thị dữ liệu lưu tạm của lần đọc trước. Kiểm tra bộ đọc SSH và kết
            nối tới Proxy.
          </p>
          <small>{resource.meta.last_error_code || 'REMOTE_SYNC_STALE'}</small>
        </div>
      </div>
    )
  if (!resource.loading && resource.data === null)
    return (
      <Empty
        title={`Chưa có ${noun}`}
        text="Nguồn chưa cung cấp dữ liệu để hiển thị."
      />
    )
  return null
}

export function Empty({
  title = 'Không có dữ liệu phù hợp',
  text = 'Hãy thử thay đổi bộ lọc hoặc khoảng thời gian.',
  children,
}) {
  return (
    <div className="v4-empty">
      <Database size={27} />
      <h3>{title}</h3>
      <p>{text}</p>
      {children}
    </div>
  )
}

export function Panel({
  title,
  subtitle,
  resource,
  children,
  className = '',
  action,
}) {
  return (
    <section
      className={`panel v4-panel ${className}`}
      aria-busy={resource?.loading || undefined}
    >
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {resource && (
        <>
          <SourceStatus resource={resource} />
          <ResourceNotice resource={resource} noun={title.toLowerCase()} />
        </>
      )}
      {children}
    </section>
  )
}

export function FieldGrid({ rows }) {
  return (
    <dl className="v4-fields">
      {rows.map(([name, value]) => (
        <div key={name}>
          <dt>{uiLabel(name)}</dt>
          <dd>
            {value === null || value === undefined || value === ''
              ? '—'
              : value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function CopyId({ value }) {
  const [state, setState] = useState('')
  const timer = useRef(null)
  useEffect(() => () => clearTimeout(timer.current), [])
  return (
    <button
      type="button"
      className="v4-copy"
      disabled={!value}
      aria-label={`Sao chép ${value || 'ID'}`}
      title={state || 'Sao chép ID'}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setState('Đã sao chép')
        } catch {
          setState('Không thể sao chép')
        }
        clearTimeout(timer.current)
        timer.current = setTimeout(() => setState(''), 2000)
      }}
    >
      {state === 'Đã sao chép' ? <Check size={13} /> : <Copy size={13} />}
      <span className="sr-only" role="status">
        {uiLabel(state)}
      </span>
    </button>
  )
}

export function Filter({ label, children }) {
  return (
    <label className="v4-filter">
      <span>{label}</span>
      {children}
    </label>
  )
}
export function SelectFilter({
  label,
  value,
  options,
  onChange,
  disabled = false,
  describedBy,
}) {
  return (
    <Filter label={label}>
      <select
        value={value || ''}
        disabled={disabled}
        aria-describedby={describedBy}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option
            key={option[0]}
            value={option[0]}
            disabled={option[2] === true}
          >
            {uiLabel(option[1])}
          </option>
        ))}
      </select>
    </Filter>
  )
}

export function CursorPager({ resource, cursor, history, onNext, onPrevious }) {
  const next = resource.meta?.next_cursor
  return (
    <div className="v4-pager">
      <span>
        Trang {history.length + 1} ·{' '}
        {resource.meta?.has_more === true
          ? 'Còn dữ liệu'
          : 'Theo phạm vi truy vấn'}
      </span>
      <div>
        <button
          className="button secondary"
          disabled={!cursor || resource.loading}
          onClick={onPrevious}
        >
          <ArrowLeft size={14} />
          Trước
        </button>
        <button
          className="button secondary"
          disabled={!next || resource.loading || Boolean(resource.error)}
          onClick={() => onNext(next)}
        >
          Tiếp
          <ArrowRight size={14} />
        </button>
      </div>
    </div>
  )
}

export function Dialog({ title, onClose, children }) {
  const ref = useRef(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  const titleId = useId()
  useEffect(() => {
    const previous = document.activeElement
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const focusable = () => [
      ...ref.current.querySelectorAll(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]'
      ),
    ]
    focusable()[0]?.focus()
    const key = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        closeRef.current()
      }
      if (event.key !== 'Tab') return
      const items = focusable(),
        first = items[0],
        last = items.at(-1)
      if (!first) {
        event.preventDefault()
        return
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', key)
    return () => {
      document.body.style.overflow = overflow
      document.removeEventListener('keydown', key)
      previous?.focus?.()
    }
  }, [])
  return createPortal(
    <div
      className="v4-dialog-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <section
        className="v4-dialog"
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header>
          <h2 id={titleId}>{title}</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Đóng"
            onClick={onClose}
          >
            <X size={19} />
          </button>
        </header>
        {children}
      </section>
    </div>,
    document.body
  )
}

export function LoginDialog() {
  const { auth, login, loginOpen, setLoginOpen } = usePortal()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (!loginOpen) return null
  const close = () => {
    if (!busy) {
      setLoginOpen(false)
      setPassword('')
      setError('')
    }
  }
  return (
    <Dialog title="Đăng nhập Portal" onClose={close}>
      <form
        onSubmit={async (event) => {
          event.preventDefault()
          setBusy(true)
          setError('')
          try {
            await login(username.trim(), password)
          } catch (failure) {
            setError(failure.message)
          } finally {
            setPassword('')
            setBusy(false)
          }
        }}
      >
        <p className="v4-form-intro">
          Sử dụng tài khoản được cấp cho Portal quản trị.
        </p>
        {auth.status === 'unavailable' && (
          <p className="v4-inline-warning">
            Chưa xác minh được dịch vụ đăng nhập. Không có phiên demo hoặc tài
            khoản mặc định.
          </p>
        )}
        <Filter label="Tên đăng nhập">
          <input
            autoComplete="username"
            name="username"
            required
            maxLength={128}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            disabled={busy}
          />
        </Filter>
        <Filter label="Mật khẩu">
          <input
            autoComplete="current-password"
            name="password"
            type="password"
            required
            maxLength={1024}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={busy}
          />
        </Filter>
        {error && (
          <p className="v4-form-error" role="alert">
            {error}
          </p>
        )}
        <footer>
          <button
            type="button"
            className="button secondary"
            disabled={busy}
            onClick={close}
          >
            Hủy
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? 'Đang đăng nhập…' : 'Đăng nhập'}
          </button>
        </footer>
      </form>
    </Dialog>
  )
}
