import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { IncidentInvestigation } from '../features/n91-investigation/Investigation'
import { StandaloneResponseHistory } from '../features/n91-investigation/ResponseHistory.jsx'
import {
  IncidentWorkbench,
  WorkbenchGate,
} from '../features/n91-investigation/IncidentWorkbench'
import {
  canReadWorkbench,
  isInvestigationId,
  resolveLegacyIdentity,
} from '../features/n91-investigation/workbenchModel.js'
import { incidentHref } from '../services/incidentLinks.js'
import { IncidentBusinessPanel } from '../features/n91-business'
import { useId, useRef, useState } from 'react'
import { ArrowLeft, ArrowUpRight, FileText, RefreshCw } from 'lucide-react'
import usePortalResource from '../hooks/usePortalResource'
import {
  canWriteNotes,
  isVerifiedNetwork,
  mapEvent,
  mapIncident,
  readCollection,
  portalRequest,
  PortalApiError,
} from '../services/portalApi'
import { usePortal } from './PortalContext'
import {
  CurrentMapping,
  DecisionChecklist,
  VerifiedSource,
} from './InvestigationUI'
import {
  initialIncidentDraft,
  incidentFilterSearch,
  incidentLocalTime,
  incidentRequestFilters,
  incidentUtcTime,
  readIncidentFilterSupport,
  withoutUnsupportedIncidentFilters,
} from '../services/incidentFilters'
import {
  Badge,
  CopyId,
  CursorPager,
  Empty,
  FieldGrid,
  Filter,
  PageHeading,
  Panel,
  ResourceNotice,
  SelectFilter,
  SourceStatus,
  display,
  useTime,
} from './PortalUI'

export function useV4Resource(path, options = {}) {
  const { sessionVersion, auth, mode } = usePortal()
  return usePortalResource(path, {
    scope: `${sessionVersion}:${auth.status}:${auth.user?.user_id || ''}`,
    ...options,
    enabled:
      mode === 'v4' && auth.status !== 'checking' && options.enabled !== false,
  })
}

export function useCursor() {
  const [cursor, setCursor] = useState(null)
  const [history, setHistory] = useState([])
  return {
    cursor,
    history,
    onNext: (next) => {
      setHistory((items) => [...items, cursor])
      setCursor(next)
    },
    onPrevious: () => {
      setCursor(history.at(-1) || null)
      setHistory((items) => items.slice(0, -1))
    },
  }
}

export function IncidentTable({ incidents, compact = false, meta, error }) {
  const time = useTime()
  return (
    <div className="table-scroll">
      <table className={`v4-table ${compact ? '' : 'v4-investigation-table'}`}>
        <thead>
          <tr>
            <th>SỰ CỐ / NGUỒN</th>
            <th>TÍN HIỆU</th>
            <th>MỨC ĐỘ / ĐỘ TIN CẬY</th>
            <th>BẰNG CHỨNG</th>
            {!compact && (
              <>
                <th>PHÁT HIỆN / PHẢN ỨNG</th>
                <th>XÁC MINH NGUỒN / ĐỐI CHIẾU</th>
              </>
            )}
            <th>LẦN CUỐI</th>
            <th>
              <span className="sr-only">Chi tiết</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={`${incident.stream_id}:${incident.incident_id}`}>
              <td>
                <a
                  className="v4-id-link"
                  href={incidentHref(incident.incident_id, incident.stream_id)}
                >
                  {incident.incident_id}
                </a>
                <small>{display(incident.source_ip)}</small>
              </td>
              <td>
                <span className="v4-rule">{display(incident.signal_rule)}</span>
              </td>
              <td>
                <Badge value={incident.severity} />
                <small>{uiLabel(incident.confidence)}</small>
              </td>
              <td>
                <strong>{display(incident.evidence_count)}</strong>
                <small>Điểm rủi ro cao nhất: {display(incident.p15_peak_score)}</small>
              </td>
              {!compact && (
                <td>
                  <Badge value={incident.incident_status} />
                  <small>
                    <Badge value={incident.response_state} />
                  </small>
                </td>
              )}
              {!compact && (
                <td>
                  <CurrentMapping
                    compact
                    mapping={incident.current_mapping}
                    error={error}
                  />
                </td>
              )}
              <td>
                <time>{time(incident.last_seen)}</time>
              </td>
              <td>
                <a
                  className="row-detail"
                  href={incidentHref(incident.incident_id, incident.stream_id)}
                  aria-label={`Xem ${incident.incident_id}`}
                >
                  <ArrowUpRight size={16} />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function IncidentsPage({ params }) {
  const { auth, timezone, sessionAuthEnabled } = usePortal()
  const time = useTime(),
    supportId = useId()
  const [draft, setDraft] = useState(() => initialIncidentDraft(params))
  const [formError, setFormError] = useState('')
  const support = readIncidentFilterSupport(auth.incidentFilters)
  const query = incidentRequestFilters(params, support)
  const pager = useCursor()
  const resource = useV4Resource('/incidents', {
    params: { ...query.filters, limit: 25, cursor: pager.cursor },
    enabled: !query.error,
    interval: 5000,
    transform: (data) => readCollection(data, 'incidents').map(mapIncident),
  })
  const apply = (event) => {
    event.preventDefault()
    const result = incidentFilterSearch(draft, support)
    setFormError(result.error)
    if (!result.error)
      window.location.hash = `/incidents${result.search ? `?${result.search}` : ''}`
  }
  const update = (key) => (value) => {
    setDraft((current) => ({ ...current, [key]: value }))
    setFormError('')
  }
  const updateTime = (key) => (value) => {
    const utc = incidentUtcTime(value, timezone)
    if (utc === null) {
      setFormError('Mốc thời gian chưa hợp lệ.')
      return
    }
    setDraft((current) => ({ ...current, [key]: utc, window: 'custom' }))
    setFormError('')
  }
  const supportedResponse = support.response_states
  return (
    <>
      <PageHeading
        title="Sự cố"
        resource={query.error ? undefined : resource}
      />
      {canReadWorkbench(auth, sessionAuthEnabled) && (
        <StandaloneResponseHistory initiallyOpen={params.response_history === '1'} />
      )}
      <form className="panel v4-filters v4-incident-filters" onSubmit={apply}>
        <Filter label="IP nguồn">
          <input
            placeholder="Ví dụ 10.0.0.204"
            value={draft.source_ip || ''}
            onChange={(event) => update('source_ip')(event.target.value)}
            maxLength={45}
          />
        </Filter>
        <SelectFilter
          label="Tín hiệu"
          value={draft.signal_rule}
          onChange={update('signal_rule')}
          options={[
            ['', "Tất cả tín hiệu"],
            ...[1, 2, 3, 4, 5].map((n) => [`CORR-00${n}`, `CORR-00${n}`]),
          ]}
        />
        <SelectFilter
          label="Danh sách mức độ"
          value={draft.severity}
          onChange={update('severity')}
          options={[
            ['', "Tất cả mức độ"],
            ...['LOW', 'WARNING', 'HIGH', 'CRITICAL'].map((value) => [
              value,
              value,
            ]),
            ...(draft.severity &&
            draft.severity !== 'ALL' &&
            !['LOW', 'WARNING', 'HIGH', 'CRITICAL'].includes(draft.severity)
              ? [[draft.severity, `${uiLabel(draft.severity)} (theo nguồn)`]]
              : []),
          ]}
        />
        <SelectFilter
          label="Trạng thái phát hiện"
          value={draft.status}
          onChange={update('status')}
          options={[
            ['', 'Tất cả trạng thái'],
            ['REVIEW_REQUIRED', 'REVIEW_REQUIRED'],
            ['OPERATIONAL_REVIEW', 'OPERATIONAL_REVIEW'],
          ]}
        />
        <SelectFilter
          label="Khoảng thời gian"
          value={draft.window}
          onChange={update('window')}
          options={[
            ['all', 'Toàn bộ lịch sử nguồn'],
            ['custom', 'Tùy chọn từ–đến'],
            ['15', '15 phút gần nhất'],
            ['60', '1 giờ gần nhất'],
            ['1440', '24 giờ gần nhất'],
            ['10080', '7 ngày gần nhất'],
          ]}
        />
        {draft.window === 'custom' && (
          <>
            <Filter label={`Từ · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}>
              <input
                type="datetime-local"
                step="1"
                value={incidentLocalTime(draft.from, timezone)}
                onInput={(event) => updateTime('from')(event.target.value)}
                onChange={(event) => updateTime('from')(event.target.value)}
              />
            </Filter>
            <Filter label={`Đến · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}>
              <input
                type="datetime-local"
                step="1"
                value={incidentLocalTime(draft.to, timezone)}
                onInput={(event) => updateTime('to')(event.target.value)}
                onChange={(event) => updateTime('to')(event.target.value)}
              />
            </Filter>
          </>
        )}
        <SelectFilter
          label="Rà soát sự cố"
          value={draft.review_state}
          onChange={update('review_state')}
          disabled={!support.review_state}
          describedBy={supportId}
          options={[
            ['', "Tất cả rà soát"],
            ...['UNREVIEWED', 'ACKNOWLEDGED', 'REVIEWED'].map((value) => [
              value,
              value,
            ]),
          ]}
        />
        <SelectFilter
          label="Xử lý state"
          value={draft.response_state}
          onChange={update('response_state')}
          disabled={!supportedResponse.length}
          describedBy={supportId}
          options={[
            ['', 'Tất cả response'],
            ...['NONE', 'QUARANTINED', 'RESTORED', 'UNKNOWN'].map((value) => [
              value,
              value,
              !supportedResponse.includes(value),
            ]),
          ]}
        />
        <button
          className="button primary"
          disabled={auth.status === 'checking'}
        >
          Áp dụng
        </button>
        <a className="text-button" href="#/incidents">
          Đặt lại
        </a>
        <p id={supportId} className="v4-filter-support">
          {!support.review_state &&
            "Nguồn hiện chưa hỗ trợ lọc Rà soát sự cố. "}
          {supportedResponse.length === 1 && supportedResponse[0] === 'UNKNOWN'
            ? "Phản ứng hiện chỉ lọc được Chưa xác định; chưa có dữ liệu để xác nhận các trạng thái còn lại."
            : !supportedResponse.length
              ? 'Nguồn chưa công bố khả năng lọc trạng thái phản ứng.'
              : `Trạng thái phản ứng có thể lọc: ${supportedResponse.join(', ')}.`}
        </p>
        <p className="v4-filter-support">
          Khoảng gần nhất tính tại lúc Áp dụng và được giữ trên URL. Chọn từ–đến
          để xem sự cố lịch sử; khoảng có đủ hai mốc tối đa 30 ngày.
        </p>
        {formError && (
          <p className="v4-form-error v4-filter-support" role="alert">
            {formError}
          </p>
        )}
      </form>
      {query.error && auth.status !== 'checking' && (
        <div className="v4-notice warn" role="alert">
          <div>
            <strong>Chưa áp dụng được bộ lọc trên đường dẫn</strong>
            <p>{query.error}</p>
            {query.unsupported && (
              <a
                className="v4-text-link"
                href={`#/incidents?${withoutUnsupportedIncidentFilters(params, support)}`}
              >
                Bỏ bộ lọc chưa hỗ trợ
              </a>
            )}
          </div>
        </div>
      )}
      {!query.error && (
        <p className="v4-filter-scope">
          {params.from || params.to
            ? `Đang lọc Last Seen: ${params.from ? time(params.from) : 'từ đầu lịch sử'} → ${params.to ? time(params.to) : 'đến cuối lịch sử'}.`
            : "Đang xem toàn bộ lịch sử trong nguồn ."}{' '}
          Sắp xếp lần xuất hiện cuối mới nhất trước.
        </p>
      )}
      <Panel title="Sự cố" resource={query.error ? undefined : resource}>
        {resource.data &&
          (resource.data.length ? (
            <IncidentTable
              incidents={resource.data}
              meta={resource.meta}
              error={resource.error}
            />
          ) : (
            <Empty title="Không có sự cố trong phạm vi lọc" />
          ))}
        {!query.error && <CursorPager resource={resource} {...pager} />}
      </Panel>
    </>
  )
}

function EvidencePanel({ id }) {
  const time = useTime()
  const resource = useV4Resource(
    `/incidents/${encodeURIComponent(id)}/evidence`,
    {
      interval: 5000,
      transform: (data) => ({
        items: readCollection(data, 'events').map(mapEvent),
        membership: data?.evidence_membership || data?.membership_type || null,
        hasMore: data?.has_more === true,
        recordedCount: data?.recorded_evidence_count,
        reconstructedCount: data?.reconstructed_request_count,
        countsMatch: data?.matches_recorded_count,
      }),
    }
  )
  return (
    <Panel
      title="Bằng chứng sự cố"
      subtitle="Liên kết sự kiện và phương pháp xác định tập hợp (membership)"
      resource={resource}
    >
      {resource.data && (
        <>
          <p className="v4-panel-note">
            Tập hợp (membership): <strong>{uiLabel(resource.data.membership)}</strong>.
            Tập tái dựng theo cửa sổ không phải membership bất biến.
          </p>
          <p className="v4-panel-note">
            Số yêu cầu ghi nhận {display(resource.data.recordedCount)} yêu cầu; tái
            dựng được {display(resource.data.reconstructedCount)} yêu cầu.
            {resource.data.countsMatch === false && (
              <strong> Hai số khác nhau; không sửa evidence_count gốc.</strong>
            )}
          </p>
          <div className="table-scroll">
            <table className="v4-table">
              <thead>
                <tr>
                  <th>SỰ KIỆN / REQUEST ID</th>
                  <th>THỜI ĐIỂM</th>
                  <th>QUY TẮC</th>
                  <th>ĐIỂM RỦI RO</th>
                  <th>QUYẾT ĐỊNH</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.items.map((event) => (
                  <tr key={`${event.stream_id}:${event.event_id}`}>
                    <td>
                      <a
                        className="v4-id-link"
                        href={`#/events/${encodeURIComponent(event.event_id)}?stream_id=${encodeURIComponent(event.stream_id || '')}`}
                      >
                        {event.event_id}
                      </a>
                      <small>{display(event.request_id)}</small>
                    </td>
                    <td>{time(event.occurred_at)}</td>
                    <td>{event.matched_rules.join(', ') || '—'}</td>
                    <td>
                      {display(event.risk.score)}
                      <small>{uiLabel(event.risk.status)}</small>
                    </td>
                    <td>
                      <Badge value={event.decision} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!resource.data.items.length && (
            <Empty
              title="Chưa có bằng chứng có thể đọc"
              text="Không suy ra nội dung yêu cầu từ số lượng bằng chứng."
            />
          )}
          {resource.data.hasMore && (
            <p className="v4-panel-note">
              Đang hiển thị một phần bằng chứng. Không dùng số dòng này làm tổng
              số yêu cầu.
            </p>
          )}
        </>
      )}
    </Panel>
  )
}

export function NetworkObservation({ observation, meta, error }) {
  const time = useTime()
  const verified = isVerifiedNetwork(observation, meta, Boolean(error))
  return (
    <div className="v4-network-observation">
      <div>
        <span className="v4-label">MẠNG HIỆN TẠI</span>
        <Badge value={verified ? observation.state : 'UNKNOWN'} />
      </div>
      <p>
        {verified
          ? 'Đã đọc trạng thái từ Neutron.'
          : "Chưa có quan sát Neutron trực tiếp đủ mới để kết luận."}
      </p>
      <FieldGrid
        rows={[
          ['Quan sát lúc', time(observation?.observed_at)],
          ['Phương pháp', uiLabel(observation?.verification)],
          [
            verified
              ? 'Security groups hiện tại'
              : 'Security groups lần quan sát trước',
            Array.isArray(observation?.security_group_ids)
              ? observation.security_group_ids.join(' · ') || 'Không có SG'
              : 'Chưa xác minh',
          ],
        ]}
      />
    </div>
  )
}

function TimelinePanel({ id }) {
  return <IncidentInvestigation incidentId={id} />
}

function DecisionPanel({ id }) {
  const time = useTime()
  const { auth } = usePortal()
  const allowed =
    auth.status === 'local_snapshot' ||
    ['Analyst', 'Operator', 'Approver', 'Executor'].includes(auth.user?.role)
  const resource = useV4Resource(
    `/incidents/${encodeURIComponent(id)}/decision`,
    { interval: 0, enabled: allowed }
  )
  return (
    <Panel
      title="Đánh giá phản ứng"
      subtitle="Dry-run không thay đổi mạng"
      resource={resource}
      action={
        <button
          type="button"
          className="button secondary v4-decision-refresh"
          disabled={!allowed || resource.loading}
          onClick={resource.refresh}
        >
          <RefreshCw size={14} className={resource.loading ? 'spin' : ''} />
          {resource.loading ? 'Đang đọc…' : 'Làm mới dry-run'}
        </button>
      }
    >
      {!allowed && (
        <p className="v4-panel-note">
          Cần đăng nhập với quyền Analyst hoặc quyền đánh giá phản ứng tương
          ứng.
        </p>
      )}
      <FieldGrid rows={[['Đánh giá lúc', time(resource.data?.evaluated_at)]]} />
      <DecisionChecklist data={resource.data} />
      <div className="v4-action-boundary">
        <button className="button secondary" disabled>
          Cách ly qua Portal · Chưa bật
        </button>
      </div>
    </Panel>
  )
}

function NotesPanel({ id }) {
  const { auth, sessionVersion } = usePortal()
  const [text, setText] = useState('')
  const [state, setState] = useState({ busy: false, error: '', saved: false })
  const pending = useRef(false)
  const key = useRef(null)
  const allowed = canWriteNotes(auth.user, auth.csrfToken)
  return (
    <Panel
      title="Ghi chú rà soát"
      subtitle="Ghi vào Portal · không thay đổi trạng thái phát hiện "
    >
      <form
        key={sessionVersion}
        onSubmit={async (event) => {
          event.preventDefault()
          if (!allowed || !text.trim() || pending.current) return
          pending.current = true
          key.current ||= crypto.randomUUID()
          setState({ busy: true, error: '', saved: false })
          try {
            await portalRequest(`/incidents/${encodeURIComponent(id)}/notes`, {
              method: 'POST',
              body: { note: text.trim() },
              csrfToken: auth.csrfToken,
              idempotencyKey: key.current,
            })
            setText('')
            key.current = null
            setState({ busy: false, error: '', saved: true })
          } catch (error) {
            setState({ busy: false, error: error.message, saved: false })
          } finally {
            pending.current = false
          }
        }}
      >
        <label className="v4-filter">
          <span>Nội dung ghi chú</span>
          <textarea
            rows={4}
            maxLength={1000}
            value={text}
            disabled={!allowed || state.busy}
            onChange={(event) => {
              setText(event.target.value)
              key.current = null
              setState((current) => ({ ...current, saved: false }))
            }}
            placeholder="Kết quả kiểm tra và hướng xử lý…"
          />
        </label>
        {!allowed && (
          <p className="v4-panel-note">
            {auth.status === 'local_snapshot'
              ? auth.remote
                ? "Nguồn SSH hiện chỉ đọc; chưa bật lưu ghi chú hoặc rà soát."
                : "Bản chụp hiện chỉ đọc; chưa bật lưu ghi chú hoặc rà soát."
              : 'Cần phiên đăng nhập hợp lệ có quyền Analyst, Operator hoặc Approver để ghi chú.'}
          </p>
        )}
        {state.error && (
          <p className="v4-form-error" role="alert">
            {state.error}
          </p>
        )}
        {state.saved && (
          <p className="v4-success" role="status">
            Đã lưu ghi chú vào Portal.
          </p>
        )}
        <button
          className="button primary"
          disabled={!allowed || !text.trim() || state.busy}
        >
          <FileText size={14} />
          {state.busy ? 'Đang lưu…' : 'Lưu ghi chú'}
        </button>
      </form>
    </Panel>
  )
}

export function IncidentDetail({ id, params = {} }) {
  if (Object.hasOwn(params, 'stream_id')) {
    if (!isInvestigationId(id) || !isInvestigationId(params.stream_id))
      return (
        <WorkbenchGate
          id={id}
          message="Cặp định danh incident / stream không hợp lệ. Không tự bỏ stream hoặc chọn nguồn khác."
        />
      )
    return (
      <IncidentWorkbench id={id} streamId={params.stream_id} params={params} />
    )
  }
  return <LegacyIncidentDetail id={id} />
}

function LegacyIncidentDetail({ id }) {
  const { sessionAuthEnabled, auth } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/incidents/${encodeURIComponent(id)}`, {
    interval: 5000,
    transform: (record) => {
      if (record?.incident_id !== id)
        throw new PortalApiError(
          "Server trả sự cố khác yêu cầu.",
          502,
          'INCIDENT_IDENTITY_MISMATCH'
        )
      return mapIncident(record)
    },
  })
  const incident = resource.data
  return (
    <>
      <a className="incident-back" href="#/incidents">
        <ArrowLeft size={15} />
        Sự cố
      </a>
      <PageHeading
        eyebrow="ĐIỀU TRA SỰ CỐ"
        title="Chi tiết sự cố"
        description={id}
        resource={resource}
      >
        <CopyId value={id} />
      </PageHeading>
      <SourceStatus resource={resource} label="Nguồn sự cố" />
      <ResourceNotice resource={resource} noun="incident" />
      {incident &&
        resolveLegacyIdentity(incident, id) &&
        canReadWorkbench(auth, sessionAuthEnabled) && (
          <div className="n91-wb-notice" role="status">
            Stream được phân giải từ phản hồi sự cố của máy chủ, chưa chứng
            minh danh tính lịch sử của VM.
            <p>
              <a href={incidentHref(id, incident.stream_id)}>
                Mở trang điều tra sự cố
              </a>
            </p>
          </div>
        )}
      {incident && (
        <>
          <section
            className="v4-incident-identity"
            aria-label="Nhận diện sự cố"
          >
            <div>
              <span className="v4-label">TÍN HIỆU </span>
              <strong>{display(incident.signal_rule)}</strong>
            </div>
            <div>
              <span className="v4-label">IP NGUỒN</span>
              <strong>{display(incident.source_ip)}</strong>
            </div>
            <div>
              <span className="v4-label">CONFIDENCE </span>
              <strong>{uiLabel(incident.confidence)}</strong>
            </div>
          </section>
          <div className="v4-detail-statuses">
            <div>
              <span>SEVERITY </span>
              <Badge value={incident.severity} />
            </div>
            <div>
              <span>PHÁT HIỆN</span>
              <Badge value={incident.incident_status} />
            </div>
            <div>
              <span>PHẢN ỨNG ĐÃ GHI NHẬN</span>
              <Badge value={incident.response_state} />
            </div>
            <div>
              <span>ĐIỂM RỦI RO CAO NHẤT </span>
              <strong>
                {display(incident.p15_peak_score)}
                <small> / 100</small>
              </strong>
            </div>
          </div>
          <div className="v4-detail-grid">
            <Panel title="Phát hiện và nguồn">
              <FieldGrid
                rows={[
                  ["Tín hiệu quy tắc", display(incident.signal_rule)],
                  ['Nguồn', display(incident.source_ip)],
                  ["Độ tin cậy", uiLabel(incident.confidence)],
                  ["Số bằng chứng ", display(incident.evidence_count)],
                  ['Lần đầu', time(incident.first_seen)],
                  ['Lần cuối', time(incident.last_seen)],
                  ["Mã luồng", display(incident.stream_id)],
                  ["Phương pháp liên kết", display(incident.evidence_membership)],
                  ["Rà soát sự cố", uiLabel(incident.review_state)],
                ]}
              />
              <p className="v4-panel-note">
                {incident.signal_rule === 'CORR-003'
                  ? "CORR-003: truy cập dữ liệu nhạy cảm lặp lại trong cửa sổ 120 giây. Tín hiệu này không tự cho phép cách ly."
                  : incident.signal_rule === 'CORR-002'
                    ? "Tín hiệu nghi vấn tấn công tương quan. Điểm rủi ro cao không tự cấp quyền cách ly."
                    : "Tín hiệu và số bằng chứng giữ theo bản ghi của nguồn."}
              </p>
            </Panel>
            <Panel
              title="Đối chiếu máy ảo"
              subtitle="Đối chiếu IP hiện tại · danh tính lịch sử được đánh giá riêng"
            >
              <CurrentMapping
                mapping={incident.current_mapping}
                error={resource.error}
              />
              <h3 className="v4-subheading">
                Xác minh danh tính trong bằng chứng </h3>
              <VerifiedSource
                mapping={incident.mapping}
                meta={resource.meta}
                error={resource.error}
              />
            </Panel>
          </div>
          <EvidencePanel id={id} />
          <div className="v4-detail-grid">
            <TimelinePanel id={id} />
            <div className="v4-stack">
              <DecisionPanel id={id} />
              {sessionAuthEnabled ? (
                <IncidentBusinessPanel id={id} streamId={incident.stream_id} />
              ) : <NotesPanel id={id} />}
            </div>
          </div>
        </>
      )}
    </>
  )
}
