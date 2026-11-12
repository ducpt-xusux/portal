import { uiLabel, uiRoleList, uiAlertSummary } from '../services/uiLanguage.js'
import { useState } from 'react'
import { IncidentBusinessPanel } from '../features/n91-business'
import { usePortal } from './PortalContext'
import { ArrowUpRight, RefreshCw } from 'lucide-react'
import {
  alertEventHref,
  alertIncidentHref,
  alertRequestFilters,
  mapAlert,
  readAlertsPage,
} from '../services/alertsApi'
import { useCursor, useV4Resource } from './IncidentPages'
import {
  Badge,
  CopyId,
  CursorPager,
  Dialog,
  Empty,
  FieldGrid,
  Filter,
  Panel,
  ResourceNotice,
  SelectFilter,
  SourceStatus,
  display,
  useTime,
} from './PortalUI'
import './AlertCenter.css'

function IncidentLink({ id, streamId }) {
  const href = alertIncidentHref(id, streamId)
  return href ? (
    <a className="v4-id-link" href={href}>
      {id}
      <ArrowUpRight size={13} />
    </a>
  ) : (
    <span className="v4-muted">Không có sự cố gắn trong cảnh báo</span>
  )
}

function AlertDetail({ id, onClose }) {
  const { sessionAuthEnabled } = usePortal()
  const time = useTime()
  const resource = useV4Resource(`/alerts/${encodeURIComponent(id)}`, {
    interval: 5000,
    transform: mapAlert,
  })
  const alert = resource.data
  return (
    <Dialog title="Chi tiết cảnh báo " onClose={onClose}>
      <div className="v4-alert-detail">
        <SourceStatus resource={resource} label="Nguồn cảnh báo" />
        <ResourceNotice resource={resource} noun="cảnh báo" />
        {alert && (
          <>
            <div className="v4-copy-row">
              <strong>{alert.alert_id}</strong>
              <CopyId value={alert.alert_id} />
            </div>
            <div className="v4-alert-badges">
              <Badge value={alert.severity} />
              <span className="v4-rule">{alert.signal_code}</span>
            </div>
            <h3>{uiLabel(alert.title)}</h3>
            <p>{uiAlertSummary(alert.summary)}</p>
            <FieldGrid
              rows={[
                ['Tạo lúc', time(alert.created_at)],
                ['Loại cảnh báo', uiLabel(alert.kind)],
                [
                  "IP nguồn",
                  alert.source_ip || 'Nguồn không công bố danh tính đầy đủ',
                ],
                [
                  "Điểm rủi ro cao nhất theo cảnh báo",
                  alert.risk_peak === null
                    ? 'Chưa có điểm hợp lệ'
                    : `${alert.risk_peak}/100`,
                ],
                [
                  'Sự cố được nguồn liên kết',
                  <IncidentLink
                    id={alert.incident_id}
                    streamId={resource.meta?.stream_id}
                  />,
                ],
                ['Nguồn', uiLabel(alert.provenance.source_system)],
                ["Cấu trúc dữ liệu", display(alert.provenance.source_schema)],
                ['Dữ liệu thu thập đến', time(alert.provenance.data_as_of)],
                ["Tham chiếu nguồn", display(alert.source_record_ref)],
              ]}
            />
            <h3 className="v4-subheading">
              Sự kiện được cảnh báo tham chiếu
            </h3>
            {alert.event_refs.length ? (
              <ul className="v4-alert-refs">
                {alert.event_refs.map((eventId) => {
                  const href = alertEventHref(eventId, resource.meta?.stream_id)
                  return (
                    <li key={eventId}>
                      {href ? (
                        <a className="v4-id-link" href={href}>
                          {eventId}
                          <ArrowUpRight size={13} />
                        </a>
                      ) : (
                        <code>{eventId}</code>
                      )}
                    </li>
                  )
                })}
              </ul>
            ) : (
              <p className="v4-panel-note">Cảnh báo chưa có liên kết sự kiện.</p>
            )}
            <p className="v4-panel-note">
              Để xem bằng chứng của sự cố, mở liên kết sự cố và chọn Dòng thời gian.
            </p>
            {sessionAuthEnabled ? (
              <IncidentBusinessPanel
                id={id}
                streamId={resource.meta?.stream_id}
                kind="alerts"
              />
            ) : (
              <p className="v4-panel-note">Rà soát cảnh báo cần phiên Portal.</p>
            )}
          </>
        )}
      </div>
    </Dialog>
  )
}

function AlertFeed({ filters, onRestart }) {
  const time = useTime(),
    pager = useCursor()
  const [selected, setSelected] = useState(null)
  const resource = useV4Resource('/alerts', {
    params: { ...filters, limit: 10, cursor: pager.cursor },
    interval: 5000,
    transform: readAlertsPage,
  })
  const data = resource.data
  return (
    <Panel
      title="Cảnh báo"
      resource={resource}
      action={
        <button type="button" className="button secondary" onClick={onRestart}>
          <RefreshCw size={14} />
          Đọc lại cảnh báo
        </button>
      }
    >
      <p className="v4-panel-note">
        {data ? (
          <strong>
            {data.total_count} cảnh báo đã thu thập phù hợp bộ lọc.{' '}
          </strong>
        ) : (
          "Chưa xác định số cảnh báo. "
        )}
        Một sự cố có thể có nhiều cảnh báo; một cảnh báo có thể chưa có sự cố.
        Nguồn chưa xác nhận toàn bộ lịch sử cảnh báo.
      </p>
      {resource.error?.status === 412 && (
        <p className="v4-panel-note">
          Nguồn đã thay đổi khi phân trang. Bấm “Đọc lại cảnh báo” để bắt đầu từ
          trang đầu.
        </p>
      )}
      {data &&
        (data.items.length ? (
          <div className="table-scroll">
            <table className="v4-table v4-alert-table">
              <thead>
                <tr>
                  <th>THỜI GIAN</th>
                  <th>CẢNH BÁO / TÍN HIỆU</th>
                  <th>MỨC ĐỘ / ĐIỂM ĐỈNH</th>
                  <th>IP NGUỒN</th>
                  <th>SỰ CỐ</th>
                  <th>CHI TIẾT</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td>
                      <time>{time(alert.created_at)}</time>
                    </td>
                    <td>
                      <strong>{uiLabel(alert.title)}</strong>
                      <small>
                        {alert.signal_code} · {uiLabel(alert.kind)}
                      </small>
                      <small>{alert.alert_id}</small>
                    </td>
                    <td>
                      <Badge value={alert.severity} />
                      <small>Điểm đỉnh: {display(alert.risk_peak)}</small>
                    </td>
                    <td>{alert.source_ip || 'Chưa công bố'}</td>
                    <td>
                      <IncidentLink
                        id={alert.incident_id}
                        streamId={resource.meta?.stream_id}
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="button secondary"
                        aria-label={`Xem cảnh báo ${alert.alert_id}`}
                        onClick={() => setSelected(alert.alert_id)}
                      >
                        Xem
                        <ArrowUpRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="Không có cảnh báo phù hợp bộ lọc"
            text="Kết quả này không xác nhận toàn bộ lịch sử cảnh báo trên Proxy."
          />
        ))}
      <CursorPager resource={resource} {...pager} />
      {selected && (
        <AlertDetail
          key={selected}
          id={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </Panel>
  )
}

export default function AlertCenter({ initialRange = null }) {
  const [draft, setDraft] = useState({
    window: 'all',
    severity: '',
    signal_code: '',
    source_ip: '',
    kind: '',
  })
  const [filters, setFilters] = useState(initialRange || {}),
    [revision, setRevision] = useState(0)
  const update = (key) => (value) =>
    setDraft((current) => ({ ...current, [key]: value }))
  return (
    <section className="v4-alert-center" aria-label="Cảnh báo">
      {filters.from && filters.to && (
        <p className="v4-panel-note">
          Cảnh báo đang lọc theo cửa sổ đã chọn: {filters.from} →{' '}
          {filters.to}. Đặt lại bộ lọc để xem các cảnh báo đã thu thập.
        </p>
      )}
      <details className="panel v4-alert-filter-panel">
        <summary>Lọc cảnh báo </summary>
        <form
          className="v4-filters"
          onSubmit={(event) => {
            event.preventDefault()
            setFilters(alertRequestFilters(draft))
            setRevision((value) => value + 1)
          }}
        >
          <SelectFilter
            label="Thời gian cảnh báo"
            value={draft.window}
            onChange={update('window')}
            options={[
              ['all', 'Tất cả cảnh báo đã thu thập'],
              ['15m', '15 phút gần nhất'],
              ['1h', '1 giờ gần nhất'],
              ['24h', '24 giờ gần nhất'],
            ]}
          />
          <SelectFilter
            label="Mức độ cảnh báo"
            value={draft.severity}
            onChange={update('severity')}
            options={[
              ['', 'Tất cả'],
              ...['CRITICAL', 'HIGH', 'WARNING', 'LOW', 'INFO'].map((value) => [
                value,
                value,
              ]),
            ]}
          />
          <Filter label="Tín hiệu cảnh báo">
            <input
              value={draft.signal_code}
              maxLength={64}
              placeholder="SINGLE_P15_HIGH / CORR-002"
              onChange={(event) => update('signal_code')(event.target.value)}
            />
          </Filter>
          <Filter label="IP nguồn cảnh báo">
            <input
              value={draft.source_ip}
              maxLength={45}
              placeholder="10.0.0.204"
              onChange={(event) => update('source_ip')(event.target.value)}
            />
          </Filter>
          <SelectFilter
            label="Loại cảnh báo"
            value={draft.kind}
            onChange={update('kind')}
            options={[
              ['', 'Tất cả'],
              ...[
                'SINGLE_P15_HIGH',
                'CORRELATED',
                'OPERATIONAL',
                'POLICY_VIOLATION',
                'AUDIT_HEALTH',
                'SYSTEM_HEALTH',
                'OTHER',
              ].map((value) => [value, value]),
            ]}
          />
          <button className="button primary">Lọc cảnh báo</button>
          <button
            type="button"
            className="button secondary"
            onClick={() => {
              setDraft({
                window: 'all',
                severity: '',
                signal_code: '',
                source_ip: '',
                kind: '',
              })
              setFilters({})
              setRevision((value) => value + 1)
            }}
          >
            Đặt lại cảnh báo
          </button>
          <p className="v4-filter-support">
            Bộ lọc riêng của Cảnh báo; không dùng cửa sổ Chỉ số kiểm toán phía
            trên. Khoảng gần nhất được chốt khi bấm Lọc.
          </p>
        </form>
      </details>
      <AlertFeed
        key={`${revision}:${JSON.stringify(filters)}`}
        filters={filters}
        onRestart={() => setRevision((value) => value + 1)}
      />
    </section>
  )
}
