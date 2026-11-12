import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { useState } from 'react'
import {
  EventComparePicker,
  EventInvestigation,
} from '../features/n91-investigation/Investigation'
import { auditEventQuery } from '../services/dashboardAudit'
import { ArrowLeft, ArrowUpRight, Search } from 'lucide-react'
import { mapEvent, readCollection } from '../services/portalApi'
import { incidentHref } from '../services/incidentLinks'
import { useCursor, useV4Resource } from './IncidentPages'
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
import { usePortal } from './PortalContext'

export function EventTable({ events, compact = false }) {
  const time = useTime()
  return (
    <div className="table-scroll">
      <table className="v4-table">
        <thead>
          <tr>
            <th>SỰ KIỆN / THỜI GIAN</th>
            <th>NGUỒN</th>
            <th>QUYẾT ĐỊNH</th>
            <th>ĐIỂM RỦI RO / TRẠNG THÁI</th>
            <th>QUY TẮC ÁP DỤNG</th>
            {!compact && <th>LOẠI / SỰ CỐ</th>}
            <th>
              <span className="sr-only">Chi tiết</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={`${event.stream_id}:${event.event_id}`}>
              <td>
                <a
                  className="v4-id-link"
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                >
                  {event.event_id}
                </a>
                <time>{time(event.occurred_at)}</time>
              </td>
              <td>
                <code>{display(event.source_ip)}</code>
                <small>{event.db_user || 'Withheld / chưa cung cấp'}</small>
              </td>
              <td>
                <Badge value={event.decision} />
                <small>Effective: {uiLabel(event.effective_action)}</small>
              </td>
              <td>
                <strong>{event.risk.score ?? 'N/A'}</strong>
                <small>{uiLabel(event.risk.status)}</small>
              </td>
              <td>
                <span className="v4-rule-list">
                  {event.matched_rules.map((rule) => (
                    <a
                      key={rule}
                      className="v4-rule"
                      href={`#/events?rule=${encodeURIComponent(rule)}${event.view_kind === 'P16H_CANONICAL_AUDIT' ? '&source=canonical' : ''}`}
                    >
                      {rule}
                    </a>
                  ))}
                </span>
                {!event.matched_rules.length && '—'}
              </td>
              {!compact && (
                <td>
                  <Badge value={event.p17_event_class} />
                  {event.incident_refs.map((id) => (
                    <a
                      key={id}
                      className="v4-id-link"
                      href={incidentHref(id, event.stream_id)}
                    >
                      {id}
                    </a>
                  ))}
                </td>
              )}
              <td>
                <a
                  className="row-detail"
                  href={`#/events/${encodeURIComponent(event.event_id)}?${auditEventQuery(event)}`}
                  aria-label={`Mở event ${event.event_id}`}
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

const localInput = (value, zone) =>
  value && Number.isFinite(Date.parse(value))
    ? new Date(Date.parse(value) + (zone === 'UTC' ? 0 : 7 * 3600000))
        .toISOString()
        .slice(0, 16)
    : ''

export function EventsPage({ params }) {
  const { timezone } = usePortal()
  const [draft, setDraft] = useState(params)
  const [error, setError] = useState('')
  const pager = useCursor()
  const resource = useV4Resource('/events', {
    params: { ...params, limit: 25, cursor: pager.cursor },
    interval: 5000,
    transform: (data) => readCollection(data, 'events').map(mapEvent),
  })
  const update = (key) => (value) =>
    setDraft((current) => ({ ...current, [key]: value }))
  return (
    <>
      <PageHeading
        eyebrow="SỰ KIỆN BẢO MẬT"
        title="Sự kiện bảo mật"
        description={
          params.source === 'canonical'
            ? 'Nhật ký kiểm toán đã nhập, phạm vi lịch sử có thể chưa đầy đủ.'
            : undefined
        }
        resource={resource}
      />
      {['TEST', 'EVALUATION'].includes(resource.meta?.import_context) && (
        <p className="v4-inline-warning" role="status">
          Dữ liệu {uiLabel(resource.meta.import_context).toLowerCase()} · bản chụp ngoại tuyến
        </p>
      )}
      <form
        className="panel v4-filters v4-event-filters"
        onSubmit={(event) => {
          event.preventDefault()
          if (
            draft.from &&
            draft.to &&
            Date.parse(draft.from) > Date.parse(draft.to)
          ) {
            setError('Thời điểm bắt đầu phải trước thời điểm kết thúc.')
            return
          }
          if (
            draft.risk_min &&
            draft.risk_max &&
            Number(draft.risk_min) > Number(draft.risk_max)
          ) {
            setError('Điểm tối thiểu phải nhỏ hơn hoặc bằng điểm tối đa.')
            return
          }
          setError('')
          const search = new URLSearchParams(
            Object.entries(draft).filter(
              ([, value]) => value && value !== 'ALL'
            )
          ).toString()
          window.location.hash = `/events${search ? `?${search}` : ''}`
        }}
      >
        <Filter label={`Từ · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}>
          <input
            type="datetime-local"
            value={localInput(draft.from, timezone)}
            onChange={(event) =>
              update('from')(
                event.target.value
                  ? new Date(
                      `${event.target.value}${timezone === 'UTC' ? 'Z' : '+07:00'}`
                    ).toISOString()
                  : ''
              )
            }
          />
        </Filter>
        <Filter label={`Đến · ${timezone === 'UTC' ? 'UTC' : 'UTC+7'}`}>
          <input
            type="datetime-local"
            value={localInput(draft.to, timezone)}
            onChange={(event) =>
              update('to')(
                event.target.value
                  ? new Date(
                      `${event.target.value}${timezone === 'UTC' ? 'Z' : '+07:00'}`
                    ).toISOString()
                  : ''
              )
            }
          />
        </Filter>
        <SelectFilter
          label="Quyết định xử lý"
          value={draft.decision}
          onChange={update('decision')}
          options={[
            ['', 'Tất cả'],
            ['ALLOW', 'ALLOW'],
            ['BLOCK', 'BLOCK'],
            ['UNKNOWN', 'UNKNOWN'],
          ]}
        />
        <Filter label="IP nguồn">
          <input
            value={draft.source_ip || ''}
            maxLength={45}
            placeholder="10.0.0.204"
            onChange={(event) => update('source_ip')(event.target.value)}
          />
        </Filter>
        <Filter label="Mã quy tắc">
          <input
            value={draft.rule || ''}
            maxLength={80}
            placeholder="INJ-001"
            onChange={(event) => update('rule')(event.target.value)}
          />
        </Filter>
        <Filter label="Mã sự cố">
          <input
            value={draft.incident_ref || ''}
            maxLength={128}
            placeholder="INC-…"
            onChange={(event) => update('incident_ref')(event.target.value)}
          />
        </Filter>
        <SelectFilter
          label="Loại sự kiện"
          value={draft.event_class}
          onChange={update('event_class')}
          options={[
            ['', 'Tất cả'],
            ...[
              'LIVE',
              'STALE',
              'HISTORICAL',
              'OUT_OF_ORDER',
              'FUTURE_SKEW',
            ].map((value) => [value, value]),
          ]}
        />
        <SelectFilter
          label="Trạng thái rủi ro"
          value={draft.risk_status}
          onChange={update('risk_status')}
          options={[
            ['', 'Tất cả'],
            ['OK', 'OK'],
            ['ERROR', 'ERROR'],
          ]}
        />
        <Filter label="Điểm rủi ro tối thiểu">
          <input
            type="number"
            min="0"
            max="100"
            value={draft.risk_min || ''}
            onChange={(event) => update('risk_min')(event.target.value)}
          />
        </Filter>
        <Filter label="Điểm rủi ro tối đa">
          <input
            type="number"
            min="0"
            max="100"
            value={draft.risk_max || ''}
            onChange={(event) => update('risk_max')(event.target.value)}
          />
        </Filter>
        <Filter label="Tài khoản cơ sở dữ liệu">
          <input
            maxLength={128}
            value={draft.db_user || ''}
            onChange={(event) => update('db_user')(event.target.value)}
            placeholder="Theo quyền xem dữ liệu"
          />
        </Filter>
        <button className="button primary">
          <Search size={14} />
          Áp dụng
        </button>
        <a
          className="text-button"
          href={
            params.source === 'canonical'
              ? '#/events?source=canonical'
              : '#/events'
          }
        >
          Đặt lại
        </a>
        {error && (
          <p role="alert" className="v4-form-error">
            {error}
          </p>
        )}
      </form>
      <details>
        <summary>So sánh APP / Clone theo kiểm toán chuẩn IDs</summary>
        <EventComparePicker />
      </details>
      <Panel
        title="Sự kiện bảo mật"
        subtitle="Một dòng cho mỗi sự kiện · nguồn và phạm vi hiển thị bên dưới"
        resource={resource}
      >
        {resource.data &&
          (resource.data.length ? (
            <EventTable events={resource.data} />
          ) : (
            <Empty title="Không có sự kiện trong phạm vi lọc" />
          ))}
        <CursorPager resource={resource} {...pager} />
      </Panel>
    </>
  )
}

export function EventDetail({ id, params }) {
  if (params.source === 'canonical' && params.stream_id) {
    return (
      <>
        <a href="#/events?source=canonical" className="incident-back">
          <ArrowLeft size={15} />
          Sự kiện bảo mật
        </a>
        <PageHeading
          eyebrow="CHI TIẾT SỰ KIỆN"
          title="Chi tiết sự kiện"
          description={id}
        />
        <EventInvestigation eventId={id} streamId={params.stream_id} />
      </>
    )
  }
  return <LegacyEventDetail id={id} params={params} />
}

function LegacyEventDetail({ id, params }) {
  const time = useTime()
  const resource = useV4Resource(`/events/${encodeURIComponent(id)}`, {
    params: { stream_id: params.stream_id, source: params.source },
    interval: 0,
    transform: mapEvent,
  })
  const event = resource.data
  return (
    <>
      <a
        href={
          params.source === 'canonical'
            ? '#/events?source=canonical'
            : '#/events'
        }
        className="incident-back"
      >
        <ArrowLeft size={15} />
        Sự kiện bảo mật
      </a>
      <PageHeading
        eyebrow="CHI TIẾT SỰ KIỆN"
        title="Chi tiết sự kiện"
        description={id}
        resource={resource}
      >
        <CopyId value={id} />
      </PageHeading>
      <SourceStatus
        resource={resource}
        label={
          event?.view_kind === 'P17_EVENT_PROJECTION'
            ? "sự kiện projection"
            : "Sự kiện nguồn"
        }
      />
      <ResourceNotice resource={resource} noun="event" />
      {event && (
        <>
          {['TEST', 'EVALUATION'].includes(event.source_provenance.context) && (
            <p className="v4-inline-warning" role="status">
              Dữ liệu {uiLabel(event.source_provenance.context).toLowerCase()} · bản chụp ngoại tuyến
            </p>
          )}
          <div className="v4-detail-statuses">
            <div>
              <span>QUYẾT ĐỊNH</span>
              <Badge value={event.decision} />
            </div>
            <div>
              <span>RISK SCORE</span>
              <strong>
                {event.risk.score ?? 'N/A'}
                <small> / 100</small>
              </strong>
            </div>
            <div>
              <span>RISK STATUS</span>
              <Badge value={event.risk.status} />
            </div>
            <div>
              <span>CLASS TẠI LÚC XỬ LÝ</span>
              <Badge value={event.p17_event_class} />
            </div>
          </div>
          <div className="v4-detail-grid">
            <div className="v4-stack">
              <Panel
                title={
                  event.view_kind === 'P17_EVENT_PROJECTION'
                    ? "sự kiện projection"
                    : "SQL & chính sách decision"
                }
                subtitle="Chỉ hiển thị SQL đã được kiểm toán chuẩn nguồn cho phép"
              >
                {event.masked_query ? (
                  <pre className="v4-code">{event.masked_query}</pre>
                ) : (
                  <div className="v4-privacy">
                    <ShieldPrivacy />
                    <strong>
                      {event.view_kind === 'P17_EVENT_PROJECTION'
                        ? "Nguồn không lưu SQL"
                        : 'SQL không khả dụng do chính sách riêng tư'}
                    </strong>
                    <p>
                      Dùng sự kiện ID, quy tắc và thông tin nguồn để truy vết. Các trường
                      kiểm toán chuẩn chưa cung cấp được giữ trống.
                    </p>
                  </div>
                )}
                <FieldGrid
                  rows={[
                    ["Căn cứ quyết định", display(event.decision_basis)],
                    ["Hành động áp dụng", uiLabel(event.effective_action)],
                    ["Kết quả xử lý", uiLabel(event.action_result)],
                    ["Chế độ vận hành", uiLabel(event.runtime_mode)],
                    ["Mã chính sách", display(event.policy_id)],
                    ["Phiên bản chính sách", display(event.policy_version)],
                    ["Lệnh MySQL", display(event.mysql_command)],
                    [
                      "Quy tắc khớp",
                      event.matched_rules.join(' · ') || 'Không có',
                    ],
                    [
                      "Quy tắc chặn",
                      event.blocking_rules.join(' · ') ||
                        (event.canonical_complete
                          ? 'Không có'
                          : 'Chưa cung cấp'),
                    ],
                    [
                      "Quy tắc giám sát",
                      event.monitor_rules.join(' · ') ||
                        (event.canonical_complete
                          ? 'Không có'
                          : 'Chưa cung cấp'),
                    ],
                  ]}
                />
                <h3 className="v4-subheading">Lý do từ chính sách</h3>
                {event.reasons.length ? (
                  <ul className="v4-reasons">
                    {event.reasons.map((reason, index) => (
                      <li key={index}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="v4-panel-note">
                    Nguồn chưa cung cấp lý do chi tiết.
                  </p>
                )}
                <p className="v4-panel-note">
                  {event.view_kind === 'P17_EVENT_PROJECTION'
                    ? "Quyết định ở đây dựa trên cờ blocked của ; chưa có kiểm toán chuẩn decision."
                    : "Hành động áp dụng và hành động result phản ánh thực thi. Monitor match không tự chứng minh đã chặn."}{' '}
                  Trạng thái cách ly VM cần bằng chứng hành động và quan sát
                  Neutron riêng.
                </p>
              </Panel>
              <Panel title="Giải thích điểm">
                <FieldGrid
                  rows={[
                    ["Điểm gốc", display(event.raw_score)],
                    ['Điểm sau giới hạn', event.risk.score ?? 'N/A'],
                    ["Trạng thái rủi ro", uiLabel(event.risk.status)],
                  ]}
                />
                {event.score_breakdown?.length ? (
                  <div className="table-scroll">
                    <table className="v4-table v4-breakdown-table">
                      <thead>
                        <tr>
                          <th>NGUỒN / RULE</th>
                          <th>NHÓM</th>
                          <th>ĐIỂM</th>
                          <th>LÝ DO</th>
                        </tr>
                      </thead>
                      <tbody>
                        {event.score_breakdown.map((component, index) => (
                          <tr key={index}>
                            <td>
                              <strong>
                                {component.rule_id ||
                                  "Component không gắn quy tắc"}
                              </strong>
                              <small>{display(component.source)}</small>
                            </td>
                            <td>{display(component.category)}</td>
                            <td>{display(component.score)}</td>
                            <td className="v4-text-cell">
                              {display(component.reason)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="v4-panel-note">
                    Chưa có chi tiết điểm từ nguồn. Điểm tổng không được dùng
                    để tự dựng các component.
                  </p>
                )}
              </Panel>
              <Panel
                title="Sự cố liên quan"
                subtitle="Liên kết bằng chứng theo nguồn "
              >
                {event.incident_refs.length ? (
                  <div className="v4-link-list">
                    {event.incident_refs.map((ref) => (
                      <a key={ref} href={incidentHref(ref, event.stream_id)}>
                        {ref}
                        <ArrowUpRight size={15} />
                      </a>
                    ))}
                  </div>
                ) : (
                  <p className="v4-panel-note">
                    Chưa có liên kết sự cố được nguồn cung cấp.
                  </p>
                )}
              </Panel>
            </div>
            <Panel title="Định danh và nguồn gốc">
              <FieldGrid
                rows={[
                  [
                    "Mã sự kiện",
                    <span className="v4-copy-row">
                      {event.event_id}
                      <CopyId value={event.event_id} />
                    </span>,
                  ],
                  ["Mã yêu cầu", display(event.request_id)],
                  ["Mã luồng", display(event.stream_id)],
                  ["Thứ tự", display(event.stream_sequence)],
                  ['Phát sinh lúc', time(event.occurred_at)],
                  ["received_utc / ingested_at", time(event.ingested_at)],
                  [
                    "Yêu cầu received · nguồn",
                    time(event.request_received_at),
                  ],
                  [
                    "Storage recorded · nguồn",
                    time(event.storage_recorded_at),
                  ],
                  ['Portal imported · PORTAL_CLOCK', time(event.imported_at)],
                  [
                    "Yêu cầu căn cứ thời gian",
                    display(event.time_basis.request_received_at),
                  ],
                  ['Identity status', display(event.identity_status)],
                  ['Thiếu trường', display(event.missing_fields_reason)],
                  ['Nguồn IP', display(event.source_ip)],
                  ["Tài khoản cơ sở dữ liệu", event.db_user || 'Withheld / chưa cung cấp'],
                  ["Cơ sở dữ liệu", display(event.database_name)],
                  [
                    "Nguồn dữ liệu",
                    uiLabel(event.source_provenance.source_system),
                  ],
                  ["Tham chiếu nguồn", display(event.source_provenance.source_ref)],
                  [
                    "SHA256 nội dung · upstream",
                    display(event.source_provenance.payload_sha256),
                  ],
                  [
                    'Hash basis',
                    display(event.source_provenance.payload_hash_basis),
                  ],
                  [
                    'Verification',
                    uiLabel(event.source_provenance.verification),
                  ],
                  ["Phạm vi dữ liệu", uiLabel(event.source_provenance.context)],
                  ['Coverage', display(event.source_provenance.coverage_kind)],
                  [
                    "Human rà soát",
                    display(event.source_provenance.human_review),
                  ],
                ]}
              />
              <details className="v4-json">
                <summary>Xem JSON đã giới hạn trường</summary>
                <pre className="v4-code">{JSON.stringify(event, null, 2)}</pre>
              </details>
            </Panel>
          </div>
        </>
      )}
    </>
  )
}

function ShieldPrivacy() {
  return (
    <span className="v4-privacy-symbol" aria-hidden="true">
      SQL
    </span>
  )
}
