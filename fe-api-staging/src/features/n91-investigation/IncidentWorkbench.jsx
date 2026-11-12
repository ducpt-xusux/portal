import { uiLabel, uiRoleList } from '../../services/uiLanguage.js'
import { useId, useRef } from 'react'
import { usePortal } from '../../portal/PortalContext'
import { EvidenceExports } from '../../portal/ReviewEvidence'
import {
  Badge,
  CopyId,
  FieldGrid,
  PageHeading,
  Panel,
  display,
  useTime,
} from '../../portal/PortalUI'
import { IncidentBusinessPanel } from '../n91-business'
import { incidentHref } from '../../services/incidentLinks.js'
import {
  WORKBENCH_TABS,
  canReadWorkbench,
  eventHref,
  workbenchTab,
} from './workbenchModel.js'
import { useWorkbench } from './useWorkbench.js'
import { ResponseHistoryView } from './ResponseHistory.jsx'
import './workbench.css'

const labels = {
  overview: 'Tổng quan',
  timeline: "Dòng thời gian",
  detection: "Căn cứ phát hiện",
  response: "Xử lý và Security Group",
  notes: "Ghi chú xử lý",
}
function Reasons({ values }) {
  return values.length ? (
    <ul className="n91-wb-reasons">
      {values.map((v) => (
        <li key={v}>
          <code>{uiLabel(v)}</code>
        </li>
      ))}
    </ul>
  ) : null
}
function Unavailable({ title, section }) {
  return (
    <section className="n91-wb-unavailable">
      <h3>{title}</h3>
      <Badge value="UNAVAILABLE" />
      <p>Chưa có dữ liệu nguồn đủ ngữ nghĩa để kết luận.</p>
      <Reasons values={section.reason_codes} />
    </section>
  )
}
function ProcessingHistory({ section }) {
  if (section.schema_version === 'portal-response-history-1')
    return <ResponseHistoryView history={section} />
  return (
    <>
      <Unavailable title="Lịch sử xử lý" section={section} />
      <a href="#/incidents?response_history=1">Mở lịch sử xử lý từ Controller</a>
    </>
  )
}
export function WorkbenchGate({ id, message }) {
  return (
    <div className="n91-workbench">
      <a href="#/incidents">← Sự cố</a>
      <PageHeading title="Điều tra sự cố" description={id} />
      <div className="n91-wb-notice" role="status">
        {message}
        <p>
          Bạn có thể mở trang sự cố cơ bản.
        </p>
        <a href={incidentHref(id)}>Xem thông tin sự cố cơ bản</a>
      </div>
    </div>
  )
}
function Sources({ meta }) {
  const time = useTime()
  return (
    <Panel title="Nguồn & phạm vi">
      <p>
        Lịch sử · {uiLabel(meta.source_context)} · phạm vi dữ liệu chưa đầy đủ. Thời điểm đọc
        không thay cho thời điểm nguồn quan sát.
      </p>
      <div className="n91-wb-sources">
        {meta.sources.map((s) => (
          <details key={s.source_system}>
            <summary>
              {uiLabel(s.source_system)} <Badge value={s.availability} />{' '}
              <Badge value={s.freshness_state} />
            </summary>
            <FieldGrid
              rows={[
                ['Đọc lúc', time(s.read_at)],
                ['Nguồn quan sát lúc', time(s.observed_at)],
                ['Chụp lúc', time(s.captured_at)],
                ['Dữ liệu đến', time(s.data_as_of)],
                ["Phạm vi dữ liệu", uiLabel(s.context)],
                ["Cấu trúc dữ liệu", display(s.source_schema)],
                ["Tham chiếu nguồn", display(s.source_ref)],
                ["Phiên bản dữ liệu", display(s.generation)],
                ['Lỗi nguồn', display(s.error_code)],
              ]}
            />
            <Reasons values={s.reason_codes} />
          </details>
        ))}
      </div>
      <details>
        <summary>Giới hạn & trường còn thiếu</summary>
        <Reasons values={meta.missing_fields} />
        <ul>
          {meta.limitations.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      </details>
    </Panel>
  )
}
function Counts({ data }) {
  const m = data.event_members
  return (
    <div className="n91-wb-counts">
      <div>
        <span>Số bằng chứng P17 ghi nhận</span>
        <strong>{m.authoritative_count}</strong>
      </div>
      <div>
        <span>Ứng viên tái dựng</span>
        <strong>{display(m.total_candidates)}</strong>
      </div>
      <div>
        <span>Liên kết trực tiếp</span>
        <strong>{display(m.direct_membership_supported ? m.verified_linked_count : null)}</strong>
      </div>
      <div>
        <span>Khớp số lượng ghi nhận</span>
        <strong>{display(m.matches_recorded_count)}</strong>
      </div>
    </div>
  )
}
function EventCard({ member: e }) {
  const time = useTime(),
    p = e.projection,
    c = e.canonical
  return (
    <details className="n91-wb-event">
      <summary>
        <strong>{e.event_ref.event_id}</strong> · thứ tự {p.stream_sequence} ·{' '}
        {time(p.occurred_at)} · {uiLabel(e.join_state)}
      </summary>
      <p>
        <Badge value={p.blocked ? 'BLOCK' : 'ALLOW'} />{' '}
        <Badge value={e.canonical_availability} />{' '}
        <Badge value={uiLabel(e.join_state)} />
      </p>
      <FieldGrid
        rows={[
          ["Yêu cầu ", e.event_ref.request_id],
          ["Phát sinh ", time(p.occurred_at)],
          ["Tiếp nhận ", time(p.ingested_at)],
          ["Thứ tự", p.stream_sequence],
          ["Trạng thái đánh giá rủi ro", uiLabel(p.risk.status)],
          ["Điểm rủi ro", display(p.risk.score)],
          ["Sự kiện class", uiLabel(p.event_class)],
          ['Được nguồn phân loại để xử lý trực tiếp', display(p.live_eligible)],
          ['Đủ điều kiện tương quan', uiLabel('UNAVAILABLE')],
          ["Quy tắc khớp ", p.matched_rules.join(', ') || '—'],
        ]}
      />
      {c && (
        <details>
          <summary>Bản ghi kiểm toán chuẩn</summary>
          <FieldGrid
            rows={[
              ["Yêu cầu kiểm toán chuẩn", display(c.request_id)],
              ["Phát sinh kiểm toán chuẩn", time(c.occurred_at)],
              ["Quyết định xử lý", uiLabel(c.decision)],
              ["Hành động áp dụng", uiLabel(c.effective_action)],
              ["Kết quả xử lý", uiLabel(c.action_result)],
              ["Chính sách", `${c.policy_id} · ${c.policy_version}`],
              ['Chế độ vận hành', uiLabel(c.runtime_mode)],
              [
                "Trạng thái rủi ro / score",
                `${uiLabel(c.risk.status)} / ${display(c.risk.score)}`,
              ],
              ["Quy tắc khớp", c.matched_rules.join(', ') || '—'],
              ["Quy tắc chặn", c.blocking_rules.join(', ') || '—'],
              ["Quy tắc giám sát", c.monitor_rules.join(', ') || '—'],
            ]}
          />
        </details>
      )}
      <p className="n91-wb-links">
        <a href={eventHref(e.event_ref, 'p17')}>Mở sự kiện </a>
        {e.canonical_availability === 'AVAILABLE' && c && (
          <a href={eventHref(e.event_ref, 'canonical')}>Mở Nhật ký kiểm toán chuẩn</a>
        )}
      </p>
      <details>
        <summary>Liên kết, đối chiếu và mã băm</summary>
        <p>
          {uiLabel(e.candidate_basis)} · Căn cứ đối chiếu mã băm: {uiLabel(e.hash_comparability)}. Hai
          mã băm có căn cứ riêng; chưa đủ dữ liệu chứng minh nội dung giống nhau.
        </p>
        <FieldGrid
          rows={[
            ["Hash ", p.payload_sha256],
            ["Basis ", p.payload_hash_basis],
            ["Hash kiểm toán chuẩn", display(c?.payload_sha256)],
            ["Basis kiểm toán chuẩn", display(c?.payload_hash_basis)],
          ]}
        />
        <Reasons values={e.reason_codes} />
      </details>
    </details>
  )
}
function Members({ data, resource }) {
  const m = data.event_members
  return (
    <>
      <p>
        <Badge value={m.membership} /> <code>{uiLabel(m.candidate_basis)}</code>
      </p>
      <p>
        Sự kiện nghi vấn dựng lại từ cửa sổ lịch sử. Liên kết này chưa được xác minh trực tiếp; bản ghi kiểm toán không tự chứng minh liên kết với sự cố.
      </p>
      <nav className="n91-wb-pager" aria-label="Phân trang sự kiện nghi vấn">
        <button
          className="button secondary"
          disabled={!resource.history.length || resource.loading}
          onClick={resource.previous}
        >
          ← Trước
        </button>
        <span>
          Trang {resource.history.length + 1} · {m.items.length} sự kiện nghi vấn
        </span>
        <button
          className="button secondary"
          disabled={!m.has_more || resource.loading || Boolean(resource.error)}
          onClick={resource.next}
        >
          Tiếp →
        </button>
      </nav>
      {!m.available ? (
        <p role="status">Nguồn không cung cấp membership có thể dựng lại.</p>
      ) : !m.items.length ? (
        <p role="status">Không có sự kiện nghi vấn trong trang này.</p>
      ) : (
        m.items.map((e) => (
          <EventCard
            key={`${e.event_ref.stream_id}:${e.event_ref.event_id}`}
            member={e}
          />
        ))
      )}
    </>
  )
}
function Alerts({ alerts }) {
  const time = useTime()
  return (
    <section>
      <h3>Alerts cùng sự cố / luồng</h3>
      <p>
        Tổng nguồn: {display(alerts.total_count)} · {uiLabel(alerts.availability)}.
        Delivered không phải ACK/rà soát.
      </p>
      {!alerts.items.length ? (
        <p>Chưa có cảnh báo để hiển thị.</p>
      ) : (
        <ol className="n91-wb-alerts">
          {alerts.items.map((a) => (
            <li key={a.alert_id}>
              <strong>{a.alert_id}</strong>
              <p>
                <time>{time(a.created_at)}</time> · {a.signal_code} ·{' '}
                <Badge value={a.severity} />
              </p>
              <p>
                Trigger:{' '}
                <a href={eventHref(a.trigger_event, 'p17')}>
                  {a.trigger_event.event_id}
                </a>
              </p>
              <small>{a.link_basis}</small>
            </li>
          ))}
        </ol>
      )}
      {alerts.has_more && (
        <p>Danh sách cảnh báo bị giới hạn ở nguồn; chưa hiển thị toàn bộ.</p>
      )}
      <Reasons values={alerts.reason_codes} />
    </section>
  )
}
function Timeline({ data, resource }) {
  const time = useTime()
  return (
    <div className="n91-wb-lanes">
      <section className="n91-wb-lane">
        <h2>1 · Phát hiện</h2>
        <p>
          Thời gian phát sinh / tiếp nhận của từng sự kiện nghi vấn ở dưới; các
          nguồn giữ căn cứ thời gian riêng.
        </p>
        <Members data={data} resource={resource} />
        <Alerts alerts={data.alerts} />
      </section>
      <section className="n91-wb-lane">
        <h2>2 · Quyết định</h2>
        <p>
          Sự cố được tạo lúc {time(data.incident.created_at)} ·{' '}
          <Badge value={data.incident.status} />
        </p>
        <p>
          Nguồn đã xác minh: {display(data.incident.source_verified)} ·
          Được phép cách ly: {display(data.incident.isolation_authorized)}
        </p>
        <Unavailable title="Điều kiện xử lý" section={data.decision} />
      </section>
      <section className="n91-wb-lane">
        <h2>3 · Xử lý</h2>
        <ProcessingHistory section={data.response} />
      </section>
    </div>
  )
}
function Notes({ data, meta }) {
  const { sessionAuthEnabled } = usePortal()
  const overlay = data.analyst_case.overlay
  const context = meta.source_context === 'TEST' ? 'TEST' : 'HISTORICAL'
  if (sessionAuthEnabled && data.analyst_case.availability === 'AVAILABLE' &&
      overlay?.execution_mode === context)
    return <IncidentBusinessPanel id={data.identity.incident_id} streamId={data.identity.stream_id} />
  return (
    <Panel title="Ghi chú xử lý">
      <Badge value="UNAVAILABLE" />
      <p>{sessionAuthEnabled
        ? 'Chưa thể mở hồ sơ xử lý của sự cố này.'
        : 'Chế độ quan sát chỉ đọc. Hồ sơ xử lý cần phiên Portal.'}</p>
      <Reasons values={data.analyst_case.reason_codes} />
    </Panel>
  )
}
export function IncidentWorkbench({ id, streamId, params }) {
  const resource = useWorkbench({ incident_id: id, stream_id: streamId })
  return (
    <IncidentWorkbenchView
      id={id}
      streamId={streamId}
      params={params}
      resource={resource}
    />
  )
}
export function IncidentWorkbenchView({ id, streamId, params, resource }) {
  const portal = usePortal(),
    baseId = useId(),
    tabs = useRef([])
  const active = workbenchTab(params.wb_tab),
    payload = resource.payload
  const time = useTime()
  const select = (tab) => {
    const query = new URLSearchParams({ stream_id: streamId, wb_tab: tab })
    window.location.hash = `/incidents/${encodeURIComponent(id)}?${query}`
  }
  if (!canReadWorkbench(portal.auth, portal.sessionAuthEnabled))
    return (
      <WorkbenchGate
        id={id}
        message={
          portal.auth.status === 'checking'
            ? 'Đang kiểm tra phiên truy cập.'
            : "Điều tra sự cố cần quyền đọc bằng chứng. Viewer tiếp tục dùng trang sự cố cũ."
        }
      />
    )
  const denied = [401, 403].includes(resource.error?.status)
  return (
    <div className="n91-workbench" aria-busy={resource.loading}>
      <a className="incident-back" href="#/incidents">
        ← Sự cố
      </a>
      <PageHeading
        eyebrow={portal.sessionAuthEnabled ? 'ĐIỀU TRA' : 'ĐIỀU TRA · CHỈ ĐỌC'}
        title="Điều tra sự cố"
        description={id}
        resource={resource}
      >
        <CopyId value={id} />
      </PageHeading>
      <p className="n91-wb-identity">
        <strong>Stream:</strong> {streamId} · <strong>Incident:</strong> {id}
      </p>
      {resource.notice && (
        <div role="status" className="n91-wb-notice">
          {resource.notice}
        </div>
      )}
      {resource.error && (
        <div role="alert" className="n91-wb-notice">
          <strong>{resource.error.code}</strong>
          <p>{resource.error.message}</p>
          {payload && (
            <p>
              <Badge value="STALE" /> Đang giữ bản đọc thành công trước trong
              cùng phạm vi.
            </p>
          )}
          {denied && (
            <p>
              Dữ liệu điều tra đã được ẩn.{' '}
              <a href={incidentHref(id)}>Xem thông tin sự cố cơ bản</a>
            </p>
          )}
          {!payload && !denied && (
            <button className="button secondary" onClick={resource.first}>
              Về trang đầu
            </button>
          )}
        </div>
      )}
      {resource.loading && !payload && (
        <p role="status">Đang tải dữ liệu điều tra sự cố…</p>
      )}
      {payload && (
        <>
          <p className="n91-wb-meta">
            <Badge
              value={resource.error ? 'STALE' : payload.meta.freshness_state}
            />{' '}
            <Badge value="PARTIAL" /> Lịch sử · {uiLabel(payload.meta.source_context)}{' '}
            · đọc lúc {time(payload.meta.read_at)} · dữ liệu đến{' '}
            {time(payload.meta.data_as_of)}
          </p>
          <Panel title="Thông tin sự cố">
            <FieldGrid
              rows={[
                ["IP nguồn", payload.data.incident.source_ip],
                ["Tín hiệu ", payload.data.incident.signal_rule],
                ["Mức độ ", uiLabel(payload.data.incident.severity)],
                ["Độ tin cậy ", uiLabel(payload.data.incident.confidence)],
                ["Status ", uiLabel(payload.data.incident.status)],
                ["Điểm rủi ro cao nhất score", display(payload.data.incident.peak_p15)],
                [
                  "Nguồn đã xác minh",
                  display(payload.data.incident.source_verified),
                ],
                [
                  "Được phép cách ly",
                  display(payload.data.incident.isolation_authorized),
                ],
                ['Lần đầu', time(payload.data.incident.first_seen)],
                ['Lần cuối', time(payload.data.incident.last_seen)],
                ["tạo lúc", time(payload.data.incident.created_at)],
                ["cập nhật lúc", time(payload.data.incident.updated_at)],
              ]}
            />
            <p>
              Mức độ và điểm là hai đại lượng riêng. HIGH hoặc =100
              không tự cấp quyền cách ly. Cờ nguồn giữ đúng giá trị đã ghi
              nhận.
            </p>
          </Panel>
          <nav
            className="n91-wb-tabs"
            role="tablist"
            aria-label="Điều tra sự cố"
          >
            {WORKBENCH_TABS.map((tab, i) => (
              <button
                key={tab}
                ref={(node) => {
                  tabs.current[i] = node
                }}
                id={`${baseId}-${tab}`}
                role="tab"
                aria-selected={active === tab}
                aria-controls={`${baseId}-panel`}
                tabIndex={active === tab ? 0 : -1}
                onClick={() => select(tab)}
                onKeyDown={(event) => {
                  const next =
                    event.key === 'ArrowRight'
                      ? (i + 1) % 5
                      : event.key === 'ArrowLeft'
                        ? (i + 4) % 5
                        : event.key === 'Home'
                          ? 0
                          : event.key === 'End'
                            ? 4
                            : null
                  if (next !== null) {
                    event.preventDefault()
                    tabs.current[next]?.focus()
                    select(WORKBENCH_TABS[next])
                  }
                }}
              >
                {labels[tab]}
              </button>
            ))}
          </nav>
          <div
            role="tabpanel"
            tabIndex={0}
            id={`${baseId}-panel`}
            aria-labelledby={`${baseId}-${active}`}
          >
            {active === 'overview' && (
              <>
                <Counts data={payload.data} />
                <EvidenceExports
                  incidentId={payload.data.identity.incident_id}
                  streamId={payload.data.identity.stream_id}
                  sessionEnabled={portal.sessionAuthEnabled}
                  available={!resource.error && payload.meta.freshness_state !== 'STALE'}
                />
                <Sources meta={payload.meta} />
                <Panel title="Tình trạng dữ liệu xử lý">
                  <Unavailable title="Điều kiện xử lý" section={payload.data.decision} />
                  {payload.data.response.schema_version
                    ? <p>Bộ điều khiển · <Badge value={payload.data.response.availability} /></p>
                    : <Unavailable title="Bộ điều khiển" section={payload.data.response} />}
                </Panel>
                {payload.data.defense_registry && (
                  <Panel title="Kho bằng chứng">
                    <p>
                      {payload.data.defense_registry.run_id} ·{' '}
                      {payload.data.defense_registry.overall_status} ·{' '}
                      {payload.data.defense_registry.artifact_count} artifact ·{' '}
                      {payload.data.defense_registry.archive_count} archive.
                    </p>
                    <p>
                      Thông tin nguồn integrity chưa chứng minh semantic phạm vi dữ liệu. Chưa
                      đủ nguồn Kiểm chứng chức năng; cần CONTENT_REVIEW.
                    </p>
                    <Reasons
                      values={payload.data.defense_registry.reason_codes}
                    />
                  </Panel>
                )}
              </>
            )}
            {active === 'timeline' && (
              <>
                <Counts data={payload.data} />
                <Timeline data={payload.data} resource={resource} />
              </>
            )}
            {active === 'detection' && (
              <Panel title="Căn cứ phát hiện">
                <Unavailable
                  title="Cấu hình bộ phát hiện"
                  section={payload.data.detection}
                />
                <Counts data={payload.data} />
                <Members data={payload.data} resource={resource} />
              </Panel>
            )}
            {active === 'response' && (
              <Panel title="Xử lý và Security Group">
                <Unavailable
                  title="Quyết định"
                  section={payload.data.decision}
                />
                <ProcessingHistory section={payload.data.response} />
              </Panel>
            )}
            {active === 'notes' && (
              <Notes data={payload.data} meta={payload.meta} />
            )}
          </div>
        </>
      )}
    </div>
  )
}
