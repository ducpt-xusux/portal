import { uiLabel, uiRoleList } from '../../services/uiLanguage.js'
import { useEffect, useId, useState } from 'react'
import { investigationApi } from './investigationApi.js'
import {
  canonicalLink,
  compareEvents,
  eventModel,
  lifecycleState,
  metricValue,
  policyDrift,
  TABS,
  traceModel,
} from './investigationModel.js'
import './investigation.css'

const show = (value) =>
  value === null || value === undefined || value === ''
    ? 'UNAVAILABLE'
    : typeof value === 'boolean'
      ? String(value)
      : value
function Fields({ rows }) {
  return (
    <dl className="n91-fields">
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{uiLabel(label)}</dt>
          <dd>{show(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
function Notice({ children }) {
  return (
    <p className="n91-notice" role="status">
      {children}
    </p>
  )
}
function Provenance({ source }) {
  return (
    <Fields
      rows={Object.entries(source || {})
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [
          k,
          typeof v === 'object' && v !== null ? "Xem thông tin bằng chứng" : v,
        ])}
    />
  )
}
function useResource(loader, keys) {
  const [state, setState] = useState({
    loading: true,
    data: null,
    error: null,
    meta: null,
  })
  const [revision, retry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setState({ loading: true, data: null, error: null, meta: null })
    Promise.resolve()
      .then(() => loader(controller.signal))
      .then((result) => {
        if (!controller.signal.aborted)
          setState({
            loading: false,
            data: result.data,
            error: null,
            meta: result.meta,
          })
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setState({
            loading: false,
            data: null,
            error: error?.code || 'SOURCE_UNAVAILABLE',
            meta: null,
          })
      })
    return () => controller.abort()
  }, [...keys, revision]) // All caller identity/API dependencies are explicit.
  return { ...state, retry: () => retry((n) => n + 1) }
}
function Resource({ resource }) {
  return resource.loading ? (
    <Notice>Đang tải</Notice>
  ) : resource.error ? (
    <Notice>
      Chưa có dữ liệu · {resource.error}{' '}
      <button type="button" onClick={resource.retry}>
        Đọc lại
      </button>
    </Notice>
  ) : resource.meta ? (
    <p className="n91-caption">
      {uiLabel(resource.meta.freshness_state)} · Thông tin theo phạm vi nguồn đã đọc · yêu cầu{' '}
      {resource.meta.request_id}
    </p>
  ) : null
}

export function SevenStageTrace({ trace }) {
  let stages
  try {
    stages = traceModel(trace)
  } catch {
    return <Notice>Chưa có dữ liệu · TRACE_STAGE_INVALID</Notice>
  }
  return (
    <div className="n91-investigation">
      <ol className="n91-trace">
        {stages.map((stage, index) => (
          <li key={uiLabel(stage.stage)}>
            <div>
              <strong>
                {index + 1}. {uiLabel(stage.stage)}
              </strong>
              <span className="n91-state">{uiLabel(stage.status)}</span>
            </div>
            <p>{show(stage.outcome)}</p>
            <small>
              {show(stage.source_ref)} · {show(stage.verification)}
            </small>
            {stage.reason_codes.length > 0 && (
              <p>{stage.reason_codes.map(uiLabel).join(' · ')}</p>
            )}
            {stage.facts.length > 0 && (
              <details>
                <summary>Dữ liệu từ nguồn</summary>
                <Fields
                  rows={stage.facts.map((f) => [
                    f.name,
                    f.status === 'PRESENT' || f.status === 'RECONSTRUCTED'
                      ? show(f.value_summary)
                      : f.status,
                  ])}
                />
              </details>
            )}
          </li>
        ))}
      </ol>
      {trace?.limitations?.map((line, i) => (
        <p className="n91-caption" key={i}>
          {line}
        </p>
      ))}
    </div>
  )
}

export function EventDetailSixTabs({
  event: raw,
  trace = null,
  traceResource = null,
  api = investigationApi,
}) {
  const [tab, setTab] = useState('Overview'),
    uid = useId()
  let event
  try {
    event = eventModel(raw)
  } catch {
    return <Notice>Chưa có dữ liệu · CANONICAL_STREAM_EVENT_REQUIRED</Notice>
  }
  const stage = (() => {
    try {
      return traceModel(trace)[0]
    } catch {
      return null
    }
  })()
  const context = event.source_provenance.context || 'HISTORICAL'
  return (
    <section className="n91-investigation" aria-label="Điều tra sự kiện">
      <Notice>
        {context} · {event.stream_id} / {event.event_id} ·{' '}
        {event.source_provenance.verification || 'UNAVAILABLE'}
      </Notice>
      <div role="tablist" aria-label="Chi tiết sự kiện" className="n91-tabs">
        {TABS.map((name, index) => (
          <button
            key={name}
            type="button"
            role="tab"
            id={`${uid}-${name}`}
            aria-controls={`${uid}-panel`}
            aria-selected={tab === name}
            tabIndex={tab === name ? 0 : -1}
            onClick={() => setTab(name)}
            onKeyDown={(e) => {
              const next =
                e.key === 'ArrowRight'
                  ? (index + 1) % TABS.length
                  : e.key === 'ArrowLeft'
                    ? (index + TABS.length - 1) % TABS.length
                    : e.key === 'Home'
                      ? 0
                      : e.key === 'End'
                        ? TABS.length - 1
                        : null
              if (next !== null) {
                e.preventDefault()
                setTab(TABS[next])
                e.currentTarget.parentElement.children[next].focus()
              }
            }}
          >
            {uiLabel(name)}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`${uid}-panel`}
        aria-labelledby={`${uid}-${tab}`}
        tabIndex={0}
      >
        {tab === 'Overview' && (
          <>
            <Fields
              rows={[
                ["Quyết định · ", uiLabel(event.decision)],
                ["Hành động áp dụng", uiLabel(event.effective_action)],
                ["Kết quả xử lý", uiLabel(event.action_result)],
                ["Chế độ vận hành", uiLabel(event.runtime_mode)],
                ["Sẽ chặn", event.would_block],
                ["Căn cứ quyết định", event.decision_basis],
                ["IP nguồn", event.source_ip],
                ["Tài khoản cơ sở dữ liệu", event.db_user],
                ["Cơ sở dữ liệu", event.database_name],
                ["Lệnh MySQL", event.mysql_command],
                ["Phát sinh lúc (UTC)", event.occurred_at],
                ["Tiếp nhận lúc (UTC)", event.request_received_at],
                ["Ghi vào kho lúc (UTC)", event.storage_recorded_at],
                ["Nhập vào Portal lúc (UTC)", event.imported_at],
              ]}
            />
            <p className="n91-caption">
              decision khác Kết quả chặn được ghi nhận. Risk không cấp quyền
              cách ly.
            </p>
            <h3>SQL · {event.sql_text_status}</h3>
            <pre>{event.masked_query || 'WITHHELD'}</pre>
            <Fields rows={Object.entries(event.time_basis)} />
          </>
        )}
        {tab === 'Parser' && (
          <>
            <Notice>
              {stage?.status || 'UNAVAILABLE'} · Parser chỉ có dữ liệu do nguồn
              xuất; không tính AST từ SQL.
            </Notice>
            {stage?.facts?.length > 0 ? (
              <Fields
                rows={stage.facts.map((f) => [
                  f.name,
                  f.status === 'PRESENT' ? f.value_summary : f.status,
                ])}
              />
            ) : (
              <p>
                parse_ok / analysis_complete / statement_types / tables /
                columns: chưa có dữ liệu
              </p>
            )}
          </>
        )}
        {tab === 'Rules' && (
          <>
            <Fields
              rows={[
                ["Phiên bản chính sách", event.policy_version],
                ["Khớp", event.matched_rules.join(' · ') || null],
                ["Chặn", event.blocking_rules.join(' · ') || null],
                ["Giám sát", event.monitor_rules.join(' · ') || null],
              ]}
            />
            <p>Monitor match không tự chứng minh BLOCK.</p>
            {event.blocking_rules.includes('CTX-006') && (
              <Notice>CTX-006 · Phạm vi dữ liệu deny. Không tự gắn nhãn SQLi.</Notice>
            )}
            <ul>
              {event.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
            <RulesExplorer api={api} event={event} compact />
          </>
        )}
        {tab === 'Risk' && (
          <>
            <Fields
              rows={[
                ["Trạng thái rủi ro", uiLabel(event.risk.status)],
                ["Điểm từ nguồn", event.risk.score],
                ["Mức độ ", uiLabel(event.risk.severity)],
                ["Điểm gốc", event.raw_score],
                [
                  'explanation_available',
                  Boolean(event.score_breakdown?.length),
                ],
              ]}
            />
            {event.score_breakdown?.length ? (
              <div className="n91-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Quy tắc / Nguồn</th>
                      <th>Điểm</th>
                      <th>Lý do</th>
                    </tr>
                  </thead>
                  <tbody>
                    {event.score_breakdown.map((c, i) => (
                      <tr key={i}>
                        <td>{c.rule_id || c.source}</td>
                        <td>{show(c.score)}</td>
                        <td>{show(c.reason)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Notice>
                Chi tiết điểm Chưa có dữ liệu · không tính lại điểm hoặc áp ngưỡng risk.
              </Notice>
            )}
          </>
        )}
        {tab === 'Trace' && (
          <>
            {traceResource && <Resource resource={traceResource} />}
            <SevenStageTrace trace={trace} />
          </>
        )}
        {tab === 'Evidence' && (
          <>
            <Fields
              rows={[
                ["Mã luồng", event.stream_id],
                ["Mã sự kiện", event.event_id],
                ["Mã yêu cầu", event.request_id],
                [
                  'Incident membership',
                  "Chưa có dữ liệu · không JOIN theo IP/time",
                ],
              ]}
            />
            <Provenance source={event.source_provenance} />
            <p>
              Mã băm chỉ xác nhận tính toàn vẹn của nội dung.
            </p>
          </>
        )}
      </div>
    </section>
  )
}

export function EventInvestigation({
  eventId,
  streamId,
  api = investigationApi,
}) {
  const resource = useResource(
    (signal) => api.event(eventId, streamId, { signal }),
    [api, eventId, streamId]
  )
  const trace = useResource(
    (signal) => api.trace(eventId, streamId, { signal }),
    [api, eventId, streamId]
  )
  return (
    <div className="n91-investigation">
      <Resource resource={resource} />
      {resource.data && (
        <EventDetailSixTabs
          key={`${streamId}:${eventId}`}
          event={resource.data}
          trace={trace.data}
          traceResource={trace}
          api={api}
        />
      )}
    </div>
  )
}

export function EventCompare({ left, right }) {
  let comparison
  try {
    comparison = compareEvents(left, right)
  } catch {
    return <Notice>Chưa có dữ liệu · Chọn hai kiểm toán chuẩn luồng/sự kiện IDs.</Notice>
  }
  const fields = [
    ['Nguồn IP', (e) => e.source_ip],
    ["Tài khoản cơ sở dữ liệu", (e) => e.db_user],
    ["Chính sách decision", (e) => e.decision],
    ["Hành động áp dụng", (e) => e.effective_action],
    ["Trạng thái rủi ro", (e) => e.risk.status],
    ['Risk score', (e) => e.risk.score],
    ["mức độ", (e) => e.risk.severity],
    ["Phiên bản chính sách", (e) => e.policy_version],
    ["Chặn", (e) => e.blocking_rules.join(' · ')],
    ["Giám sát", (e) => e.monitor_rules.join(' · ')],
  ]
  return (
    <section className="n91-investigation" aria-label="APP Clone compare">
      <h3>APP / Clone · ID-based compare</h3>
      {comparison.same_identity && (
        <Notice>
          SAME_STREAM_EVENT · hai lựa chọn đang là cùng một sự kiện.
        </Notice>
      )}
      <div className="n91-scroll">
        <table>
          <thead>
            <tr>
              <th>Nguồn fact</th>
              <th>
                APP selection{' '}
                <a href={canonicalLink(comparison.left)}>
                  {comparison.left.stream_id} / {comparison.left.event_id}
                </a>
              </th>
              <th>
                Clone selection{' '}
                <a href={canonicalLink(comparison.right)}>
                  {comparison.right.stream_id} / {comparison.right.event_id}
                </a>
              </th>
            </tr>
          </thead>
          <tbody>
            {fields.map(([label, read]) => (
              <tr key={label}>
                <th>{label}</th>
                <td>{show(read(comparison.left))}</td>
                <td>{show(read(comparison.right))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {comparison.context_denial && <Notice>CTX-006 · Phạm vi dữ liệu deny</Notice>}
      {comparison.limitations.map((line) => (
        <p className="n91-caption" key={line}>
          {line}
        </p>
      ))}
    </section>
  )
}

export function EventComparePicker({ api = investigationApi }) {
  const [selection, setSelection] = useState(null),
    [draft, setDraft] = useState({
      leftStream: '',
      leftEvent: '',
      rightStream: '',
      rightEvent: '',
    })
  return (
    <section className="n91-investigation">
      <form
        className="n91-form"
        onSubmit={(e) => {
          e.preventDefault()
          setSelection({ ...draft })
        }}
      >
        {Object.keys(draft).map((name) => (
          <label key={name}>
            {name}
            <input
              required
              maxLength={160}
              pattern="[A-Za-z0-9][A-Za-z0-9_.:\-]*"
              value={draft[name]}
              onChange={(e) => setDraft({ ...draft, [name]: e.target.value })}
            />
          </label>
        ))}
        <button>Compare IDs</button>
      </form>
      {selection && (
        <LoadedCompare
          key={JSON.stringify(selection)}
          selection={selection}
          api={api}
        />
      )}
    </section>
  )
}
function LoadedCompare({ selection: s, api }) {
  const left = useResource(
    (signal) => api.event(s.leftEvent, s.leftStream, { signal }),
    [api, s.leftEvent, s.leftStream]
  )
  const right = useResource(
    (signal) => api.event(s.rightEvent, s.rightStream, { signal }),
    [api, s.rightEvent, s.rightStream]
  )
  const matches =
    left.data?.stream_id === s.leftStream &&
    left.data?.event_id === s.leftEvent &&
    right.data?.stream_id === s.rightStream &&
    right.data?.event_id === s.rightEvent
  return (
    <>
      <Resource resource={left} />
      <Resource resource={right} />
      {left.data &&
        right.data &&
        (matches ? (
          <EventCompare left={left.data} right={right.data} />
        ) : (
          <Notice>Chưa có dữ liệu · CANONICAL_IDENTITY_MISMATCH</Notice>
        ))}
    </>
  )
}

export function RulesExplorer({
  api = investigationApi,
  event = null,
  compact = false,
}) {
  const resource = useResource((signal) => api.policies({ signal }), [api])
  const [ruleId, select] = useState(null),
    [filter, setFilter] = useState('')
  const catalog = resource.data
  const mismatch =
    catalog &&
    policyDrift(
      { policy_version: catalog.policy_version, policy_sha256: catalog.sha256 },
      event
    )
  const rows =
    Array.isArray(catalog?.rules) && !mismatch
      ? catalog.rules.filter(
          (r) =>
            (!compact || event?.matched_rules.includes(r.rule_id)) &&
            `${r.rule_id} ${r.category}`
              .toLowerCase()
              .includes(filter.toLowerCase())
        )
      : []
  return (
    <section className="n91-investigation">
      <h3>Quy tắc Explorer · pinned bản chụp</h3>
      <Resource resource={resource} />
      {mismatch && (
        <Notice>
          CURRENT_VERSION_MISMATCH · Sự kiện {event.policy_version} / catalog{' '}
          {catalog.policy_version}. Không thay quy tắc bản chụp của sự kiện bằng quy tắc
          hiện tại.
        </Notice>
      )}
      {catalog && (
        <>
          <Fields
            rows={[
              ["Phiên bản chính sách", catalog.policy_version],
              ['Bytes SHA256', catalog.sha256],
              ['Captured UTC', catalog.captured_at],
              ['Rule count · catalog', catalog.rules.length],
            ]}
          />
          <label>
            Quy tắc / nhóm{' '}
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              maxLength={160}
            />
          </label>
          <div className="n91-scroll">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Nhóm</th>
                  <th>Tác dụng</th>
                  <th>Nguồn</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td>
                      <button
                        type="button"
                        onClick={() => select(rule.rule_id)}
                      >
                        {rule.rule_id}
                      </button>
                    </td>
                    <td>{rule.category}</td>
                    <td>{rule.effect}</td>
                    <td>{rule.source_ref}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length === 0 && (
            <Notice>EMPTY · Không có quy tắc trong bộ lọc.</Notice>
          )}
        </>
      )}
      {ruleId && (
        <RuleDetail key={ruleId} ruleId={ruleId} api={api} event={event} />
      )}
    </section>
  )
}
function RuleDetail({ ruleId, api, event }) {
  const resource = useResource(
    (signal) => api.rule(ruleId, { signal }),
    [api, ruleId]
  )
  const rule = resource.data
  if (policyDrift(rule, event)) return <Notice>CURRENT_VERSION_MISMATCH</Notice>
  return (
    <article>
      <Resource resource={resource} />
      {rule && (
        <>
          <h4>
            {rule.rule_id} · {rule.mode}/{rule.action}
          </h4>
          <Fields
            rows={[
              ["Nhóm", rule.category],
              ['Priority', uiLabel(rule.priority)],
              ['Enabled', rule.enabled],
              ['Description', rule.description],
              ["Phiên bản chính sách", rule.policy_version],
              ["Chính sách SHA256", rule.policy_sha256],
              ["Nguồn", rule.source_ref],
            ]}
          />
          {['all_conditions', 'any_conditions'].map((key) => (
            <div key={key}>
              <h4>{key}</h4>
              {rule[key]?.length ? (
                <Fields
                  rows={rule[key].map((c, i) => [
                    `${i + 1}. ${c.path} ${c.op}`,
                    c.value_redacted,
                  ])}
                />
              ) : (
                <p>No conditions in nguồn bản chụp.</p>
              )}
            </div>
          ))}
          <p className="n91-caption">
            Immutable catalog; predicates không chạy trên SQL gốc tại Portal.
          </p>
        </>
      )}
    </article>
  )
}

export function IncidentTimeline({ timeline }) {
  return (
    <section className="n91-investigation">
      <Fields
        rows={[
          ["sự cố status", timeline?.incident_status],
          ["Hiện tại response state", timeline?.response_state || 'UNKNOWN'],
        ]}
      />
      <ol className="n91-trace">
        {timeline?.items?.map((item) => (
          <li key={item.item_id}>
            <strong>{item.type}</strong>
            <time>{show(item.occurred_at)}</time>
            <p>{item.description}</p>
            <small>
              {item.source_ref} · {uiLabel(item.verification)}
            </small>
          </li>
        ))}
      </ol>
      {timeline?.limitations?.map((line, i) => (
        <p className="n91-caption" key={i}>
          {line}
        </p>
      ))}
    </section>
  )
}

export function SgLifecycle({ data }) {
  const [now, tick] = useState(Date.now())
  useEffect(() => {
    const timer = setInterval(() => tick(Date.now()), 5000)
    return () => clearInterval(timer)
  }, [])
  const current = lifecycleState(data, now)
  return (
    <section className="n91-investigation">
      <h3>SG BEFORE / DURING / AFTER / hiện tại</h3>
      <Notice>
        {data?.source?.execution_mode || 'UNAVAILABLE'} · Lịch sử Controller
        bằng chứng khác hiện tại Neutron read-back.
      </Notice>
      <div className="n91-sg-grid">
        {['BEFORE', 'DURING', 'AFTER'].map((phase) => {
          const snapshot = data?.history?.[phase]
          return (
            <article key={phase}>
              <h4>{uiLabel(phase)} · Lịch sử</h4>
              {snapshot ? (
                <>
                  <GroupList groups={snapshot.security_group_ids} />
                  <small>{snapshot.observed_at}</small>
                  <code>{snapshot.source_ref}</code>
                </>
              ) : (
                <p>Chưa có dữ liệu · giai đoạn not đã quan sát</p>
              )}
            </article>
          )
        })}
        <article>
          <h4>CURRENT · {uiLabel(current.state)}</h4>
          {current.reason ? (
            <p>{current.reason}</p>
          ) : (
            <>
              <GroupList groups={data.current.security_group_ids} />
              <small>{data.current.observed_at}</small>
              <code>{data.current.source.source_ref}</code>
            </>
          )}
        </article>
      </div>
      <Fields
        rows={[
          ['Incident', data?.incident_id],
          ['Cycle', data?.cycle_id],
          ["Lịch sử hành động state", data?.action?.action_state],
        ]}
      />
      <h4>Duration semantics · seconds</h4>
      <Fields
        rows={(data?.metrics || []).map((m) => [m.metric, metricValue(m)])}
      />
      <details>
        <summary>Timestamp, đồng hồ và căn cứ thời gian</summary>
        <Fields
          rows={[
            ['containment.quarantined_at_utc', data?.action?.started_at],
            ['containment.restored_at_utc', data?.action?.finished_at],
          ]}
        />
        {data?.clock_marks?.map((mark, i) => (
          <p key={i}>
            <strong>{uiLabel(mark.kind)}</strong> · {mark.timestamp} · {mark.clock_id} ·{' '}
            {mark.time_basis} · {mark.source_ref}
          </p>
        ))}
      </details>
      {data?.arm_context?.length > 0 && (
        <details>
          <summary>ARM context · không direct Incident bằng chứng</summary>
          {data.arm_context.map((r, i) => (
            <p key={i}>
              {uiLabel(r.kind)} · {r.timestamp} · {r.link_quality}
            </p>
          ))}
        </details>
      )}
      {data?.limitations?.map((line, i) => (
        <p className="n91-caption" key={i}>
          {line}
        </p>
      ))}
    </section>
  )
}
function GroupList({ groups }) {
  return !Array.isArray(groups) ? (
    <p>Chưa có dữ liệu</p>
  ) : groups.length ? (
    <ul>
      {groups.map((id) => (
        <li key={id}>
          <code>{id}</code>
        </li>
      ))}
    </ul>
  ) : (
    <p>Đã quan sát empty SG set</p>
  )
}
export function LoadedSgLifecycle({ actionId, api = investigationApi }) {
  const resource = useResource(
    (signal) => api.lifecycle(actionId, { signal }),
    [api, actionId]
  )
  return (
    <>
      <Resource resource={resource} />
      {resource.data && <SgLifecycle data={resource.data} />}
    </>
  )
}
export function IncidentInvestigation({ incidentId, api = investigationApi }) {
  const trace = useResource(
    (signal) => api.incidentTrace(incidentId, { signal }),
    [api, incidentId]
  )
  const timeline = useResource(
    (signal) => api.timeline(incidentId, { signal }),
    [api, incidentId]
  )
  return (
    <section className="n91-investigation">
      <h3>Luồng xử lý</h3>
      <Resource resource={trace} />
      <SevenStageTrace trace={trace.data} />
      <h3>Incident / hành động timeline</h3>
      <Resource resource={timeline} />
      {timeline.data && <IncidentTimeline timeline={timeline.data} />}
    </section>
  )
}
