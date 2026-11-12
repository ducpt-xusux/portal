import { uiLabel, uiRoleList } from '../../services/uiLanguage.js'
import React, { useEffect, useMemo, useState } from 'react'
import EvidenceMetadataPanel from '../../portal/EvidenceMetadataPanel'
import { usePortal } from '../../portal/PortalContext'
import { createEvaluationApi, filterCases } from './api.js'
import './evaluation.css'

const defaultApi = createEvaluationApi()
const show = (value) =>
  value === null || value === undefined ? 'Chưa xác định' : typeof value === 'boolean' ? uiLabel(value) : String(value)
const tabs = [
  ['evaluation', "Đánh giá"],
  ['recoveries', "Khôi phục"],
  ['resilience', 'Tính sẵn sàng và khả năng phục hồi'],
  ['tls', 'TLS'],
  ['privacy', "Bảo vệ dữ liệu"],
  ['staging', "Kiểm thử"],
  ['p19', "Nghiệm thu"],
]

function useRead(load, dependencies) {
  const [state, setState] = useState({ loading: true })
  const [generation, retry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setState({ loading: true })
    Promise.resolve()
      .then(() => load(controller.signal))
      .then((response) => {
        if (!controller.signal.aborted)
          setState({ ...response, loading: false })
      })
      .catch((error) => {
        if (!controller.signal.aborted) setState({ error, loading: false })
      })
    return () => controller.abort()
  }, [...dependencies, generation])
  return [state, () => retry((value) => value + 1)]
}

function Resource({ state, retry, children }) {
  if (state.loading) return <p role="status">Đang đọc nguồn…</p>
  if (state.error)
    return (
      <div role="alert">
        <p>Chưa có dữ liệu · {state.error.code || 'SOURCE_UNAVAILABLE'}</p>
        <p>Chưa có quan sát dùng được trong phạm vi này.</p>
        <button onClick={retry}>Thử lại</button>
      </div>
    )
  return (
    <>
      <p className="n91-source">
        Lịch sử · Đọc lúc (UTC) {state.meta?.read_at || 'Chưa xác định'} ·{' '}
        {state.meta?.sources?.[0]?.source_ref || 'Chưa xác định'}
      </p>
      {children}
    </>
  )
}

function Scope({ value }) {
  return (
    <p className="n91-scope">
      Phạm vi dữ liệu <strong>{uiLabel(value.context)}</strong> · Thực hiện{' '}
      {uiLabel(value.execution_mode)} · Tình trạng cập nhật {uiLabel(value.freshness_state)}
      <br />
      Lần thực hiện {value.run_id} · Nguồn {uiLabel(value.source_system)}
      <br />
      Quan sát lúc (UTC) {value.observed_at} · Dữ liệu đến {value.data_as_of}
    </p>
  )
}

function Refs({ refs = [], onEvidence }) {
  return (
    <div className="n91-refs">
      {refs.length ? (
        refs.map((ref) => (
          <button key={ref} onClick={() => onEvidence(ref)}>
            {ref}
          </button>
        ))
      ) : (
        <span>Bằng chứng: Chưa xác định</span>
      )}
    </div>
  )
}

export function EvaluationExplorer({ api = defaultApi, onEvidence }) {
  const [catalog, catalogRetry] = useRead(
    (signal) => api.catalog({ signal }),
    [api]
  )
  const [runs, runsRetry] = useRead((signal) => api.runs({ signal }), [api])
  const [selected, select] = useState('')
  const options = runs.data?.items || []
  const run = options.some((row) => row.run_id === selected)
    ? selected
    : options[0]?.run_id || ''
  return (
    <section>
      <h2>Đánh giá · dự kiến và đã quan sát</h2>
      <p>
        Bộ kế hoạch gồm 60 ca kiểm thử và 13 kịch bản. Kết quả thực hiện và kết quả rà soát được theo dõi riêng.
      </p>
      <Resource state={catalog} retry={catalogRetry}>
        {catalog.data && (
          <>
            <p>
              Kế hoạch: 60 ca kiểm thử và 13 kịch bản; chưa có kết quả thực hiện.
            </p>
            <details>
              <summary>
                Danh mục 60 ca kiểm thử và 13 kịch bản dự kiến
              </summary>
              <div className="n91-cards">
                {catalog.data.cases.map((row) => (
                  <article key={row.case_id}>
                    <h3>
                      {row.case_id} · {uiLabel(row.catalog_flag)}
                    </h3>
                    <p>{row.scenario}</p>
                    <p>
                      {uiLabel(row.partition)} · {uiRoleList(row.role)} · Kết quả dự kiến{' '}
                      {row.expected_old}
                    </p>
                    <p>
                      Mới có kế hoạch, chưa có kết quả thực hiện.
                    </p>
                  </article>
                ))}
              </div>
              <h3>Kế hoạch kiểm thử tương quan</h3>
              <div className="n91-cards">
                {catalog.data.correlations.map((row) => (
                  <article key={row.scenario_id}>
                    <h4>
                      {row.scenario_id} · {uiLabel(row.catalog_flag)}
                    </h4>
                    <p>
                      {row.signal_rule} · Dự kiến sự cố{' '}
                      {show(row.expected_incident)} · Số sự kiện dự kiến{' '}
                      {row.input_event_count}
                    </p>
                    <p>
                      Mới có kế hoạch, chưa có kết quả thực hiện.
                    </p>
                  </article>
                ))}
              </div>
            </details>
          </>
        )}
      </Resource>
      <Resource state={runs} retry={runsRetry}>
        <label>
          Lần đánh giá{' '}
          <select value={run} onChange={(event) => select(event.target.value)}>
            <option value="">Chọn lần thực hiện</option>
            {options.map((row) => (
              <option key={row.run_id} value={row.run_id}>
                {row.run_id} · {uiLabel(row.status)} · {uiLabel(row.review_state)}
              </option>
            ))}
          </select>
        </label>
      </Resource>
      {run && (
        <RunExplorer
          key={run}
          api={api}
          run={run}
          catalog={catalog.data}
          onEvidence={onEvidence}
        />
      )}
    </section>
  )
}

function RunExplorer({ api, run, catalog, onEvidence }) {
  const [state, retry] = useRead(
    (signal) => api.evaluation(run, { signal }),
    [api, run]
  )
  const [partition, setPartition] = useState('')
  const [mode, setMode] = useState('')
  const [verdict, setVerdict] = useState('')
  const rows = useMemo(
    () => filterCases(state.data?.cases || [], { partition, mode, verdict }),
    [state.data, partition, mode, verdict]
  )
  return (
    <Resource state={state} retry={retry}>
      {state.data && (
        <>
          <p>
            Kết quả rà soát lần thực hiện: {uiLabel(state.data.run.review_state)} · Đã quan sát{' '}
            {state.data.cases.length}/60 bản ghi kiểm thử ·{' '}
            {state.data.observed_correlations}/13 kịch bản tương quan. Số ca kiểm thử khác số yêu cầu.
          </p>
          <div className="n91-filters">
            {[
              [
                'Nhóm kiểm thử',
                partition,
                setPartition,
                [
                  'LIVE_READ_ONLY',
                  'OFFLINE_POLICY',
                  'PROTOCOL_OFFLINE',
                  'P17_OFFLINE',
                ],
              ],
              [
                "Chế độ thực hiện",
                mode,
                setMode,
                ['LIVE', 'ISOLATED', 'STAGING', 'HISTORICAL'],
              ],
              [
                "Kết quả",
                verdict,
                setVerdict,
                ['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA'],
              ],
            ].map(([label, value, set, values]) => (
              <label key={label}>
                {label}
                <select
                  aria-label={label}
                  value={value}
                  onChange={(event) => set(event.target.value)}
                >
                  <option value="">Tất cả</option>
                  {values.map((v) => (
                    <option key={v} value={v}>{uiLabel(v)}</option>
                  ))}
                </select>
              </label>
            ))}
          </div>
          {!rows.length && (
            <p>Chưa có kết quả quan sát phù hợp bộ lọc.</p>
          )}
          <div className="n91-cards">
            {rows.map((row) => (
              <article key={row.case_id}>
                <h3>
                  {row.case_id} · {uiLabel(row.verdict)}
                </h3>
                <Scope value={row.scope} />
                <p>
                  {uiLabel(row.partition)} · Kế hoạch chưa chạy · Kết quả dự kiến{' '}
                  {catalog?.cases.find((c) => c.case_id === row.case_id)
                    ?.expected_old || 'Chưa xác định'}{' '}
                  → Đã quan sát {uiLabel(row.observed_action)}
                </p>
                <p>
                  Rà soát {uiLabel(row.label_status)} · Số yêu cầu{' '}
                  {show(row.request_count)}
                </p>
                <p>Mã yêu cầu: {row.request_refs.join(', ') || 'Chưa xác định'}</p>
                <p>
                  Mã sự kiện: {row.event_refs.join(', ') || 'Chưa xác định'} · Mã sự cố: {row.incident_refs.join(', ') || 'Chưa xác định'}
                </p>
                <Refs refs={row.evidence_refs} onEvidence={onEvidence} />
              </article>
            ))}
          </div>
          <h3>13 kịch bản tương quan · kết quả đã lưu từ môi trường riêng</h3>
          <div className="n91-cards">
            {state.data.correlations.map((row) => (
              <article key={row.scenario_id}>
                <h4>
                  {row.scenario_id} · {uiLabel(row.verdict)}
                </h4>
                <Scope value={row.scope} />
                <p>
                  Dự kiến sự cố{' '}
                  {show(
                    catalog?.correlations.find(
                      (c) => c.scenario_id === row.scenario_id
                    )?.expected_incident
                  )}{' '}
                  · Đã quan sát sự cố {show(row.observed_incident)}
                </p>
                <Refs refs={row.evidence_refs} onEvidence={onEvidence} />
              </article>
            ))}
          </div>
        </>
      )}
    </Resource>
  )
}

const labels = {
  backups: [
    'Backup artifacts',
    [
      'backup_id',
      'source_node',
      'backup_type',
      'sha256',
      'sha256_verified',
      'size_bytes',
    ],
  ],
  recoveries: [
    'Khôi phục dữ liệu · thử nghiệm',
    [
      'restore_run_id',
      'target_name',
      'observation_kind',
      'verification_state',
      'current_verification',
      'mariadb_status',
      'committed_marker_ids',
      'restored_marker_ids',
      'lost_marker_ids',
      'lost_marker_count',
      'rpo_gap_seconds',
      'lab_rto_seconds',
      'lab_rto_reason',
      'unit',
      'metric_semantics',
      'production_measurement',
    ],
  ],
  resilience: [
    'Tính sẵn sàng và khả năng phục hồi',
    [
      'resilience_id',
      'gate',
      'scenario',
      'expected_outcome',
      'observed_outcome',
      'verdict',
    ],
  ],
  tls: [
    'Bằng chứng kết nối TLS',
    [
      'route_id',
      'source',
      'destination',
      'negotiated_version',
      'peer_verified',
      'status',
      'handshake_retry_limitation',
    ],
  ],
  privacy: [
    'Bảo vệ dữ liệu · phạm vi mẫu đã đọc',
    [
      'privacy_id',
      'coverage_kind',
      'sample_count',
      'masked_count',
      'canary_count',
      'leaked_count',
      'unknown_family_count',
      'verification',
    ],
  ],
  staging: [
    'Kiểm thử giao thức',
    [
      'finding_id',
      'staging_sha256',
      'production_sha256',
      'passed',
      'total',
      'production_status',
      'production_cutover_verified',
    ],
  ],
  p19: [
    'Điều kiện nghiệm thu',
    [
      'lab_scope_status',
      'strict_ready',
      'authority',
      'owner_attestation',
      'ack_disposition',
      'exceptions',
    ],
  ],
}

const fieldLabels = {
  rpo_gap_seconds: 'Backup gap (LAB)',
  lab_rto_seconds: "Fault → verified truy vấn (LAB)",
  lost_marker_count: 'Lost marker count',
  metric_semantics: "Chỉ số scope",
  production_measurement: 'Production measurement',
  lab_rto_reason: 'Timing limitation',
  committed_marker_ids: 'Committed markers',
  restored_marker_ids: 'Restored markers',
  lost_marker_ids: 'Lost markers',
}
function fieldValue(row, field) {
  if (field === 'metric_semantics')
    return 'Đo khoảng cách sao lưu và thời gian từ sự cố đến truy vấn được xác minh trong môi trường thử nghiệm; chưa đo ở môi trường vận hành.'
  if (field === 'lab_rto_reason' && row[field] === null) return '—'
  if (Array.isArray(row[field]))
    return (
      row[field].join(', ') ||
      (row.marker_capture_complete === false ? 'UNKNOWN' : 'Chưa ghi nhận mốc dữ liệu')
    )
  return ['status', 'verification_state', 'current_verification', 'production_measurement', 'lab_scope_status', 'strict_ready', 'authority', 'gate', 'verdict', 'observation_kind'].includes(field) ? uiLabel(row[field]) : show(row[field])
}

export function SystemSourcePanel({ kind, api = defaultApi, onEvidence }) {
  const [state, retry] = useRead(
    (signal) => api.panel(kind, { signal }),
    [api, kind]
  )
  const [title, fields] = labels[kind]
  return (
    <section>
      <h2>{uiLabel(title)}</h2>
      {kind === 'recoveries' && (
        <p>
          Các khoảng thời gian được đo bằng giây trong môi trường thử nghiệm. Chưa có số đo RPO/RTO của môi trường vận hành; quan sát hiện tại và lịch sử được theo dõi riêng.
        </p>
      )}
      {kind === 'p19' && <p>Chưa xác nhận đủ điều kiện nghiệm thu.</p>}
      {kind === 'tls' && (
        <p>
          Giới hạn thử lại kết nối TLS giữ theo nguồn. Thiếu dữ liệu không đồng nghĩa dịch vụ ngừng hoạt động.
        </p>
      )}
      {kind === 'staging' && (
        <p>
          Kết quả môi trường kiểm thử chưa xác nhận việc chuyển sang vận hành chính thức.
        </p>
      )}
      <Resource state={state} retry={retry}>
        <div className="n91-cards">
          {state.data?.items.map((row, index) => (
            <article key={index}>
              <Scope value={row.scope} />
              <dl>
                {fields.map((field) => (
                  <React.Fragment key={field}>
                    <dt>{uiLabel(fieldLabels[field] || field)}</dt>
                    <dd>{fieldValue(row, field)}</dd>
                  </React.Fragment>
                ))}
              </dl>
              <Refs refs={row.evidence_refs} onEvidence={onEvidence} />
            </article>
          ))}
        </div>
      </Resource>
    </section>
  )
}

function AuthenticatedTabs({ initialTab = 'evaluation', api = defaultApi }) {
  const [tab, setTab] = useState(
    tabs.some(([id]) => id === initialTab) ? initialTab : 'evaluation'
  )
  const [evidenceId, setEvidence] = useState(null)
  return (
    <div className="n91-evaluation">
      <nav aria-label="Đánh giá và trạng thái hệ thống">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            aria-pressed={tab === id}
            onClick={() => {
              setTab(id)
              setEvidence(null)
            }}
          >
            {uiLabel(label)}
          </button>
        ))}
      </nav>
      {tab === 'evaluation' ? (
        <EvaluationExplorer api={api} onEvidence={setEvidence} />
      ) : (
        <>
          <SystemSourcePanel
            key={tab}
            kind={tab}
            api={api}
            onEvidence={setEvidence}
          />
          {tab === 'recoveries' && (
            <SystemSourcePanel
              kind="backups"
              api={api}
              onEvidence={setEvidence}
            />
          )}
        </>
      )}
      {evidenceId && (
        <EvidenceMetadataPanel
          key={evidenceId}
          evidenceId={evidenceId}
          onClose={() => setEvidence(null)}
        />
      )}
    </div>
  )
}

export default function EvaluationSystemTabs(props) {
  const portal = usePortal()
  if (portal?.auth?.status !== 'authenticated')
    return (
      <div className="n91-evaluation" role="status">
        SESSION_REQUIRED · Đánh giá/System cần phiên đã xác thực.
      </div>
    )
  const scope = `${portal.sessionVersion}:${portal.auth.status}:${portal.auth.user?.user_id}:${portal.auth.user?.role}`
  return <AuthenticatedTabs key={scope} {...props} />
}
