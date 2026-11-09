import React, { useEffect, useMemo, useState } from 'react'
import EvidenceMetadataPanel from '../../portal/EvidenceMetadataPanel'
import { usePortal } from '../../portal/PortalContext'
import { createEvaluationApi, filterCases } from './api.js'
import './evaluation.css'

const defaultApi = createEvaluationApi()
const show = value => value === null || value === undefined ? 'UNKNOWN' : String(value)
const tabs = [['evaluation','Evaluation'],['recoveries','Recovery'],['resilience','HA / Resilience'],['tls','TLS'],['privacy','Privacy'],['staging','Staging'],['p19','P19']]

function useRead(load, dependencies) {
  const [state, setState] = useState({ loading: true })
  const [generation, retry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setState({ loading: true })
    Promise.resolve().then(() => load(controller.signal)).then(response => {
      if (!controller.signal.aborted) setState({ ...response, loading: false })
    }).catch(error => { if (!controller.signal.aborted) setState({ error, loading: false }) })
    return () => controller.abort()
  }, [...dependencies, generation])
  return [state, () => retry(value => value + 1)]
}

function Resource({ state, retry, children }) {
  if (state.loading) return <p role="status">Đang đọc nguồn…</p>
  if (state.error) return <div role="alert"><p>UNAVAILABLE · {state.error.code || 'SOURCE_UNAVAILABLE'}</p><p>Chưa có quan sát dùng được trong phạm vi này.</p><button onClick={retry}>Thử lại</button></div>
  return <><p className="n91-source">HISTORICAL · Read UTC {state.meta?.read_at || 'UNKNOWN'} · {state.meta?.sources?.[0]?.source_ref || 'UNKNOWN'}</p>{children}</>
}

function Scope({ value }) {
  return <p className="n91-scope">Context <strong>{value.context}</strong> · Execution {value.execution_mode} · Freshness {value.freshness_state}<br />Run {value.run_id} · Source {value.source_system}<br />Observed UTC {value.observed_at} · Data as of {value.data_as_of}</p>
}

function Refs({ refs = [], onEvidence }) {
  return <div className="n91-refs">{refs.length ? refs.map(ref => <button key={ref} onClick={() => onEvidence(ref)}>{ref}</button>) : <span>Evidence: UNKNOWN</span>}</div>
}

export function EvaluationExplorer({ api = defaultApi, onEvidence }) {
  const [catalog, catalogRetry] = useRead(signal => api.catalog({ signal }), [api])
  const [runs, runsRetry] = useRead(signal => api.runs({ signal }), [api])
  const [selected, select] = useState('')
  const options = runs.data?.items || []
  const run = options.some(row => row.run_id === selected) ? selected : options[0]?.run_id || ''
  return <section><h2>Evaluation · expected và observed</h2><p>Catalog 60 case / 13 scenario là DESIGN_ONLY. Expected OLD và NOT_RUN giữ nguyên; kết quả kỹ thuật và human review được hiển thị riêng theo run.</p>
    <Resource state={catalog} retry={catalogRetry}>{catalog.data && <><p>DESIGN_ONLY · 60 case · 18 LIVE_READ_ONLY / 32 OFFLINE_POLICY / 3 PROTOCOL_OFFLINE / 7 P17_OFFLINE · 13 frozen scenarios</p><details><summary>Catalog đầy đủ · 60 expected case / 13 expected scenario</summary><div className="n91-cards">{catalog.data.cases.map(row => <article key={row.case_id}><h3>{row.case_id} · {row.catalog_flag}</h3><p>{row.scenario}</p><p>{row.partition} · {row.role} · Expected OLD {row.expected_old}</p><p>DESIGN_ONLY · Chưa suy ra observed/verdict từ catalog.</p></article>)}</div><h3>Expected correlation catalog</h3><div className="n91-cards">{catalog.data.correlations.map(row => <article key={row.scenario_id}><h4>{row.scenario_id} · {row.catalog_flag}</h4><p>{row.signal_rule} · Expected incident {show(row.expected_incident)} · Expected events {row.input_event_count}</p><p>DESIGN_ONLY · Chưa suy ra observed/verdict từ catalog.</p></article>)}</div></details></>}</Resource>
    <Resource state={runs} retry={runsRetry}><label>Evaluation run <select value={run} onChange={event => select(event.target.value)}><option value="">Chọn run</option>{options.map(row => <option key={row.run_id} value={row.run_id}>{row.run_id} · {row.status} · {row.review_state}</option>)}</select></label></Resource>
    {run && <RunExplorer key={run} api={api} run={run} catalog={catalog.data} onEvidence={onEvidence} />}
  </section>
}

function RunExplorer({ api, run, catalog, onEvidence }) {
  const [state, retry] = useRead(signal => api.evaluation(run, { signal }), [api, run])
  const [partition, setPartition] = useState('')
  const [mode, setMode] = useState('')
  const [verdict, setVerdict] = useState('')
  const rows = useMemo(() => filterCases(state.data?.cases || [], { partition, mode, verdict }), [state.data, partition, mode, verdict])
  return <Resource state={state} retry={retry}>{state.data && <><p>Run summary review: {state.data.run.review_state} · Observed {state.data.cases.length}/60 case records · {state.data.observed_correlations}/13 correlation observations. Case count không phải request count.</p>
    <div className="n91-filters">{[['Partition',partition,setPartition,['LIVE_READ_ONLY','OFFLINE_POLICY','PROTOCOL_OFFLINE','P17_OFFLINE']],['Execution mode',mode,setMode,['LIVE','ISOLATED','STAGING','HISTORICAL']],['Verdict',verdict,setVerdict,['PASS','FAIL','INCOMPLETE','NOT_EXECUTED','UNKNOWN','NA']]].map(([label,value,set,values]) => <label key={label}>{label}<select aria-label={label} value={value} onChange={event => set(event.target.value)}><option value="">Tất cả</option>{values.map(v => <option key={v}>{v}</option>)}</select></label>)}</div>
    {!rows.length && <p>Không có observation khớp bộ lọc; không suy PASS.</p>}
    <div className="n91-cards">{rows.map(row => <article key={row.case_id}><h3>{row.case_id} · {row.verdict}</h3><Scope value={row.scope} /><p>{row.partition} · Catalog NOT_RUN · Expected OLD {catalog?.cases.find(c => c.case_id === row.case_id)?.expected_old || 'UNKNOWN'} → Observed {show(row.observed_action)}</p><p>Review {row.label_status} · Request count {show(row.request_count)}</p><p>Request IDs: {row.request_refs.join(', ') || 'UNKNOWN'}</p><p>Event IDs: {row.event_refs.join(', ') || 'UNKNOWN'} · Incident IDs: {row.incident_refs.join(', ') || 'UNKNOWN'}</p><Refs refs={row.evidence_refs} onEvidence={onEvidence} /></article>)}</div>
    <h3>13 correlation scenarios · frozen isolated observations</h3><div className="n91-cards">{state.data.correlations.map(row => <article key={row.scenario_id}><h4>{row.scenario_id} · {row.verdict}</h4><Scope value={row.scope} /><p>Expected incident {show(catalog?.correlations.find(c => c.scenario_id === row.scenario_id)?.expected_incident)} · Observed incident {show(row.observed_incident)}</p><Refs refs={row.evidence_refs} onEvidence={onEvidence} /></article>)}</div></>}</Resource>
}

const labels = {
  backups: ['Backup artifacts', ['backup_id','source_node','backup_type','sha256','sha256_verified','size_bytes']],
  recoveries: ['G07 recovery · LAB', ['restore_run_id','target_name','observation_kind','verification_state','current_verification','mariadb_status','committed_marker_ids','restored_marker_ids','lost_marker_ids','lost_marker_count','rpo_gap_seconds','lab_rto_seconds','lab_rto_reason','unit','metric_semantics','production_measurement']],
  resilience: ['HA / Resilience', ['resilience_id','gate','scenario','expected_outcome','observed_outcome','verdict']],
  tls: ['TLS negotiated evidence', ['route_id','source','destination','negotiated_version','peer_verified','status','handshake_retry_limitation']],
  privacy: ['Privacy · bounded samples', ['privacy_id','coverage_kind','sample_count','masked_count','canary_count','leaked_count','unknown_family_count','verification']],
  staging: ['F01 / F02 staging', ['finding_id','staging_sha256','production_sha256','passed','total','production_status','production_cutover_verified']],
  p19: ['P19 · strict readiness', ['lab_scope_status','strict_ready','authority','owner_attestation','ack_disposition','exceptions']],
}

const fieldLabels = {rpo_gap_seconds:'Backup gap (LAB)',lab_rto_seconds:'Fault → verified query (LAB)',
  lost_marker_count:'Lost marker count',metric_semantics:'Metric scope',production_measurement:'Production measurement',
  lab_rto_reason:'Timing limitation',committed_marker_ids:'Committed markers',restored_marker_ids:'Restored markers',lost_marker_ids:'Lost markers'}
function fieldValue(row,field) {
  if (field==='metric_semantics') return 'LAB backup gap; fault → verified query. Production not measured.'
  if (field==='lab_rto_reason' && row[field]===null) return '—'
  if (Array.isArray(row[field])) return row[field].join(', ') || (row.marker_capture_complete===false ? 'UNKNOWN' : 'NONE_CAPTURED')
  return show(row[field])
}

export function SystemSourcePanel({ kind, api = defaultApi, onEvidence }) {
  const [state,retry] = useRead(signal => api.panel(kind,{signal}),[api,kind])
  const [title,fields] = labels[kind]
  return <section><h2>{title}</h2>{kind === 'recoveries' && <p>LAB backup gap và fault → verified query có đơn vị giây. Production RPO/RTO NOT_MEASURED. Current .54 và historical C1 .44 là quan sát riêng.</p>}{kind === 'p19' && <p>STRICT_READY: NO · Không có authority: UNKNOWN.</p>}{kind === 'tls' && <p>Handshake retry limitation: OPEN / UNKNOWN theo nguồn. UNAVAILABLE không có nghĩa unhealthy.</p>}{kind === 'staging' && <p>Staging regression không xác nhận production cutover. F01/F02 production còn OPEN / UNKNOWN.</p>}
    <Resource state={state} retry={retry}><div className="n91-cards">{state.data?.items.map((row,index) => <article key={index}><Scope value={row.scope} /><dl>{fields.map(field => <React.Fragment key={field}><dt>{fieldLabels[field] || field.replaceAll('_',' ')}</dt><dd>{fieldValue(row,field)}</dd></React.Fragment>)}</dl><Refs refs={row.evidence_refs} onEvidence={onEvidence} /></article>)}</div></Resource>
  </section>
}

function AuthenticatedTabs({ initialTab = 'evaluation', api = defaultApi }) {
  const [tab,setTab] = useState(tabs.some(([id]) => id===initialTab) ? initialTab : 'evaluation')
  const [evidenceId,setEvidence] = useState(null)
  return <div className="n91-evaluation"><nav aria-label="Evaluation and System panels">{tabs.map(([id,label]) => <button key={id} aria-pressed={tab===id} onClick={() => {setTab(id);setEvidence(null)}}>{label}</button>)}</nav>{tab==='evaluation' ? <EvaluationExplorer api={api} onEvidence={setEvidence} /> : <><SystemSourcePanel key={tab} kind={tab} api={api} onEvidence={setEvidence} />{tab==='recoveries' && <SystemSourcePanel kind="backups" api={api} onEvidence={setEvidence} />}</>}{evidenceId && <EvidenceMetadataPanel key={evidenceId} evidenceId={evidenceId} onClose={() => setEvidence(null)} />}</div>
}

export default function EvaluationSystemTabs(props) {
  const portal = usePortal()
  if (portal?.auth?.status !== 'authenticated') return <div className="n91-evaluation" role="status">SESSION_REQUIRED · Evaluation/System cần phiên đã xác thực.</div>
  const scope = `${portal.sessionVersion}:${portal.auth.status}:${portal.auth.user?.user_id}:${portal.auth.user?.role}`
  return <AuthenticatedTabs key={scope} {...props} />
}
