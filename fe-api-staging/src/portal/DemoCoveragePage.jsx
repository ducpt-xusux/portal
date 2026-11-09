import { useEffect, useState } from 'react'
import { useV4Resource } from './IncidentPages'
import { demoBookmark, demoFilters, expectedScenes, readCoverage, sceneRoute } from '../services/demoCoverageApi'
import EvidenceMetadataPanel from './EvidenceMetadataPanel'
import './demoCoverage.css'

export default function DemoCoveragePage() {
  const resource = useV4Resource('/system/demo-coverage', { interval: 0, transform: readCoverage })
  const [filters, setFilters] = useState(() => demoFilters(window.location.hash))
  const [evidenceId, setEvidenceId] = useState(null)
  useEffect(() => {
    const change = () => { setFilters(demoFilters(window.location.hash)); setEvidenceId(null) }
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  // A failed refresh must not leave previous observations presented as usable results.
  const data = resource.error ? null : resource.data
  const run = data?.runs.find(item => item.run_id === filters.run) || (!filters.run ? data?.runs[0] : null)
  const selected = data && run ? data.items.filter(item => item.run_id === run.run_id) : expectedScenes
  const rows = selected.filter(item => (!filters.mode || item.execution_modes.includes(filters.mode)) && (!filters.verdict || item.verdict === filters.verdict))
  const observedCount = selected.filter(item => item.basis === 'IMPORTED_OBSERVATION').length
  const state = resource.loading ? 'LOADING' : resource.error ? 'UNAVAILABLE' : !run ? 'UNAVAILABLE' : observedCount < 16 ? 'PARTIAL' : 'HISTORICAL'
  function update(key, value) { window.location.hash = demoBookmark({ ...filters, [key]: value }) }
  return <section className="demo-coverage" aria-labelledby="demo-coverage-heading">
    <div className="demo-heading"><div><p className="demo-eyebrow">READ-ONLY · EVIDENCE REGISTRY</p><h2 id="demo-coverage-heading">Demo Coverage</h2></div><button onClick={resource.refresh}>Đọc lại nguồn</button></div>
    <p>16 cảnh EXPECTED theo handoff 08/11/2026. Số scene khác testcase, request, alert, incident và action count.</p>
    <p className="demo-notice" role={resource.error ? 'alert' : 'status'}><strong>{state}</strong> · {resource.error ? `${resource.error.code || 'NETWORK_ERROR'} · ` : ''}
      {!run ? 'Kế hoạch demo, chưa có kết quả nhập cho run được chọn. Results unavailable.' : 'Frozen import; verdict do nguồn báo cáo, chưa phải independent signoff.'}
      {resource.error && <button onClick={resource.refresh}>Thử lại</button>}</p>
    <div className="demo-context"><span>Run: <strong>{run?.run_id || 'NOT_IMPORTED'}</strong></span><span>Context: {run?.context || 'DESIGN / EXPECTED'}</span>
      <span>Source: {data ? resource.meta?.source_system || 'UNKNOWN' : 'UNAVAILABLE'}</span><span>Data as of UTC: {run?.data_as_of || 'UNKNOWN'}</span>
      <span>Read at UTC: {resource.meta?.read_at || 'UNKNOWN'}</span><span>16 expected · {run ? observedCount : 'UNKNOWN'} observed scenes</span>
      <span>P19 STRICT_READY: <strong>UNKNOWN</strong> · P19_SOURCE_NOT_CONNECTED</span></div>
    <div className="demo-filters"><label>Run<select aria-label="Run" value={filters.run} onChange={event => update('run', event.target.value)}><option value="">Run đầu tiên / kế hoạch</option>
      {filters.run && !data?.runs.some(run => run.run_id === filters.run) && <option value={filters.run}>{filters.run} · unavailable</option>}
      {data?.runs.map(run => <option key={run.run_id} value={run.run_id}>{run.run_id} · {run.context}</option>)}</select></label>
      <label>Execution mode<select aria-label="Execution mode" value={filters.mode} onChange={event => update('mode', event.target.value)}><option value="">Tất cả</option>{['LIVE', 'OFFLINE', 'ISOLATED', 'STAGING', 'HISTORICAL', 'DESIGN_ONLY'].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Verdict<select aria-label="Verdict" value={filters.verdict} onChange={event => update('verdict', event.target.value)}><option value="">Tất cả</option>{['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA'].map(value => <option key={value}>{value}</option>)}</select></label>
      <a href={demoBookmark({})}>Xóa bộ lọc</a></div>
    <p className="demo-muted">Bộ lọc phía client trên registry đầy đủ của snapshot; bookmark trên URL, không gửi query giả tới API. API refs là contract refs, không xác nhận endpoint đã tích hợp.</p>
    {!rows.length ? <p role="status">EMPTY · Không có scene phù hợp bộ lọc.</p> : <div className="demo-table-scroll" tabIndex={0} role="region" aria-label="Bảng demo coverage có thể cuộn"><table><thead><tr><th>Scene / expected</th><th>Mode / verdict</th><th>Observed / evidence</th><th>Portal / contract refs</th></tr></thead><tbody>
      {rows.map(row => <tr key={row.scenario_id}><td><strong>{row.scenario_id} · {row.title}</strong><small>DESIGN / EXPECTED · {row.expected_modes.join(', ')}</small><p>{row.expected_outcome}</p></td>
        <td><strong>{row.execution_modes.join(' + ')}</strong><p>{row.verdict}{row.basis === 'IMPORTED_OBSERVATION' ? ' · source reported' : ' · chưa nhập observed'}</p><small>{row.context} · {row.basis}</small></td>
        <td><p>{row.observed_outcome || 'UNAVAILABLE'}</p><small>Evaluated UTC: {row.last_evaluated_at || 'UNKNOWN'}</small><div className="demo-ref-list">{row.evidence_refs.map(id => <button key={id} onClick={() => setEvidenceId(id)}>{id}</button>)}</div>
          {row.missing_evidence_refs.map(id => <small key={id}>Ref chưa hợp lệ: {id}</small>)}{row.reason_codes.map(code => <small key={code}>{code}</small>)}</td>
        <td>{sceneRoute(row.scenario_id) ? <a href={sceneRoute(row.scenario_id)}>{row.portal_section}</a> : <span>{row.portal_section} · màn hình scene chưa triển khai đầy đủ</span>}
          {row.api_refs.map(ref => <code key={ref}>{ref}</code>)}</td></tr>)}
    </tbody></table></div>}
    {evidenceId && <EvidenceMetadataPanel key={evidenceId} evidenceId={evidenceId} onClose={() => setEvidenceId(null)} />}
  </section>
}
