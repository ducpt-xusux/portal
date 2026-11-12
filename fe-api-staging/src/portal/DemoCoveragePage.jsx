import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { demoSceneLabel } from '../services/demoSceneLabels.js'
import { useEffect, useState } from 'react'
import { useV4Resource } from './IncidentPages'
import {
  demoBookmark,
  demoFilters,
  expectedScenes,
  readCoverage,
  sceneRoute,
} from '../services/demoCoverageApi'
import EvidenceMetadataPanel from './EvidenceMetadataPanel'
import DefenseRunCoverage from './DefenseRunCoverage'
import { readDefenseCoverage } from '../services/defenseCoverageApi.js'
import './demoCoverage.css'

export default function DemoCoveragePage() {
  const [hash, setHash] = useState(() => window.location.hash)
  useEffect(() => {
    const change = () => setHash(window.location.hash)
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  const params = new URLSearchParams(hash.split('?')[1] || '')
  const legacy = params.get('view') === 'legacy' || params.has('mode') || params.has('verdict')
  const defense = useV4Resource('/system/demo-coverage/defense-run', {
    interval: 0,
    enabled: !legacy,
    transform: readDefenseCoverage,
  })
  const data = defense.error ? null : defense.data
  if (!legacy) {
    if (defense.loading && !data)
      return <p role="status">Đang đọc bằng chứng kiểm chứng…</p>
    if (params.get('view') === 'defense' || (data && (!params.get('run') || params.get('run') === data.run_id)))
      return <DefenseRunCoverage data={data} params={params} refresh={defense.refresh} error={defense.error} />
  }
  return <LegacyDemoCoverage />
}

function LegacyDemoCoverage() {
  const resource = useV4Resource('/system/demo-coverage', {
    interval: 0,
    transform: readCoverage,
  })
  const [filters, setFilters] = useState(() =>
    demoFilters(window.location.hash)
  )
  const [evidenceId, setEvidenceId] = useState(null)
  useEffect(() => {
    const change = () => {
      setFilters(demoFilters(window.location.hash))
      setEvidenceId(null)
    }
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  // A failed refresh must not leave previous observations presented as usable results.
  const data = resource.error ? null : resource.data
  const run =
    data?.runs.find((item) => item.run_id === filters.run) ||
    (!filters.run ? data?.runs[0] : null)
  const selected =
    data && run
      ? data.items.filter((item) => item.run_id === run.run_id)
      : expectedScenes
  const rows = selected.filter(
    (item) =>
      (!filters.mode || item.execution_modes.includes(filters.mode)) &&
      (!filters.verdict || item.verdict === filters.verdict)
  )
  const observedCount = selected.filter(
    (item) => item.basis === 'IMPORTED_OBSERVATION'
  ).length
  const state = resource.loading
    ? 'LOADING'
    : resource.error
      ? 'UNAVAILABLE'
      : !run
        ? 'UNAVAILABLE'
        : observedCount < 16
          ? 'PARTIAL'
          : 'HISTORICAL'
  function update(key, value) {
    const href = demoBookmark({ ...filters, [key]: value })
    window.location.hash = href + (href.includes('?') ? '&' : '?') + 'view=legacy'
  }
  return (
    <section className="demo-coverage" aria-labelledby="demo-coverage-heading">
      <div className="demo-heading">
        <div>
          <p className="demo-eyebrow">CHỈ ĐỌC · KHO BẰNG CHỨNG</p>
          <h2 id="demo-coverage-heading">Kiểm chứng chức năng</h2>
        </div>
        <button onClick={resource.refresh}>Đọc lại nguồn</button>
      </div>
      <p>
        Theo dõi 16 kịch bản kiểm chứng. Kịch bản chưa có kết quả được hiển thị riêng.
      </p>
      <p><a href="#/system/demo-coverage?view=defense">Bằng chứng lần chạy 07D</a></p>
      <p className="demo-notice" role={resource.error ? 'alert' : 'status'}>
        <strong>{uiLabel(state)}</strong> ·{' '}
        {resource.error ? `${resource.error.code || 'NETWORK_ERROR'} · ` : ''}
        {!run
          ? "Chưa có kết quả kiểm chứng cho lần thực hiện được chọn."
          : "Kết quả lịch sử từ nguồn; chưa được nghiệm thu độc lập."}
        {resource.error && <button onClick={resource.refresh}>Thử lại</button>}
      </p>
      <div className="demo-context">
        <span>
          Lần thực hiện: <strong>{run?.run_id || 'NOT_IMPORTED'}</strong>
        </span>
        <span>Phạm vi dữ liệu: {run?.context || 'DESIGN / EXPECTED'}</span>
        <span>
          Nguồn:{' '}
          {data ? resource.meta?.source_system || 'UNKNOWN' : 'UNAVAILABLE'}
        </span>
        <span>Dữ liệu đến (UTC): {run?.data_as_of || 'UNKNOWN'}</span>
        <span>Đọc lúc (UTC): {resource.meta?.read_at || 'UNKNOWN'}</span>
        <span>
          16 kịch bản dự kiến · {run ? observedCount : 'UNKNOWN'} đã quan sát kịch bản
        </span>
        <span>
          Điều kiện nghiệm thu: <strong>Chưa xác định</strong>
        </span>
      </div>
      <div className="demo-filters">
        <label>
          Lần thực hiện
          <select
            aria-label="Lần thực hiện"
            value={filters.run}
            onChange={(event) => update('run', event.target.value)}
          >
            <option value="">Lần thực hiện đầu tiên / kế hoạch</option>
            {filters.run &&
              !data?.runs.some((run) => run.run_id === filters.run) && (
                <option value={filters.run}>{filters.run} · unavailable</option>
              )}
            {data?.runs.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {run.run_id} · {uiLabel(run.context)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Chế độ thực hiện
          <select
            aria-label="Chế độ thực hiện"
            value={filters.mode}
            onChange={(event) => update('mode', event.target.value)}
          >
            <option value="">Tất cả</option>
            {[
              'LIVE',
              'OFFLINE',
              'ISOLATED',
              'STAGING',
              'HISTORICAL',
              'DESIGN_ONLY',
            ].map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </select>
        </label>
        <label>
          Kết quả
          <select
            aria-label="Kết quả"
            value={filters.verdict}
            onChange={(event) => update('verdict', event.target.value)}
          >
            <option value="">Tất cả</option>
            {[
              'PASS',
              'FAIL',
              'INCOMPLETE',
              'NOT_EXECUTED',
              'UNKNOWN',
              'NA',
            ].map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </select>
        </label>
        <a href="#/system/demo-coverage?view=legacy">Xóa bộ lọc</a>
      </div>
      <p className="demo-muted">
        Kết quả được lọc trong bản chụp đã chọn.
      </p>
      {!rows.length ? (
        <p role="status">Không có kịch bản phù hợp bộ lọc.</p>
      ) : (
        <div
          className="demo-table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Bảng kiểm chứng chức năng có thể cuộn"
        >
          <table>
            <thead>
              <tr>
                <th>Kịch bản / dự kiến</th>
                <th>Chế độ / kết quả</th>
                <th>Quan sát / bằng chứng</th>
                <th>Màn hình liên quan</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.scenario_id}>
                  <td>
                    <strong>
                      {row.scenario_id} · {demoSceneLabel(row.scenario_id, 'title', row.title)}
                    </strong>
                    <small>
                      Kế hoạch / dự kiến · {row.expected_modes.map(uiLabel).join(', ')}
                    </small>
                    <p>{demoSceneLabel(row.scenario_id, 'expected_outcome', row.expected_outcome)}</p>
                  </td>
                  <td>
                    <strong>{row.execution_modes.map(uiLabel).join(' + ')}</strong>
                    <p>
                      {uiLabel(row.verdict)}
                      {row.basis === 'IMPORTED_OBSERVATION'
                        ? " · theo kết quả nguồn"
                        : " · chưa có kết quả quan sát"}
                    </p>
                    <small>
                      {uiLabel(row.context)} · {uiLabel(row.basis)}
                    </small>
                  </td>
                  <td>
                    <p>{uiLabel(row.observed_outcome || 'UNAVAILABLE')}</p>
                    <small>
                      Đánh giá lúc (UTC): {row.last_evaluated_at || 'Chưa có thời điểm'}
                    </small>
                    <div className="demo-ref-list">
                      {row.evidence_refs.map((id) => (
                        <button key={id} onClick={() => setEvidenceId(id)}>
                          {id}
                        </button>
                      ))}
                    </div>
                    {row.missing_evidence_refs.map((id) => (
                      <small key={id}>Tham chiếu chưa hợp lệ: {id}</small>
                    ))}
                    {row.reason_codes.map((code) => (
                      <small key={code}>{uiLabel(code)}</small>
                    ))}
                  </td>
                  <td>
                    {sceneRoute(row.scenario_id) ? (
                      <a href={sceneRoute(row.scenario_id)}>
                        {demoSceneLabel(row.scenario_id, 'portal_section', row.portal_section)}
                      </a>
                    ) : (
                      <span>
                        {demoSceneLabel(row.scenario_id, 'portal_section', row.portal_section)} · màn hình kịch bản chưa triển khai
                        đầy đủ
                      </span>
                    )}
                    {row.api_refs.map((ref) => (
                      <details key={ref}><summary>Tham chiếu kỹ thuật</summary><code>{ref}</code></details>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {evidenceId && (
        <EvidenceMetadataPanel
          key={evidenceId}
          evidenceId={evidenceId}
          onClose={() => setEvidenceId(null)}
        />
      )}
    </section>
  )
}
