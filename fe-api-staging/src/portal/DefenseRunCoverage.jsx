import { demoSceneLabel } from '../services/demoSceneLabels.js'
import { expectedScenes, sceneRoute } from '../services/demoCoverageApi.js'
import { defenseCoverageHref, selectedDefenseEvidence } from '../services/defenseCoverageApi.js'
import { Badge } from './PortalUI'

const observations = {
  PREFLIGHT_OBSERVED: 'Có bản ghi kiểm tra trước khi chạy.',
  ALLOW: 'Máy ứng dụng gửi truy vấn thành công và audit ghi nhận ALLOW.',
  BLOCK: 'Audit ghi nhận yêu cầu bị chặn.',
  CORR002_CANDIDATES: 'Ba yêu cầu riêng biệt được đối chiếu với sự cố CORR-002.',
  LAB_QUARANTINE: 'Controller ghi nhận cách ly trong lab. Probe TCP của máy clone bị timeout trong khoảng này.',
  LAB_RESTORE: 'Hai bản chụp đúng port xác nhận bộ Security Group gốc đã được khôi phục.',
  FIXTURES_PENDING: 'Đã nhập danh mục ca kiểm thử.',
  AUDIT_MASKED: 'Audit ghi nhận trạng thái đã che nội dung cho ba yêu cầu.',
  TLS_HA_SAMPLES: 'Có kết quả TLS hai chặng và kiểm tra chuyển đổi dự phòng độc lập.',
  ISOLATED_RECOVERY: 'Báo cáo ghi nhận truy vấn khôi phục trên MariaDB cô lập.',
  STAGING_REGRESSION: 'Có kết quả hồi quy giao thức trên mã staging.',
}
const reasons = {
  OBSERVATION_NOT_AVAILABLE: 'Chưa có bằng chứng phù hợp để xác nhận kết quả.',
  PREFLIGHT_ONLY: 'Phạm vi kiểm tra trước khi chạy.',
  SOURCE_REPORTED_OBSERVATION: 'Kết quả theo báo cáo nguồn.',
  EVENT_IN_RECONSTRUCTED_WINDOW: 'Mẫu đầu trong cửa sổ tương quan. Chưa có lần chạy riêng cho cảnh này.',
  RECONSTRUCTED_WINDOW: 'Liên kết tái dựng từ cửa sổ thời gian.',
  CONTROLLER_RECORDED_LAB: 'Bằng chứng lịch sử của lần xử lý trong lab.',
  FIXTURE_CATALOG_ONLY: 'Các ca vẫn chờ chạy và rà soát.',
  MASKED_SAMPLE_ONLY: 'Phạm vi giới hạn ở mẫu audit đã đối chiếu.',
  NODE_FAILURE_NOT_EXECUTED: 'Ca lỗi node Galera chưa chạy.',
  NODE_FAILURE_UNAVAILABLE: 'Chưa có kết quả ca lỗi node Galera.',
  LAB_SCOPE_ONLY: 'Chỉ số đo trong lab.',
  STAGING_SCOPE_ONLY: 'Phạm vi mã staging.',
  CORRELATION_EXECUTION_REPORT_MISSING: 'Chưa có báo cáo chạy 13 kịch bản tương quan.',
  DECISION_SOURCE_UNAVAILABLE: 'Chưa có quyết định cách ly được xác minh.',
  POLICY_CATALOG_NOT_VERIFIED: 'Chưa xác minh được danh mục 40 quy tắc của lần chạy.',
  P19_SOURCE_NOT_CONNECTED: 'Chưa có kết quả nghiệm thu có thẩm quyền.',
}
const metricLabels = {
  node_observations: 'Node có bản chụp',
  event_sequences: 'Thứ tự sự kiện',
  window_seconds: 'Cửa sổ quan sát (giây)',
  tcp_timeouts: 'Mẫu TCP timeout trong lúc cách ly',
  duration_seconds: 'Thời gian cách ly (giây)',
  during_canary_pass: 'Mẫu canary thành công trong lúc cách ly',
  record_count: 'Tổng số ca',
  not_executed_count: 'Chưa chạy',
  pending_review_count: 'Chờ rà soát',
  masked_events: 'Sự kiện đã che',
  isolated_pass: 'Kiểm tra độc lập đạt theo báo cáo',
  isolated_total: 'Tổng kiểm tra độc lập',
  frontend_sessions: 'Phiên TLS phía client',
  backend_sessions: 'Phiên TLS phía backend',
  rpo_seconds: 'RPO lab (giây)',
  rto_seconds: 'RTO lab (giây)',
  staging_pass: 'Kiểm tra staging đạt theo báo cáo',
}

function metricValue(key, value) {
  if (key === 'event_sequences')
    return Array.isArray(value) && value.length <= 3 && value.every(Number.isSafeInteger) ? value.join(', ') : null
  return Number.isFinite(value) && value >= 0 ? value.toLocaleString('vi-VN', { maximumFractionDigits: 6 }) : null
}

function EvidenceDetails({ data, selection }) {
  const { scene, ref } = selection
  return (
    <section className="demo-notice" aria-label="Tham chiếu bằng chứng">
      <strong>{scene.scene_id} · {ref.host} · {ref.label}</strong>
      <p>Mã bằng chứng <code>{ref.evidence_id}</code></p>
      <p>SHA-256 <code>{ref.sha256}</code> · {ref.size_bytes} byte</p>
      <p>Chế độ nguồn {ref.origin_mode} · {ref.scope === 'LAB' ? 'Lab' : 'Phạm vi theo nguồn'}</p>
      <p>Thời điểm tạo manifest {ref.manifest_created_at || 'Chưa có'}</p>
      <a href={defenseCoverageHref(data.run_id, scene.scene_id)}>Đóng chi tiết</a>
    </section>
  )
}

export default function DefenseRunCoverage({ data, params, refresh, error }) {
  const focused = params.get('scene')
  const matchingRun = Boolean(data && (!params.get('run') || params.get('run') === data.run_id))
  const selection = matchingRun ? selectedDefenseEvidence(data, params) : null
  const filtered = matchingRun && focused ? data.scenes.filter((row) => row.scene_id === focused) : data?.scenes
  return (
    <section className="demo-coverage" aria-labelledby="demo-defense-heading">
      <div className="demo-heading">
        <h2 id="demo-defense-heading">Kiểm chứng chức năng</h2>
        <button type="button" onClick={refresh}>Đọc lại nguồn</button>
      </div>
      <p><a href="#/system/demo-coverage?view=legacy">Danh mục và các lần chạy khác</a></p>
      {!matchingRun ? (
        <p className="demo-notice" role="status">Chưa đọc được bằng chứng của lần chạy này. {error?.code}</p>
      ) : (
        <>
          <div className="demo-context">
            <strong>{data.run_id}</strong>
            <Badge value="HISTORICAL">{data.context === 'TEST' ? 'Dữ liệu kiểm thử' : 'Bằng chứng lịch sử'}</Badge>
            <span>{data.verified_archive_count}/8 bundle · {data.artifact_count} artifact đã kiểm</span>
            {data.missing_hosts.length > 0 && <span>Thiếu bundle {data.missing_hosts.join(', ')}</span>}
            {data.unavailable_hosts.length > 0 && <span>Không đọc được {data.unavailable_hosts.join(', ')}</span>}
            <span>Nghiệm thu tổng thể chưa xác định</span>
          </div>
          {focused && <p><a href={defenseCoverageHref(data.run_id)}>Xem cả 16 kịch bản</a></p>}
          {selection && <EvidenceDetails data={data} selection={selection} />}
          {params.has('evidence') && !selection && (
            <p role="status">Mã bằng chứng chưa có trong cảnh đã chọn của lần chạy này.</p>
          )}
          {!filtered.length ? <p role="status">Chưa tìm thấy kịch bản này.</p> : (
            <div className="demo-table-scroll" tabIndex={0} role="region" aria-label="Bảng kiểm chứng">
              <table>
                <thead>
                  <tr><th>Kịch bản / dự kiến</th><th>Trạng thái</th><th>Quan sát / bằng chứng</th><th>Màn hình liên quan</th></tr>
                </thead>
                <tbody>
                  {filtered.map((row) => {
                    const expected = expectedScenes.find((item) => item.scenario_id === row.scene_id)
                    const related = sceneRoute(row.scene_id)
                    return (
                      <tr key={row.scene_id}>
                        <td>
                          <a href={defenseCoverageHref(data.run_id, row.scene_id)}>
                            {row.scene_id} · {demoSceneLabel(row.scene_id, 'title', expected.title)}
                          </a>
                          <p>{demoSceneLabel(row.scene_id, 'expected_outcome', expected.expected_outcome)}</p>
                        </td>
                        <td><Badge value={row.status}>{row.status === 'OBSERVED_LIMITED' ? 'Đã quan sát một phần' : undefined}</Badge></td>
                        <td>
                          {row.outcome && <p>{observations[row.outcome]}</p>}
                          {row.reason && <small>{reasons[row.reason] || row.reason}</small>}
                          {row.evidence.length > 0 && <small>Quan sát (UTC) {row.observed_at || 'Chưa có thời điểm'}</small>}
                          {Object.entries(metricLabels).map(([key, label]) => {
                            const value = metricValue(key, row.metrics[key])
                            return value !== null ? <small key={key}>{label} · {value}</small> : null
                          })}
                          <div className="demo-ref-list">
                            {row.evidence.map((ref) => (
                              <a key={ref.evidence_id} href={defenseCoverageHref(data.run_id, row.scene_id, ref.evidence_id)}>
                                {ref.host} · {ref.label}
                              </a>
                            ))}
                          </div>
                        </td>
                        <td>{related && <a href={related}>{demoSceneLabel(row.scene_id, 'portal_section', expected.portal_section)}</a>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}
