import test from 'node:test'
import assert from 'node:assert/strict'
import { uiErrorMessage, uiLabel, uiRoleList } from './uiLanguage.js'
import { demoSceneLabel } from './demoSceneLabels.js'

test('UI statuses are translated without modifying transport values', () => {
  const source = { status: 'FRESH', decision: 'BLOCK', source_verified: false, score: null }
  const before = structuredClone(source)
  assert.equal(uiLabel(source.status), 'Đã cập nhật')
  assert.equal(uiLabel(source.decision), 'Chặn')
  assert.equal(uiLabel(source.source_verified), 'Không')
  assert.equal(uiLabel(source.score), 'Chưa xác định')
  assert.deepEqual(source, before)
  assert.notEqual(uiLabel('UNKNOWN'), uiLabel('PASS'))
  assert.equal(uiLabel('TEST'), 'Thử nghiệm')
  assert.equal(uiLabel('HISTORICAL'), 'Lịch sử')
})

test('unknown IDs remain exact, including inherited Object names', () => {
  for (const value of ['INC-TEST-1', '192.0.2.1', 'constructor', '__proto__', 'toString', 'db-firewall-other.service'])
    assert.equal(uiLabel(value), value)
})

test('report and source labels explain values without changing hashes, SQL or source keys', () => {
  const evidence = { BACKUP_SHA256: 'a'.repeat(64), GALERA_2_TLS_VERSION: 'TLSv1.3',
    PRODUCTION_RPO: 'NOT_MEASURED', APP_READER_PRIVILEGES: 'GRANT SELECT ON `p17-test`.* TO `reader`' }
  assert.equal(uiLabel('GALERA_2_TLS_VERSION'), 'Galera 2 · Phiên bản TLS')
  assert.equal(uiLabel(evidence.PRODUCTION_RPO), 'Chưa đo')
  assert.equal(uiLabel(evidence.BACKUP_SHA256), evidence.BACKUP_SHA256)
  assert.equal(uiLabel(evidence.APP_READER_PRIVILEGES), evidence.APP_READER_PRIVILEGES)
  assert.equal(uiLabel('db-firewall-p17.service'), 'Bộ phát hiện hành vi · dịch vụ systemd')
  assert.match(uiErrorMessage({ code: 'AUTO_CONTROLLER_UNAVAILABLE' }), /SSH.*hạn khóa/)
})

test('role labels and investigation stages remain presentation-only', () => {
  assert.equal(uiRoleList('Analyst, Viewer'), 'Chuyên viên phân tích, Người xem')
  assert.equal(uiLabel('P17_DETECTION'), 'Phát hiện sự cố')
  assert.equal(uiLabel('RECONSTRUCTED_WINDOW'), 'Liên kết dựng lại theo cửa sổ thời gian')
  assert.equal(uiLabel('UNAVAILABLE'), 'Chưa có dữ liệu')
})

test('planned scene copy does not change observed outcomes or exact refs', () => {
  const row = { scenario_id: 'SC-06', title: 'Decision eligibility', observed_outcome: 'NOT_VERIFIED', evidence_refs: ['TEST-ref'] }
  const before = structuredClone(row)
  assert.equal(demoSceneLabel(row.scenario_id, 'title', row.title), 'Điều kiện xử lý sự cố')
  assert.deepEqual(row, before)
  assert.equal(demoSceneLabel('SC-other', 'title', 'Nguồn cung cấp'), 'Nguồn cung cấp')
  assert.equal(uiLabel(row.observed_outcome), 'Chưa xác minh')
})
