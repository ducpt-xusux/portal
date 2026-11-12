import test from 'node:test'
import assert from 'node:assert/strict'
import { uiLabel, uiRoleList } from './uiLanguage.js'
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
  for (const value of ['INC-TEST-1', '192.0.2.1', 'constructor', '__proto__', 'toString', 'db-firewall-p17.service'])
    assert.equal(uiLabel(value), value)
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
