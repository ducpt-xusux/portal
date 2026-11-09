import test from 'node:test'
import assert from 'node:assert/strict'
import { canExportEvidence, canReviewIncident, csvCell, prepareEvidenceFile, requestEvidenceFile, submitIncidentReview } from './incidentActions.js'

const auth = { status: 'authenticated', user: { user_id: 'u-1', role: 'Analyst' }, csrfToken: 'csrf', writeEnabled: true, capabilities: ['incidents:review', 'evidence:export'] }
const event = { event_id: 'evt-1', request_id: 'req-1', stream_id: 'stream-1', occurred_at: '2026-10-30T00:00:00Z', source_ip: '192.0.2.204',
  decision: 'BLOCK', risk: { score: 0, status: 'OK' }, matched_rules: ['INJ-001'], masked_query: 'PRIVATE_MASKED', raw_sql: 'PRIVATE_SQL', db_user: 'PRIVATE_USER',
  note: 'PRIVATE_NOTE', score_breakdown: [{ reason: 'PRIVATE_REASON', score: 0 }], source_provenance: { source_ref: 'p17:evt-1', payload_sha256: 'hash-1', token: 'PRIVATE_TOKEN' } }
const exportData = format => ({ incident_id: 'INC-1', export_id: 'exp-1', audit_id: 'audit-1', generated_at: '2026-10-30T00:00:00Z',
  format, complete: true, has_more: false, evidence_membership: 'RECONSTRUCTED_WINDOW', recorded_evidence_count: 3, items: [event], token: 'PRIVATE_TOKEN' })
const ok = data => ({ ok: true, status: 200, json: async () => ({ data, meta: { request_id: 'r-1' }, error: null }) })

test('review and export require explicit server capabilities and a real session', () => {
  assert.equal(canReviewIncident(auth), true)
  assert.equal(canExportEvidence(auth), true)
  for (const status of ['local_snapshot', 'anonymous', 'checking', 'unavailable']) {
    assert.equal(canReviewIncident({ ...auth, status }), false)
    assert.equal(canExportEvidence({ ...auth, status }), false)
  }
  assert.equal(canReviewIncident({ ...auth, capabilities: [] }), false)
  assert.equal(canExportEvidence({ ...auth, capabilities: [] }), false)
  assert.equal(canReviewIncident({ ...auth, writeEnabled: false }), false)
  assert.equal(canReviewIncident({ ...auth, user: { role: 'Viewer' } }), false)
  assert.equal(canExportEvidence({ ...auth, user: { role: 'Viewer' } }), true)
  assert.equal(canExportEvidence({ ...auth, csrfToken: null }), false)
})

test('readonly callers never send a review or export POST', async () => {
  let calls = 0
  const fetcher = async () => { calls++; return ok({}) }
  const readonly = { ...auth, status: 'local_snapshot', user: null, csrfToken: null }
  await assert.rejects(submitIncidentReview(readonly, 'INC-1', { reviewState: 'ACKNOWLEDGED', note: '', revision: 'r-1', idempotencyKey: 'key-1' }, fetcher), error => error.status === 403)
  await assert.rejects(requestEvidenceFile(readonly, 'INC-1', 'json', 'key-1', fetcher), error => error.status === 403)
  assert.equal(calls, 0)
})

test('review carries revision, CSRF and idempotency and does not write P17 detection or network state', async () => {
  let seen
  const result = await submitIncidentReview(auth, 'INC-1', { reviewState: 'ACKNOWLEDGED', note: ' Checked ', revision: 'r-1', idempotencyKey: 'key-1' }, async (url, options) => {
    seen = { url, options }
    return ok({ incident_id: 'INC-1', review_state: 'ACKNOWLEDGED', annotation_id: 'ann-1', review_revision: 'r-2', incident_status: 'SHOULD_NOT_BE_MAPPED' })
  })
  assert.equal(seen.url, '/api/v1/incidents/INC-1/review')
  assert.equal(seen.options.headers['X-CSRF-Token'], 'csrf')
  assert.equal(seen.options.headers['Idempotency-Key'], 'key-1')
  assert.deepEqual(JSON.parse(seen.options.body), { review_state: 'ACKNOWLEDGED', note: 'Checked', expected_revision: 'r-1' })
  assert.deepEqual(result, { annotation_id: 'ann-1', review_state: 'ACKNOWLEDGED', review_revision: 'r-2' })
})

test('a 200 envelope without a confirmed annotation cannot report review success', async () => {
  await assert.rejects(submitIncidentReview(auth, 'INC-1', { reviewState: 'REVIEWED', note: '', revision: 'r-1', idempotencyKey: 'key-1' }, async () => ok({ incident_id: 'INC-1', review_state: 'REVIEWED' })), error => error.code === 'UPSTREAM_INVALID')
})

test('conflicts and lost connections do not silently retry a review write', async () => {
  let calls = 0
  const input = { reviewState: 'REVIEWED', note: '', revision: 'r-1', idempotencyKey: 'key-1' }
  await assert.rejects(submitIncidentReview(auth, 'INC-1', input, async () => { calls++; return { ok: false, status: 409, json: async () => ({ data: null, meta: {}, error: { code: 'REVIEW_CONFLICT' } }) } }), error => error.status === 409)
  assert.equal(calls, 1)
  await assert.rejects(submitIncidentReview(auth, 'INC-1', { ...input, note: 'x'.repeat(1001) }, async () => { calls++; return ok({}) }))
  assert.equal(calls, 1)
})

test('evidence JSON uses an explicit reference allowlist, preserving source count and valid zero score', () => {
  const file = prepareEvidenceFile(exportData('json'), 'INC-1', 'json')
  assert.ok(!file.content.includes('PRIVATE'))
  const parsed = JSON.parse(file.content)
  assert.equal(parsed.metadata.audit_id, 'audit-1')
  assert.equal(parsed.metadata.recorded_evidence_count, 3)
  assert.equal(parsed.metadata.exported_event_count, 1)
  assert.equal(parsed.items[0].risk_score, 0)
  assert.equal(parsed.items[0].source_ref, 'p17:evt-1')
  assert.equal(Object.hasOwn(parsed.items[0], 'masked_query'), false)
  assert.equal(file.filename, 'INC-1-evidence.json')
})

test('an export without an audit receipt, exact incident, completeness or unique events is rejected', () => {
  for (const change of [{ audit_id: null }, { export_id: null }, { incident_id: 'INC-OTHER' }, { complete: undefined }, { has_more: true }, { items: [event, event] }]) {
    assert.throws(() => prepareEvidenceFile({ ...exportData('json'), ...change }, 'INC-1', 'json'))
  }
})

test('partial exports are clearly marked and missing risk is never converted to zero', () => {
  const file = prepareEvidenceFile({ ...exportData('json'), complete: false, has_more: true, items: [{ ...event, risk: { score: 0, status: 'ERROR' } }] }, 'INC-1', 'json')
  assert.equal(file.completeness, 'PARTIAL')
  assert.equal(file.filename, 'INC-1-evidence-partial.json')
  assert.equal(JSON.parse(file.content).items[0].risk_score, null)
})

test('CSV exports retain metadata/audit even for an empty authorized result', () => {
  const file = prepareEvidenceFile({ ...exportData('csv'), items: [], recorded_evidence_count: 0 }, 'INC-1', 'csv')
  assert.ok(file.content.includes('METADATA') && file.content.includes('audit-1'))
  assert.ok(!file.content.includes('PRIVATE'))
  assert.equal(file.content.split('\r\n').length, 2)
})

for (const value of ['=HYPERLINK("x")', '+cmd', '-cmd', '@SUM(A1)', '  =1', '\t=1', '\r=1', '\n=1']) {
  test(`CSV protects spreadsheet formula prefix ${JSON.stringify(value.slice(0, 3))}`, () => {
    assert.ok(csvCell(value).startsWith('"\''))
  })
}

test('export creates an audited request and sanitizes the server result again', async () => {
  let seen
  const file = await requestEvidenceFile(auth, 'INC-1', 'csv', 'key-export', async (url, options) => { seen = { url, options }; return ok(exportData('csv')) })
  assert.equal(seen.url, '/api/v1/incidents/INC-1/evidence/exports')
  assert.deepEqual(JSON.parse(seen.options.body), { format: 'csv', scope: 'EVIDENCE_REFERENCES' })
  assert.equal(seen.options.headers['Idempotency-Key'], 'key-export')
  assert.equal(seen.options.headers['X-CSRF-Token'], 'csrf')
  assert.ok(!file.content.includes('PRIVATE'))
  assert.equal(file.audit_id, 'audit-1')
})
