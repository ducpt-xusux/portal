import test from 'node:test'
import assert from 'node:assert/strict'
import { reportEventCoverage } from './reportFields.js'
import { eventModel } from '../features/n91-investigation/investigationModel.js'
import { mapPort } from './portalApi.js'

const source = {
  event_id: 'TEST-REQUIRED', stream_id: 'TEST-stream', stream_sequence: 0,
  view_kind: 'P16H_CANONICAL_AUDIT', occurred_at: '2026-11-18T00:00:00Z',
  source_ip: '192.0.2.10', db_user: 'test_reader', database_name: 'TEST_DB',
  policy_version: 'TEST-policy', matched_rules: [], effective_action: 'ALLOW',
  decision: 'ALLOW', risk: { status: 'OK', score: 0, severity: 'LOW' }, score_breakdown: [],
  source_provenance: { payload_sha256: 'a'.repeat(64) }, sql_text_status: 'MASKED',
}

test('all report Table 3.6 fields survive the canonical view model, including sequence and score zero', () => {
  const mapped = eventModel(source)
  assert.equal(mapped.stream_sequence, 0)
  assert.equal(mapped.risk.score, 0)
  assert.deepEqual(reportEventCoverage(mapped), { complete: true, missing: [] })
})

test('missing source fields remain explicit deficiencies instead of becoming invented values', () => {
  const mapped = eventModel({ ...source, stream_sequence: undefined, database_name: null, score_breakdown: undefined })
  assert.deepEqual(reportEventCoverage(mapped), { complete: false, missing: ['stream_sequence', 'database', 'breakdown'] })
})

test('Neutron revision zero remains a source value; absent revision is not replaced', () => {
  assert.equal(mapPort({ revision_number: 0 }).revision_number, 0)
  assert.equal(mapPort({}).revision_number, null)
})
