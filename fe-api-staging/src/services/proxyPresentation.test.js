import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dashboardMetrics, evidenceDecision, galeraNodeState, isolationEpisodes, sourceReadTimestamp } from './proxyPresentation.js'

test('unknown, failed and stale sources do not become zero or fresh isolation counts', () => {
  assert.deepEqual(dashboardMetrics({}, {}), { total: null, blocked: null, review: null, isolated: null })
  const summary = { data: { projection_counts: { processed_events: 0 }, event_counts: { block: 0 }, incident_counts: { review_required: 0 } } }
  const isolated = { data: {}, meta: { source_mode: 'LIVE', network_classification: 'CONFIGURED', freshness_state: 'FRESH', total_count: 0 } }
  assert.deepEqual(dashboardMetrics(summary, isolated), { total: 0, blocked: 0, review: 0, isolated: 0 })
  isolated.meta.freshness_state = 'STALE'
  assert.equal(dashboardMetrics(summary, isolated).isolated, null)
  assert.equal(dashboardMetrics({ ...summary, error: {} }, isolated).blocked, null)
})

test('a recent failed MariaDB read never means fresh successful wsrep', () => {
  const node = { source_mode: 'SNAPSHOT', scope: 'LOCAL_SOCKET_WSREP', read_ok: false, source_ref: 'test:node', observed_at: null, collection_freshness_state: 'FRESH' }
  assert.deepEqual(galeraNodeState(node), { valid: false, fresh: false })
  node.read_ok = true; node.observed_at = '2026-11-18T00:00:00Z'; node.observation_freshness_state = 'STALE'
  assert.deepEqual(galeraNodeState(node), { valid: true, fresh: false })
})

test('isolation history pairs observations and preserves missing starts and unknown gaps', () => {
  const row = (state, seconds, previous_state) => ({ state, observed_at: `2026-11-18T00:00:0${seconds}Z`, previous_state })
  assert.deepEqual(isolationEpisodes([row('NORMAL', 2, 'QUARANTINED')]), [{ started: null, restored: '2026-11-18T00:00:02Z' }])
  assert.deepEqual(isolationEpisodes([row('QUARANTINED', 1), row('NORMAL', 3)]), [{ started: '2026-11-18T00:00:01Z', restored: '2026-11-18T00:00:03Z' }])
  assert.deepEqual(isolationEpisodes([row('QUARANTINED', 1), row('UNKNOWN', 2), row('NORMAL', 3)]), [{ started: '2026-11-18T00:00:01Z', restored: null }])
})

test('source timestamps and decisions retain provenance instead of borrowing unrelated facts', () => {
  assert.equal(sourceReadTimestamp({ source_schema: 'audit-v1.0', data_as_of: '2026-11-18' }, 'last_success'), 'NO_SEPARATE_TIMESTAMP')
  assert.equal(sourceReadTimestamp({ source_schema: 'other', data_as_of: '2026-11-18' }, 'last_success'), null)
  assert.equal(evidenceDecision({ blocked: false }), 'ALLOW')
  assert.equal(evidenceDecision({ trace: { p17: { matched_signals: ['CORR-002'] } } }), 'UNKNOWN')
})
