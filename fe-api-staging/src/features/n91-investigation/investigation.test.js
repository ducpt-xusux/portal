import assert from 'node:assert/strict'
import test from 'node:test'
import { createInvestigationApi, sourceId } from './investigationApi.js'
import {
  canonicalLink,
  compareEvents,
  eventModel,
  lifecycleState,
  metricValue,
  policyDrift,
  STAGES,
  TABS,
  traceModel,
} from './investigationModel.js'

const event = (changes = {}) => ({
  event_id: 'TEST-same',
  stream_id: 'TEST-app',
  request_id: 'TEST-request',
  view_kind: 'P16H_CANONICAL_AUDIT',
  decision: 'ALLOW',
  effective_action: 'ALLOW',
  risk: { status: 'OK', score: 0, severity: 'LOW' },
  policy_version: 'TEST-RC5',
  matched_rules: ['TEST-monitor'],
  monitor_rules: ['TEST-monitor'],
  blocking_rules: [],
  sql_text_status: 'WITHHELD',
  masked_query: 'SENSITIVE_CANARY',
  source_provenance: {
    context: 'TEST',
    verification: 'IMPORTED_UNVERIFIED',
    human_review: 'UNAVAILABLE',
  },
  ...changes,
})

test('six tab catalog and seven frozen stage names', () => {
  assert.deepEqual(TABS, [
    'Overview',
    'Parser',
    'Rules',
    'Risk',
    'Trace',
    'Evidence',
  ])
  assert.equal(STAGES.length, 7)
  assert.equal(
    traceModel(null).every((s) => s.status === 'UNAVAILABLE'),
    true
  )
})

test('privacy whitelist withholds SQL unless exact MASKED, keeps TEST and upstream verification', () => {
  const mapped = eventModel(
    event({
      raw_sql: 'RAW_CANARY',
      source_metadata: { password: 'SECRET_CANARY' },
    })
  )
  assert.equal(mapped.masked_query, null)
  assert.equal(mapped.source_provenance.context, 'TEST')
  assert.equal(JSON.stringify(mapped).includes('CANARY'), false)
  assert.equal(
    eventModel(event({ sql_text_status: 'MASKED', masked_query: 'SELECT ?' }))
      .masked_query,
    'SELECT ?'
  )
  assert.throws(() => eventModel(event({ stream_id: null })))
  assert.throws(() => eventModel(event({ view_kind: 'P17_EVENT_PROJECTION' })))
})

test('risk ERROR and missing breakdown never fabricated; zero preserved without thresholds', () => {
  assert.equal(eventModel(event()).risk.score, 0)
  const error = eventModel(
    event({
      risk: { status: 'ERROR', score: 100, severity: 'CRITICAL' },
      raw_score: 120,
      score_breakdown: [{ score: 100, rule_id: 'TEST-rule' }],
    })
  )
  assert.equal(error.risk.score, null)
  assert.equal(error.risk.severity, null)
  assert.equal(error.score_breakdown, null)
  assert.equal(error.raw_score, null)
  assert.equal(
    eventModel(event({ risk: { status: 'OK', score: 60, severity: 'LOW' } }))
      .risk.severity,
    'LOW'
  )
})

test('APP Clone comparison uses composite IDs; CTX-006 context deny never guessed SQLi', () => {
  const comparison = compareEvents(
    event(),
    event({
      stream_id: 'TEST-clone',
      decision: 'BLOCK',
      blocking_rules: ['CTX-006'],
    })
  )
  assert.equal(comparison.same_identity, false)
  assert.equal(comparison.same_request, false)
  assert.equal(comparison.context_denial, true)
  assert.equal(
    canonicalLink(comparison.right),
    '#/events/TEST-same?source=canonical&stream_id=TEST-clone'
  )
  assert.equal(comparison.right.decision, 'BLOCK')
})

test('NOT_TRIGGERED requires emitted stage; duplicates and unknown stage/status rejected', () => {
  const row = {
    stage: 'P17_DETECTION',
    status: 'NOT_TRIGGERED',
    outcome: 'NO_ALERT',
    facts: [],
  }
  const stages = traceModel({ stages: [row] })
  assert.equal(stages[4].status, 'NOT_TRIGGERED')
  assert.equal(stages[6].status, 'UNAVAILABLE')
  assert.throws(() => traceModel({ stages: [row, row] }))
  assert.throws(() => traceModel({ stages: [{ ...row, stage: 'GUESSED' }] }))
  assert.throws(() => traceModel({ stages: [{ ...row, status: 'PASS' }] }))
})

test('WITHHELD trace facts never display provided values', () => {
  const trace = traceModel({
    stages: [
      {
        stage: 'SQL_PARSE',
        status: 'UNAVAILABLE',
        facts: [
          {
            name: 'withheld',
            status: 'WITHHELD',
            value_summary: 'SENSITIVE_CANARY',
          },
        ],
      },
    ],
  })
  assert.equal(JSON.stringify(trace).includes('SENSITIVE_CANARY'), false)
})

test('historical restore cannot become current; stale expires and invalid observations stay UNKNOWN', () => {
  const now = Date.parse('2026-11-08T02:00:00Z')
  assert.equal(
    lifecycleState({ action: { action_state: 'RESTORED' } }, now).state,
    'UNKNOWN'
  )
  const data = {
    current_state: 'QUARANTINED',
    current: {
      source_system: 'NEUTRON_LIVE',
      source: { freshness_state: 'FRESH' },
      security_group_ids: ['TEST-qsg'],
      observed_at: '2026-11-08T01:59:50Z',
      expires_at: '2026-11-08T02:00:20Z',
    },
  }
  assert.equal(lifecycleState(data, now).state, 'QUARANTINED')
  assert.equal(lifecycleState(data, now + 30000).state, 'UNKNOWN')
  data.current.source.freshness_state = 'HISTORICAL'
  assert.equal(lifecycleState(data, now).state, 'UNKNOWN')
})

test('duration value requires unit, explicit clock/basis and nonnegative source value', () => {
  const metric = {
    seconds: 0,
    unit: 'seconds',
    clock_id: 'TEST-clock',
    time_basis: 'TEST-basis',
  }
  assert.equal(metricValue(metric), '0 s')
  assert.match(metricValue({ ...metric, seconds: null }), /UNAVAILABLE/)
  assert.match(metricValue({ ...metric, seconds: -1 }), /UNAVAILABLE/)
  assert.match(metricValue({ ...metric, time_basis: null }), /UNAVAILABLE/)
  assert.match(
    metricValue({ ...metric, unavailable_reason: 'CLOCK_TIME_BASIS_MISMATCH' }),
    /UNAVAILABLE/
  )
})

test('rule detail detects same version hash drift and policy version mismatch', () => {
  assert.equal(policyDrift({ policy_version: 'other' }, event()), true)
  const comparable = {
    ...event(),
    policy_config_hash: 'a',
    policy_hash_basis: 'FILE_BYTES_SHA256',
  }
  assert.equal(
    policyDrift({ policy_version: 'TEST-RC5', policy_sha256: 'b' }, comparable),
    true
  )
  assert.equal(
    policyDrift({ policy_version: 'TEST-RC5', policy_sha256: 'a' }, comparable),
    false
  )
  assert.equal(
    policyDrift(
      { policy_version: 'TEST-RC5', policy_sha256: 'b' },
      { ...comparable, policy_hash_basis: 'UNKNOWN' }
    ),
    false
  )
})

test('API uses canonical source/stream and same-origin shared session request; no mutation method', async () => {
  const calls = [],
    request = async (path, options) => {
      calls.push({ path, options })
      return { data: {}, meta: {} }
    }
  const api = createInvestigationApi(request)
  await api.event('TEST-same', 'TEST-clone')
  await api.trace('TEST-same', 'TEST-clone')
  await api.lifecycle('TEST-action')
  await api.timeline('TEST-incident')
  assert.deepEqual(calls[0].options.params, {
    source: 'canonical',
    stream_id: 'TEST-clone',
  })
  assert.deepEqual(calls[1].options.params, { stream_id: 'TEST-clone' })
  assert.equal(calls[2].path, '/investigation/actions/TEST-action/sg-lifecycle')
  assert.equal(
    calls.every((c) => !c.options?.method),
    true
  )
  assert.throws(() => sourceId('../unsafe'))
  assert.throws(() => sourceId('x?token=y'))
})
