import test from 'node:test'
import {
  readFunnel,
  funnelLink,
  dashboardHref,
  readEvaluationRun,
  funnelStages,
} from './dashboardFunnel.js'
import assert from 'node:assert/strict'
import {
  auditEventQuery,
  dashboardEventCounts,
  dashboardSeriesPoints,
  incidentGroupLink,
  readIncidentBreakdown,
} from './dashboardAudit.js'

const snapshot = {
  source_mode: 'SNAPSHOT',
  freshness_state: 'FRESH',
  read_at: new Date().toISOString(),
  stale_after_seconds: 30,
}

function testFunnel(context = 'LIVE') {
  const from = '2026-11-07T12:00:00Z',
    to = '2026-11-07T12:15:00Z'
  return {
    context,
    run_id: context === 'LIVE' ? null : 'fixture',
    window_from: from,
    window_to: to,
    scope: 'INDEPENDENT_SOURCE_COUNTERS',
    cohort_linked: false,
    stages: funnelStages.map((stage) => ({
      stage,
      status: 'PARTIAL',
      window_from: from,
      window_to: to,
      metrics: [
        {
          key: stage === 'POLICY' ? 'block' : 'audit_events',
          count: 3,
          unit: 'AUDIT_EVENTS',
        },
      ],
      source: {
        source_system: 'unit-test',
        coverage_kind: 'NOT_PROVEN',
        read_at: to,
      },
    })),
  }
}

test('funnel requires exact context, run and window; never converts missing counters to zero', () => {
  const data = testFunnel()
  data.stages[0].metrics[0].count = null
  assert.equal(readFunnel(data, 'LIVE').stages[0].metrics[0].count, null)
  assert.throws(() => readFunnel(data, 'EVALUATION', 'fixture'))
  assert.throws(() => readFunnel({ ...data, cohort_linked: true }, 'LIVE'))
  const wrong = testFunnel()
  wrong.stages[0].window_to = '2026-11-08T00:00:00Z'
  assert.throws(() => readFunnel(wrong, 'LIVE'))
  const missing = testFunnel()
  missing.stages[0].status = 'UNAVAILABLE'
  assert.throws(() => readFunnel(missing, 'LIVE'))
  const stale = testFunnel()
  stale.stages[0].status = 'STALE'
  assert.equal(readFunnel(stale, 'LIVE').stages[0].metrics[0].count, 3)
})

test('funnel drilldowns retain source and exact window without treating created incidents as last_seen', () => {
  const data = testFunnel()
  const href = funnelLink(data, data.stages[2], data.stages[2].metrics[0])
  const query = new URLSearchParams(href.split('?')[1])
  assert.equal(query.get('source'), 'canonical')
  assert.equal(query.get('decision'), 'BLOCK')
  assert.equal(query.get('from'), data.window_from)
  assert.equal(query.get('to'), data.window_to)
  assert.equal(
    funnelLink(data, data.stages[4], data.stages[4].metrics[0]),
    '#/incidents'
  )
  assert.equal(
    new URLSearchParams(
      funnelLink(data, data.stages[3], data.stages[3].metrics[0]).split('?')[1]
    ).get('alerts_from'),
    data.window_from
  )
  const evaluation = testFunnel('EVALUATION')
  assert.equal(
    funnelLink(
      evaluation,
      evaluation.stages[2],
      evaluation.stages[2].metrics[0]
    ),
    null
  )
})

test('evaluation routes never silently reuse live scope or turn fixture expected into PASS', () => {
  assert.match(
    dashboardHref('EVALUATION', '1h', 'run/with?escape'),
    /run_id=run%2Fwith%3Fescape/
  )
  assert.equal(
    dashboardHref('LIVE', '24h', 'old-run'),
    '#/dashboard?context=LIVE&window=24h'
  )
  const run = {
    run_id: 'fixture',
    run_kind: 'OFFLINE',
    status: 'NOT_EXECUTED',
    case_count: 60,
    counts: {
      pass: 0,
      fail: 0,
      incomplete: 0,
      not_executed: 60,
      unknown: 0,
      na: 0,
    },
    provenance: {},
  }
  assert.equal(readEvaluationRun(run).counts.not_executed, 60)
  assert.throws(() =>
    readEvaluationRun({
      ...run,
      counts: { ...run.counts, pass: 60, not_executed: 0 },
    })
  )
})

test('unconfirmed empty windows never display zero KPI', () => {
  const result = dashboardEventCounts(
    {
      event_counts: { allow: 0, block: 0 },
      coverage: { complete: false, records_in_window: 0 },
    },
    snapshot
  )
  assert.equal(result.allow, null)
  assert.equal(result.block, null)
})

test('historical export counts stay historical rather than being dropped because event time is old', () => {
  const data = {
    event_counts: { allow: 16, block: 3, unknown: 0, risk_errors: 0 },
    coverage: { complete: false, records_in_window: 19 },
  }
  assert.equal(
    dashboardEventCounts(data, {
      ...snapshot,
      data_as_of: '2026-10-31T09:21:41Z',
    }).allow,
    16
  )
  assert.equal(
    dashboardEventCounts(data, {
      ...snapshot,
      source_mode: 'REMOTE_READONLY',
      freshness_state: 'STALE',
    }).allow,
    null
  )
})

test('incomplete buckets create gaps, retaining real zero of the other decision in occupied buckets', () => {
  const points = dashboardSeriesPoints(
    {
      points: [
        {
          occurred_at: '2026-10-31T09:10:00Z',
          allow: 0,
          block: 0,
          records: 0,
          coverage_complete: false,
        },
        {
          occurred_at: '2026-10-31T09:11:00Z',
          allow: 0,
          block: 1,
          records: 1,
          coverage_complete: false,
        },
      ],
    },
    snapshot
  )
  assert.deepEqual(
    points.map((p) => [p.allow, p.block, p.gap]),
    [
      [null, null, true],
      [0, 1, false],
    ]
  )
})

test('malformed series cannot be graphed as zero', () => {
  assert.equal(
    dashboardSeriesPoints(
      { points: [{ occurred_at: 'invalid', allow: 1, block: 2 }] },
      snapshot
    ),
    null
  )
  assert.equal(
    dashboardSeriesPoints(
      {
        points: [{ occurred_at: '2026-10-31T09:10:00Z', allow: -1, block: 0 }],
      },
      snapshot
    ),
    null
  )
})

test('canonical drilldown uses explicit source and never invents a P17 stream', () => {
  assert.equal(
    auditEventQuery({ view_kind: 'P16H_CANONICAL_AUDIT', stream_id: null }),
    'source=canonical'
  )
  assert.equal(
    auditEventQuery({
      view_kind: 'P17_EVENT_PROJECTION',
      stream_id: 'stream-a',
    }),
    'stream_id=stream-a'
  )
  assert.equal(
    auditEventQuery({
      view_kind: 'P16H_CANONICAL_AUDIT',
      stream_id: 'stream:b',
    }),
    'source=canonical&stream_id=stream%3Ab'
  )
})

const groups = () => ({
  total: 8,
  scope: 'ALL_P17_INCIDENTS',
  basis: 'DISTINCT_INCIDENT_IDS',
  by_severity: [
    { severity: 'HIGH', count: 8 },
    { severity: 'CRITICAL', count: 0 },
  ],
  by_signal: [
    { signal_rule: 'CORR-002', count: 4 },
    { signal_rule: 'CORR-003', count: 4 },
  ],
})

test('incident groups drill down to the same source field without applying the audit window', () => {
  const result = readIncidentBreakdown(groups())
  assert.equal(result.total, 8)
  assert.equal(result.by_severity[0].href, '#/incidents?severity=HIGH')
  assert.equal(result.by_signal[1].href, '#/incidents?signal_rule=CORR-003')
  assert.equal(result.by_severity[1].count, 0)
})

test('missing or inconsistent incident totals never fall back to a recent page or zero', () => {
  assert.equal(readIncidentBreakdown(null), null)
  assert.equal(readIncidentBreakdown({ ...groups(), total: 9 }), null)
  assert.equal(readIncidentBreakdown({ ...groups(), by_signal: [] }), null)
  assert.equal(
    readIncidentBreakdown({ ...groups(), basis: 'RULE_MATCHES' }),
    null
  )
  assert.equal(
    readIncidentBreakdown({ ...groups(), scope: 'AUDIT_WINDOW' }),
    null
  )
})

test('duplicate groups, negative counts, fractions and invalid signal labels are rejected', () => {
  for (const by_signal of [
    [
      { signal_rule: 'CORR-002', count: 4 },
      { signal_rule: 'CORR-002', count: 4 },
    ],
    [
      { signal_rule: 'CORR-002', count: -1 },
      { signal_rule: 'CORR-003', count: 9 },
    ],
    [
      { signal_rule: 'CORR-002', count: 4.5 },
      { signal_rule: 'CORR-003', count: 3.5 },
    ],
    [{ signal_rule: 'INVALID', count: 8 }],
  ])
    assert.equal(readIncidentBreakdown({ ...groups(), by_signal }), null)
})

test('a supplied empty incident dataset retains real zero counts', () => {
  const value = {
    ...groups(),
    total: 0,
    by_severity: [{ severity: 'HIGH', count: 0 }],
    by_signal: [{ signal_rule: 'CORR-002', count: 0 }],
  }
  assert.equal(readIncidentBreakdown(value).total, 0)
  assert.equal(readIncidentBreakdown(value).by_signal[0].count, 0)
})

test('source severity labels survive and URL values cannot inject another filter', () => {
  const label = 'MEDIUM&status=REVIEW_REQUIRED'
  const value = { ...groups(), by_severity: [{ severity: label, count: 8 }] }
  const result = readIncidentBreakdown(value)
  assert.equal(result.by_severity[0].value, label)
  const query = new URLSearchParams(result.by_severity[0].href.split('?')[1])
  assert.equal(query.get('severity'), label)
  assert.equal(query.has('status'), false)
  assert.equal(incidentGroupLink('source_ip', 'HIGH'), null)
})
