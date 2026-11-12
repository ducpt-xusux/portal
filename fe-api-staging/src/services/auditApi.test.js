import test from 'node:test'
import assert from 'node:assert/strict'
import {
  AUDIT_FILTERS,
  AuditApiError,
  auditCsv,
  auditRequest,
  eventParams,
  getAuditDashboard,
  mapAuditEvent,
} from './auditApi.js'

const record = {
  event_id: '26b1abbe-3fe2-4db8-ad12-3c3892e09664',
  timestamp: '2026-10-19T13:55:55.626000Z',
  client_ip: '10.0.0.30',
  db_user: 'app_reader',
  query_masked: 'SELECT password_hash FROM users WHERE id = ? OR ?=?',
  policy_decision: 'BLOCK',
  severity: 'CRITICAL',
  risk_score: 100,
  raw_score: 130,
  matched_rules: ['OBJ-004', 'INJ-001', 'OBJ-003'],
  policy_version: '1.4.0',
  score_breakdown: [
    {
      source: 'matched_rule',
      rule_id: 'OBJ-004',
      score: 50,
      category: 'sensitive_data',
      reason: 'Access to password_hash',
    },
    {
      source: 'matched_rule',
      rule_id: 'INJ-001',
      score: 40,
      category: 'injection',
      reason: 'Tautology',
    },
    {
      source: 'matched_rule',
      rule_id: 'OBJ-003',
      score: 40,
      category: 'forbidden_object',
      reason: 'Users table',
    },
  ],
  reasons: ['Tautological predicate detected'],
  risk_status: 'OK',
  risk_error: null,
  action: 'BLOCK',
  action_result: 'BLOCKED',
  dominant_rule: 'OBJ-004',
  recommended_action: 'BLOCK_AUDIT_CONSIDER_ISOLATION',
}

test('P16 scores/actions are preserved without demo enrichment or isolation claims', () => {
  const event = mapAuditEvent(record)
  assert.equal(event.score, 100)
  assert.equal(event.rawScore, 130)
  assert.deepEqual(
    event.ruleBreakdown.map((p) => p.score),
    [50, 40, 40]
  )
  assert.equal(event.action, 'BLOCK')
  assert.equal(event.actionResult, 'BLOCKED')
  assert.equal(event.incidentId, null)
  assert.equal(event.vmId, null)
  assert.equal(event.policyVersion, '1.4.0')
  assert.equal(event.source, 'audit_api')
})

test('default-deny component and unknown risk remain visible', () => {
  const event = mapAuditEvent({
    ...record,
    score_breakdown: [
      {
        source: 'default_deny',
        rule_id: null,
        score: 30,
        category: 'policy',
        reason: 'Default deny',
      },
    ],
  })
  assert.equal(event.ruleBreakdown[0].id, null)
  assert.equal(event.ruleBreakdown[0].source, 'default_deny')
  const unknown = mapAuditEvent({
    ...record,
    risk_score: null,
    raw_score: null,
    severity: null,
    risk_status: 'ERROR',
    score_breakdown: null,
  })
  assert.equal(unknown.score, null)
  assert.equal(unknown.severity, 'UNKNOWN')
})

test('default events range includes history; explicit ranges use current time', () => {
  assert.equal(eventParams(AUDIT_FILTERS).start, undefined)
  const parameters = eventParams(
    {
      ...AUDIT_FILTERS,
      minutes: 60,
      sourceIp: '10.0.0.99',
      rule: 'NEW-001',
      actionResult: 'BLOCKED',
    },
    Date.parse('2026-10-21T12:00:00Z')
  )
  assert.equal(parameters.start, '2026-10-21T11:00:00.000Z')
  assert.equal(parameters.client_ip, '10.0.0.99')
  assert.equal(parameters.rule, 'NEW-001')
  assert.equal(parameters.action_result, 'BLOCKED')
})

test('API query uses URL encoding and excludes ALL filters', async () => {
  let called
  const body = await auditRequest('/events', {
    params: { q: 'SELECT ? OR ?=?', severity: 'ALL', page: 2 },
    fetcher: async (url) => {
      called = url
      return {
        ok: true,
        json: async () => ({
          data: { total: 0 },
          meta: { data_state: 'HISTORICAL' },
          error: null,
        }),
      }
    },
  })
  const url = new URL(called, 'http://localhost')
  assert.equal(url.searchParams.get('q'), 'SELECT ? OR ?=?')
  assert.equal(url.searchParams.has('severity'), false)
  assert.equal(body.data.total, 0)
})

test('network/API/non-JSON failures do not fall back to mock events', async () => {
  await assert.rejects(
    auditRequest('/events', {
      fetcher: async () => {
        throw new TypeError('offline')
      },
    }),
    AuditApiError
  )
  await assert.rejects(
    auditRequest('/events', {
      fetcher: async () => ({
        ok: false,
        status: 503,
        json: async () => ({ error: { code: 'AUDIT_SOURCE_UNAVAILABLE' } }),
      }),
    }),
    (e) => e.status === 503
  )
  await assert.rejects(
    auditRequest('/events', {
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error('HTML')
        },
      }),
    }),
    (e) => e.code === 'INVALID_RESPONSE'
  )
})

test('historical dashboard explicitly anchors to source time and retains block counts', async () => {
  const previous = globalThis.fetch
  const urls = []
  const meta = {
    timestamp: '2026-10-21T12:00:00Z',
    data_state: 'HISTORICAL',
    audit_source: { mode: 'snapshot', state: 'REACHABLE' },
  }
  globalThis.fetch = async (path) => {
    const url = new URL(path, 'http://localhost')
    urls.push(url)
    const data = url.pathname.endsWith('/health')
      ? {
          audit_source: meta.audit_source,
          last_event_at: '2026-10-19T14:04:28.997000Z',
        }
      : url.pathname.endsWith('/summary')
        ? {
            events: { total: 12, allowed: 6, blocked: 6 },
            unique_client_ips: 1,
          }
        : url.pathname.endsWith('/event-series')
          ? {
              points: [
                { timestamp: '2026-10-19T14:00:00Z', allowed: 2, blocked: 3 },
              ],
            }
          : { events: [record] }
    return { ok: true, json: async () => ({ data, meta, error: null }) }
  }
  try {
    const data = await getAuditDashboard()
    assert.equal(data.end, '2026-10-19T14:04:28.997000Z')
    assert.equal(data.historical, true)
    assert.equal(data.counts.total, 12)
    assert.equal(data.events[0].timestamp, record.timestamp)
    assert.equal(data.activity.chart[0].blocked, 3)
    assert.equal(
      urls
        .find((url) => url.pathname.endsWith('/summary'))
        .searchParams.get('end'),
      data.end
    )
  } finally {
    globalThis.fetch = previous
  }
})

test('CSV uses actual P16 scores/results and protects spreadsheet formulas', () => {
  const csv = auditCsv([{ ...mapAuditEvent(record), user: '=CMD()' }])
  assert.match(csv, /"raw_score","risk_score"/)
  assert.match(csv, /"130","100"/)
  assert.match(csv, /"BLOCK","BLOCKED"/)
  assert.match(csv, /"'=CMD\(\)"/)
  assert.doesNotMatch(csv, /risk_score_demo|ISOLATE|SUCCESS/)
})
