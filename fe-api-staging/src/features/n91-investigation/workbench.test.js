import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  canReadWorkbench,
  eventHref,
  parseInvestigation,
  parseResponseHistory,
  resolveLegacyIdentity,
  resetsMemberPage,
  workbenchTab,
} from './workbenchModel.js'
import { readInvestigation } from './workbenchApi.js'
import { historyFixture } from './tests/responseHistoryFixture.js'

const fixture = JSON.parse(
  readFileSync(new URL('./tests/workbench-test-partial.json', import.meta.url))
)
const pair = fixture.data.identity
const fresh = () => structuredClone(fixture)
const rejected = (edit) => {
  const p = fresh()
  edit(p)
  assert.throws(() => parseInvestigation(p, pair), {
    code: 'INVESTIGATION_INVALID_RESPONSE',
  })
}

test('P0-05 preserves standalone PARTIAL history, null versus observed empty SG, and exact pairs', () => {
  const standalone = parseResponseHistory(historyFixture(pair.incident_id))
  assert.equal(standalone.stream_id, null)
  assert.equal(standalone.cycles[0].history.DURING, null)
  assert.deepEqual(standalone.cycles[0].history.AFTER.security_group_ids, [])
  assert.equal(standalone.cycles[0].current_state, 'UNKNOWN')
  const aggregate = fresh()
  aggregate.meta.source_context = 'TEST'
  aggregate.data.response = historyFixture(pair.incident_id, pair.stream_id)
  assert.equal(parseInvestigation(aggregate, pair).data.response.cycles[0].metrics[0].seconds, 20.125)
  assert.throws(() => parseResponseHistory(aggregate.data.response), { code: 'INVESTIGATION_INVALID_RESPONSE' })
  for (const edit of [
    (history) => { history.stream_id = 'TEST-other-stream' },
    (history) => { history.cycles[0].history.AFTER.port_id = 'TEST-other-port' },
    (history) => { history.cycles[0].metrics[0].cycle_id = 'TEST-other-cycle' },
    (history) => { history.cycles[0].current_state = 'RESTORED' },
  ]) {
    const invalid = structuredClone(aggregate)
    edit(invalid.data.response)
    assert.throws(() => parseInvestigation(invalid, pair), { code: 'INVESTIGATION_INVALID_RESPONSE' })
  }
})

test('P0-03 preserves provisional source semantics and separate counts', () => {
  const p = parseInvestigation(fixture, pair)
  assert.equal(p.data.incident.source_verified, false)
  assert.equal(p.data.incident.isolation_authorized, false)
  assert.equal(p.data.incident.severity, 'HIGH')
  assert.equal(p.data.incident.peak_p15, 100)
  assert.equal(p.data.event_members.verified_linked_count, 0)
  assert.equal(p.data.event_members.membership, 'RECONSTRUCTED_WINDOW')
  assert.equal(p.data.event_members.candidate_basis, 'LEGACY_UNPINNED')
  assert.equal(p.meta.data_as_of, null)
  assert.equal(p.meta.sources[0].observed_at, null)
  assert.equal(p.data.response.outcome, null)
  p.data.incident.source_verified = true
  assert.equal(
    fixture.data.incident.source_verified,
    false,
    'wire data is not mutated'
  )
})
test('schema/version/unknown-key guard is closed at every boundary', () => {
  rejected((p) => {
    p.data.schema_version = 'portal-investigation-2'
  })
  rejected((p) => {
    p.data.response.actions = []
  })
  rejected((p) => {
    p.meta.sources[0].path = '/var/private'
  })
  rejected((p) => {
    p.data.event_members.items[0].canonical.raw_sql = 'secret'
  })
  rejected((p) => {
    p.data.analyst_case.write_enabled = true
  })
})
test('identity is exact in incident/member/canonical/alert/overlay; no IP fallback', () => {
  assert.throws(() =>
    parseInvestigation(fixture, { ...pair, stream_id: 'OTHER' })
  )
  rejected((p) => {
    p.data.incident.incident_id = 'OTHER'
  })
  rejected((p) => {
    p.data.event_members.items[0].event_ref.stream_id = 'OTHER'
  })
  rejected((p) => {
    p.data.event_members.items[0].canonical.event_id = 'OTHER'
  })
  rejected((p) => {
    p.data.alerts.items[0].stream_id = 'OTHER'
  })
})
test('canonical missing request stays unknown; request mismatch must not produce a canonical link', () => {
  const missing = fresh()
  missing.data.event_members.items[0].canonical.request_id = null
  assert.equal(
    parseInvestigation(missing, pair).data.event_members.items[0].canonical
      .request_id,
    null
  )
  rejected((p) => {
    p.data.event_members.items[0].canonical.request_id = 'WRONG'
  })
  const mismatch = fresh(),
    e = mismatch.data.event_members.items[0]
  e.canonical = null
  e.canonical_availability = 'MISMATCH'
  e.join_state = 'MISMATCH'
  e.reason_codes = ['CANONICAL_REQUEST_ID_MISMATCH']
  assert.equal(
    parseInvestigation(mismatch, pair).data.event_members.items[0].canonical,
    null
  )
  rejected((p) => {
    p.data.event_members.items[0].canonical_availability = 'UNAVAILABLE'
  })
})
test('null is distinct from zero; ERROR score and unavailable totals remain unknown', () => {
  const p = fresh()
  p.data.event_members.items[0].projection.risk = {
    status: 'ERROR',
    score: null,
    severity: null,
  }
  p.data.event_members.total_candidates = null
  p.data.event_members.verified_linked_count = null
  assert.equal(
    parseInvestigation(p, pair).data.event_members.items[0].projection.risk
      .score,
    null
  )
  rejected((p) => {
    p.data.incident.peak_p15 = '100'
  })
  rejected((p) => {
    p.data.incident.source_verified = 0
  })
  rejected((p) => {
    p.data.incident.first_seen = '2026-11-08T01:00:00'
  })
})
test('page must preserve opaque cursor, limit and authoritative totals', () => {
  rejected((p) => {
    p.meta.next_cursor = 'different'
  })
  rejected((p) => {
    p.data.event_members.has_more = false
  })
  rejected((p) => {
    p.data.event_members.authoritative_count = 99
  })
  rejected((p) => {
    p.data.event_members.items.push(
      structuredClone(p.data.event_members.items[0])
    )
  })
  assert.equal(
    resetsMemberPage({ status: 409, code: 'INVESTIGATION_SOURCE_CHANGED' }),
    true
  )
  assert.equal(
    resetsMemberPage({ status: 422, code: 'INVESTIGATION_CURSOR_INVALID' }),
    true
  )
  assert.equal(
    resetsMemberPage({ status: 409, code: 'INVESTIGATION_IDENTITY_CONFLICT' }),
    false
  )
  assert.equal(
    resetsMemberPage({ status: 503, code: 'INVESTIGATION_SOURCE_INVALID' }),
    false
  )
})
test('SESSION Viewer never calls aggregate; observation permission remains server owned', () => {
  assert.equal(
    canReadWorkbench(
      { status: 'authenticated', user: { roles: ['Viewer'] } },
      true
    ),
    false
  )
  assert.equal(
    canReadWorkbench(
      { status: 'authenticated', user: { roles: ['Analyst'] } },
      true
    ),
    true
  )
  assert.equal(
    canReadWorkbench(
      { status: 'authenticated', user: { roles: ['admin'] } },
      true
    ),
    false
  )
  assert.equal(canReadWorkbench({ status: 'local_snapshot' }, false), true)
  assert.equal(canReadWorkbench({ status: 'checking' }, false), false)
})
test('legacy resolution requires server response exact ID and nonempty stream', () => {
  assert.deepEqual(resolveLegacyIdentity(pair, pair.incident_id), pair)
  assert.equal(
    resolveLegacyIdentity({ ...pair, incident_id: 'WRONG' }, pair.incident_id),
    null
  )
  assert.equal(
    resolveLegacyIdentity({ ...pair, stream_id: '' }, pair.incident_id),
    null
  )
  assert.equal(
    resolveLegacyIdentity({ ...pair, stream_id: '../bad' }, pair.incident_id),
    null
  )
})
test('event deep links pin source and stream; wb_tab never changes other page tab semantics', () => {
  const ref = fixture.data.event_members.items[0].event_ref
  assert.equal(
    eventHref(ref, 'canonical'),
    `#/events/${ref.event_id}?stream_id=${ref.stream_id}&source=canonical`
  )
  assert.match(eventHref(ref, 'p17'), /source=p17$/)
  assert.equal(eventHref({ ...ref, stream_id: 'bad/x' }, 'p17'), null)
  assert.equal(workbenchTab('response'), 'response')
  assert.equal(workbenchTab('javascript:alert(1)'), 'overview')
})
test('API sends only exact pair, fixed limit and untouched signed cursor', async () => {
  let request
  const signal = new AbortController().signal
  const p = await readInvestigation(pair, {
    cursor: 'opaque+/cursor=',
    signal,
    fetcher: async (url, options) => {
      request = { url, options }
      return { ok: true, status: 200, json: async () => fixture }
    },
  })
  const url = new URL(request.url, 'http://test')
  assert.equal(
    url.pathname,
    `/api/v1/portal/incidents/${pair.incident_id}/investigation`
  )
  assert.equal(url.searchParams.get('stream_id'), pair.stream_id)
  assert.equal(url.searchParams.get('events_limit'), '25')
  assert.equal(url.searchParams.get('events_cursor'), 'opaque+/cursor=')
  assert.equal(request.options.method, 'GET')
  assert.equal(request.options.credentials, 'include')
  assert.equal(p.meta.source_context, 'TEST')
})
test('API authorization, invalid cursor and corrupt aggregate stay typed failures', async () => {
  for (const [status, code] of [
    [403, 'INVESTIGATION_ROLE_REQUIRED'],
    [422, 'INVESTIGATION_CURSOR_INVALID'],
    [409, 'INVESTIGATION_SOURCE_CHANGED'],
  ]) {
    await assert.rejects(
      readInvestigation(pair, {
        fetcher: async () => ({
          ok: false,
          status,
          json: async () => ({
            data: null,
            meta: { request_id: 'TEST-request' },
            error: { code },
          }),
        }),
      }),
      { status, code }
    )
  }
  await assert.rejects(
    readInvestigation(pair, {
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ data: {}, meta: {} }),
      }),
    }),
    { code: 'INVESTIGATION_INVALID_RESPONSE' }
  )
})
