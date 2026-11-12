import test from 'node:test'
import assert from 'node:assert/strict'
import {
  readIncidentFilterSupport,
  initialIncidentDraft,
  incidentRequestFilters,
  incidentFilterSearch,
  withoutUnsupportedIncidentFilters,
  incidentLocalTime,
  incidentUtcTime,
} from './incidentFilters.js'

const readonly = readIncidentFilterSupport({
  review_state: false,
  response_states: ['UNKNOWN'],
})
const full = readIncidentFilterSupport({
  review_state: true,
  response_states: ['NONE', 'QUARANTINED', 'RESTORED', 'UNKNOWN'],
})

test('unknown or malformed filter support grants no features and is independent of write role', () => {
  assert.deepEqual(readIncidentFilterSupport(), {
    review_state: false,
    response_states: [],
  })
  assert.deepEqual(
    readIncidentFilterSupport({
      review_state: 'true',
      response_states: ['UNKNOWN', 'UNKNOWN', 'FAKE', 1],
    }),
    readonly
  )
  assert.equal(
    readIncidentFilterSupport({ review_state: true }).review_state,
    true
  )
})

test('readonly supports UNKNOWN filter but blocks unavailable review/response without sending a broad query', () => {
  assert.equal(
    incidentRequestFilters({ response_state: 'UNKNOWN' }, readonly).error,
    ''
  )
  for (const params of [
    { review_state: 'UNREVIEWED' },
    { response_state: 'QUARANTINED' },
  ]) {
    const result = incidentRequestFilters(params, readonly)
    assert.equal(result.unsupported, true)
    assert.ok(result.error)
    assert.deepEqual(result.filters, params)
  }
  assert.equal(
    incidentRequestFilters(
      { review_state: 'REVIEWED', response_state: 'RESTORED' },
      full
    ).error,
    ''
  )
})

test('recovering an unsupported deep link preserves time and supported investigation filters', () => {
  const input = {
    source_ip: '10.0.0.204',
    signal_rule: 'CORR-002',
    from: '2026-10-27T00:00:00Z',
    to: '2026-10-28T00:00:00Z',
    review_state: 'REVIEWED',
    response_state: 'UNKNOWN',
  }
  const values = Object.fromEntries(
    new URLSearchParams(withoutUnsupportedIncidentFilters(input, readonly))
  )
  assert.equal(values.review_state, undefined)
  assert.equal(values.response_state, 'UNKNOWN')
  assert.equal(values.from, input.from)
  assert.equal(values.source_ip, input.source_ip)
  assert.equal(input.review_state, 'REVIEWED')
})

test('UTC+7 local inputs retain second precision and cross UTC date boundaries correctly', () => {
  assert.equal(
    incidentUtcTime('2026-10-28T00:15:30', 'Asia/Ho_Chi_Minh'),
    '2026-10-27T17:15:30.000Z'
  )
  assert.equal(
    incidentLocalTime('2026-10-27T17:15:30Z', 'Asia/Ho_Chi_Minh'),
    '2026-10-28T00:15:30'
  )
  assert.equal(
    incidentUtcTime('2026-10-27T17:15', 'UTC'),
    '2026-10-27T17:15:00.000Z'
  )
  assert.equal(incidentUtcTime('', 'UTC'), '')
})

test('invalid and impossible local dates never normalize silently into another day', () => {
  for (const input of ['2026-02-30T12:00', '2026-10-31T25:10', 'garbage'])
    assert.equal(incidentUtcTime(input, 'UTC'), null)
})

test('explicit historical ranges retain original timestamps including microseconds', () => {
  const draft = initialIncidentDraft({
    from: '2026-10-27T16:49:04.262123Z',
    to: '2026-10-28T00:00:00Z',
    signal_rule: 'CORR-002',
  })
  assert.equal(draft.window, 'custom')
  const query = new URLSearchParams(
    incidentFilterSearch(draft, readonly).search
  )
  assert.equal(query.get('from'), draft.from)
  assert.equal(query.get('to'), draft.to)
})

test('relative presets use one anchor and remain fixed across polling/reload', () => {
  const now = Date.parse('2026-10-31T10:00:00Z')
  const result = incidentFilterSearch(
    { window: '15', source_ip: '10.0.0.204' },
    readonly,
    now
  )
  const query = Object.fromEntries(new URLSearchParams(result.search))
  assert.equal(query.from, '2026-10-31T09:45:00.000Z')
  assert.equal(query.to, '2026-10-31T10:00:00.000Z')
  assert.equal(initialIncidentDraft(query).window, '15')
  assert.equal(incidentRequestFilters(query, readonly).filters.to, query.to)
  assert.equal(
    incidentRequestFilters(query, readonly).filters.window,
    undefined
  )
})

test('all-history clears only the time range, preserving the other filters', () => {
  const query = new URLSearchParams(
    incidentFilterSearch(
      {
        window: 'all',
        from: '2026-10-27T00:00:00Z',
        to: '2026-10-28T00:00:00Z',
        severity: 'HIGH',
      },
      readonly
    ).search
  )
  assert.equal(query.get('from'), null)
  assert.equal(query.get('to'), null)
  assert.equal(query.get('severity'), 'HIGH')
})

test('reversed, oversized and unzoned ranges are rejected before requesting the backend', () => {
  for (const params of [
    { from: '2026-10-28T00:00:00Z', to: '2026-10-27T00:00:00Z' },
    { from: '2026-09-01T00:00:00Z', to: '2026-10-31T00:00:00Z' },
    { from: '2026-10-27T00:00:00' },
  ])
    assert.ok(incidentRequestFilters(params, readonly).error)
  assert.ok(
    incidentFilterSearch({ window: 'custom', from: '', to: '' }, readonly).error
  )
})

test('API query allowlist excludes UI fields and unrelated URL input', () => {
  const result = incidentRequestFilters(
    {
      source_ip: '10.0.0.204',
      window: '15',
      cursor: 'injected',
      limit: '100000',
      token: 'PRIVATE',
    },
    readonly
  )
  assert.deepEqual(result.filters, { source_ip: '10.0.0.204' })
})
