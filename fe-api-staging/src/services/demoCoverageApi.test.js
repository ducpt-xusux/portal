import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { expectedScenes, readCoverage, readEvidence, sceneRoute, demoFilters, demoBookmark, loadDemoCoverage, loadEvidence } from './demoCoverageApi.js'

const fixture = name => JSON.parse(readFileSync(new URL(`../../tests/fixtures/${name}-response.json`, import.meta.url)))

test('16 design scenes contain no invented observations, evidence, time or PASS', () => {
  assert.equal(expectedScenes.length, 16)
  assert.equal(new Set(expectedScenes.map(row => row.scenario_id)).size, 16)
  for (const row of expectedScenes) {
    assert.equal(row.basis, 'DESIGN_EXPECTED'); assert.equal(row.context, 'DESIGN')
    assert.equal(row.observed_outcome, null); assert.equal(row.last_evaluated_at, null)
    assert.equal(row.verdict, 'NOT_EXECUTED'); assert.deepEqual(row.evidence_refs, [])
    assert.deepEqual(row.execution_modes, ['DESIGN_ONLY'])
  }
})

test('actual module API DTO preserves STAGING and ISOLATED with frozen freshness independent', () => {
  const page = readCoverage(fixture('coverage').data)
  assert.equal(page.items.length, 16); assert.equal(page.strict_ready, 'UNKNOWN')
  assert.deepEqual(page.items[14].execution_modes, ['STAGING'])
  assert.deepEqual(page.items[11].execution_modes, ['ISOLATED'])
  assert.deepEqual(page.items[0].execution_modes, ['LIVE'])
  assert.equal(page.items.filter(row => row.basis === 'IMPORTED_OBSERVATION').length, 3)
  assert.ok(page.items.every(row => row.verdict !== 'PASS'))
})

test('registry client rejects wrong schema, incomplete pages, duplicate scenes and counts', () => {
  for (const mutate of [data => data.schema_version = 'old', data => data.has_more = true,
    data => data.items.pop(), data => data.items[1] = data.items[0], data => data.items[0].context = 'LIVE',
    data => data.observed_scene_count = 16, data => data.strict_ready = 'PASS', data => data.runs = [],
    data => data.items[0].execution_modes = ['SECRET'], data => data.items[0].evidence_refs = ['../../private']]) {
    const value = fixture('coverage').data; mutate(value)
    assert.throws(() => readCoverage(value), error => error.code === 'DEMO_INVALID_SCHEMA')
  }
})

test('browser uses checked-in route and expected text allowlists, never source URLs or extra fields', () => {
  const data = fixture('coverage').data
  data.items[0].portal_route = 'https://evil.invalid/private'; data.items[0].title = 'CANARY_PRIVATE'
  data.items[0].api_refs = ['javascript:CANARY_PRIVATE']; data.items[0].raw_sql = 'CANARY_PRIVATE'
  const result = readCoverage(data)
  assert.equal(JSON.stringify(result).includes('CANARY_PRIVATE'), false)
  assert.equal(sceneRoute('SC-01'), '#/system/health')
  assert.equal(sceneRoute('SC-07'), null); assert.equal(sceneRoute('unknown'), null)
})

test('metadata projection discards raw/path/download extras and accepts only typed notes', () => {
  const data = fixture('evidence').data
  const clean = readEvidence({ ...data, raw_sql: 'CANARY_PRIVATE', path: 'CANARY_PRIVATE', url: 'https://invalid' })
  assert.equal(clean.download_allowed, false)
  assert.equal(clean.provenance.freshness_state, 'HISTORICAL')
  assert.equal(clean.sha256.length, 64)
  assert.throws(() => readEvidence(data, 'TEST-different'))
  assert.equal(JSON.stringify(clean).includes('CANARY_PRIVATE'), false)
  for (const patch of [{ notes: ['CANARY_PRIVATE SELECT * FROM secrets'] }, { download_allowed: true },
    { sha256: 'invalid' }, { sanitization_state: 'RAW' }, { size_bytes: -1 }]) {
    assert.throws(() => readEvidence({ ...data, ...patch }))
  }
})

test('filters bookmark only client-supported values with no arbitrary path or URI', () => {
  const filters = { run: 'TEST-module-only', mode: 'STAGING', verdict: 'UNKNOWN' }
  assert.deepEqual(demoFilters(demoBookmark(filters)), filters)
  assert.deepEqual(demoFilters('#/system/demo-coverage?run=../../secret&mode=FAKE&verdict=GREEN'), { run: '', mode: '', verdict: '' })
  assert.equal(demoBookmark({ run: '../../secret', mode: 'FAKE' }), '#/system/demo-coverage')
})

test('loaders request only GET contract routes and no fake server filter params', async () => {
  const requests = []
  const fetcher = async (url, options) => {
    requests.push({ url, options })
    return { ok: true, status: 200, json: async () => fixture(url.includes('/evidence/') ? 'evidence' : 'coverage') }
  }
  await loadDemoCoverage({ fetcher }); await loadEvidence('TEST-SC-15', { fetcher })
  assert.deepEqual(requests.map(row => row.url), ['/api/v1/system/demo-coverage', '/api/v1/evidence/TEST-SC-15'])
  assert.ok(requests.every(row => row.options.method === 'GET' && row.options.cache === 'no-store'))
  await assert.rejects(loadEvidence('../../secret', { fetcher }))
  assert.equal(requests.length, 2)
})

test('unavailable and forbidden stay typed errors and never become empty success', async () => {
  for (const [status, code] of [[503, 'EVIDENCE_SOURCE_NOT_CONFIGURED'], [403, 'EVIDENCE_ROLE_REQUIRED']]) {
    const fetcher = async () => ({ ok: false, status, json: async () => ({ data: null,
      meta: { request_id: 'TEST-request' }, error: { code, message: 'CANARY_PRIVATE_PATH' } }) })
    await assert.rejects(loadDemoCoverage({ fetcher }), error => error.code === code && error.status === status && !error.message.includes('CANARY'))
  }
})
