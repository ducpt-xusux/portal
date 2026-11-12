import assert from 'node:assert/strict'
import test from 'node:test'
import { expectedScenes } from './demoCoverageApi.js'
import { defenseCoverageHref, readDefenseCoverage, selectedDefenseEvidence } from './defenseCoverageApi.js'

const sha = 'a'.repeat(64)
const evidence = { evidence_id: 'EVD-' + sha, host: 'proxy', label: 'NEW_CORR002_AUDIT',
  sha256: sha, size_bytes: 100, origin_mode: 'LIVE', scope: 'UNKNOWN', manifest_created_at: null,
  raw_download_allowed: false }

function fixture() {
  const scenes = expectedScenes.map(({ scenario_id }) => ({
    scene_id: scenario_id, status: 'UNAVAILABLE', outcome: null, reason: null,
    observed_at: null, evidence: [], metrics: {},
  }))
  Object.assign(scenes[4], { status: 'OBSERVED_LIMITED', outcome: 'CORR002_CANDIDATES',
    evidence: [{ ...evidence }], metrics: { event_sequences: [909, 911, 913] } })
  return {
    schema_version: 'portal-defense-coverage-1', run_id: 'TEST-defense', context: 'TEST',
    freshness_state: 'HISTORICAL', strict_ready: 'UNKNOWN', registry_sha256: sha,
    verified_archive_count: 7, artifact_count: 31, missing_hosts: ['galera-3'], unavailable_hosts: [], scenes,
  }
}

test('coverage retains historical access and origin mode as separate fields', () => {
  const result = readDefenseCoverage(fixture())
  assert.equal(result.freshness_state, 'HISTORICAL')
  assert.equal(result.scenes[4].evidence[0].origin_mode, 'LIVE')
  for (const edit of [
    (data) => { data.scenes[4].status = 'PASS' },
    (data) => { data.scenes[4].evidence[0].raw_download_allowed = true },
    (data) => { data.scenes[4].evidence[0].host = 'galera-3' },
    (data) => { data.scenes[5].scene_id = 'SC-05' },
  ]) {
    const data = fixture()
    edit(data)
    assert.throws(() => readDefenseCoverage(data), { code: 'DEFENSE_COVERAGE_INVALID' })
  }
})

test('evidence bookmark resolves only inside the exact run and scene', () => {
  const data = fixture()
  const href = defenseCoverageHref(data.run_id, 'SC-05', evidence.evidence_id)
  const params = new URLSearchParams(href.split('?')[1])
  assert.equal(selectedDefenseEvidence(data, params).ref.evidence_id, evidence.evidence_id)
  params.set('scene', 'SC-06')
  assert.equal(selectedDefenseEvidence(data, params), null)
  params.set('scene', 'SC-05')
  params.set('run', 'TEST-other')
  assert.equal(selectedDefenseEvidence(data, params), null)
  assert.equal(defenseCoverageHref(data.run_id, 'SC-05', 'https://example.com'), null)
})
