import { expectedScenes } from './demoCoverageApi.js'
import { PortalApiError } from './portalApi.js'

const scenes = expectedScenes.map((row) => row.scenario_id)
const statuses = ['OBSERVED_LIMITED', 'PARTIAL', 'NOT_EXECUTED', 'UNAVAILABLE']
const outcomes = [
  'PREFLIGHT_OBSERVED', 'ALLOW', 'BLOCK', 'CORR002_CANDIDATES', 'LAB_QUARANTINE',
  'LAB_RESTORE', 'FIXTURES_PENDING', 'AUDIT_MASKED', 'TLS_HA_SAMPLES',
  'ISOLATED_RECOVERY', 'STAGING_REGRESSION',
]
const hosts = ['app', 'controller', 'g07-restore-c1', 'galera-1', 'galera-2',
  'galera-3', 'p17-lab-clone', 'proxy']
const modes = ['LIVE', 'LIVE_LAB', 'HISTORICAL', 'HISTORICAL_LAB',
  'LIVE_PREFLIGHT', 'ISOLATED', 'STAGING', 'OFFLINE', 'UNKNOWN']
const sha = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const evidenceId = (value) => typeof value === 'string' && /^EVD-[a-f0-9]{64}$/.test(value)
const runId = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/.test(value)
const code = (value) => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(value)
const time = (value) => value === null || (typeof value === 'string' && value.length <= 40 &&
  /(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value)))
const count = (value, max) => Number.isInteger(value) && value >= 0 && value <= max
const hostList = (value) => Array.isArray(value) && value.length <= hosts.length &&
  new Set(value).size === value.length && value.every((host) => hosts.includes(host))

function check(valid) {
  if (!valid) throw new PortalApiError('Phản hồi kiểm chứng chưa hợp lệ.', 502, 'DEFENSE_COVERAGE_INVALID')
}

export function readDefenseCoverage(data) {
  check(data?.schema_version === 'portal-defense-coverage-1' && runId(data.run_id) &&
    ['TEST', 'IMPORTED_UNVERIFIED'].includes(data.context) && data.freshness_state === 'HISTORICAL' &&
    data.strict_ready === 'UNKNOWN' && sha(data.registry_sha256) &&
    count(data.verified_archive_count, 8) && count(data.artifact_count, 1024) &&
    hostList(data.missing_hosts) && hostList(data.unavailable_hosts) &&
    data.missing_hosts.every((host) => !data.unavailable_hosts.includes(host)) &&
    data.verified_archive_count + data.missing_hosts.length + data.unavailable_hosts.length === 8 &&
    Array.isArray(data.scenes) && data.scenes.length === scenes.length)
  data.scenes.forEach((row, index) => {
    check(row?.scene_id === scenes[index] && statuses.includes(row.status) &&
      (row.outcome === null || outcomes.includes(row.outcome)) &&
      (row.reason === null || code(row.reason)) && time(row.observed_at) &&
      Array.isArray(row.evidence) && row.evidence.length <= 8 &&
      row.metrics && typeof row.metrics === 'object' && !Array.isArray(row.metrics))
    check(new Set(row.evidence.map((ref) => ref?.evidence_id)).size === row.evidence.length)
    if (['OBSERVED_LIMITED', 'PARTIAL'].includes(row.status))
      check(row.outcome !== null && row.evidence.length > 0)
    if (row.status === 'UNAVAILABLE')
      check(row.outcome === null && !row.evidence.length && row.observed_at === null)
    row.evidence.forEach((ref) => {
      check(evidenceId(ref?.evidence_id) && sha(ref.sha256) && hosts.includes(ref.host) &&
        !data.missing_hosts.includes(ref.host) && !data.unavailable_hosts.includes(ref.host) &&
        code(ref.label) && count(ref.size_bytes, 8 * 1024 * 1024) && modes.includes(ref.origin_mode) &&
        ['LAB', 'UNKNOWN'].includes(ref.scope) && time(ref.manifest_created_at) &&
        ref.raw_download_allowed === false)
    })
  })
  return data
}

export function defenseCoverageHref(run, scene, evidence) {
  if (!runId(run) || (scene && !scenes.includes(scene)) ||
      (evidence && (!scene || !evidenceId(evidence)))) return null
  const params = new URLSearchParams({ run, view: 'defense' })
  if (scene) params.set('scene', scene)
  if (evidence) params.set('evidence', evidence)
  return '#/system/demo-coverage?' + params
}

export function selectedDefenseEvidence(data, params) {
  if (data.run_id !== params.get('run')) return null
  const scene = data.scenes.find((row) => row.scene_id === params.get('scene'))
  const ref = scene?.evidence.find((row) => row.evidence_id === params.get('evidence'))
  return ref ? { scene, ref } : null
}
