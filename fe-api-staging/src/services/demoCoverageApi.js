import catalog from './demoExpectedCatalog.json' with { type: 'json' }
import { PortalApiError, portalRequest } from './portalApi.js'

const idPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/
const modes = [
  'LIVE',
  'OFFLINE',
  'ISOLATED',
  'STAGING',
  'HISTORICAL',
  'DESIGN_ONLY',
]
const verdicts = ['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA']
const outcomes = [
  'ALLOW',
  'BLOCK',
  'REVIEW_REQUIRED',
  'QUARANTINED',
  'RESTORED',
  'VERIFIED',
  'FAILED',
  'NOT_VERIFIED',
  'NOT_CAPTURED',
]
const bad = () => {
  throw new PortalApiError(
    'Phản hồi Evidence/Demo không đúng schema.',
    502,
    'DEMO_INVALID_SCHEMA'
  )
}
const validId = (value) => typeof value === 'string' && idPattern.test(value)
const ids = (value) =>
  Array.isArray(value) && value.length <= 30 && value.every(validId)
const date = (value) =>
  typeof value === 'string' &&
  value.length < 50 &&
  /(?:Z|[+-]\d\d:\d\d)$/.test(value) &&
  Number.isFinite(Date.parse(value))
const enums = (value, allowed) =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.length <= 6 &&
  value.every((item) => allowed.includes(item))

export const expectedScenes = catalog.map((scene) => ({
  ...scene,
  expected_modes: [...scene.expected_modes],
  run_id: null,
  context: 'DESIGN',
  basis: 'DESIGN_EXPECTED',
  execution_modes: ['DESIGN_ONLY'],
  mode: null,
  observed_outcome: null,
  verdict: 'NOT_EXECUTED',
  evidence_refs: [],
  missing_evidence_refs: [],
  last_evaluated_at: null,
  reason_codes: ['OBSERVATION_NOT_IMPORTED'],
}))

// Routes come only from the checked-in catalog, never an artifact-provided URL.
export function sceneRoute(sceneId) {
  return (
    catalog.find((scene) => scene.scenario_id === sceneId)?.portal_route || null
  )
}

export function readCoverage(data) {
  if (
    data?.schema_version !== 'portal-demo-coverage-2' ||
    data.has_more !== false ||
    data.next_cursor !== null ||
    data.expected_scene_count !== 16 ||
    data.strict_ready !== 'UNKNOWN' ||
    data.strict_reason !== 'P19_SOURCE_NOT_CONNECTED' ||
    !Array.isArray(data.runs) ||
    !data.runs.length ||
    data.runs.length > 32 ||
    !Array.isArray(data.items) ||
    data.items.length !== data.runs.length * 16
  )
    bad()
  const runs = data.runs.map((run) => {
    if (
      !validId(run.run_id) ||
      !['TEST', 'EVALUATION', 'LIVE'].includes(run.context) ||
      !date(run.data_as_of)
    )
      bad()
    return {
      run_id: run.run_id,
      context: run.context,
      data_as_of: run.data_as_of,
    }
  })
  if (new Set(runs.map((run) => run.run_id)).size !== runs.length) bad()
  const seen = new Set()
  const items = data.items.map((row) => {
    const definition = catalog.find(
      (scene) => scene.scenario_id === row.scenario_id
    )
    const run = runs.find((run) => run.run_id === row.run_id)
    const key = `${row.run_id}:${row.scenario_id}`
    if (
      !definition ||
      !run ||
      seen.has(key) ||
      row.context !== run.context ||
      !enums(row.execution_modes, modes) ||
      !verdicts.includes(row.verdict) ||
      !ids(row.evidence_refs) ||
      !ids(row.missing_evidence_refs) ||
      !['IMPORTED_OBSERVATION', 'DESIGN_EXPECTED'].includes(row.basis) ||
      !(
        row.observed_outcome === null || outcomes.includes(row.observed_outcome)
      ) ||
      !(row.last_evaluated_at === null || date(row.last_evaluated_at)) ||
      !Array.isArray(row.reason_codes) ||
      !row.reason_codes.every((code) => /^[A-Z_]{1,100}$/.test(code))
    )
      bad()
    if (
      row.basis === 'DESIGN_EXPECTED' &&
      (row.verdict !== 'NOT_EXECUTED' ||
        row.observed_outcome !== null ||
        row.evidence_refs.length ||
        row.last_evaluated_at !== null ||
        row.execution_modes.join(',') !== 'DESIGN_ONLY')
    )
      bad()
    seen.add(key)
    return {
      ...definition,
      run_id: run.run_id,
      context: run.context,
      basis: row.basis,
      execution_modes: [...row.execution_modes],
      verdict: row.verdict,
      observed_outcome: row.observed_outcome,
      evidence_refs: [...row.evidence_refs],
      missing_evidence_refs: [...row.missing_evidence_refs],
      last_evaluated_at: row.last_evaluated_at,
      reason_codes: [...row.reason_codes],
    }
  })
  if (
    !Number.isInteger(data.observed_scene_count) ||
    data.observed_scene_count !==
      items.filter((row) => row.basis === 'IMPORTED_OBSERVATION').length
  )
    bad()
  return {
    schema_version: data.schema_version,
    runs,
    items,
    strict_ready: 'UNKNOWN',
    strict_reason: data.strict_reason,
  }
}

const exactNotes = [
  'integrity=BYTE_HASH_MATCH_AT_IMPORT',
  'hash_basis=SUPPLIED_MANIFEST; not testcase PASS or human signoff',
  'source_bytes_not_served; current_source_hash_not_rechecked',
]
function safeNote(note) {
  if (typeof note !== 'string') return false
  if (exactNotes.includes(note)) return true
  if (/^(run_id|source_host)=/.test(note)) return validId(note.split('=')[1])
  if (/^context=(TEST|EVALUATION|LIVE)$/.test(note)) return true
  if (/^scene_ids=(SC-(0[1-9]|1[0-6])(,SC-(0[1-9]|1[0-6]))*)?$/.test(note))
    return true
  if (note.startsWith('imported_at=')) return date(note.slice(12))
  return /^original_sha256_unverified=[a-f0-9]{64}$/.test(note)
}

export function readEvidence(data, expectedId = null) {
  const source = data?.provenance
  if (
    !validId(data?.evidence_id) ||
    ![
      'SCENE_SUMMARY',
      'ACTION_SUMMARY',
      'RECOVERY_SUMMARY',
      'SCREENSHOT',
      'OTHER_WITHHELD',
    ].includes(data.evidence_kind) ||
    !['RUN', 'EVENT', 'INCIDENT', 'ACTION', 'RESTORE'].includes(
      data.related_entity_type
    ) ||
    !validId(data.related_entity_id) ||
    !['PROXY', 'CONTROLLER', 'G07', 'TEST'].includes(data.source_system) ||
    !['SANITIZED', 'WITHHELD'].includes(data.sanitization_state) ||
    data.download_allowed !== false ||
    data.access_method !== 'METADATA_ONLY' ||
    !/^[a-f0-9]{64}$/.test(data.sha256) ||
    !Number.isInteger(data.size_bytes) ||
    data.size_bytes < 0 ||
    data.size_bytes > 1048576 ||
    !date(data.captured_at) ||
    !Array.isArray(data.notes) ||
    data.notes.length > 16 ||
    !data.notes.every(safeNote) ||
    source?.freshness_state !== 'HISTORICAL' ||
    source.coverage_kind !== 'NOT_PROVEN' ||
    !date(source.read_at) ||
    !date(source.data_as_of) ||
    !date(source.observed_at) ||
    source.source_ref !== `sha256:${data.sha256}`
  )
    bad()
  if (expectedId !== null && data.evidence_id !== expectedId) bad()
  return Object.fromEntries(
    [
      'evidence_id',
      'evidence_kind',
      'related_entity_type',
      'related_entity_id',
      'sha256',
      'size_bytes',
      'captured_at',
      'source_system',
      'sanitization_state',
      'download_allowed',
      'access_method',
      'notes',
    ]
      .map((key) => [key, data[key]])
      .concat([
        [
          'provenance',
          {
            source_system: data.source_system,
            source_ref: source.source_ref,
            freshness_state: 'HISTORICAL',
            coverage_kind: 'NOT_PROVEN',
            data_as_of: source.data_as_of,
            observed_at: source.observed_at,
            read_at: source.read_at,
          },
        ],
      ])
  )
}

export function demoFilters(hash) {
  const params = new URLSearchParams(hash.split('?')[1] || '')
  return {
    run: validId(params.get('run')) ? params.get('run') : '',
    mode: modes.includes(params.get('mode')) ? params.get('mode') : '',
    verdict: verdicts.includes(params.get('verdict'))
      ? params.get('verdict')
      : '',
  }
}

export function demoBookmark(filters) {
  const params = new URLSearchParams()
  if (validId(filters.run)) params.set('run', filters.run)
  if (modes.includes(filters.mode)) params.set('mode', filters.mode)
  if (verdicts.includes(filters.verdict)) params.set('verdict', filters.verdict)
  return '#/system/demo-coverage' + (params.size ? `?${params}` : '')
}

export async function loadDemoCoverage(options) {
  return readCoverage(
    (await portalRequest('/system/demo-coverage', options)).data
  )
}
export async function loadEvidence(id, options) {
  if (!validId(id)) bad()
  return readEvidence(
    (await portalRequest(`/evidence/${encodeURIComponent(id)}`, options)).data,
    id
  )
}
