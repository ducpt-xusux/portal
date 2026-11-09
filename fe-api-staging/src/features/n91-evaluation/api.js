import { portalRequest, PortalApiError } from '../../services/portalApi.js'

const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/.test(value)
const date = value => typeof value === 'string' && /(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value))
const ids = value => Array.isArray(value) && value.length <= 100 && value.every(id) && new Set(value).size === value.length
const invalid = () => { throw new PortalApiError('Evaluation/System schema unavailable.', 502, 'EVALUATION_SYSTEM_INVALID_SCHEMA') }
const modes = ['LIVE', 'ISOLATED', 'STAGING', 'HISTORICAL']
const contexts = ['TEST', 'EVALUATION', 'LIVE']
const partitions = ['LIVE_READ_ONLY', 'OFFLINE_POLICY', 'PROTOCOL_OFFLINE', 'P17_OFFLINE']
const verdicts = ['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA']
export const kinds = ['backups','recoveries','resilience','tls','privacy','staging','p19']
const numberOrNull = value => value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0

function scope(value, expectedRun) {
  if (!id(value?.run_id) || expectedRun && value.run_id !== expectedRun || !contexts.includes(value.context) ||
    !modes.includes(value.execution_mode) || !id(value.source_system) || !date(value.data_as_of) ||
    !date(value.observed_at) || value.freshness_state !== 'HISTORICAL') invalid()
}
function linked(value, run) { scope(value?.scope, run); if (!ids(value.evidence_refs)) invalid() }

export function readEvaluation(data, run) {
  if (data?.schema_version !== 'n91-evaluation-panel-1' || data.run?.run_id !== run ||
      data.catalog_basis !== 'DESIGN_ONLY' || data.catalog_flag !== 'NOT_RUN' ||
      !Array.isArray(data.cases) || !Array.isArray(data.correlations) || data.expected_correlations !== 13) invalid()
  const expected = [18,32,3,7]
  partitions.forEach((key, i) => {
    if (data.expected_partitions?.[key] !== expected[i] || !Number.isInteger(data.observed_partitions?.[key]) ||
        data.observed_partitions[key] < 0 || data.observed_partitions[key] > expected[i]) invalid()
  })
  const seen = new Set()
  for (const row of data.cases) {
    linked(row, run)
    if (!/^C-0(0[1-9]|[1-5][0-9]|60)$/.test(row.case_id) || seen.has(row.case_id) ||
        !partitions.includes(row.partition) || !verdicts.includes(row.verdict) || !ids(row.request_refs) ||
        !ids(row.event_refs) || !ids(row.incident_refs) || !numberOrNull(row.request_count) ||
        row.request_count !== null && row.request_count !== row.request_refs.length ||
        row.verdict === 'PASS' && (row.observed_action === null || !row.evidence_refs.length) ||
        row.scope.execution_mode === 'LIVE' && row.partition !== 'LIVE_READ_ONLY') invalid()
    seen.add(row.case_id)
  }
  const corr = new Set()
  for (const row of data.correlations) {
    linked(row, run)
    if (!id(row.scenario_id) || corr.has(row.scenario_id) || !verdicts.includes(row.verdict) ||
        !Number.isInteger(row.input_event_count) || row.input_event_count < 0 ||
        ![true,false,null].includes(row.observed_incident) || !['ISOLATED','HISTORICAL'].includes(row.scope.execution_mode) ||
        row.verdict === 'PASS' && (row.observed_incident === null || !row.evidence_refs.length)) invalid()
    corr.add(row.scenario_id)
  }
  return data
}

export function readPanel(data, kind) {
  if (!kinds.includes(kind) || data?.schema_version !== 'n91-system-panel-1' || data.kind !== kind ||
      !Array.isArray(data.items) || !data.items.length || data.items.length > 100) invalid()
  for (const row of data.items) {
    linked(row)
    if (kind === 'recoveries' && (row.production_rpo_seconds !== null || row.production_rto_seconds !== null ||
        row.production_rpo_measured !== false || row.full_app_proxy_galera_rto_measured !== false ||
        row.unit !== 'seconds' || !numberOrNull(row.rpo_gap_seconds) || !numberOrNull(row.lab_rto_seconds) ||
        row.lost_marker_count > 0 && row.rpo_gap_seconds === 0 || row.production_measurement !== 'NOT_MEASURED')) invalid()
    if (kind === 'staging' && (row.scope.execution_mode !== 'STAGING' || row.production_cutover_verified !== false ||
        !['OPEN','UNKNOWN'].includes(row.production_status) || !Number.isInteger(row.passed) || row.passed > row.total)) invalid()
    if (kind === 'p19' && (row.strict_ready !== false || !['SIGNED_LAB_SCOPE','UNAVAILABLE'].includes(row.authority) ||
        row.authority === 'UNAVAILABLE' && row.lab_scope_status !== 'UNKNOWN')) invalid()
    if (kind === 'tls' && (!['OPEN','UNKNOWN'].includes(row.handshake_retry_limitation) ||
        row.status === 'VERIFIED' && (!['TLSv1.2','TLSv1.3'].includes(row.negotiated_version) || row.peer_verified !== true || !row.evidence_refs.length))) invalid()
    if (kind === 'privacy' && (!['RECENT_SAMPLE','ISOLATED_CANARY'].includes(row.coverage_kind) || row.masked_count > row.sample_count)) invalid()
  }
  return data
}

export function evidenceRoute(evidenceId) { if (!id(evidenceId)) invalid(); return `/evidence/${encodeURIComponent(evidenceId)}` }
export function filterCases(rows, { partition = '', mode = '', verdict = '' }) {
  return rows.filter(row => (!partition || row.partition === partition) && (!mode || row.scope.execution_mode === mode) && (!verdict || row.verdict === verdict))
}
export function createEvaluationApi(request = portalRequest) {
  return {
    async catalog(options) {
      const response = await request('/n91/evaluation-system/catalog', options)
      const data = response.data
      if (data?.schema_version !== 'n91-evaluation-design-catalog-1' || data.basis !== 'DESIGN_ONLY' ||
          data.cases?.length !== 60 || data.correlations?.length !== 13 ||
          data.cases.some(r => r.catalog_flag !== 'NOT_RUN' || r.basis !== 'DESIGN_ONLY')) invalid()
      return response
    },
    async runs(options) { return request('/evaluations/runs', options) },
    async evaluation(run, options) {
      if (!id(run)) invalid()
      const response = await request(`/n91/evaluation-system/runs/${encodeURIComponent(run)}`, options)
      return { ...response, data: readEvaluation(response.data, run) }
    },
    async panel(kind, options) {
      if (!kinds.includes(kind)) invalid()
      const response = await request(`/n91/evaluation-system/panels/${kind}`, options)
      return { ...response, data: readPanel(response.data, kind) }
    },
  }
}
