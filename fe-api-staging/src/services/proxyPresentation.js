const count = value => Number.isInteger(value) && value >= 0 ? value : null
export function dashboardMetrics(summary, isolated) {
  const data = summary.error ? null : summary.data
  const meta = isolated.meta
  return {
    total: count(data?.projection_counts?.processed_events) ?? (data ? count(summary.meta?.available_records) : null),
    blocked: data ? count(summary.meta?.retained_counts?.block) ?? count(data?.event_counts?.block) : null,
    review: count(data?.incident_counts?.review_required),
    isolated: !isolated.error && isolated.data && ['LIVE', 'REMOTE_READONLY'].includes(meta?.source_mode) && meta?.network_classification === 'CONFIGURED' && meta?.freshness_state === 'FRESH' ? count(meta.total_count) : null,
  }
}
export function galeraNodeState(node) {
  const valid = node?.source_mode === 'SNAPSHOT' && node.scope === 'LOCAL_SOCKET_WSREP' && node.read_ok === true && typeof node.source_ref === 'string' && Number.isFinite(Date.parse(node.observed_at))
  return { valid, fresh: valid && node.observation_freshness_state === 'FRESH' && node.collection_freshness_state === 'FRESH' }
}
export function sourceReadTimestamp(source, field) {
  if (source[field]) return source[field]
  return source.source_schema === 'audit-v1.0' && source.data_as_of ? 'NO_SEPARATE_TIMESTAMP' : null
}
export function evidenceDecision(evidence) {
  const blocked = evidence.blocked ?? evidence.trace?.p14?.blocked
  return blocked === true ? 'BLOCK' : blocked === false ? 'ALLOW' : 'UNKNOWN'
}

export function isolationEpisodes(rows) {
  const changes = (Array.isArray(rows) ? rows : []).filter(row =>
    row && ['NORMAL', 'QUARANTINED', 'MISMATCH', 'UNKNOWN'].includes(row.state) && Number.isFinite(Date.parse(row.observed_at))
  ).slice().sort((a, b) => Date.parse(a.observed_at) - Date.parse(b.observed_at))
  const episodes = []
  let active = null
  for (const row of changes) {
    if (row.state === 'QUARANTINED') {
      if (active) episodes.push(active)
      active = { started: row.observed_at, restored: null }
    } else if (row.state === 'NORMAL') {
      if (active) {
        episodes.push({ ...active, restored: row.observed_at })
        active = null
      } else if (row.previous_state === 'QUARANTINED') {
        episodes.push({ started: null, restored: row.observed_at })
      }
    } else if (active) {
      // An unknown interval breaks continuity; a later NORMAL observation
      // cannot prove restoration of this particular isolation episode.
      episodes.push(active)
      active = null
    }
  }
  if (active) episodes.push(active)
  return episodes.reverse()
}
