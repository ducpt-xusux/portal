import { count, freshness } from './portalApi.js'

export function dashboardEventCounts(data, meta, error = false) {
  const missing = { allow: null, block: null, unknown: null, risk_errors: null }
  if (
    !data ||
    (freshness(meta, error) !== 'FRESH' && meta?.source_mode !== 'SNAPSHOT')
  )
    return missing
  if (
    data.coverage?.complete === false &&
    data.coverage.records_in_window === 0
  )
    return missing
  return Object.fromEntries(
    Object.keys(missing).map((key) => [key, count(data.event_counts?.[key])])
  )
}

export function dashboardSeriesPoints(data, meta, error = false) {
  if (
    !data ||
    (freshness(meta, error) !== 'FRESH' && meta?.source_mode !== 'SNAPSHOT')
  )
    return null
  if (!Array.isArray(data.points)) return null
  const points = data.points.map((point) => {
    const gap = point.coverage_complete === false && point.records === 0
    return {
      occurred_at: point.occurred_at,
      allow: gap ? null : count(point.allow),
      block: gap ? null : count(point.block),
      gap,
    }
  })
  return points.every(
    (point) =>
      Number.isFinite(Date.parse(point.occurred_at)) &&
      (point.gap || (point.allow !== null && point.block !== null))
  )
    ? points
    : null
}

export function auditEventQuery(event) {
  return new URLSearchParams({
    ...(event?.view_kind === 'P16H_CANONICAL_AUDIT'
      ? { source: 'canonical' }
      : {}),
    ...(event?.stream_id ? { stream_id: event.stream_id } : {}),
  }).toString()
}

export function incidentGroupLink(field, value) {
  if (
    !['severity', 'signal_rule'].includes(field) ||
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > 64
  )
    return null
  if (field === 'signal_rule' && !/^CORR-00[1-5]$/.test(value)) return null
  return `#/incidents?${new URLSearchParams({ [field]: value })}`
}

export function readIncidentBreakdown(value) {
  if (
    !value ||
    value.scope !== 'ALL_P17_INCIDENTS' ||
    value.basis !== 'DISTINCT_INCIDENT_IDS' ||
    !Number.isSafeInteger(value.total) ||
    value.total < 0
  )
    return null
  const groups = {}
  for (const [key, field] of [
    ['by_severity', 'severity'],
    ['by_signal', 'signal_rule'],
  ]) {
    const rows = value[key]
    if (!Array.isArray(rows) || !rows.length) return null
    const seen = new Set()
    groups[key] = []
    for (const row of rows) {
      const label = row?.[field],
        amount = row?.count
      const href = incidentGroupLink(field, label)
      if (
        !href ||
        seen.has(label) ||
        !Number.isSafeInteger(amount) ||
        amount < 0 ||
        amount > value.total
      )
        return null
      seen.add(label)
      groups[key].push({ value: label, count: amount, href })
    }
    if (
      groups[key].reduce((total, row) => total + row.count, 0) !== value.total
    )
      return null
  }
  return { total: value.total, ...groups }
}
