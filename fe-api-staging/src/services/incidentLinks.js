const identifier = (value) =>
  typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(value)

// Missing stream retains a legacy link for server-side unique resolution.
// An explicitly invalid stream must never silently lose its identity scope.
export function incidentHref(incidentId, streamId) {
  if (!identifier(incidentId)) return null
  const path = `#/incidents/${encodeURIComponent(incidentId)}`
  if (streamId === undefined || streamId === null) return path
  if (!identifier(streamId)) return null
  return `${path}?${new URLSearchParams({ stream_id: streamId })}`
}

export function incidentSectionHref(incidentId, streamId, tab) {
  const url = identifier(streamId) && incidentHref(incidentId, streamId)
  return url && ['detection', 'response'].includes(tab) ? `${url}&wb_tab=${tab}` : null
}

export function incidentEventsHref(incidentId, streamId) {
  if (!identifier(incidentId) || !identifier(streamId)) return null
  return `#/events?${new URLSearchParams({ view: 'incidents', incident_ref: incidentId, stream_id: streamId })}`
}

export function sameRequestEvent(left, right) {
  return ['stream_id', 'event_id', 'request_id'].every(
    (key) => identifier(left?.[key]) && left[key] === right?.[key],
  )
}

export function analysisEventHref(event) {
  if (!identifier(event?.event_id) || !identifier(event.stream_id)) return null
  const query = new URLSearchParams({ analysis: '1', event_id: event.event_id, stream_id: event.stream_id })
  if (identifier(event.request_id)) query.set('request_id', event.request_id)
  return `#/incidents?${query}`
}

export function analysisCaseHref(caseId, streamId) {
  if (!identifier(caseId) || !identifier(streamId)) return null
  return `#/incidents?${new URLSearchParams({ analysis: '1', case_id: caseId, stream_id: streamId })}`
}

export function workloadJournalHref(serverId, operationId) {
  if (!identifier(serverId) || !identifier(operationId)) return null
  return `#/workloads/${encodeURIComponent(serverId)}?${new URLSearchParams({ operation_id: operationId })}`
}
