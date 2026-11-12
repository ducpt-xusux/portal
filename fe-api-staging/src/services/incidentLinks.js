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
