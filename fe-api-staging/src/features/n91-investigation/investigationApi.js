import { portalRequest } from '../../services/portalApi.js'

const idPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/
export function sourceId(value) {
  if (typeof value !== 'string' || !idPattern.test(value)) throw new Error('INVESTIGATION_ID_REQUIRED')
  return encodeURIComponent(value)
}

export function createInvestigationApi(request = portalRequest) {
  return Object.freeze({
    event: (eventId, streamId, options = {}) => request(`/events/${sourceId(eventId)}`, {
      ...options, params: { source: 'canonical', stream_id: streamId || undefined },
    }),
    trace: (eventId, streamId, options = {}) => request(`/events/${sourceId(eventId)}/decision-trace`, {
      ...options, params: { stream_id: streamId || undefined },
    }),
    incidentTrace: (id, options = {}) => request(`/incidents/${sourceId(id)}/decision-trace`, options),
    timeline: (id, options = {}) => request(`/incidents/${sourceId(id)}/timeline`, options),
    policies: (options = {}) => request('/system/policies', options),
    rule: (id, options = {}) => request(`/system/policies/${sourceId(id)}`, options),
    actions: (incidentId, options = {}) => request('/actions', { ...options, params: { incident_id: incidentId, limit: 100 } }),
    lifecycle: (id, options = {}) => request(`/investigation/actions/${sourceId(id)}/sg-lifecycle`, options),
  })
}

export const investigationApi = createInvestigationApi()
