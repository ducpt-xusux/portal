import { portalRequest } from '../../services/portalApi.js'
import { isInvestigationId, parseInvestigation } from './workbenchModel.js'

export async function readInvestigation(
  identity,
  { cursor = null, signal, fetcher } = {}
) {
  if (
    !isInvestigationId(identity?.incident_id) ||
    !isInvestigationId(identity?.stream_id)
  )
    throw new Error('INVALID_INVESTIGATION_IDENTITY')
  const result = await portalRequest(
    `/portal/incidents/${encodeURIComponent(identity.incident_id)}/investigation`,
    {
      params: {
        stream_id: identity.stream_id,
        events_limit: 25,
        events_cursor: cursor,
      },
      signal,
      fetcher,
    }
  )
  return parseInvestigation(result, identity)
}
