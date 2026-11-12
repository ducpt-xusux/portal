import { evidenceAttachment, evidenceTypes } from '../../services/incidentActions.js'

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/
const evidenceRoles = ['Analyst', 'Operator', 'Approver', 'Executor', 'Auditor']
export class BusinessApiError extends Error {
  constructor(status, code) {
    super(code)
    this.status = status
    this.code = code
  }
}
export function sourceKey(id, streamId) {
  if (typeof id !== 'string' || !ID.test(id) ||
      (streamId != null && (typeof streamId !== 'string' || !ID.test(streamId))))
    throw new BusinessApiError(422, 'INVALID_SOURCE_REF')
  return `${encodeURIComponent(id)}${streamId ? `?stream_id=${encodeURIComponent(streamId)}` : ''}`
}
export function newIntent() {
  return crypto.randomUUID()
}
export function permissions(session, capabilities) {
  const roles = Array.isArray(session?.roles) ? session.roles : []
  return {
    canTriage:
      capabilities?.can_triage === true &&
      roles.some((r) => ['Analyst', 'Operator'].includes(r)),
    canReadNotes:
      capabilities?.can_read_notes === true &&
      roles.some((r) => evidenceRoles.includes(r)),
    canExportEvidence:
      capabilities?.can_export_evidence === true &&
      roles.some((r) => evidenceRoles.includes(r)),
    canAdmin: capabilities?.portal_admin === true,
    canAudit: capabilities?.portal_admin === true || roles.includes('Auditor'),
    networkActionsEnabled: false,
  }
}
export function createBusinessClient({
  fetchImpl = globalThis.fetch,
  onExpired = () => {},
} = {}) {
  let csrf = null
  async function request(
    path,
    { method = 'GET', body, intent, signal, csv = false, evidence = null } = {}
  ) {
    if (
      !path.startsWith('/api/v1/') ||
      path.includes('://') ||
      path.includes('..')
    )
      throw new BusinessApiError(422, 'INVALID_API_PATH')
    const write = !['GET', 'HEAD'].includes(method)
    const requestCsrf = csrf
    const headers = { Accept: evidence ? evidenceTypes[evidence.format] : csv ? 'text/csv' : 'application/json' }
    if (write) {
      headers['Content-Type'] = 'application/json'
      if (csrf) headers['X-CSRF-Token'] = csrf
      if (intent) headers['Idempotency-Key'] = intent
    }
    let response
    try {
      response = await fetchImpl(path, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        signal,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      })
    } catch (error) {
      if (error.name === 'AbortError') throw error
      throw new BusinessApiError(0, 'NETWORK_UNAVAILABLE')
    }
    if (response.status === 401 && !signal?.aborted && requestCsrf === csrf) {
      csrf = null
      onExpired()
    }
    if (evidence && response.ok) {
      const file = await evidenceAttachment(response, evidence)
      if (signal?.aborted || requestCsrf !== csrf) throw new DOMException('Request aborted', 'AbortError')
      if (!file) throw new BusinessApiError(502, 'INVALID_EVIDENCE_EXPORT')
      return file
    }
    if (csv && response.ok) return response.text()
    let payload
    try {
      payload = await response.json()
    } catch {
      throw new BusinessApiError(response.status, 'INVALID_RESPONSE')
    }
    if (!response.ok || payload.error) {
      const code = /^[A-Z0-9_]{1,64}$/.test(payload?.error?.code)
        ? payload.error.code
        : 'BUSINESS_UNAVAILABLE'
      throw new BusinessApiError(response.status, code)
    }
    if (!payload || !payload.meta || payload.data == null)
      throw new BusinessApiError(503, 'INVALID_RESPONSE')
    return Array.isArray(payload.data?.items)
      ? { ...payload.data, next_cursor: payload.meta.next_cursor || null }
      : payload.data
  }
  function acceptSession(data) {
    if (
      typeof data.username !== 'string' ||
      !Array.isArray(data.roles) ||
      typeof data.csrf_token !== 'string' ||
      !Number.isFinite(Date.parse(data.expires_at))
    )
      throw new BusinessApiError(503, 'INVALID_SESSION')
    csrf = data.csrf_token
    return data
  }
  const scoped = (kind, id, streamId, suffix) => {
    const key = sourceKey(id, streamId),
      [encoded, query] = key.split('?')
    return `/api/v1/portal/${kind}/${encoded}/${suffix}${query ? '?' + query : ''}`
  }
  return {
    request,
    adoptSession: (data) => {
      if (data) return acceptSession(data)
      csrf = null
    },
    async me() {
      return acceptSession(await request('/api/v1/auth/me'))
    },
    async login(username, password) {
      csrf = null
      return acceptSession(
        await request('/api/v1/auth/login', {
          method: 'POST',
          body: { username, password },
        })
      )
    },
    async logout() {
      try {
        return await request('/api/v1/auth/logout', {
          method: 'POST',
          body: {},
        })
      } finally {
        csrf = null
      }
    },
    capabilities: () => request('/api/v1/portal/session/capabilities'),
    overlay: (kind, id, streamId, signal) =>
      request(scoped(kind, id, streamId, 'overlay'), { signal }),
    notes: (id, streamId, cursor, signal) => {
      const path = scoped('incidents', id, streamId, 'notes')
      return request(
        `${path}${cursor ? `${path.includes('?') ? '&' : '?'}cursor=${encodeURIComponent(cursor)}` : ''}`,
        { signal }
      )
    },
    notesCsv: (id, streamId) =>
      request(scoped('incidents', id, streamId, 'notes.csv'), { csv: true }),
    async exportEvidence(id, streamId, format, intent, signal) {
      if (!csrf) throw new BusinessApiError(401, 'SESSION_REQUIRED')
      if (!streamId || !Object.hasOwn(evidenceTypes, format) || !/^[A-Za-z0-9_.:-]{16,128}$/.test(intent || ''))
        throw new BusinessApiError(422, 'INVALID_EVIDENCE_EXPORT')
      const [encoded, query] = sourceKey(id, streamId).split('?')
      return request('/api/v1/incidents/' + encoded + '/evidence/exports?' + query, {
        method: 'POST',
        body: { format, scope: 'EVIDENCE_REFERENCES' },
        intent,
        signal,
        evidence: { id, streamId, format },
      })
    },
    assignees: (signal) => request('/api/v1/portal/assignees?limit=100', { signal }),
    triage: (id, streamId, payload, intent, signal) =>
      request(scoped('incidents', id, streamId, 'triage'), {
        method: 'PATCH',
        body: payload,
        intent,
        signal,
      }),
    reviewAlert: (id, streamId, payload, intent, signal) =>
      request(scoped('alerts', id, streamId, 'review'), {
        method: 'PATCH',
        body: payload,
        intent,
        signal,
      }),
    readState: (id, streamId, signal) =>
      request(scoped('incidents', id, streamId, 'read-state'), { signal }),
    setReadState: (id, streamId, payload, intent, signal) =>
      request(scoped('incidents', id, streamId, 'read-state'), {
        method: 'PATCH',
        body: payload,
        intent,
        signal,
      }),
    addNote: (id, note, intent, streamId, signal) => {
      const [encoded, query] = sourceKey(id, streamId).split('?')
      return request(`/api/v1/incidents/${encoded}/notes${query ? '?' + query : ''}`, {
        method: 'POST',
        body: { note },
        intent,
        signal,
      })
    },
    users: () => request('/api/v1/portal/admin/users?limit=100'),
    createUser: (payload, intent) =>
      request('/api/v1/portal/admin/users', {
        method: 'POST',
        body: payload,
        intent,
      }),
    updateUser: (id, payload, intent) => {
      sourceKey(id)
      return request(`/api/v1/portal/admin/users/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: payload,
        intent,
      })
    },
    audit: () => request('/api/v1/portal/admin/audit?limit=100'),
  }
}
