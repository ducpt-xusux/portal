import test from 'node:test'
import assert from 'node:assert/strict'
import { createBusinessClient, permissions } from '../features/n91-business/businessApi.js'

const session = {
  username: 'test.analyst',
  roles: ['Analyst', 'Auditor'],
  csrf_token: 'test-csrf',
  expires_at: '2030-10-30T00:00:00Z',
}
const incident = 'INC-1'
const stream = 'TEST:stream'
const intent = 'test-evidence-intent'
const ids = {
  audit_id: 'fb3242e2-d683-4057-8fea-688b48a42ff3',
  export_id: 'f9f53068-a6f3-459f-b113-6272f8a037f3',
}
const types = { csv: 'text/csv', json: 'application/vnd.n91.evidence+json' }

function attachment(format, options = {}) {
  const content = format === 'csv'
    ? 'record_type,completeness\r\nMETADATA,PARTIAL\r\n'
    : '{"metadata":{"completeness":"PARTIAL"},"items":[]}'
  return new Response(content, {
    headers: {
      'Content-Type': types[format],
      'Content-Disposition': 'attachment; filename="INC-1-evidence-partial.' + format + '"',
      'X-Audit-ID': ids.audit_id,
      'X-Export-ID': ids.export_id,
      'X-Incident-ID': incident,
      'X-Stream-ID': stream,
      'X-Export-Completeness': 'PARTIAL',
      'X-Exported-Event-Count': '0',
      ...options,
    },
  })
}

test('the evidence capability and an allowed role are both required', () => {
  assert.equal(permissions(session, { can_export_evidence: true }).canExportEvidence, true)
  assert.equal(permissions(session, { can_read_notes: true }).canExportEvidence, false)
  assert.equal(permissions({ roles: ['Viewer'] }, { can_export_evidence: true }).canExportEvidence, false)
})

test('downloads both server attachments with the exact stream, session, CSRF and retry intent', async () => {
  for (const format of ['csv', 'json']) {
    const controller = new AbortController()
    const client = createBusinessClient({ fetchImpl: async (path, request) => {
      assert.equal(path, '/api/v1/incidents/INC-1/evidence/exports?stream_id=TEST%3Astream')
      assert.equal(request.method, 'POST')
      assert.equal(request.credentials, 'same-origin')
      assert.equal(request.cache, 'no-store')
      assert.equal(request.headers['X-CSRF-Token'], session.csrf_token)
      assert.equal(request.headers['Idempotency-Key'], intent)
      assert.equal(request.headers.Accept, types[format])
      assert.equal(request.signal, controller.signal)
      assert.deepEqual(JSON.parse(request.body), { format, scope: 'EVIDENCE_REFERENCES' })
      return attachment(format)
    } })
    client.adoptSession(session)
    const file = await client.exportEvidence(incident, stream, format, intent, controller.signal)
    assert.equal(file.filename, 'INC-1-evidence-partial.' + format)
    assert.equal(file.auditId, ids.audit_id)
    assert.equal(file.exportId, ids.export_id)
    assert.equal(file.eventCount, 0)
    assert.match(await file.blob.text(), /PARTIAL/)
  }
})

test('rejects missing auth, invalid input, cross-stream data, missing receipts and notes responses', async () => {
  let hits = 0
  const client = createBusinessClient({ fetchImpl: async () => { hits++; return attachment('csv') } })
  await assert.rejects(client.exportEvidence(incident, stream, 'csv', intent), { status: 401 })
  client.adoptSession(session)
  await assert.rejects(client.exportEvidence(incident, '', 'csv', intent), { status: 422 })
  await assert.rejects(client.exportEvidence(incident, stream, 'xlsx', intent), { status: 422 })
  assert.equal(hits, 0)
  for (const options of [
    { 'X-Stream-ID': 'TEST-other-stream' },
    { 'X-Audit-ID': '' },
    { 'X-Export-Completeness': 'COMPLETE' },
    { 'X-Exported-Event-Count': '101' },
    { 'Content-Type': 'application/json' },
    { 'Content-Disposition': 'attachment; filename="portal-notes.csv"' },
  ]) {
    const mismatched = createBusinessClient({ fetchImpl: async () => attachment('csv', options) })
    mismatched.adoptSession(session)
    await assert.rejects(mismatched.exportEvidence(incident, stream, 'csv', intent), { code: 'INVALID_EVIDENCE_EXPORT' })
  }
})

test('returns authorization errors from the API and discards data on session expiry', async () => {
  let expired = 0
  const client = createBusinessClient({
    fetchImpl: async () => Response.json({ error: { code: 'SESSION_REQUIRED' } }, { status: 401 }),
    onExpired: () => { expired++ },
  })
  client.adoptSession(session)
  await assert.rejects(client.exportEvidence(incident, stream, 'csv', intent), { status: 401, code: 'SESSION_REQUIRED' })
  assert.equal(expired, 1)
})
