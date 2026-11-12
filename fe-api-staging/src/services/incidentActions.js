export const evidenceTypes = Object.freeze({
  csv: 'text/csv',
  json: 'application/vnd.n91.evidence+json',
})

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/

export async function evidenceAttachment(response, { id, streamId, format }) {
  const header = (name) => response.headers.get(name) || ''
  const auditId = header('X-Audit-ID')
  const exportId = header('X-Export-ID')
  const count = header('X-Exported-Event-Count')
  const filename = id.replaceAll(':', '_').replace(/\.+$/, '') + '-evidence-partial.' + format
  if (
    header('Content-Type').split(';')[0].trim().toLowerCase() !== evidenceTypes[format] ||
    header('Content-Disposition') !== 'attachment; filename="' + filename + '"' ||
    header('X-Incident-ID') !== id ||
    header('X-Stream-ID') !== streamId ||
    header('X-Export-Completeness') !== 'PARTIAL' ||
    !UUID.test(auditId) || !UUID.test(exportId) ||
    !/^(?:0|[1-9][0-9]?|100)$/.test(count)
  ) return null

  const blob = await response.blob()
  if (!blob.size || blob.size > 2 * 1024 * 1024) return null
  return { blob, filename, auditId, exportId, eventCount: Number(count) }
}
