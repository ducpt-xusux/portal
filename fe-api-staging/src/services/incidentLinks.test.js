import assert from 'node:assert/strict'
import test from 'node:test'
import { incidentHref } from './incidentLinks.js'
import { alertIncidentHref } from './alertsApi.js'

test('incident and alert links retain exact stream across duplicate incident IDs', () => {
  const first = incidentHref('TEST-incident', 'TEST-stream-a')
  const second = incidentHref('TEST-incident', 'TEST-stream-b')
  assert.notEqual(first, second)
  assert.equal(
    new URLSearchParams(first.split('?')[1]).get('stream_id'),
    'TEST-stream-a'
  )
  assert.equal(alertIncidentHref('TEST-incident', 'TEST-stream-a'), first)
})

test('missing stream stays explicitly legacy while invalid identity never creates a link', () => {
  assert.equal(incidentHref('TEST-incident'), '#/incidents/TEST-incident')
  assert.equal(
    alertIncidentHref('TEST-incident', null),
    '#/incidents/TEST-incident'
  )
  for (const id of ['', '../other', 'https://example.test', '<script>', 12])
    assert.equal(incidentHref(id, 'TEST-stream'), null)
  for (const stream of ['', '../other', 'a&stream_id=b', 12])
    assert.equal(incidentHref('TEST-incident', stream), null)
})
