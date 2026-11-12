// Isolated preview entry. Never imported by App, routing, PortalProvider or LIVE.
import React from 'react'
import { createRoot } from 'react-dom/client'
import {
  EventCompare,
  EventDetailSixTabs,
  IncidentTimeline,
  RulesExplorer,
  SevenStageTrace,
  SgLifecycle,
} from './Investigation.jsx'
import fixture from './tests/TEST-preview.json'

const envelope = (data) =>
  Promise.resolve({
    data,
    meta: {
      request_id: 'TEST-preview-request',
      freshness_state: 'HISTORICAL',
      coverage_note:
        'execution_mode=TEST; static module fixture; no backend/source acceptance.',
    },
  })
const api = Object.freeze({
  policies: () => envelope(fixture.catalog),
  rule: (id) => envelope(fixture.rules[id]),
})
const style = {
  maxWidth: 1320,
  margin: '0 auto',
  padding: 24,
  fontFamily: 'Segoe UI, sans-serif',
  color: '#20314a',
  background: '#fff',
}
function Preview() {
  return (
    <main style={style}>
      <header>
        <p style={{ color: '#8b4715', fontWeight: 700 }}>
          TEST ONLY · MODULE PREVIEW · APP_INTEGRATION_PENDING
        </p>
        <h1>N91 investigation</h1>
        <p>
          Isolated component preview · sanitized synthetic fixtures · no source
          calls, cloud actions or production auth claim.
        </p>
        <nav style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
          <a href="#event">Event six tabs</a>
          <a href="#compare">APP / Clone compare</a>
          <a href="#trace">Seven-stage trace</a>
          <a href="#timeline">Incident timeline</a>
          <a href="#sg">SG lifecycle</a>
          <a href="#rules">Rules40 TEST</a>
        </nav>
      </header>
      <section id="event">
        <h2>Canonical Event Detail</h2>
        <EventDetailSixTabs
          event={fixture.right}
          trace={fixture.trace}
          api={api}
        />
      </section>
      <section id="compare">
        <h2>Event comparison</h2>
        <EventCompare left={fixture.left} right={fixture.right} />
      </section>
      <section id="trace">
        <h2>Decision Trace · seven stages</h2>
        <SevenStageTrace trace={fixture.trace} />
        <h3>Incident flags · persisted zero</h3>
        <SevenStageTrace trace={fixture.incidentTrace} />
      </section>
      <section id="timeline">
        <h2>Incident timeline</h2>
        <IncidentTimeline timeline={fixture.timeline} />
      </section>
      <section id="sg">
        <SgLifecycle data={fixture.lifecycle} />
      </section>
      <section id="rules">
        <RulesExplorer api={api} />
      </section>
    </main>
  )
}
createRoot(document.getElementById('root')).render(<Preview />)
