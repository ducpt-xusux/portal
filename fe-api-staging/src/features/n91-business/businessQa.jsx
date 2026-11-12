// Standalone TEST entry only; never imported by the application entry point.
import React from 'react'
import { createRoot } from 'react-dom/client'
import {
  BusinessSessionProvider,
  BusinessLoginPanel,
  IncidentBusinessPanel,
  BusinessAdminPanel,
} from './index'
function TestPreview() {
  return (
    <main
      style={{
        maxWidth: 1120,
        margin: '24px auto',
        padding: '0 16px',
        fontFamily: 'system-ui',
      }}
    >
      <h1>N91 Business · TEST fixture</h1>
      <p role="status">
        Isolated module QA. APP_INTEGRATION_PENDING. No LIVE source, no network
        action.
      </p>
      <BusinessSessionProvider>
        <BusinessLoginPanel />
        <IncidentBusinessPanel id="TEST-INC" streamId="TEST-stream" />
        <BusinessAdminPanel />
      </BusinessSessionProvider>
    </main>
  )
}
createRoot(document.getElementById('root')).render(<TestPreview />)
