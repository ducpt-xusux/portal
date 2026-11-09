import React from 'react'
import ReactDOM from 'react-dom/client'
import '@fontsource-variable/inter'
import App from './App'
import './styles.css'
import './incidents.css'
import './securityEvents.css'
import './workloads.css'
import './system.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>,
)

import './auditApi.css'
import './portal/portal.css'
