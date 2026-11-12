import { useEffect, useState } from 'react'

export function parseRoute(hash) {
  const [pathname, query = ''] = hash.replace(/^#/, '').split('?')
  const parts = pathname.split('/').filter(Boolean)
  const page = [
    'dashboard',
    'incidents',
    'events',
    'workloads',
    'system',
    'actions',
  ].includes(parts[0])
    ? parts[0]
    : 'dashboard'
  let id = null
  try {
    id = parts[1] ? decodeURIComponent(parts[1]) : null
  } catch {
    id = null
  }
  return {
    page,
    id,
    params: Object.fromEntries(new URLSearchParams(query)),
    systemTab: parts[1] || 'health',
    ruleId: parts[2] || null,
    eventId: page === 'events' ? id : null,
  }
}

export default function useHashRoute() {
  const [route, setRoute] = useState(() => parseRoute(window.location.hash))
  useEffect(() => {
    const change = () => {
      setRoute(parseRoute(window.location.hash))
      window.scrollTo({ top: 0 })
    }
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  return [
    route,
    (path) => {
      window.location.hash = path
    },
  ]
}
