import { useCallback, useEffect, useRef, useState } from 'react'
import { portalRequest, queryString } from '../services/portalApi'

export default function usePortalResource(path, { params = {}, interval = 15000, enabled = true, scope = '', transform } = {}) {
  const query = queryString(params)
  const key = `${scope}:${path || ''}${query}`
  const [state, setState] = useState({ key: '', data: null, meta: null, error: null, loading: false })
  const [tick, setTick] = useState(0)
  const refresh = useCallback(() => setTick(value => value + 1), [])
  const transformRef = useRef(transform)
  transformRef.current = transform
  useEffect(() => {
    if (!enabled || !path) return
    const controller = new AbortController()
    setState(previous => previous.key === key ? { ...previous, loading: true } : { key, data: null, meta: null, error: null, loading: true })
    portalRequest(`${path}${query}`, { signal: controller.signal }).then(payload => {
      const data = transformRef.current ? transformRef.current(payload.data) : payload.data
      if (!controller.signal.aborted) setState({ key, data, meta: payload.meta, error: null, loading: false })
    }).catch(error => {
      if (!controller.signal.aborted) setState(previous => ({
        key, data: [401, 403].includes(error.status) || previous.key !== key ? null : previous.data,
        meta: [401, 403].includes(error.status) || previous.key !== key ? null : previous.meta,
        error, loading: false,
      }))
    })
    return () => controller.abort()
  }, [path, query, key, tick, enabled])
  useEffect(() => {
    if (!enabled || !path || !interval) return
    const timer = setInterval(() => { if (!document.hidden) refresh() }, interval)
    return () => clearInterval(timer)
  }, [path, interval, enabled, refresh])
  const visible = state.key === key && enabled ? state : { data: null, meta: null, error: null, loading: enabled }
  return { ...visible, refresh }
}
