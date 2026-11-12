import { useCallback, useEffect, useState } from 'react'
import { usePortal } from '../../portal/PortalContext'
import { readInvestigation } from './workbenchApi.js'
import { canReadWorkbench, resetsMemberPage } from './workbenchModel.js'

export function useWorkbench(identity) {
  const { auth, sessionAuthEnabled, sessionVersion } = usePortal()
  const enabled = canReadWorkbench(auth, sessionAuthEnabled)
  const scope = JSON.stringify([
    identity.stream_id,
    identity.incident_id,
    sessionVersion,
    sessionAuthEnabled,
    auth.status,
    auth.user?.user_id,
    auth.user?.roles,
    auth.user?.role,
  ])
  const [page, setPage] = useState({
    scope,
    cursor: null,
    history: [],
    notice: '',
  })
  const current =
    page.scope === scope
      ? page
      : { scope, cursor: null, history: [], notice: '' }
  const key = JSON.stringify([scope, current.cursor])
  const [state, setState] = useState({
    key: null,
    payload: null,
    loading: true,
    error: null,
  })
  const [revision, setRevision] = useState(0)
  const refresh = useCallback(() => setRevision((v) => v + 1), [])
  useEffect(() => {
    if (!enabled) {
      setState({ key, payload: null, loading: false, error: null })
      return
    }
    let active = true
    const controller = new AbortController()
    setState((s) => ({
      key,
      payload: s.key === key ? s.payload : null,
      loading: true,
      error: null,
    }))
    readInvestigation(identity, {
      cursor: current.cursor,
      signal: controller.signal,
    })
      .then((payload) => {
        if (active) setState({ key, payload, loading: false, error: null })
      })
      .catch((error) => {
        if (!active) return
        if (current.cursor && resetsMemberPage(error)) {
          setState({ key, payload: null, loading: false, error })
          setPage({
            scope,
            cursor: null,
            history: [],
            notice: `${error.code}: nguồn/cursor đã thay đổi, trở về trang đầu.`,
          })
          return
        }
        const clear =
          [401, 403, 404, 409, 422].includes(error.status) ||
          error.code === 'INVESTIGATION_INVALID_RESPONSE'
        setState((s) => ({
          key,
          payload: !clear && s.key === key ? s.payload : null,
          loading: false,
          error,
        }))
      })
    return () => {
      active = false
      controller.abort()
    }
  }, [key, enabled, revision]) // key contains the exact principal, pair and opaque page.
  useEffect(() => {
    if (!enabled) return
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') refresh()
    }, 15000)
    return () => clearInterval(timer)
  }, [enabled, scope, refresh])
  const visible =
    state.key === key ? state : { payload: null, loading: enabled, error: null }
  return {
    ...visible,
    enabled,
    refresh,
    notice: current.notice,
    history: current.history,
    next: () => {
      const next = visible.payload?.data.event_members.next_cursor
      if (!next || visible.loading || visible.error) return
      setPage({
        scope,
        cursor: next,
        history: [...current.history, current.cursor],
        notice: '',
      })
    },
    previous: () => {
      if (!current.history.length || visible.loading) return
      setPage({
        scope,
        cursor: current.history.at(-1),
        history: current.history.slice(0, -1),
        notice: '',
      })
    },
    first: () => {
      setPage({ scope, cursor: null, history: [], notice: '' })
      refresh()
    },
  }
}
