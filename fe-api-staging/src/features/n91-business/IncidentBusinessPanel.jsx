import { uiLabel } from '../../services/uiLanguage.js'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useBusinessSession } from './BusinessSession'
import { newIntent } from './businessApi'

export function IncidentBusinessPanel({
  id,
  streamId,
  kind = 'incidents',
  readOnly = false,
}) {
  const auth = useBusinessSession()
  if (auth.status !== 'authenticated')
    return <p role="status">Đăng nhập để xem hồ sơ xử lý.</p>
  if (!streamId)
    return (
      <p role="status">Hồ sơ xử lý cần định danh stream của nguồn dữ liệu.</p>
    )
  const scope = JSON.stringify([
    kind, id, streamId, auth.capabilities?.user_id, auth.session?.username,
    auth.session?.expires_at, auth.canTriage, auth.canReadNotes, readOnly,
  ])
  return (
    <CasePanel key={scope} auth={auth} id={id} streamId={streamId} kind={kind} readOnly={readOnly} />
  )
}

const errors = {
  BUSINESS_STORE_MIGRATION_REQUIRED: 'Cần cập nhật cơ sở dữ liệu Portal để lưu trạng thái đọc cá nhân.',
  VALIDATION_ERROR: 'Kiểm tra lại dữ liệu nhập. Ghi chú chỉ nhận văn bản hợp lệ.',
  ASSIGNEE_NOT_ELIGIBLE: 'Tài khoản được chọn không còn đủ điều kiện nhận phân công.',
}
const reviewLabel = (state) => state === 'REVIEWED' ? 'Đã rà soát' : 'Chưa rà soát'

function CasePanel({ auth, id, streamId, kind, readOnly }) {
  const { client } = auth
  const isIncident = kind === 'incidents'
  const canWrite = auth.canTriage && !readOnly
  const canReadNotes = auth.canReadNotes && isIncident
  const [overlay, setOverlay] = useState(null)
  const [readState, setReadState] = useState(null)
  const [readError, setReadError] = useState('')
  const [notes, setNotes] = useState([])
  const [nextCursor, setNextCursor] = useState(null)
  const [assignees, setAssignees] = useState([])
  const [draft, setDraft] = useState(null)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [conflict, setConflict] = useState(false)
  const lifetime = useRef(null)
  const intents = useRef({})

  const load = useCallback(async (signal) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const [result, personal, notePage, assigneePage] = await Promise.all([
        client.overlay(kind, id, streamId, signal),
        isIncident ? client.readState(id, streamId, signal).catch((e) => e) : null,
        canReadNotes ? client.notes(id, streamId, undefined, signal) : { items: [] },
        canWrite && isIncident ? client.assignees(signal) : { items: [] },
      ])
      if (signal.aborted) return
      if (result.object_id !== id || result.stream_id !== streamId ||
          result.kind !== (isIncident ? 'incident' : 'alert'))
        throw new Error('SOURCE_REFERENCE_INVALID')
      const personalMatches = personal?.incident_id === id && personal.stream_id === streamId &&
        personal.execution_mode === result.execution_mode
      setOverlay(result)
      setDraft(result)
      setReadState(personalMatches ? personal : null)
      setReadError(isIncident && !personalMatches ? personal?.code || 'SOURCE_REFERENCE_INVALID' : '')
      setNotes(notePage.items)
      setNextCursor(notePage.next_cursor || null)
      setAssignees(assigneePage.items)
      setConflict(false)
      intents.current = { note: intents.current.note }
    } catch (e) {
      if (!signal.aborted) {
        setOverlay(null)
        setError(e.code || 'SOURCE_REFERENCE_INVALID')
      }
    } finally {
      if (!signal.aborted) setBusy(false)
    }
  }, [client, id, streamId, kind, isIncident, canReadNotes, canWrite])

  useEffect(() => {
    const controller = new AbortController()
    lifetime.current = controller
    load(controller.signal)
    return () => controller.abort()
  }, [load])

  async function write(action, request, apply) {
    if (!canWrite || busy) return
    const signal = lifetime.current.signal
    setBusy(true)
    setError('')
    setNotice('')
    try {
      intents.current[action] ||= newIntent()
      const result = await request(intents.current[action], signal)
      if (signal.aborted) return
      delete intents.current[action]
      apply(result)
    } catch (e) {
      if (signal.aborted) return
      if (e.status === 409) {
        delete intents.current[action]
        if (e.code === 'VERSION_CONFLICT') setConflict(true)
      }
      setError(e.code || 'BUSINESS_UNAVAILABLE')
    } finally {
      if (!signal.aborted) setBusy(false)
    }
  }

  async function save(event) {
    event.preventDefault()
    if (conflict) return
    const body = {
      version: overlay.version,
      review_state: draft.review_state,
      acknowledged: draft.acknowledged,
      ...(isIncident
        ? { assignee_id: draft.assignee_id || null, priority: draft.priority }
        : {}),
    }
    const request = isIncident ? client.triage : client.reviewAlert
    await write('triage', (intent, signal) => request(id, streamId, body, intent, signal), (result) => {
      setOverlay(result)
      setDraft(result)
      setNotice(isIncident ? 'Đã lưu hồ sơ xử lý.' : 'Đã lưu rà soát cảnh báo.')
    })
  }

  async function addNote(event) {
    event.preventDefault()
    if (!note.trim()) return
    await write('note', (intent, signal) => client.addNote(id, note, intent, streamId, signal), (result) => {
      setNotes((previous) => [...previous.filter((item) => item.note_id !== result.note_id), result])
      setNote('')
      setNotice('Đã thêm ghi chú.')
    })
  }

  async function toggleReadState() {
    if (conflict) return
    const payload = { version: readState.version, is_read: !readState.is_read }
    await write('read-state', (intent, signal) => client.setReadState(id, streamId, payload, intent, signal), (result) => {
      setReadState(result)
      setNotice('Đã lưu trạng thái đọc của bạn.')
    })
  }

  async function loadMoreNotes() {
    const signal = lifetime.current.signal
    setBusy(true)
    setError('')
    try {
      const page = await client.notes(id, streamId, nextCursor, signal)
      if (signal.aborted) return
      setNotes((previous) => [...new Map([...previous, ...page.items].map((item) => [item.note_id, item])).values()])
      setNextCursor(page.next_cursor)
    } catch (e) {
      if (!signal.aborted) setError(e.code || 'BUSINESS_UNAVAILABLE')
    } finally {
      if (!signal.aborted) setBusy(false)
    }
  }

  function updateDraft(key, value) {
    delete intents.current.triage
    setDraft({ ...draft, [key]: value })
  }

  return (
    <section className="n91-business" aria-busy={busy}>
      <h2>{isIncident ? 'Hồ sơ xử lý sự cố' : 'Rà soát cảnh báo'}</h2>
      <p>Các thay đổi trong hồ sơ được lưu vào cơ sở dữ liệu Portal.</p>
      {error && <p role="alert">{errors[error] || 'Yêu cầu xử lý chưa hoàn tất.'} <code>{error}</code></p>}
      {notice && <p role="status">{notice}</p>}
      {conflict && <p role="status">Bản ghi đã thay đổi. Tải phiên bản mới trước khi lưu lại.</p>}
      <button type="button" disabled={busy} onClick={() => load(lifetime.current.signal)}>
        {conflict ? 'Tải phiên bản mới để rà soát lại' : 'Tải lại hồ sơ'}
      </button>
      {!overlay ? (
        busy && <p role="status">Đang tải hồ sơ xử lý…</p>
      ) : (
        <>
          <p>
            <strong>{reviewLabel(overlay.review_state)}</strong> · Tiếp nhận:{' '}
            {overlay.acknowledged ? 'Đã ghi nhận' : 'Chưa ghi nhận'} · v
            {overlay.version} · {uiLabel(overlay.execution_mode)}
          </p>
          {isIncident && (
            <div>
              {readState ? (
                <>
                  <p>Trạng thái đọc của bạn · {readState.is_read ? 'Đã đọc' : 'Chưa đọc'}</p>
                  {canWrite && (
                    <button type="button" disabled={busy || conflict} onClick={toggleReadState}>
                      {readState.is_read ? 'Đánh dấu chưa đọc' : 'Đánh dấu đã đọc'}
                    </button>
                  )}
                </>
              ) : <p role="status">{errors[readError] || 'Trạng thái đọc cá nhân chưa có dữ liệu.'}</p>}
            </div>
          )}
          {canWrite ? (
            <form onSubmit={save}>
              <label>
                Rà soát
                <select
                  aria-label="Rà soát"
                  value={draft.review_state}
                  disabled={busy}
                  onChange={(e) => updateDraft('review_state', e.target.value)}
                >
                  <option value="UNREAD">{reviewLabel('UNREAD')}</option>
                  <option value="REVIEWED">{reviewLabel('REVIEWED')}</option>
                </select>
              </label>
              <label className="n91-business-check">
                <input
                  type="checkbox"
                  checked={draft.acknowledged}
                  disabled={busy}
                  onChange={(e) => updateDraft('acknowledged', e.target.checked)}
                />
                Xác nhận đã tiếp nhận
              </label>
              {isIncident && (
                <>
                  <label>
                    Phân công
                    <select
                      aria-label="Phân công"
                      value={draft.assignee_id || ''}
                      disabled={busy}
                      onChange={(e) => updateDraft('assignee_id', e.target.value)}
                    >
                      <option value="">Chưa phân công</option>
                      {draft.assignee_id && !assignees.some((a) => a.user_id === draft.assignee_id) && (
                        <option value={draft.assignee_id}>Phân công hiện tại · {draft.assignee_id}</option>
                      )}
                      {assignees.map((a) => (
                        <option key={a.user_id} value={a.user_id}>
                          {a.username}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Ưu tiên
                    <select
                      aria-label="Ưu tiên"
                      value={draft.priority}
                      disabled={busy}
                      onChange={(e) => updateDraft('priority', e.target.value)}
                    >
                      {['UNSET', 'LOW', 'MEDIUM', 'HIGH', 'URGENT'].map((p) => (
                        <option key={p} value={p}>{uiLabel(p)}</option>
                      ))}
                    </select>
                  </label>
                </>
              )}
              <button disabled={busy || conflict}>Lưu rà soát</button>
            </form>
          ) : (
            <p>Hồ sơ chỉ đọc với quyền truy cập hiện tại.</p>
          )}
          {canReadNotes && (
            <div>
              <h3>Ghi chú Portal</h3>
              {notes.length === 0 ? (
                <p>Chưa có ghi chú trong trang này.</p>
              ) : (
                <ol>
                  {notes.map((n) => (
                    <li key={n.note_id}>
                      <p className="n91-business-note">{n.note}</p>
                      <small>
                        {n.actor_id} · {n.created_at}
                      </small>
                    </li>
                  ))}
                </ol>
              )}
              {nextCursor && <button type="button" disabled={busy} onClick={loadMoreNotes}>Xem thêm ghi chú</button>}
              {canWrite && (
                <form onSubmit={addNote}>
                  <label>
                    Ghi chú dạng văn bản (không SQL/raw log/secret)
                    <textarea
                      maxLength={1000}
                      required
                      value={note}
                      disabled={busy}
                      onChange={(e) => {
                        delete intents.current.note
                        setNote(e.target.value)
                      }}
                    />
                  </label>
                  <button disabled={busy || !note.trim()}>Thêm ghi chú</button>
                </form>
              )}
            </div>
          )}
        </>
      )}
    </section>
  )
}
