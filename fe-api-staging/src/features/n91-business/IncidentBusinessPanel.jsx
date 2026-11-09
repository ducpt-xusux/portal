import { useCallback,useEffect,useRef,useState } from 'react'
import { useBusinessSession } from './BusinessSession'
import { newIntent } from './businessApi'

export function IncidentBusinessPanel({ id,streamId,kind='incidents' }) {
  const auth=useBusinessSession(),[overlay,setOverlay]=useState(null),[notes,setNotes]=useState([]),[assignees,setAssignees]=useState([])
  const [draft,setDraft]=useState(null),[note,setNote]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[conflict,setConflict]=useState(false)
  const intent=useRef(null),noteIntent=useRef(null),generation=useRef(0)
  const load=useCallback(async()=>{
    const current=++generation.current
    if(auth.status!=='authenticated') {setOverlay(null);setNotes([]);return}
    setError('')
    try{
      const result=await auth.client.overlay(kind,id,streamId)
      const [n,a]=await Promise.all([auth.canReadNotes&&kind==='incidents'?auth.client.notes(id,streamId):{items:[]},auth.canTriage?auth.client.assignees():{items:[]}])
      if(current!==generation.current)return
      setOverlay(result);setDraft(result);setNotes(n.items);setAssignees(a.items)
    }catch(e){if(current===generation.current){setOverlay(null);setError(e.code || 'BUSINESS_UNAVAILABLE')}}
  },[auth.status,auth.client,auth.canReadNotes,auth.canTriage,id,streamId,kind])
  useEffect(()=>{setOverlay(null);setNotes([]);setConflict(false);intent.current=null;noteIntent.current=null;load();return()=>{generation.current++}},[load])
  async function save(event){
    event.preventDefault();setBusy(true);setError('')
    intent.current ||= newIntent()
    const body={version:overlay.version,review_state:draft.review_state,acknowledged:draft.acknowledged,...(kind==='incidents'?{assignee_id:draft.assignee_id||null,priority:draft.priority}:{})}
    try{if(kind==='incidents')await auth.client.triage(id,streamId,body,intent.current);else await auth.client.reviewAlert(id,streamId,body,intent.current);intent.current=null;setConflict(false);await load()}
    catch(e){setError(e.code||'BUSINESS_UNAVAILABLE');if(e.status===409){setConflict(true);intent.current=null}}
    finally{setBusy(false)}
  }
  async function addNote(event){event.preventDefault();setBusy(true);setError('');noteIntent.current ||= newIntent();try{await auth.client.addNote(id,note,noteIntent.current);setNote('');noteIntent.current=null;await load()}catch(e){setError(e.code||'BUSINESS_UNAVAILABLE');if(e.status===409)noteIntent.current=null}finally{setBusy(false)}}
  if(auth.status!=='authenticated')return <section className="n91-business" role="status">Đăng nhập để xem Portal overlay.</section>
  return <section className="n91-business"><h2>Portal review</h2><p>Review/ack và phân công chỉ lưu Portal DB. P17 status, delivered và trạng thái mạng giữ nguồn riêng.</p>{error&&<p role="alert">{error}</p>}{!overlay?<button onClick={load}>Tải Portal overlay</button>:<><p><strong>{overlay.review_state}</strong> · Portal ack: {overlay.acknowledged?'Đã ghi nhận':'Chưa ghi nhận'} · v{overlay.version} · {overlay.execution_mode}</p>{auth.canTriage?<form onSubmit={save}><label>Review<select aria-label="Review" value={draft.review_state} onChange={e=>{intent.current=null;setDraft({...draft,review_state:e.target.value})}}><option>UNREAD</option><option>REVIEWED</option></select></label><label className="n91-business-check"><input type="checkbox" checked={draft.acknowledged} onChange={e=>{intent.current=null;setDraft({...draft,acknowledged:e.target.checked})}}/>Portal acknowledge</label>{kind==='incidents'&&<><label>Phân công<select aria-label="Phân công" value={draft.assignee_id||''} onChange={e=>{intent.current=null;setDraft({...draft,assignee_id:e.target.value})}}><option value="">Chưa phân công</option>{assignees.map(a=><option key={a.user_id} value={a.user_id}>{a.username}</option>)}</select></label><label>Ưu tiên<select aria-label="Ưu tiên" value={draft.priority} onChange={e=>{intent.current=null;setDraft({...draft,priority:e.target.value})}}>{['UNSET','LOW','MEDIUM','HIGH','URGENT'].map(p=><option key={p}>{p}</option>)}</select></label></>}<button disabled={busy||conflict}>Lưu review</button>{conflict&&<p role="status">Bản ghi đã thay đổi. <button type="button" onClick={async()=>{await load();setConflict(false)}}>Tải phiên bản mới để review lại</button></p>}</form>:<p>Quyền đọc. Analyst/Operator mới được sửa review.</p>}{auth.canReadNotes&&kind==='incidents'&&<div><h3>Ghi chú Portal</h3>{notes.length===0?<p>Chưa có ghi chú trong trang này.</p>:<ol>{notes.map(n=><li key={n.note_id}><p className="n91-business-note">{n.note}</p><small>{n.actor_id} · {n.created_at}</small></li>)}</ol>}{auth.canTriage&&<form onSubmit={addNote}><label>Ghi chú dạng văn bản (không SQL/raw log/secret)<textarea maxLength={1000} required value={note} onChange={e=>{noteIntent.current=null;setNote(e.target.value)}} /></label><button disabled={busy||!note.trim()}>Thêm ghi chú</button></form>}<small>Tối đa 25 ghi chú/trang; API hỗ trợ phân trang. Không phải toàn bộ lịch sử nguồn.</small></div>}</>}<p><button disabled aria-disabled="true">Thao tác mạng · FEATURE_DISABLED</button></p></section>
}
