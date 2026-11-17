/* DBSEC unified analysis workbench for built Portal 5188.
   GET-only; uses same-origin Portal session and committed export API.
   Fails closed on unavailable/stale source; never issues SQL or network isolation actions.
*/
(() => {
  'use strict';
  if (window.__N91_UNIFIED_WORKBENCH__) return;
  window.__N91_UNIFIED_WORKBENCH__ = true;
  const API = '/api/v1/p17-vnext';
  const root = document.createElement('section');
  root.id = 'n91-unified-workbench';
  root.className = 'n91u';
  let currentKey = '';
  let inFlight = 0;
  let data = {cases: [], events: [], status: null, caseDetail: null, eventDetail: null, meta: null, error: null, loading: false, authMissing: false, filterIp: ""};
  const esc = (x) => String(x ?? '—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const validId = (s) => typeof s === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/.test(s);
  const number = (x) => typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('vi-VN') : '—';
  const time = (x) => {if(!x || !Number.isFinite(Date.parse(x)))return '—';return new Date(x).toLocaleString('vi-VN',{timeZone:'Asia/Ho_Chi_Minh',day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});};
  const statusName = (x) => ({HIGH:'Cao',WARNING:'Cảnh báo',CRITICAL:'Rất cao',LOW:'Thấp',REVIEW_REQUIRED:'Cần xem xét',NO_ACTION:'Chưa cách ly',BLOCK:'Chặn',ALLOW:'Cho phép',FRESH:'Đã cập nhật',STALE:'Dữ liệu cũ',PARTIAL:'Dữ liệu giới hạn',UNKNOWN:'Chưa xác minh'}[x] || String(x||'Chưa xác minh'));
  const signalNames = {'CORR-001':'Vi phạm chính sách lặp lại','CORR-002':'Thử SQL Injection nhiều lần','CORR-003':'Truy cập dữ liệu nhạy cảm lặp lại','CORR-004':'Kết hợp nhiều kỹ thuật','CORR-005':'Lỗi tương thích giao thức lặp lại','CORR-012':'Truy cập từ nguồn không được phép','CORR-013':'SQL Injection từ nguồn không được phép','CORR-014':'Dò tìm cấu trúc lặp lại','CORR-015':'Dò tìm rồi thử hành vi nguy hiểm','CORR-022':'Chuỗi hành vi tăng mức nguy hiểm'};
  const ruleNames = {'INJ-008':'Dấu hiệu SQL Injection','CTX-006':'Nguồn truy cập không được phép'};
  const chip = (t,tone='') => `<span class="n91u-chip ${tone}">${esc(t)}</span>`;
  const cls = (s) => s==='HIGH'||s==='WARNING'?'warn':s==='CRITICAL'||s==='FAILED'?'danger':s==='FRESH'?'good':'neutral';
  const pills = (xs,transform) => Array.isArray(xs)?xs.map(v=>chip(transform(v))).join(' '):'';
  const route = () => {
    const [path, query=''] = (location.hash||'').replace(/^#/,'').split('?');
    if(path !== '/incidents')return {active:false};
    const q=new URLSearchParams(query);
    const chosen = q.get('analysis') === '1';
    const c=q.get('case_id'), e=q.get('event_id');
    return {active:true,chosen,caseId:validId(c)?c:null,eventId:validId(e)?e:null,view:q.get('view')==='events'?'events':'cases'};
  };
  async function get(path){
    const resp=await fetch(API+path,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    const body=await resp.json().catch(()=>null);
    if(!resp.ok||!body||body.error){const code=body?.error?.code||`HTTP_${resp.status}`;
      const error=new Error(code==='SESSION_REQUIRED'?'Phiên đăng nhập chưa hợp lệ. Đăng nhập lại trên Portal 5188.':`Không đọc được dữ liệu phân tích (${code}).`);
      error.code=code;error.httpStatus=resp.status;throw error;}
    return body;
  }
  const href = (sub) => '#/incidents?analysis=1'+(sub?'&'+sub:'');
  function nav(chosen){return `<div class="n91u-nav" role="navigation" aria-label="Chức năng sự cố"><a href="#/incidents" ${chosen?'':'aria-current="page"'}>Danh sách sự cố</a><a href="${href()}" ${chosen?'aria-current="page"':''}>Phân tích hành vi</a></div>`;}
  function sourceStatus(){const m=data.meta||{};return `<div class="n91u-source">${chip(statusName(m.freshness_state),'neutral')} · Phạm vi: tối đa 50 hồ sơ, 100 sự kiện · Chỉ xem xét${m.data_as_of?' · Nguồn: '+esc(time(m.data_as_of)):''}</div>`;}
  function loadingBlock(){return `<div class="n91u-status" role="status">Đang đọc hồ sơ đã ghi nhận…</div>`;}
  function errBlock(){return `<div class="n91u-error" role="alert">${esc(data.error)} <button type="button" data-action="refresh">Thử lại</button></div>`;}
  function metrics(){return `<div class="n91u-metrics"><article><span>Hồ sơ phân tích hành vi</span><strong>${number(data.status?.vnext_case_total)}</strong></article><article><span>Sự kiện đã phân tích</span><strong>${number(data.status?.vnext_event_total)}</strong></article><article><span>Sự cố ghi nhận trước nâng cấp</span><strong>${number(data.status?.legacy_incident_count)}</strong></article></div>`;}
  function caseList(){const rows=data.cases||[];return `<div class="n91u-head"><div><small>PHÂN TÍCH HÀNH VI</small><h2>Hồ sơ cần xem xét</h2></div><button type="button" data-action="refresh">↻ Làm mới</button></div>${metrics()}<section class="n91u-card"><div class="n91u-card-title"><h3>Danh sách hồ sơ phân tích</h3>${chip('Chỉ đọc','neutral')}</div><label class="n91u-filter">Lọc theo IP nguồn <input type="search" data-role="ip-filter" autocomplete="off" placeholder="Ví dụ: 10.0.0.204" value="${esc(data.filterIp)}" /></label>${!rows.length?'<p class="n91u-status">Chưa có hồ sơ nào trong dữ liệu đã xuất.</p>':rows.map(c=>{
    const t=(c.signals||[]).includes('CORR-002')?'Nghi vấn thử SQL Injection lặp lại':(c.signals||[]).map(x=>signalNames[x]).filter(Boolean).join(' · ')||'Hồ sơ hành vi cần xem xét';
    return `<div class="n91u-case" data-source-ip="${esc(c.source_ip)}"><div><strong>${esc(t)}</strong><small>IP nguồn ${esc(c.source_ip)} · ${number(c.evidence_count)} truy vấn làm bằng chứng · Điểm rủi ro cao nhất ${number(c.peak_p15)}/100</small></div><div class="n91u-case-actions">${chip(statusName(c.severity),cls(c.severity))}<button type="button" data-action="open-case" data-id="${esc(c.case_id)}">Xem hồ sơ →</button></div></div>`;
  }).join('')}<p class="n91u-hint">Hồ sơ mới không tự động cộng vào tổng số sự cố đã ghi nhận trước nâng cấp.</p></section>`;}
  function evidenceView(c){const sorted=[...(c.evidence||[])].sort((a,b)=>Number(a.event_ms||0)-Number(b.event_ms||0));const span=(sorted.length>=2 && Number.isFinite(sorted.at(-1).event_ms-sorted[0].event_ms))?((sorted.at(-1).event_ms-sorted[0].event_ms)/1000).toLocaleString('vi-VN',{maximumFractionDigits:3,minimumFractionDigits:3}):null;
    return `<section class="n91u-card"><div class="n91u-card-title"><h3>Truy vấn làm bằng chứng</h3>${chip(`${number(sorted.length)} truy vấn`,'neutral')}</div>${span?`<p class="n91u-notice">Khoảng cách giữa các bằng chứng: <b>${esc(span)} giây</b>. Việc liên kết hồ sơ mới không bắt buộc nằm trong 60/120 giây.</p>`:''}
    ${sorted.length?sorted.map(e=>{const t=e.trace||{};const p=t.p14||{};const r=t.p15||{};const d=t.p17||{};const sig=Array.isArray(d.matched_signals)?d.matched_signals:[];const evals=d.detector_evaluations&&typeof d.detector_evaluations==='object'?Object.entries(d.detector_evaluations):[];
      return `<details class="n91u-evidence"><summary><strong>Truy vấn thứ tự ${esc(e.stream_sequence)}</strong><span>${esc(time(t.event_time))} · Điểm rủi ro ${number(e.risk_score)}/100 ${chip('Đã chặn','danger')}</span></summary><div class="n91u-trace"><div><b>Kiểm soát truy vấn</b><p>${p.matched_rules?.length?pills(p.matched_rules,v=>ruleNames[v]||'Quy tắc kiểm soát truy vấn'):'Chưa ghi nhận quy tắc trong bản xuất'}</p></div><div><b>Đánh giá rủi ro</b><p>Điểm ghi nhận: ${number(e.risk_score)}/100 · ${esc(statusName(r.status))}</p></div><div><b>Phát hiện hành vi</b><p>${sig.length?pills(sig,v=>signalNames[v]||'Mẫu hành vi đã ghi nhận'):'Không có mẫu hành vi mới khớp'}</p></div><div><b>Phản ứng</b><p>Chỉ rà soát · Không tự động cách ly</p></div></div>
      ${evals.length?`<details class="n91u-technical"><summary>Đánh giá ${evals.length} mẫu hành vi</summary><div class="n91u-table-wrap"><table><thead><tr><th>Mẫu phát hiện</th><th>Đánh giá</th><th>Đã ghi nhận</th><th>Mốc tham chiếu</th></tr></thead><tbody>${evals.map(([key,v])=>`<tr><td>${esc(signalNames[key]||key)}</td><td>${v.met?'Đủ điều kiện':'Chưa đủ điều kiện'}</td><td>${number(v.actual)}</td><td>${number(v.required)}</td></tr>`).join('')}</tbody></table></div></details>`:''}
      <details class="n91u-technical"><summary>Thông tin kỹ thuật</summary><p>Mã sự kiện: <code>${esc(e.event_id)}</code></p><p>Quy tắc: <code>${esc((p.matched_rules||[]).join(', '))}</code></p><p>Mẫu: <code>${esc(sig.join(', '))}</code></p></details></details>`;
    }).join(''):'<p class="n91u-status">Bản xuất chưa có bằng chứng để xem. Không được tự tạo truy vấn.</p>'}</section>`;
  }
  function caseDetail(c){if(!c)return loadingBlock();const signals=Array.isArray(c.signals)?c.signals:[];
    return `<button class="n91u-back" type="button" data-action="back">← Danh sách hồ sơ</button><section class="n91u-card"><div class="n91u-card-title"><div><small>HỒ SƠ PHÂN TÍCH HÀNH VI</small><h2>${esc(signals.includes('CORR-002')?'Nghi vấn thử SQL Injection lặp lại':'Hồ sơ hành vi cần xem xét')}</h2></div>${chip(statusName(c.status),'warn')}</div><p class="n91u-notice">Dựa trên các truy vấn đã ghi nhận và bị chặn. Hồ sơ không chứng minh tấn công thành công và không cấp quyền cách ly.</p>
    <div class="n91u-summary"><div><small>IP nguồn</small><b>${esc(c.source_ip)}</b></div><div><small>Mức độ</small><b>${esc(statusName(c.severity))}</b></div><div><small>Điểm rủi ro cao nhất</small><b>${number(c.peak_p15)}/100</b></div><div><small>Bằng chứng</small><b>${number(c.evidence_count)}</b></div></div></section>
    <div class="n91u-columns"><section class="n91u-card"><h3>Hành vi được nhận diện</h3>${signals.length?signals.map(s=>`<div class="n91u-finding">${chip('!','warn')}<b>${esc(signalNames[s]||'Hành vi đã ghi nhận')}</b></div>`).join(''):'<p>Chưa có mẫu hành vi được xác nhận.</p>'}</section><section class="n91u-card"><h3>Kết luận và ứng phó</h3><dl class="n91u-kv"><dt>Trạng thái</dt><dd>${esc(statusName(c.status))}</dd><dt>Biện pháp cách ly</dt><dd>${esc(statusName(c.response))}</dd><dt>Được phép tự động cách ly</dt><dd>${c.isolation_authorized===false?'Không':'Chưa xác minh'}</dd><dt>Phạm vi bằng chứng</dt><dd>${c.evidence_export_complete===true?'Đã xuất đủ':'Giới hạn, chưa đủ để kết luận toàn bộ'}</dd></dl></section></div>
    ${evidenceView(c)}<details class="n91u-technical"><summary>Thông tin kỹ thuật của hồ sơ</summary><p>Mã hồ sơ: <code>${esc(c.case_id)}</code></p><p>Mã các mẫu: <code>${esc(signals.join(', '))}</code></p></details>`;
  }
  function eventDetailView(e){
    if(!e)return loadingBlock();
    const t=e.trace||{}, p=t.p14||{}, r=t.p15||{}, d=t.p17||{};
    const sign=Array.isArray(d.matched_signals)?d.matched_signals:[];
    return `<button class="n91u-back" type="button" data-action="back-events">← Danh sách sự kiện</button>
    <section class="n91u-card"><div class="n91u-card-title"><div><small>KIỂM TRA TRUY VẤN ĐÃ GHI NHẬN</small><h2>Chi tiết sự kiện</h2></div>${chip(e.blocked?'Đã chặn':'Cho phép',e.blocked?'danger':'good')}</div>
    <div class="n91u-summary"><div><small>IP nguồn</small><b>${esc(t.source_ip)}</b></div><div><small>Thứ tự</small><b>${esc(e.stream_sequence)}</b></div><div><small>Điểm rủi ro</small><b>${number(e.risk_score)}/100</b></div><div><small>Thời gian</small><b>${esc(time(t.event_time))}</b></div></div></section>
    <section class="n91u-card"><h3>Quá trình kiểm tra và ra quyết định</h3><div class="n91u-trace"><div><b>Kiểm soát truy vấn</b><p>${p.matched_rules?.length?pills(p.matched_rules,v=>ruleNames[v]||'Quy tắc kiểm soát'):'Chưa có quy tắc trong bản xuất'}</p></div><div><b>Đánh giá rủi ro</b><p>${number(e.risk_score)}/100 · ${esc(statusName(r.status))}</p></div><div><b>Phát hiện hành vi</b><p>${sign.length?pills(sign,v=>signalNames[v]||'Mẫu đã ghi nhận'):'Chưa có mẫu mới khớp'}</p></div><div><b>Ứng phó</b><p>Không tự động cách ly</p></div></div>
    <details class="n91u-technical"><summary>Thông tin kỹ thuật</summary><p>Mã sự kiện: <code>${esc(e.event_id)}</code></p><p>Mã quy tắc: <code>${esc((p.matched_rules||[]).join(', '))}</code></p></details></section>`;
  }
  function applyIpFilter(){
    const input=root.querySelector('[data-role="ip-filter"]');
    if(!input)return;
    const query=String(data.filterIp||'').trim().toLowerCase();
    root.querySelectorAll('.n91u-case').forEach(el=>{
      el.hidden=Boolean(query && !String(el.dataset.sourceIp||'').toLowerCase().includes(query));
    });
  }
  function eventsView(){return `<div class="n91u-head"><div><small>PHÂN TÍCH HÀNH VI</small><h2>Sự kiện truy vấn</h2></div><button type="button" data-action="refresh">↻ Làm mới</button></div><div class="n91u-card"><p class="n91u-hint">Danh sách các sự kiện trong bản xuất giới hạn; không phải toàn bộ nhật ký kiểm toán.</p><div class="n91u-table-wrap"><table><thead><tr><th>Thứ tự</th><th>IP nguồn</th><th>Quyết định</th><th>Điểm rủi ro</th><th></th></tr></thead><tbody>${(data.events||[]).map(e=>`<tr><td>${esc(e.stream_sequence)}</td><td>${esc(e.source_ip)}</td><td>${chip(e.blocked?'Chặn':'Cho phép',e.blocked?'danger':'good')}</td><td>${number(e.risk_score)}</td><td><button type="button" data-action="open-event" data-id="${esc(e.event_id)}">Chi tiết</button></td></tr>`).join('')}</tbody></table></div></div>`;}
  function render(){const r=route();if(!r.active||!r.chosen)return;
    root.innerHTML=nav(true)+`<div class="n91u-head n91u-headtop"><div><small>PHÂN TÍCH VÀ ĐIỀU TRA</small><h1>Sự cố</h1></div><span class="n91u-chip neutral">Chỉ xem xét · Không tự động cách ly</span></div>`+ (data.meta?sourceStatus():'') + (data.loading?loadingBlock():'') +(data.error?errBlock():'') +(!data.error && !data.loading?(r.caseId?caseDetail(data.caseDetail):r.eventId?eventDetailView(data.eventDetail):r.view==='events'?eventsView():caseList()):'')+
      `<div class="n91u-bottom-nav"><a href="${href()}">Hồ sơ phân tích</a><a href="${href('view=events')}">Sự kiện truy vấn</a></div>`;
    if(r.view==='cases' && !r.caseId){applyIpFilter();}
    const main=document.querySelector('main#main');
    if(main) main.classList.toggle('n91u-show-analysis',Boolean(r.active && r.chosen && !data.authMissing));
  }
  async function refreshView(force=false){const r=route();if(!r.active||!r.chosen)return; const serial=++inFlight;data.loading=true;data.error=null;data.authMissing=false;render();
    try{if(r.caseId){const res=await get('/cases/'+encodeURIComponent(r.caseId));if(serial!==inFlight)return;data.caseDetail=res.data;data.meta=res.meta;}
      else if(r.eventId){const res=await get('/events/'+encodeURIComponent(r.eventId));if(serial!==inFlight)return;data.eventDetail=res.data;data.meta=res.meta;}
      else if(r.view==='events'){const res=await get('/events?limit=40');if(serial!==inFlight)return;data.events=Array.isArray(res.data?.events)?res.data.events:[];data.meta=res.meta;}
      else{const [s,c]=await Promise.all([get('/status'),get('/cases?limit=50')]);if(serial!==inFlight)return;data.status=s.data;data.cases=Array.isArray(c.data?.cases)?c.data.cases:[];data.meta=c.meta;}
     }catch(e){if(serial!==inFlight)return;data.error=e?.message||'Không đọc được dữ liệu phân tích.';data.authMissing=e?.code==='SESSION_REQUIRED'||e?.httpStatus===401;}finally{if(serial===inFlight){data.loading=false;render();}}
  }
  function ensureMounted(){const r=route();const main=document.querySelector('main#main');if(!main)return;
    const content=main.querySelector('.v4-page-content');if(!content)return;
    if(root.parentElement!==main)main.insertBefore(root,content);
    root.hidden=!r.active;
    main.classList.toggle('n91u-show-analysis',Boolean(r.active&&r.chosen&&!data.authMissing));
    const key=r.active?[r.chosen,r.caseId,r.eventId,r.view].join('|'):'off';
    if(key!==currentKey){currentKey=key;if(r.active&&r.chosen){data.error=null;data.loading=false;refreshView();}else if(r.active){root.innerHTML=nav(false);}}
  }
  let tickScheduled=false;
  function schedule(){if(tickScheduled)return;tickScheduled=true;requestAnimationFrame(()=>{tickScheduled=false;ensureMounted();});}
  window.addEventListener('hashchange',schedule);
  const observer=new MutationObserver(schedule);
  observer.observe(document.body,{childList:true,subtree:true});
  root.addEventListener('click',e=>{const b=e.target.closest('button[data-action]');if(!b)return;
    const action=b.dataset.action;
    if(action==='refresh')refreshView(true);
    if(action==='open-case'&&validId(b.dataset.id))location.hash=href('case_id='+encodeURIComponent(b.dataset.id));
    if(action==='open-event'&&validId(b.dataset.id))location.hash=href('event_id='+encodeURIComponent(b.dataset.id));
    if(action==='back')location.hash=href();
    if(action==='back-events')location.hash=href('view=events');
  });
  root.addEventListener('input',e=>{
    if(e.target.matches('[data-role="ip-filter"]')){data.filterIp=e.target.value;applyIpFilter();}
  });
  schedule();
})();
