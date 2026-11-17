/* N91 dashboard clean layer. GET-only, no service/process control and no P17 changes.
   Existing Portal API remains authoritative; missing coverage is never converted to zero. */
(() => {
  'use strict';
  const VERSION = 'n91-dashboard-balanced-v7-no-small-captions';
  const ROOT_ID = 'n91-compact-overview';
  let host = null;
  let busy = false;
  let lastUpdated = 0;
  let lastRoute = null;
  let current = null;
  let refreshQueued = false;
  const escape = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const num = (v) => Number.isInteger(v) && v >= 0 ? v.toLocaleString('vi-VN') : '—';
  const isoTime = (s) => {
    if (!s || !Number.isFinite(Date.parse(s))) return 'Chưa có mốc thời gian';
    return new Intl.DateTimeFormat('vi-VN', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',timeZone:'Asia/Ho_Chi_Minh'}).format(new Date(s));
  };
  const badge = (v) => v === 'BLOCK' ? '<span class="n91-status n91-status-danger">Chặn</span>' :
    v === 'ALLOW' ? '<span class="n91-status n91-status-good">Cho phép</span>' :
    '<span class="n91-status n91-status-muted">Chưa xác định</span>';
  const collection = (v, key) => Array.isArray(v) ? v : Array.isArray(v?.items) ? v.items : Array.isArray(v?.[key]) ? v[key] : [];
  const field = (r,...keys) => { for (const k of keys) {if (r && r[k] !== null && r[k] !== undefined) return r[k];} return null; };
  const fetchApi = async (uri) => {
    try {
      const res = await fetch(uri, {method:'GET',credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'},signal:AbortSignal.timeout(6500)});
      const body = await res.json();
      if (!res.ok || body?.error || !body || !Object.prototype.hasOwnProperty.call(body,'data')) return {ok:false,status:res.status};
      return {ok:true,data:body.data,meta:body.meta||{}};
    } catch { return {ok:false,status:null}; }
  };
  function isDashboard(){
    const h = window.location.hash || '#/dashboard';
    return h === '#' || h === '#/' || /^#\/dashboard(?:[/?]|$)/.test(h);
  }
  function isSignIn(){
    return Boolean(document.querySelector('.v4-page-content input[type="password"]'));
  }
  function ensureHost(){
    const main = document.querySelector('.v4-main');
    if (!main) return null;
    let root = document.getElementById(ROOT_ID);
    if (!root || root.parentNode !== main) {
      root = document.createElement('section'); root.id = ROOT_ID; root.className = 'n91-clean-dashboard';
      root.setAttribute('aria-label','Tổng quan bảo mật');
      main.insertBefore(root,main.firstChild);
      root.innerHTML = '<div class="n91-clean-loading" role="status">Đang đọc số liệu bảo mật...</div>';
    }
    host = root;
    return root;
  }
  function updateVisibility(){
    const route = isDashboard();
    const active = route && !isSignIn() && Boolean(document.querySelector('.v4-main'));
    document.body.classList.toggle('n91-clean-on',active);
    if (active) {
      ensureHost();
      if (lastRoute !== 'dashboard') void refresh();
    }
    lastRoute = active ? 'dashboard' : 'other';
    if (!active)adaptWorkloads();
  }
  function sourceState(payload){
    if (!payload?.ok) return 'Không truy cập được';
    const meta = payload.meta || {};
    if (meta.source_mode === 'SNAPSHOT' || meta.freshness_state === 'HISTORICAL') return 'Dữ liệu bản chụp';
    if (meta.freshness_state === 'FRESH' && meta.source_mode !== 'SNAPSHOT') return 'Nguồn dữ liệu bảo mật đã đọc';
    return 'Chưa xác minh độ mới';
  }
  function detailOfRule(rules){
    const l = Array.isArray(rules) ? rules : [];
    if (l.some(x => /^INJ-/.test(x) && x!=='INJ-003')) return 'Dấu hiệu SQL Injection';
    if (l.includes('CTX-006')) return 'Nguồn truy cập không được phép';
    if (l.some(x => /^OBJ-/.test(x))) return 'Truy cập đối tượng bảo vệ';
    if (l.some(x => /^PROTO-/.test(x))) return 'Lỗi / khác biệt giao thức';
    return l.length ? 'Áp dụng chính sách truy vấn' : 'Không có quy tắc được công bố';
  }
  function toEvent(r){
    return {
      id: r?.event_id,
      when: field(r,'occurred_at','request_received_at','timestamp'),
      ip: field(r,'source_ip','client_ip') || 'Không rõ nguồn',
      action: field(r,'decision','effective_action'),
      risk: field(r?.risk,'score') ?? field(r,'risk_score'),
      rules: field(r,'matched_rules','blocking_rules') || [],
    };
  }
  function toIncident(r){
    return {
      id: r?.incident_id,
      ip: field(r,'source_ip') || 'Không rõ nguồn',
      severity: field(r,'severity') || 'UNKNOWN',
      count: field(r,'evidence_count'),
      seen: field(r,'last_seen','updated_at','last_seen_at'),
      reason: field(r,'signal_rule'),
    };
  }
  const ICONS = Object.freeze({
    activity: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 12 7 12 10 5 14 19 17 12 21 12"/></svg>',
    blocked: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 9 6 6m0-6-6 6"/></svg>',
    incident: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m10.3 3.1-8.1 14a2 2 0 0 0 1.8 3h16a2 2 0 0 0 1.8-3l-8.1-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/></svg>',
    source: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg>',
    arrow: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 11a8 8 0 0 0-14.7-4.3L3 9m0-6v6h6M4 13a8 8 0 0 0 14.7 4.3L21 15m0 6v-6h-6"/></svg>',
  });
  const timeParts = (raw) => {
    if (!raw || !Number.isFinite(Date.parse(raw))) return {date:'Chưa có mốc', clock:'—'};
    const parts=Object.fromEntries(new Intl.DateTimeFormat('vi-VN', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',timeZone:'Asia/Ho_Chi_Minh',hourCycle:'h23'}).formatToParts(new Date(raw)).map(x=>[x.type,x.value]));
    return {date:`${parts.day}/${parts.month}`,clock:`${parts.hour}:${parts.minute}`};
  };
  function rowEvent(raw, eventSource){
    const e=toEvent(raw);
    const risk=e.risk === null || e.risk === undefined ? '—' : num(e.risk);
    const href= typeof e.id==='string' && /^[A-Za-z0-9_.:-]+$/.test(e.id) ? `#/events/${encodeURIComponent(e.id)}?source=${eventSource==='canonical'?'canonical':'p17'}` : `#/events?source=${eventSource==='canonical'?'canonical':'p17'}`;
    const ts=timeParts(e.when);
    return `<a class="n91-item n91-event-item" href="${href}" aria-label="Xem sự kiện nguồn ${escape(e.ip)}">
        <span class="n91-item-symbol ${e.action==='BLOCK'?'n91-symbol-block':'n91-symbol-allow'}" aria-hidden="true">${e.action==='BLOCK'?'!':'✓'}</span>
        <span class="n91-item-content"><strong>${escape(e.ip)}</strong><small>${escape(detailOfRule(e.rules))}</small></span>
        <span class="n91-item-action">${badge(e.action)}<span class="n91-item-risk">${risk}</span></span>
        <span class="n91-item-time"><time>${escape(ts.clock)}</time><small>${escape(ts.date)}</small></span>
        <span class="n91-item-chevron" aria-hidden="true">${ICONS.arrow}</span></a>`;
  }
  function rowIncident(raw){
    const e=toIncident(raw);
    const href= typeof e.id==='string' && /^[A-Za-z0-9_.:-]+$/.test(e.id) ? `#/incidents/${encodeURIComponent(e.id)}` : '#/incidents';
    const tone=['HIGH','CRITICAL'].includes(e.severity)?'n91-status-danger':'n91-status-muted';
    const sev=e.severity==='HIGH'?'Cao':e.severity==='CRITICAL'?'Rất cao':e.severity==='WARNING'?'Cảnh báo':'Chưa xác minh';
    const ts=timeParts(e.seen);
    const evidence=Number.isInteger(e.count) ? `${num(e.count)} bằng chứng` : 'Bằng chứng chưa rõ';
    return `<a class="n91-item n91-incident-item" href="${href}" aria-label="Xem hồ sơ nguồn ${escape(e.ip)}">
        <span class="n91-item-symbol n91-symbol-incident" aria-hidden="true">${ICONS.incident}</span>
        <span class="n91-item-content"><strong>${escape(e.ip)}</strong><small>Hồ sơ điều tra · ${escape(evidence)}</small></span>
        <span class="n91-item-action"><span class="n91-status ${tone}">${sev}</span></span>
        <span class="n91-item-time"><time>${escape(ts.clock)}</time><small>${escape(ts.date)}</small></span>
        <span class="n91-item-chevron" aria-hidden="true">${ICONS.arrow}</span></a>`;
  }
  function card(value,label,href,style,icon){
    return `<a class="n91-metric ${style}" href="${href}">
        <span class="n91-metric-top"><span class="n91-metric-label">${escape(label)}</span><span class="n91-metric-icon" aria-hidden="true">${ICONS[icon]}</span></span>
        <strong class="n91-metric-value">${escape(value)}</strong></a>`;
  }
  /* Exact 7-column Galera table moved from System into Dashboard.
     Collection freshness and successful MariaDB read are separate facts. */
  const NODE_ERROR = Object.freeze({
    WSREP_READ_FAILED: 'Không đọc được wsrep qua socket MariaDB',
    WSREP_TIMEOUT: 'Đọc wsrep quá thời gian',
    WSREP_SOURCE_UNREACHABLE: 'Controller không kết nối được nguồn qua SSH',
    WSREP_FIELDS_MISSING: 'Kết quả wsrep thiếu trường',
    WSREP_CLIENT_UNAVAILABLE: 'Thiếu trình khách MariaDB',
    WSREP_RESULT_INVALID: 'Phản hồi wsrep không hợp lệ',
    GALERA_NODE_UNAVAILABLE: 'Chưa nhận được tệp quan sát',
    GALERA_NODE_INVALID: 'Tệp quan sát không hợp lệ'
  });
  function galeraPanel(payload){
    const data=payload?.ok?payload.data:null;
    const nodes=Array.isArray(data?.nodes)?data.nodes:[];
    const summary=data?.summary||{};
    const meta=payload?.ok?payload.meta||{}:{};
    const fileFresh=meta.collection_mode==='PERIODIC'&&meta.freshness_state==='FRESH';
    const state=fileFresh&&(summary.current_status==='HEALTHY'||summary.current_status==='DEGRADED')
      ?(summary.current_status==='HEALTHY'?'Đồng bộ':'Cần kiểm tra'):'Chưa xác minh';
    const stateTone=state==='Đồng bộ'?'n91-status-good':state==='Cần kiểm tra'?'n91-status-danger':'n91-status-muted';
    const fmt=(raw)=>{
      if(!raw||!Number.isFinite(Date.parse(raw)))return 'Chưa có thời điểm';
      return new Intl.DateTimeFormat('vi-VN',{hour:'2-digit',minute:'2-digit',second:'2-digit',day:'2-digit',month:'2-digit',year:'2-digit',hourCycle:'h23',timeZone:'Asia/Ho_Chi_Minh'}).format(new Date(raw));
    };
    const isValid=(n)=>n?.source_mode==='SNAPSHOT'&&n?.scope==='LOCAL_SOCKET_WSREP'&&
      n?.read_ok===true&&typeof n?.source_ref==='string'&&Number.isFinite(Date.parse(n.observed_at));
    const pill=(label,kind='muted')=>`<span class="n91-galera-pill ${kind}">${escape(label)}</span>`;
    const named=(name)=>{
      const n=nodes.find(x=>x?.node_id===name||x?.name===name)||{};
      const valid=isValid(n);
      const freshSuccess=valid&&n.observation_freshness_state==='FRESH'&&n.collection_freshness_state==='FRESH';
      const cluster=valid ? String(n.wsrep_cluster_status||'Chưa xác định') : 'Chưa xác định';
      const local=valid ? String(n.wsrep_local_state_comment||'Chưa xác định') : 'Chưa xác định';
      const clusterTone=freshSuccess&&cluster.toUpperCase()==='PRIMARY'?'good':'muted';
      const localTone=freshSuccess&&local.toUpperCase()==='SYNCED'?'good':'muted';
      const members=valid&&Number.isInteger(n.wsrep_cluster_size)?String(n.wsrep_cluster_size):'—';
      const ready=valid?`${escape(n.wsrep_ready||'—')} / ${escape(n.wsrep_connected||'—')}`:'—';
      const observed=valid ? fmt(n.observed_at):n.attempted_at ? 'Lần thử '+fmt(n.attempted_at):'—';
      // A recent *failed* attempt must never get the green "Trong thời hạn" badge.
      const freshnessLabel=valid&&freshSuccess?'Trong thời hạn':valid?'Đã quá hạn':
        n.collection_freshness_state==='FRESH'?'Lần thử mới':
        n.collection_freshness_state==='STALE'?'Lần thử cũ':'Chưa có quan sát';
      const freshnessTone=valid&&freshSuccess?'good':valid||n.collection_freshness_state==='STALE'?'warn':'muted';
      const error=valid?'Kết quả đọc tại thời điểm đo':NODE_ERROR[n.last_error_code]||'Chưa có kết quả wsrep hợp lệ';
      return `<tr>
        <td class="n91-galera-node-cell"><strong>${escape(name)}</strong><small>${escape(error)}</small></td>
        <td>${pill(cluster,clusterTone)}</td>
        <td class="n91-galera-numeric">${escape(members)}</td>
        <td>${pill(local,localTone)}</td>
        <td>${ready}</td>
        <td class="n91-galera-observed">${escape(observed)}</td>
        <td>${pill(freshnessLabel,freshnessTone)}</td>
      </tr>`;
    };
    const hasAnyFail=nodes.some(n=>n.read_ok===false||n.last_error_code);
    const message=!payload?.ok?'Chưa kết nối được API giám sát Galera.':
      hasAnyFail?'':
      state==='Chưa xác minh'?'Chưa đủ dữ liệu đồng thời, hợp lệ để xác nhận trạng thái cụm.':'';
    return `<section class="n91-galera-summary n91-galera-exact" aria-label="Trạng thái cụm cơ sở dữ liệu Galera">
      <div class="n91-galera-heading"><div class="n91-galera-title">
        <span class="n91-galera-icon" aria-hidden="true">${ICONS.source}</span>
        <div><h2>Cụm cơ sở dữ liệu Galera</h2></div>
      </div><div class="n91-galera-heading-right">${pill(state,stateTone==='n91-status-good'?'good':stateTone==='n91-status-danger'?'warn':'muted')}
        <a href="#/system/galera" class="n91-galera-link" title="Xem trạng thái chi tiết và thông tin kiểm tra">Chi tiết ${ICONS.arrow}</a>
      </div></div>
      <div class="n91-galera-table-wrap" role="region" aria-label="Bảng kiểm tra Galera" tabindex="0">
       <table class="n91-galera-exact-table"><thead><tr>
        <th>NODE</th><th>TRẠNG THÁI CỤM</th><th>SỐ NODE BÁO CÁO</th>
        <th>TRẠNG THÁI NODE</th><th>WSREP READY / CONNECTED</th>
        <th>QUAN SÁT TRÊN NODE</th><th>ĐỘ MỚI</th>
       </tr></thead><tbody>${['galera-1','galera-2','galera-3'].map(named).join('')}</tbody></table>
      </div>
      ${message?`<p class="n91-galera-warning" role="status">${escape(message)}</p>`:''}
    </section>`;
  }
  /* Minor layout cleanup for the running React VM inventory, no changes to
     data, API or confinement controls. Only approved listing headers/cells. */
  function adaptWorkloads(){
    if (!/^#\/workloads(?:[/?]|$)/.test(window.location.hash))return;
    const main=document.querySelector('.v4-main');
    if(!main)return;
    const tables=main.querySelectorAll('table');
    for (const table of tables){
      const hs=Array.from(table.querySelectorAll('thead th'));
      const risk=hs.findIndex(th=>th.textContent.trim().toUpperCase()==='RỦI RO LIÊN QUAN');
      const machine=hs.findIndex(th=>/MÁY ẢO\s*\/\s*PROJECT/i.test(th.textContent));
      if (risk===-1||machine===-1)continue;
      table.classList.add('n91-workload-table-slim');
      // We mark the header instead of directly rewriting React-owned DOM nodes.
      hs[machine].classList.add('n91-vm-name-heading');
      hs[machine].setAttribute('aria-label','Máy ảo');
      hs[risk].classList.add('n91-vm-risk-hidden');
      for (const row of table.querySelectorAll('tbody tr')){
        if(row.cells[machine])row.cells[machine].classList.add('n91-vm-name-cell');
        if(row.cells[risk])row.cells[risk].classList.add('n91-vm-risk-hidden');
        if(row.cells[4])row.cells[4].classList.add('n91-vm-attached-sg');
      }
      const parent=table.closest('.panel');
      if (parent){
        const note=Array.from(parent.querySelectorAll('p.muted')).find(x=>x.textContent.trim().startsWith('Nhãn Bình thường'));
        note?.classList.add('n91-redundant-helper');
      }
    }
    const projectFilter=Array.from(main.querySelectorAll('form.v4-filters label')).find(e=>e.textContent.includes('Mã project'));
    projectFilter?.classList.add('n91-redundant-helper');
    const banner=Array.from(main.querySelectorAll('.v4-snapshot-notice')).find(e=>(e.querySelector('strong')?.textContent||'').includes('Nova / Neutron'));
    if (banner){
      banner.classList.add('n91-vm-source-banner');
      const text=Array.from(banner.querySelectorAll('p')).find(e=>e.textContent.trim().startsWith('Project:'));
      text?.classList.add('n91-hide-source-verbose');
      if (banner.children.length===2 && text)banner.classList.add('n91-no-source-warning');
    }
  }
  function render(all){
    if (!host || !isDashboard() || isSignIn()) return;
    const {sum,evs,incs,galera,isolated,eventSource='p17'}=all;
    const s=sum.ok?sum.data:{};
    const counts=s?.event_counts||{};
    const sample=s?.projection_counts||{};
    const incidentCount=s?.incident_counts||{};
    const events=evs.ok?collection(evs.data,'events').slice(0,3):[];
    const incidents=incs.ok?collection(incs.data,'incidents').slice(0,3):[];
    const hasSource=Boolean(sum.ok||evs.ok||incs.ok);
    const seenTotal=Number.isInteger(sample.processed_events) ? sample.processed_events :
      Number.isInteger(sum.meta?.available_records)?sum.meta.available_records:null;
    const listed=Number.isInteger(incidentCount.review_required)?incidentCount.review_required:null;
    const currentSource=sourceState(sum.ok?sum:evs.ok?evs:incs);
    // A network classification is meaningful only when it is observed and fresh.
    const qm=isolated?.meta||{};
    const networkCount=isolated?.ok && qm.source_mode==='LIVE' &&
      qm.network_classification==='CONFIGURED' && qm.freshness_state==='FRESH' &&
      Number.isInteger(qm.total_count) && qm.total_count>=0 ? qm.total_count:null;
    const latest=events[0]?toEvent(events[0]):null;
    const lastDataAt=latest?.when?isoTime(latest.when):null;
    const statusTone=!hasSource?'n91-data-unavailable':currentSource==='Chưa xác minh độ mới'?'n91-data-unknown':'n91-data-ok';
    const nav=(href,text)=>`<a class="n91-section-action" href="${href}">${text}${ICONS.arrow}</a>`;
    host.innerHTML = `
      <header class="n91-hero">
        <div class="n91-hero-main"><span class="n91-kicker"><span class="n91-kicker-dot" aria-hidden="true"></span>TRUNG TÂM GIÁM SÁT</span>
          <h1>Tổng quan bảo mật</h1><p>Theo dõi truy vấn cơ sở dữ liệu và các sự cố cần điều tra.</p>
        </div>
        <div class="n91-hero-actions"><span class="n91-data-indicator ${statusTone}"><span class="n91-indicator-dot" aria-hidden="true"></span>${escape(currentSource)}</span>
        <button id="n91-dash-refresh" type="button">${ICONS.refresh}<span>Làm mới</span></button></div>
      </header>
      ${!hasSource?'<div class="n91-clean-notice" role="status">Không đọc được nguồn dữ liệu. Số lượng chưa xác định không được hiểu là bằng 0.</div>':''}
      <div class="n91-metric-grid" aria-label="Các chỉ số bảo mật">
       ${card(num(seenTotal),'Sự kiện được ghi nhận','#/events','n91-metric-neutral','activity')}
       ${card(num(counts.block),'Truy vấn bị chặn','#/events?decision=BLOCK','n91-metric-danger','blocked')}
       ${card(num(listed),'Sự cố cần xem xét','#/incidents','n91-metric-warn','incident')}
       ${card(num(networkCount),'Máy ảo đang cách ly',networkCount===null?'#/workloads':'#/workloads?network_state=QUARANTINED','n91-metric-source','source')}
      </div>
      <div class="n91-clean-columns">
       <section class="n91-clean-section" aria-label="Sự kiện gần đây">
         <header class="n91-section-head"><div><span class="n91-section-eyebrow">${eventSource==='canonical'?'NH\u1eacT K\u00dd TRUY V\u1ea4N':'D\u1eee LI\u1ec6U PH\u00c1T HI\u1ec6N'}</span><h2>Sự kiện gần đây</h2></div>${nav(eventSource==='canonical'?'#/events?source=canonical':'#/events?source=p17','Xem tất cả')}</header>
         <div class="n91-rows">${events.length?events.map(row=>rowEvent(row,eventSource)).join(''):evs.ok?'<p class="n91-empty">Chưa có sự kiện trong nguồn được chọn.</p>':'<p class="n91-empty">Không đọc được nguồn sự kiện. Hãy kiểm tra kết nối dữ liệu.</p>'}</div>
       </section>
       <section class="n91-clean-section" aria-label="Hồ sơ sự cố gần đây">
         <header class="n91-section-head"><div><span class="n91-section-eyebrow">ĐIỀU TRA VÀ XỬ LÝ</span><h2>Sự cố cần chú ý</h2></div>${nav('#/incidents','Xem tất cả')}</header>
         <div class="n91-rows">${incidents.length?incidents.map(rowIncident).join(''):'<p class="n91-empty">Chưa có hồ sơ sự cố từ nguồn trả về.</p>'}</div>
       </section>
      </div>
      ${galeraPanel(galera)}
      <footer class="n91-clean-foot">
        <span class="n91-foot-item"><span class="n91-foot-dot" aria-hidden="true"></span>Đọc lúc <strong>${escape(isoTime(new Date().toISOString()))}</strong></span>
        <span class="n91-foot-item">${lastDataAt?'Sự kiện mới nhất '+escape(lastDataAt):'Chưa có mốc sự kiện mới nhất'}</span>
        <span class="n91-foot-disclaimer">Số liệu theo phạm vi từng nguồn · Không đại diện toàn bộ lịch sử</span>
        <a href="#/system/sources">Chi tiết nguồn ${ICONS.arrow}</a>
      </footer>`;
    host.querySelector('#n91-dash-refresh')?.addEventListener('click',()=>{void refresh(true)});
  }
  async function refresh(force=false){
    if (busy|| !isDashboard() || isSignIn())return;
    if (!force && Date.now()-lastUpdated < 7000 && current){render(current);return;}
    busy=true;
    try {
      // These are existing authenticated read-only APIs. No database or service mutation.
      const [sum,incs,galera,isolated]=await Promise.all([
        fetchApi('/api/v1/dashboard/summary?window=24h'),
        fetchApi('/api/v1/incidents?limit=4'),
        fetchApi('/api/v1/system/galera'),
        fetchApi('/api/v1/workloads?network_state=QUARANTINED&limit=1')
      ]);
      // Use the source declared by the summary. Projection != canonical audit.
      // Avoid repeatedly calling unavailable canonical audit when the summary
      // itself is the incident/event projection (e.g., 947 recorded events).
      let eventSource=sum.ok && sum.data?.view_kind==='P16H_CANONICAL_AUDIT'?'canonical':'p17';
      let evs=await fetchApi(`/api/v1/events?source=${eventSource}&limit=4`);
      // A canonical request can fail independently; an explicitly labeled
      // projection fallback is safer than a blank dashboard or fake audit data.
      if(!evs.ok && eventSource==='canonical'){
        const projection=await fetchApi('/api/v1/events?source=p17&limit=4');
        if(projection.ok){evs=projection;eventSource='p17';}
      }
      current={sum,evs,incs,galera,isolated,eventSource}; lastUpdated=Date.now();render(current);
    } finally {busy=false;}
  }
  function reconcile(){
    if(refreshQueued)return;
    refreshQueued=true;
    setTimeout(()=>{refreshQueued=false;updateVisibility()},100);
  }
  document.addEventListener('DOMContentLoaded',()=>{
    document.documentElement.dataset.n91UiVersion=VERSION;
    updateVisibility();
    window.addEventListener('hashchange',reconcile);
    // React can remount the login content. Refresh visibility without touching its state.
    const root=document.getElementById('root');
    if(root){const obs=new MutationObserver(reconcile);obs.observe(root,{childList:true,subtree:true});}
    setInterval(()=>{if(isDashboard()&&!isSignIn()&&document.body.classList.contains('n91-clean-on'))void refresh();},15000);
  });
})();


/* V10 semantic presentation adapter. Keeps all existing React panels and rows.
   Never changes API responses, business values, status codes or action controls. */
(() => {
  'use strict';
  const labels = Object.freeze({
    'db-firewall.service': 'B\u1ed9 ki\u1ec3m so\u00e1t truy v\u1ea5n SQL',
    'db-firewall-audit.service': 'B\u1ed9 ghi nh\u1eadn nh\u1eadt k\u00fd b\u1ea3o m\u1eadt',
    'db-firewall-p17.service': 'B\u1ed9 ph\u00e1t hi\u1ec7n h\u00e0nh vi v\u00e0 s\u1ef1 c\u1ed1'
  });
  const exact = Object.freeze({
    'P17 snapshot reader': 'B\u1ed9 \u0111\u1ecdc d\u1eef li\u1ec7u s\u1ef1 c\u1ed1',
    'Proxy P17 SSH reader': 'B\u1ed9 \u0111\u1ecdc d\u1eef li\u1ec7u s\u1ef1 c\u1ed1',
    'P17 worker live': 'B\u1ed9 ph\u00e1t hi\u1ec7n h\u00e0nh vi v\u00e0 s\u1ef1 c\u1ed1',
    'P16H canonical reader': 'B\u1ed9 \u0111\u1ecdc nh\u1eadt k\u00fd b\u1ea3o m\u1eadt',
    'P17.5 controller': 'B\u1ed9 \u0111i\u1ec1u khi\u1ec3n c\u00e1ch ly v\u00e0 kh\u00f4i ph\u1ee5c',
    'Nova / Neutron': 'H\u1ea1 t\u1ea7ng m\u00e1y \u1ea3o v\u00e0 m\u1ea1ng',
    'P16H canonical audit': 'Nh\u1eadt k\u00fd ki\u1ec3m to\u00e1n b\u1ea3o m\u1eadt',
    'P17 snapshot': 'Ngu\u1ed3n ph\u00e2n t\u00edch s\u1ef1 c\u1ed1',
    'Proxy P17 via SSH': 'D\u1eef li\u1ec7u s\u1ef1 c\u1ed1 t\u1eeb Proxy',
    'DB Firewall': 'B\u1ed9 ki\u1ec3m so\u00e1t truy v\u1ea5n SQL'
  });
  const isSystemOverview = () => /^#\/system(?:\/health)?(?:\?|$)/.test(location.hash||'');
  const roles = Object.freeze({
    'P12': 'Ph\u00e2n t\u00edch giao th\u1ee9c SQL',
    'P13': 'Ph\u00e2n t\u00edch c\u00fa ph\u00e1p SQL',
    'P14': 'Ki\u1ec3m so\u00e1t truy v\u1ea5n SQL',
    'P15': '\u0110\u00e1nh gi\u00e1 r\u1ee7i ro truy v\u1ea5n',
    'P16': 'Ghi nh\u1eadn nh\u1eadt k\u00fd b\u1ea3o m\u1eadt',
    'P16H': 'Ki\u1ec3m to\u00e1n nh\u1eadt k\u00fd b\u1ea3o m\u1eadt',
    'P17': 'Ph\u00e1t hi\u1ec7n v\u00e0 ph\u00e2n t\u00edch s\u1ef1 c\u1ed1',
    'P17.3': 'Ki\u1ec3m tra \u0111i\u1ec1u ki\u1ec7n \u1ee9ng ph\u00f3',
    'P17.5': 'C\u00e1ch ly v\u00e0 kh\u00f4i ph\u1ee5c m\u00e1y \u1ea3o',
    'P18': 'B\u1ea3o v\u1ec7 k\u1ebft n\u1ed1i v\u00e0 sao l\u01b0u',
    'P19': 'Ki\u1ec3m th\u1eed v\u00e0 \u0111\u00e1nh gi\u00e1'
  });
  function presentRoles(main) {
    const walker=document.createTreeWalker(main,NodeFilter.SHOW_TEXT);
    const originals=Object.keys(exact).sort((a,b)=>b.length-a.length);
    let item;
    while((item=walker.nextNode())){
      const parent=item.parentElement;
      if(!parent || parent.closest('code,pre,textarea,script,style,details,.v4-rule,.v4-id-link,.v4-code,.v4-provenance'))continue;
      const raw=item.nodeValue;
      if(!raw || !/P1[2-9]|DB Firewall|Nova \/ Neutron/.test(raw))continue;
      let clean=raw;
      for(const phrase of originals){if(clean.includes(phrase))clean=clean.split(phrase).join(exact[phrase]);}
      clean=clean.replace(/\b(P17\.5|P17\.3|P16H|P12|P13|P14|P15|P16|P17|P18|P19)(?![A-Za-z0-9_.-])/g,(whole,key)=>roles[key]||whole);
      if(clean!==raw)item.nodeValue=clean;
    }
  }
  const matchText = (element,expected,replacement) => {
    if(element && element.textContent.trim()===expected && element.textContent!==replacement)
      element.textContent=replacement;
  };
  function visit() {
    const main=document.querySelector('.v4-main');
    if(!main) return;
    const overview=isSystemOverview();
    for(const panel of main.querySelectorAll('section.v4-panel')){
      const proxy=panel.querySelector('.v4-proxy-services');
      const source=panel.querySelector('.v4-service-grid');
      const heading=panel.querySelector('.panel-heading h2');
      if(proxy && overview){
        panel.classList.add('n91-v10-proxy');
        matchText(heading,'D\u1ecbch v\u1ee5 tr\u00ean Proxy','Tr\u1ea1ng th\u00e1i d\u1ecbch v\u1ee5 b\u1ea3o m\u1eadt');
        for(const item of panel.querySelectorAll('.v4-proxy-service')){
          const unit=item.querySelector('.v4-proxy-unit')?.textContent.trim();
          const name=item.querySelector('.v4-proxy-service-title h3');
          if(unit && Object.hasOwn(labels,unit) && name && name.textContent!==labels[unit])
            name.textContent=labels[unit];
        }
        for(const button of panel.querySelectorAll('button')){
          for(const node of button.childNodes){
            if(node.nodeType===Node.TEXT_NODE && node.nodeValue.includes('\u0110\u1ecdc l\u1ea1i t\u1ec7p'))
              node.nodeValue=node.nodeValue.replace('\u0110\u1ecdc l\u1ea1i t\u1ec7p','L\u00e0m m\u1edbi tr\u1ea1ng th\u00e1i');
          }
        }
      }
      if(source && overview){
        panel.classList.add('n91-v10-reader');
        matchText(heading,'Tr\u1ea1ng th\u00e1i d\u1ecbch v\u1ee5','D\u1eef li\u1ec7u ph\u1ee5c v\u1ee5 \u0111i\u1ec1u tra');
        for(const card of panel.querySelectorAll('.v4-service-card h3')){
          const replacement=exact[card.textContent.trim()];
          if(replacement && card.textContent!==replacement) card.textContent=replacement;
        }
      }
    }
    // Other screens: rename only known presentation labels. NEVER rewrite
    // rule IDs, technical evidence, SQL content, or API/request identifiers.
    for(const h of main.querySelectorAll('h1,h2,h3')){
      if(h.closest('code,pre,.v4-rule,.v4-id-link'))continue;
      const next=exact[h.textContent.trim()];
      if(next && h.textContent!==next)h.textContent=next;
    }
    presentRoles(main);
  }
  let queued=false;
  function schedule(){
    if(queued)return;
    queued=true;
    requestAnimationFrame(()=>{queued=false;visit();});
  }
  const init=()=>{
    schedule();
    addEventListener('hashchange',schedule);
    const root=document.getElementById('root');
    if(root)new MutationObserver(schedule).observe(root,{childList:true,subtree:true,characterData:true});
  };
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});
  else init();
})();


/* V12 - Workloads only. Converts the historical isolation <details> into a
   clickable pill and a read-only modal. No API writes, no service changes. */
(() => {
  'use strict';
  const RX = /^#\/workloads(?:[/?]|$)/;
  const CSS = 'n91-v12-isolation';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const formatTime = raw => {
    if (!raw || !Number.isFinite(Date.parse(raw))) return 'Không có mốc ghi nhận';
    return new Intl.DateTimeFormat('vi-VN', {
      hour:'2-digit', minute:'2-digit', second:'2-digit',
      day:'2-digit', month:'2-digit', year:'numeric',
      timeZone:'Asia/Ho_Chi_Minh', hourCycle:'h23'
    }).format(new Date(raw));
  };
  let dialog = null;
  let abortRequest = null;
  let openingButton = null;
  let scheduled = false;

  function selectedTables() {
    if (!RX.test(location.hash || '')) return [];
    const main = document.querySelector('.v4-main');
    if (!main) return [];
    return Array.from(main.querySelectorAll('table.v4-table')).filter(table => {
      const headers = Array.from(table.querySelectorAll('thead th')).map(h => h.textContent.trim().toUpperCase());
      return headers.some(h => h === 'TRẠNG THÁI MẠNG') && headers.some(h => h.includes('MÁY ẢO'));
    });
  }

  function update() {
    for (const table of selectedTables()) {
      const columns = Array.from(table.querySelectorAll('thead th')).map(h => h.textContent.trim().toUpperCase());
      const networkColumn = columns.indexOf('TRẠNG THÁI MẠNG');
      if (networkColumn < 0) continue;
      for (const row of table.querySelectorAll('tbody tr')) {
        const cell = row.cells[networkColumn];
        const anchor = row.querySelector('td:first-child a[href^="#/workloads/"]');
        if (!cell || !anchor) continue;
        const match = /^#\/workloads\/([^/?#]+)/.exec(anchor.getAttribute('href') || '');
        if (!match) continue;
        let vmId;
        try { vmId = decodeURIComponent(match[1]); } catch { continue; }
        if (!/^[a-zA-Z0-9_.:-]{1,128}$/.test(vmId)) continue;
        // V13: same visual size for the three states, without altering API values.
        const statusBadge = cell.querySelector(':scope > .v4-badge');
        if (statusBadge) {
          statusBadge.classList.add('n91-v13-network-label');
          if (statusBadge.textContent.trim() === 'Đã cô lập') {
            const node = Array.from(statusBadge.childNodes).find(n =>
              n.nodeType === 3 && n.nodeValue.includes('Đã cô lập'));
            if (node) node.nodeValue = node.nodeValue.replace('Đã cô lập', 'Đang bị cách ly');
          }
        }
        const native = cell.querySelector('details');
        const hasIsolation = Boolean(native?.querySelector('summary')?.textContent.includes('Cô lập gần nhất'));
        let pill = cell.querySelector('button[data-n91-v12-isolation]');
        if (!hasIsolation) {
          if (pill) pill.remove();
          native?.classList.remove('n91-v12-hide-native-history');
          continue;
        }
        native.classList.add('n91-v12-hide-native-history');
        if (!pill) {
          pill = document.createElement('button');
          pill.type = 'button';
          pill.className = 'n91-v12-isolation-pill';
          pill.setAttribute('data-n91-v12-isolation', '');
          pill.innerHTML = '<span class="n91-v12-isolation-dot" aria-hidden="true"></span>Lịch sử cách ly';
          cell.appendChild(pill);
        }
        if (pill.dataset.vmId !== vmId) pill.dataset.vmId = vmId;
        const name = anchor.textContent.trim() || 'Máy ảo';
        if (pill.dataset.vmName !== name) pill.dataset.vmName = name;
        const accessible = 'Xem bảng lịch sử cách ly của ' + name;
        if (pill.getAttribute('aria-label') !== accessible) pill.setAttribute('aria-label', accessible);
      }
    }
  }

  // The API exposes up to 10 recent *state transitions* per VM, not a full
  // history of Controller actions. Pair verified QUARANTINED -> NORMAL states.
  function isolationEpisodes(rows) {
    const changes = (Array.isArray(rows) ? rows : []).filter(x =>
      x && ['NORMAL','QUARANTINED','MISMATCH','UNKNOWN'].includes(x.state) &&
      Number.isFinite(Date.parse(x.observed_at))
    ).slice().sort((a,b)=>Date.parse(a.observed_at)-Date.parse(b.observed_at));
    const episodes = [];
    let active = null;
    for (const row of changes) {
      if (row.state === 'QUARANTINED') {
        if (active) episodes.push(active);
        active = {started:row.observed_at, restored:null, startSource:row.source || null, partial:false};
      } else if (row.state === 'NORMAL') {
        if (active) {
          active.restored = row.observed_at;
          active.restoreSource = row.source || null;
          episodes.push(active);
          active = null;
        } else if (row.previous_state === 'QUARANTINED') {
          // A start can fall outside the API's limited 10-transition window.
          episodes.push({started:null, restored:row.observed_at, startSource:null,
            restoreSource:row.source || null, partial:true});
        }
      }
    }
    if (active) episodes.push(active);
    return episodes.reverse();
  }

  function closeDialog() {
    if (abortRequest) { abortRequest.abort(); abortRequest = null; }
    if (!dialog) return;
    const item = dialog;
    dialog = null;
    if (item.open) item.close();
    item.remove();
    if (openingButton?.isConnected) openingButton.focus({preventScroll:true});
    openingButton = null;
  }

  function setContent(html) {
    if (dialog) {
      const content = dialog.querySelector('.n91-v12-modal-content');
      if (content) content.innerHTML = html;
    }
  }

  async function load(vmId) {
    if (!dialog) return;
    if (abortRequest) abortRequest.abort();
    const controller = new AbortController();
    abortRequest = controller;
    const target = dialog;
    setContent('<p class="n91-v12-modal-empty" role="status">Đang đọc các lần cách ly đã ghi nhận…</p>');
    const timer = setTimeout(()=>controller.abort(),9000);
    try {
      const result = await fetch('/api/v1/workloads/' + encodeURIComponent(vmId), {
        method:'GET', credentials:'same-origin', cache:'no-store',
        headers:{Accept:'application/json'}, signal:controller.signal
      });
      if (!result.ok) throw new Error('HTTP ' + result.status);
      const envelope = await result.json();
      if (dialog !== target || abortRequest !== controller) return;
      if (!envelope || envelope.error || !envelope.data || typeof envelope.data !== 'object' ||
          envelope.data.server_id !== vmId || !Array.isArray(envelope.data.network_history))
        throw new Error('INVALID_HISTORY');
      if (envelope.meta?.network_history_error) throw new Error('HISTORY_UNAVAILABLE');
      const items = isolationEpisodes(envelope.data.network_history);
      const count = envelope.data.network_history.length;
      const scope = '<p class="n91-v12-modal-scope">Tối đa 10 mốc thay đổi mạng gần nhất được hệ thống ghi nhận.</p>';
      if (!items.length) {
        setContent('<p class="n91-v12-modal-empty" role="status">Chưa có lần cách ly được xác minh trong phạm vi lịch sử hiện có.</p>' + scope);
        return;
      }
      const currentState = envelope.data.network_state;
      const fresh = envelope.meta?.source_mode === 'LIVE' && envelope.meta?.freshness_state === 'FRESH';
      const rows = items.map((episode,i)=>{
        const ongoing = !episode.restored;
        const status = episode.restored ? 'Đã khôi phục' :
          (fresh && currentState === 'QUARANTINED' && i === 0 ? 'Chưa khôi phục' : 'Chưa có mốc khôi phục');
        const cls = episode.restored ? 'n91-v12-done' : 'n91-v12-unresolved';
        return '<tr><td class="n91-v12-ordinal">'+(i+1)+'</td>'+
          '<td>'+ (episode.started ? esc(formatTime(episode.started)) : 'Ngoài phạm vi lịch sử') +'</td>'+
          '<td>'+ (episode.restored ? esc(formatTime(episode.restored)) : '—') +'</td>'+
          '<td><span class="n91-v12-episode-status '+cls+'">'+status+'</span></td></tr>';
      }).join('');
      setContent('<div class="n91-v12-table-scroll"><table class="n91-v12-history-table">'+
        '<thead><tr><th>Lần</th><th>Bắt đầu cách ly</th><th>Khôi phục</th><th>Kết quả ghi nhận</th></tr></thead>'+
        '<tbody>'+rows+'</tbody></table></div>'+scope);
    } catch (error) {
      if (controller.signal.aborted || dialog !== target || abortRequest !== controller) return;
      setContent('<div class="n91-v12-modal-error" role="alert">'+
        '<strong>Chưa đọc được lịch sử cách ly.</strong><p>Vui lòng kiểm tra nguồn dữ liệu rồi thử lại.</p>'+
        '<button type="button" class="n91-v12-retry" data-n91-v12-retry>Thử lại</button></div>');
    } finally {
      clearTimeout(timer);
      if (abortRequest === controller) abortRequest = null;
    }
  }

  function openHistory(button) {
    if (!button?.isConnected || !RX.test(location.hash || '')) return;
    const vmId = button.dataset.vmId;
    if (!vmId || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(vmId)) return;
    closeDialog();
    openingButton = button;
    const name = button.dataset.vmName || 'Máy ảo';
    const modal = document.createElement('dialog');
    modal.className = 'n91-v12-isolation-dialog';
    modal.setAttribute('aria-labelledby','n91-v12-isolation-heading');
    modal.innerHTML = '<div class="n91-v12-modal-head">'+
      '<div><span class="n91-v12-modal-eyebrow">MÁY ẢO · TRẠNG THÁI MẠNG</span>'+
      '<h2 id="n91-v12-isolation-heading">Lịch sử cách ly</h2>'+
      '<p class="n91-v12-modal-vm">'+esc(name)+'</p></div>'+
      '<button type="button" class="n91-v12-close" data-n91-v12-close aria-label="Đóng cửa sổ lịch sử">Đóng ✕</button></div>'+
      '<div class="n91-v12-modal-content" aria-live="polite"></div>';
    document.body.appendChild(modal);
    dialog = modal;
    modal.addEventListener('close',()=>{
      if (dialog === modal) closeDialog();
    });
    modal.addEventListener('click',e=>{
      if (e.target.closest('[data-n91-v12-close]')) closeDialog();
      else if (e.target.closest('[data-n91-v12-retry]')) void load(vmId);
    });
    modal.showModal();
    modal.querySelector('.n91-v12-close')?.focus({preventScroll:true});
    void load(vmId);
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(()=>{scheduled=false;update();});
  }
  const init=()=>{
    schedule();
    document.addEventListener('click', e => {
      const button = e.target.closest?.('button[data-n91-v12-isolation]');
      if (!button) return;
      e.preventDefault(); e.stopPropagation(); openHistory(button);
    });
    addEventListener('hashchange',()=>{closeDialog();schedule();});
    const app = document.getElementById('root');
    if (app) new MutationObserver(schedule).observe(app,{childList:true,subtree:true,characterData:true});
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init,{once:true});
  else init();
})();
