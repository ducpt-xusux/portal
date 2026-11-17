/* N91 Portal Data Gaps UI V1.
 * Additive presentation layer for all Event records, all Workload details,
 * and the System / Sources table. Does NOT alter API data, evidence, auth,
 * old application bundles, VM operations or persistence.
 * Hosts and timestamps are NEVER invented.
 */
(() => {
  'use strict';
  const doc = document;
  const HIDE = 'n91-gaps-hide-v1';
  const MARK = 'n91GapsV1';
  let scheduled = false;
  let currentHostRequest = null;
  let currentAudit = null;

  function normalized(value) {
    return String(value ?? '').normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '').replace(/[\u0111\u0110]/g, 'd')
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }
  function isMissing(value) {
    const t = normalized(value);
    return !t || /^(?:—|-|--|unknown|unavailable|n\/a|none|null|undefined|chua xac dinh|khong xac dinh|chua co du lieu|chua cung cap|chua co thoi diem|khong kha dung|withheld)(?:\s*[·:;(/].*)?$/.test(t);
  }
  function routeInfo() {
    const hash = window.location.hash || '';
    const pathname = hash.slice(1).split('?')[0];
    const event = /^\/events\/([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})\/?$/.exec(pathname);
    if (event) return {type: 'event', id: event[1]};
    const vm = /^\/workloads\/([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})\/?$/.exec(pathname);
    if (vm) return {type: 'vm', id: vm[1], console: new URLSearchParams(hash.split('?')[1] || '').get('tab') === 'console'};
    if (pathname === '/system/sources') return {type: 'sources'};
    return {type: ''};
  }
  function panelHeading(node) {
    return normalized(node?.querySelector(':scope > .panel-heading h2')?.textContent);
  }
  function panelFor(root, heading) {
    return Array.from(root.querySelectorAll('section.v4-panel'))
      .find(p => panelHeading(p) === heading) || null;
  }
  function setHide(node, yes) {
    if (node && node.classList.contains(HIDE) !== !!yes) node.classList.toggle(HIDE, !!yes);
  }
  function fieldRows(panel) {
    return Array.from(panel?.querySelectorAll('.v4-fields > div') || []);
  }
  function rowLabel(row) {return normalized(row.querySelector(':scope > dt')?.textContent);}
  function rowValue(row) {return (row.querySelector(':scope > dd')?.textContent || '').trim();}

  function eventPage(root) {
    const grid = root.querySelector('.v4-detail-grid');
    if (!grid || !root.querySelector('.v4-detail-statuses')) return;
    for (const row of fieldRows(grid)) {
      const key = rowLabel(row);
      if (key === 'hanh dong ap dung' || key === 'ket qua xu ly') {
        // Only hide absent actions; a genuine Canonical field must remain.
        setHide(row, isMissing(rowValue(row)));
      }
    }
    for (const el of grid.querySelectorAll('.v4-privacy')) {
      // This huge SQL placeholder is not evidence. Valid masked SQL <pre> stays.
      const parent = el.closest('section.v4-panel');
      if (parent && parentHeading(parent) !== 'ban ghi su kien' &&
          parentHeading(parent) !== 'sql & chinh sach decision' &&
          parentHeading(parent) !== 'su kien projection') continue;
      setHide(el, !parent?.querySelector('pre.v4-code'));
    }
    for (const p of grid.querySelectorAll('.v4-panel-note')) {
      const t = normalized(p.textContent);
      if (t.includes('quyet dinh duoc suy ra tu co blocked') ||
          t.includes('trang thai cach ly vm can bang chung') ||
          t.includes('nguon chua cung cap ly do chi tiet')) setHide(p, true);
    }
    for (const h of grid.querySelectorAll('h3.v4-subheading')) {
      if (normalized(h.textContent) !== 'ly do tu chinh sach') continue;
      const next = h.nextElementSibling;
      const empty = !next || isMissing(next.textContent) ||
        normalized(next.textContent).includes('quyet dinh duoc suy ra tu co blocked');
      if (empty) {setHide(h, true); setHide(next, true);}
    }
    // V3 already provides its own verified Canonical panel. For V2, offer
    // the same evidence-only enrichment without changing P17 data fields.
    if (!window.n91DetailDemoV3) readCanonicalForV2(root, routeInfo());
  }

  function visibleField(root, labels) {
    const names = new Set(labels);
    for (const row of root.querySelectorAll('.v4-detail-grid .v4-fields > div')) {
      if (names.has(rowLabel(row))) return rowValue(row);
    }
    return '';
  }
  function observedDecision(root) {
    for (const div of root.querySelectorAll('.v4-detail-statuses > div')) {
      if (normalized(div.querySelector(':scope > span')?.textContent) !== 'quyet dinh') continue;
      const value = normalized(div.textContent);
      if (value.includes('chan') || value.includes('block')) return 'BLOCK';
      if (value.includes('cho phep') || value.includes('allow')) return 'ALLOW';
    }
    return null;
  }
  function localDateToEpoch(text) {
    const match = String(text).match(/(\d{1,2}):(\d{2}):(\d{2})\s+(\d{1,2})\/(\d{1,2})\/(\d{2,4})/);
    if (!match) return null;
    const y = Number(match[6]) < 100 ? 2000 + Number(match[6]) : Number(match[6]);
    const date = Date.UTC(y, Number(match[5])-1, Number(match[4]), Number(match[1])-7, Number(match[2]), Number(match[3]));
    return Number.isFinite(date) ? date : null;
  }
  function projectionIdentity(root, route) {
    const sourceIp = visibleField(root, ['ip nguon', 'nguon ip']);
    const dbUser = visibleField(root, ['tai khoan co so du lieu']);
    const decision = observedDecision(root);
    const time = localDateToEpoch(visibleField(root, ['phat sinh luc']));
    if (isMissing(sourceIp) || !decision) return null;
    return {event_id: route.id, stream_id: new URLSearchParams((location.hash.split('?')[1] || '')).get('stream_id'),
      source_ip: sourceIp, db_user: isMissing(dbUser) ? null : dbUser, decision, time};
  }
  function sameCanonical(a, b) {
    if (!a || !b || b.view_kind !== 'P16H_CANONICAL_AUDIT' ||
        b.event_id !== a.event_id || b.source_ip !== a.source_ip ||
        b.decision !== a.decision) return false;
    if (a.db_user && b.db_user && a.db_user !== b.db_user) return false;
    if (a.stream_id && b.stream_id && a.stream_id !== b.stream_id) return false;
    const eventTime = Date.parse(b.occurred_at);
    if (a.time !== null && Number.isFinite(eventTime) && Math.abs(a.time - eventTime) > 2000) return false;
    return (a.stream_id && b.stream_id && a.stream_id === b.stream_id) ||
      (a.time !== null && Number.isFinite(eventTime) && Math.abs(a.time - eventTime) <= 2000);
  }
  function addCanonicalProof(root, route, record) {
    if (window.n91DetailDemoV3 || root.querySelector('.n91-demo-audit-v3')) return;
    const stack = root.querySelector('.v4-detail-grid .v4-stack');
    if (!stack) return;
    let panel = stack.querySelector('[data-n91-gaps-audit-v1]');
    if (panel && panel.dataset.n91EventId !== route.id) {panel.remove(); panel = null;}
    if (!panel) {
      panel = doc.createElement('section');
      panel.className = 'panel v4-panel n91-gaps-canonical-v1';
      panel.dataset.n91GapsAuditV1 = '1';
      panel.dataset.n91EventId = route.id;
      stack.append(panel);
    }
    if (panel.childElementCount) return;
    const hd = doc.createElement('div'); hd.className = 'panel-heading';
    const grp = doc.createElement('div');
    const h2 = doc.createElement('h2'); h2.textContent = 'Kết quả từ kiểm toán chuẩn';
    const intro = doc.createElement('p');
    intro.textContent = 'Nguồn Canonical Audit · đã đối chiếu Event ID, IP, quyết định và luồng/thời gian';
    grp.append(h2, intro); hd.append(grp); panel.append(hd);
    const dl = doc.createElement('dl'); dl.className = 'v4-fields';
    const labels = {BLOCK:'Đã chặn', ALLOW:'Cho phép', BLOCKED:'Đã chặn', FORWARDED:'Đã chuyển tiếp'};
    const add = (name, value) => {
      if (isMissing(value)) return;
      const row = doc.createElement('div');
      const dt = doc.createElement('dt'); dt.textContent = name;
      const dd = doc.createElement('dd'); dd.textContent = labels[String(value).toUpperCase()] || String(value);
      row.append(dt, dd); dl.append(row);
    };
    add('Hành động thực thi (Canonical)', record.effective_action);
    add('Kết quả xử lý (Canonical)', record.action_result);
    add('Phiên bản chính sách', record.policy_version);
    if (dl.children.length) panel.append(dl);
    if (record.sql_text_status === 'MASKED' && !isMissing(record.masked_query)) {
      const h3 = doc.createElement('h3'); h3.className = 'v4-subheading'; h3.textContent = 'SQL đã che';
      const pre = doc.createElement('pre'); pre.className = 'v4-code'; pre.textContent = record.masked_query;
      panel.append(h3, pre);
    }
    const risk = record.risk || {};
    const breakdown = record.score_breakdown || risk.score_breakdown;
    if (/^(OK|VALID|SUCCESS|SCORED)$/i.test(String(risk.status || record.risk_status || '')) && Array.isArray(breakdown)) {
      for (const component of breakdown.slice(0, 5)) {
        if (!component || !Number.isFinite(component.score)) continue;
        const p = doc.createElement('p'); p.className = 'n91-gaps-rule-v1';
        p.textContent = `${component.rule_id || 'Quy tắc'}: +${component.score}${component.reason ? ' · ' + component.reason : ''}`;
        panel.append(p);
      }
    }
    const link = doc.createElement('a');
    link.href = `#/events/${encodeURIComponent(route.id)}?source=canonical`;
    link.textContent = 'Xem nhật ký kiểm toán chuẩn';
    panel.append(link);
  }
  function readCanonicalForV2(root, route) {
    if (route.type !== 'event' || typeof window.fetch !== 'function') return;
    const id = projectionIdentity(root, route);
    if (!id) return;
    const key = `${route.id}|${id.stream_id || ''}`;
    if (currentAudit && currentAudit.key !== key) {
      currentAudit.controller?.abort();
      currentAudit = null;
    }
    if (currentAudit?.key === key) {
      if (sameCanonical(id, currentAudit.data)) addCanonicalProof(root, route, currentAudit.data);
      return;
    }
    const controller = new AbortController();
    currentAudit = {key, controller, data:null};
    fetch('/api/v1/events/' + encodeURIComponent(route.id) + '?source=canonical', {
      method:'GET', credentials:'include', cache:'no-store', headers:{Accept:'application/json'},
      signal: controller.signal,
    }).then(r => r.ok ? r.json() : null).then(payload => {
      if (controller.signal.aborted || currentAudit?.key !== key || payload?.error) return;
      const data = payload?.data;
      if (!sameCanonical(id, data)) return;
      currentAudit.data = data;
      const updated = routeInfo();
      const latest = doc.getElementById('root');
      if (updated.type !== 'event' || updated.id !== route.id || !latest ||
          !sameCanonical(projectionIdentity(latest, updated), data)) return;
      addCanonicalProof(latest, updated, data);
    }).catch(() => { /* Missing source or access denied: no claim of execution. */ });
  }

  function hideEmptyHistory(panel) {
    if (!panel) return;
    const evidenceRows = panel.querySelectorAll('table tbody tr');
    const actualRows = Array.from(evidenceRows).filter(r =>
      r.querySelector('a[href^="#/actions/"]') ||
      (r.querySelectorAll('td').length >= 2 && !isMissing(r.textContent)));
    const text = normalized(panel.textContent);
    const explicitMissing =
      text.includes('controller_evidence_unavailable') ||
      text.includes('chua doc duoc lich su xu ly') ||
      text.includes('nguon du lieu chua san sang') ||
      text.includes('khong co ban ghi xu ly') ||
      text.includes('chua co hanh dong') ||
      text.includes('chua co lich su xu ly') ||
      text.includes('khong co hanh dong') ||
      text.includes('khong co du lieu');
    // Error or explicit empty + no substantive rows => hide. Never hide evidence.
    setHide(panel, explicitMissing && actualRows.length === 0);
  }
  function hostValid(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 255 &&
      !isMissing(value) && /^[\w.:-]+$/.test(value);
  }
  function writeHost(host, routeId) {
    const route = routeInfo();
    if (route.type !== 'vm' || route.id !== routeId || route.console) return;
    const root = doc.getElementById('root');
    if (!root) return;
    const overview = root.querySelector('section[aria-label="Overview máy ảo"]');
    const identity = overview && panelFor(overview, 'thong tin dinh danh');
    if (!identity) return;
    const grid = identity.querySelector('.v4-fields');
    if (!grid) return;
    let row = fieldRows(identity).find(r => rowLabel(r) === 'compute host');
    if (row && !isMissing(rowValue(row))) return;
    if (!row) {
      row = doc.createElement('div');
      row.dataset.n91GapsHostV1 = '1';
      const dt = doc.createElement('dt'); dt.textContent = 'Compute host';
      const dd = doc.createElement('dd'); dd.textContent = host;
      row.append(dt, dd);
      grid.append(row);
    } else {
      // Raw same-VM API confirmed a host; preserve original DOM if rendered value exists.
      const dd = row.querySelector(':scope > dd');
      if (dd && isMissing(dd.textContent)) dd.textContent = host;
    }
  }
  function fetchHost(routeId) {
    if (typeof window.fetch !== 'function') return;
    if (currentHostRequest?.id === routeId) {
      if (currentHostRequest.host) writeHost(currentHostRequest.host, routeId);
      return;
    }
    currentHostRequest?.controller?.abort();
    const controller = new AbortController();
    currentHostRequest = {id: routeId, controller, host: ''};
    fetch('/api/v1/workloads/' + encodeURIComponent(routeId), {
      method: 'GET', credentials: 'include', cache: 'no-store',
      headers: {Accept: 'application/json'}, signal: controller.signal,
    }).then(response => response.ok ? response.json() : null)
      .then(payload => {
        if (controller.signal.aborted || currentHostRequest?.id !== routeId ||
            payload?.error || payload?.data?.server_id !== routeId) return;
        const host = payload.data.compute_host;
        if (!hostValid(host)) return;
        currentHostRequest.host = host;
        writeHost(host, routeId);
      }).catch(() => { /* Do not invent host and do not change auth on error. */ });
  }
  function workloadPage(root, route) {
    if (route.console) return;
    const overview = root.querySelector('section[aria-label="Overview máy ảo"]');
    if (!overview) return;
    const identity = panelFor(overview, 'thong tin dinh danh');
    if (identity) {
      for (const row of fieldRows(identity)) {
        const key = rowLabel(row);
        if (key === 'vai tro' || key === 'protected may ao' || key === 'protected') setHide(row, true);
        // Do not hide/forge Compute host: show it if Nova returned it.
        if (key === 'compute host') setHide(row, isMissing(rowValue(row)));
      }
      fetchHost(route.id);
    }
    const security = panelFor(overview, 'thong tin bao mat');
    if (security) {
      for (const p of security.querySelectorAll('p')) {
        const t = normalized(p.textContent);
        if (t.includes('chua co su co lien quan duoc nguon cung cap')) setHide(p, true);
      }
    }
    // Real actions remain visible. Only empty/error panel is suppressed.
    hideEmptyHistory(panelFor(overview, 'lich su xu ly'));
  }
  function sourcePage(root) {
    const panel = panelFor(root, 'nguon va tinh trang cap nhat');
    if (!panel) return;
    const rows = Array.from(panel.querySelectorAll('table tbody tr'));
    for (const tr of rows) {
      const td = tr.querySelectorAll('td');
      if (td.length < 5) continue;
      const name = normalized(td[0].textContent);
      // Only special case canonical file audit, not other live collectors.
      if (!(name.includes('audit-v1.0') || name.includes('nhat ky kiem toan bao mat') ||
            name.includes('canonical-audit'))) continue;
      const hasDataTime = !isMissing(td[4].textContent);
      // Missing independent last_success / last_attempt are NOT equal to no data.
      // The observed event timestamp stays in its own distinct column.
      if (!hasDataTime) continue;
      for (const cell of [td[2], td[3]]) {
        if (normalized(cell.textContent) !== 'chua co thoi diem') continue;
        cell.textContent = 'Không có mốc riêng';
        cell.title = 'Nguồn kiểm toán không cung cấp mốc đọc/thử riêng trong báo cáo trạng thái. Cột Dữ liệu đến là thời điểm sự kiện cuối, không phải thời điểm đồng bộ.';
        cell.dataset.n91GapsTimestampV1 = '1';
      }
    }
  }
  function update() {
    scheduled = false;
    const route = routeInfo();
    const root = doc.getElementById('root');
    doc.documentElement.dataset.n91GapsRoute = route.type || '';
    if (!root) return;
    if (route.type === 'event') eventPage(root);
    if (route.type === 'vm') workloadPage(root, route);
    if (route.type === 'sources') sourcePage(root);
  }
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    Promise.resolve().then(update);
  }
  function start() {
    const root = doc.getElementById('root');
    if (!root) return;
    const observer = new MutationObserver(schedule);
    observer.observe(root, {childList: true, subtree: true, characterData: true});
    window.addEventListener('hashchange', () => {
      currentHostRequest?.controller?.abort();
      currentHostRequest = null;
      currentAudit?.controller?.abort();
      currentAudit = null;
      schedule();
    });
    schedule();
    window[MARK] = Object.freeze({version: '1.0', scope: 'event,workload,sources'});
  }
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', start, {once: true});
  else start();
})();
