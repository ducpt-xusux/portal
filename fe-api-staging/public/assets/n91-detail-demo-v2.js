/* N91 Portal: compact presentation for ALL Event/Incident detail records.
   DOM-only additive overlay; no API requests, no fabricated data, no mutations of backend. */
(() => {
  'use strict';
  const doc = document;
  const html = doc.documentElement;
  const HIDE = 'n91-demo-hide-v2';
  const TAB_HIDE = 'n91-demo-tab-hide-v2';
  const BUTTON_ID = 'n91-detail-demo-switch-v2';
  const state = {compact: true, scheduled: false};

  function normal(value) {
    return String(value ?? '').normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '').replace(/[\u0111\u0110]/g, 'd')
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }
  // IMPORTANT: These are ROUTE PATTERNS, never two hard-coded record IDs.
  // The selected record's data always comes from the existing Portal React page.
  function currentRoute() {
    const hash = window.location.hash || '';
    if (!hash.startsWith('#/')) return null;
    const question = hash.indexOf('?');
    const path = hash.slice(1, question < 0 ? undefined : question);
    const query = question < 0 ? '' : hash.slice(question + 1);
    const params = new URLSearchParams(query);
    let type, rawId;
    let found = path.match(/^\/events\/([^/?#]+)\/?$/);
    if (found) { type = 'event'; rawId = found[1]; }
    else {
      found = path.match(/^\/incidents\/([^/?#]+)\/?$/);
      if (!found) return null;
      type = 'incident'; rawId = found[1];
    }
    let id;
    try { id = decodeURIComponent(rawId); } catch { return null; }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(id)) return null;
    return {type, id, params};
  }
  function validValue(raw) {
    const value = normal(raw);
    if (!value) return false;
    return !/^(—|-|--|n\/a|none|null|undefined|unavailable|withheld|khong co|chua cung cap|chua co du lieu|withheld \/ chua cung cap)(\s*[·:;].*)?$/.test(value);
  }
  function hide(node, disabled, kind = HIDE) {
    if (node) node.classList.toggle(kind, !!disabled);
  }
  function filterFields(container, allowed) {
    if (!container) return;
    const rows = Array.from(container.querySelectorAll('.v4-fields > div, .n91-fields > div'));
    const parsed = rows.map((row) => ({
      row,
      term: row.querySelector(':scope > dt'),
      body: row.querySelector(':scope > dd'),
    })).filter(({term, body}) => term && body);
    // Fail closed on unfamiliar live markup: unknown versions are left intact.
    // Never hide every field when only one/zero known labels can be recognized.
    if (parsed.filter(({term}) => allowed.has(normal(term.textContent))).length < 2) return;
    for (const {row, term, body} of parsed) {
      const key = normal(term.textContent);
      hide(row, !allowed.has(key) || !validValue(body.textContent));
    }
  }
  function titleOf(panel) {
    return normal(panel?.querySelector(':scope > .panel-heading h2')?.textContent);
  }
  const eventFields = new Set([
    'can cu quyet dinh', 'hanh dong ap dung', 'ket qua xu ly',
    'phien ban chinh sach', 'quy tac khop', 'quy tac chan',
    'ma su kien', 'ma luong', 'thu tu', 'phat sinh luc',
    'nguon ip', 'ip nguon', 'tai khoan co so du lieu',
    'co so du lieu', 'nguon du lieu',
  ]);
  const incidentFields = new Set([
    'ip nguon', 'tin hieu', 'tin hieu quy tac', 'muc do', 'do tin cay',
    'status', 'diem rui ro cao nhat score', 'nguon da xac minh',
    'lan dau', 'lan cuoi', 'so bang chung', 'ma luong',
  ]);
  const evidenceFields = new Set([
    'phat sinh', 'trang thai danh gia rui ro', 'diem rui ro', 'quy tac khop',
  ]);
  const canonicalFields = new Set([
    'quyet dinh ·', 'quyet dinh', 'hanh dong ap dung', 'ket qua xu ly',
    'ip nguon', 'tai khoan co so du lieu', 'co so du lieu',
    'phat sinh luc (utc)', 'phien ban chinh sach', 'khop', 'chan',
    'trang thai rui ro', 'diem tu nguon', 'muc do', 'diem goc',
    'ma luong', 'ma su kien', 'ma yeu cau',
  ]);

  function guardKeyboard(tablist, kind) {
    const prop = kind === 'event' ? 'n91DemoEventGuard' : 'n91DemoIncidentGuard';
    if (tablist.dataset[prop]) return;
    tablist.dataset[prop] = '1';
    tablist.addEventListener('keydown', (ev) => {
      if (html.dataset.n91DemoMode !== 'compact' ||
          html.dataset.n91DemoPage !== kind) return;
      if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(ev.key)) return;
      const visible = Array.from(tablist.querySelectorAll('button[role="tab"]'))
        .filter((b) => !b.classList.contains(TAB_HIDE));
      if (!visible.length) return;
      const selected = visible.findIndex((b) => b.getAttribute('aria-selected') === 'true');
      let index = selected < 0 ? 0 : selected;
      if (ev.key === 'ArrowRight') index = (index + 1) % visible.length;
      if (ev.key === 'ArrowLeft') index = (index - 1 + visible.length) % visible.length;
      if (ev.key === 'Home') index = 0;
      if (ev.key === 'End') index = visible.length - 1;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      visible[index].focus();
      visible[index].click();
    }, true);
  }
  function compactTabs(tablist, kind, omit) {
    if (!tablist) return;
    for (const button of tablist.querySelectorAll('button[role="tab"]')) {
      const label = normal(button.textContent);
      // Never hide the selected tab, including an incoming deep link.
      const selected = button.getAttribute('aria-selected') === 'true';
      hide(button, omit.has(label) && !selected, TAB_HIDE);
    }
    guardKeyboard(tablist, kind);
  }

  function eventClassic(root) {
    const detail = root.querySelector('.v4-detail-grid');
    if (!detail || !root.querySelector('.v4-detail-statuses')) return false;
    filterFields(detail, eventFields);
    for (const card of detail.querySelectorAll('.v4-panel')) {
      const heading = titleOf(card);
      if (heading === 'su co lien quan') {
        hide(card, !card.querySelector('a[href^="#/incidents/"]'));
      } else if (heading === 'giai thich diem') {
        // A missing breakdown is not equivalent to risk 0.
        hide(card, !card.querySelector('.v4-breakdown-table tbody tr'));
      }
    }
    for (const el of detail.querySelectorAll('details.v4-json')) hide(el, true);
    for (const el of detail.querySelectorAll('.v4-panel-note')) {
      const txt = normal(el.textContent);
      hide(el, txt.startsWith('nguon chua cung cap') ||
        txt.startsWith('chua co chi tiet diem') ||
        txt.startsWith('chua co lien ket su co'));
    }
    for (const tile of root.querySelectorAll('.v4-detail-statuses > div')) {
      const name = normal(tile.querySelector('span')?.textContent);
      hide(tile, name.startsWith('class tai luc xu ly'));
    }
    return true;
  }
  function eventCanonical(root) {
    const section = root.querySelector('.n91-investigation[aria-label="Điều tra sự kiện"]');
    if (!section) return false;
    compactTabs(section.querySelector('.n91-tabs[role="tablist"]'), 'event',
      new Set(['phan tich cu phap', 'luong xu ly', 'parser', 'trace']));
    const activePanel = section.querySelector('[role="tabpanel"]');
    filterFields(activePanel, canonicalFields);
    if (activePanel) {
      // Remove placeholder SQL only. Never reveal a raw query.
      const pre = activePanel.querySelector(':scope > pre');
      if (pre && !validValue(pre.textContent)) {
        hide(pre, true);
        const heading = pre.previousElementSibling;
        if (heading?.tagName === 'H3') hide(heading, true);
      }
    }
    return true;
  }
  function incidentWorkbench(root) {
    const workbench = root.querySelector('.n91-workbench');
    if (!workbench || !workbench.querySelector('.v4-panel')) return false;
    for (const card of workbench.querySelectorAll('.v4-panel')) {
      const heading = titleOf(card);
      if (heading === 'thong tin su co') filterFields(card, incidentFields);
      else if (heading === 'nguon & pham vi' ||
               heading === 'tinh trang du lieu xu ly' ||
               heading === 'kho bang chung') hide(card, true);
    }
    hide(workbench.querySelector('.n91-wb-identity'), true);
    for (const tile of workbench.querySelectorAll('.n91-wb-counts > div')) {
      const label = normal(tile.querySelector('span')?.textContent);
      hide(tile, label !== 'so bang chung p17 ghi nhan' &&
        label !== 'lien ket truc tiep');
    }
    for (const event of workbench.querySelectorAll('.n91-wb-event')) {
      filterFields(event, evidenceFields);
      for (const panel of event.querySelectorAll(':scope > details')) {
        const heading = normal(panel.querySelector(':scope > summary')?.textContent);
        hide(panel, heading.startsWith('lien ket, doi chieu') ||
          heading.startsWith('ban ghi kiem toan chuan'));
      }
    }
    compactTabs(workbench.querySelector('.n91-wb-tabs[role="tablist"]'),
      'incident', new Set(['dong thoi gian', 'ghi chu xu ly']));
    return true;
  }
  function incidentClassic(root) {
    const identity = root.querySelector('.v4-incident-identity');
    if (!identity || !root.querySelector('.v4-detail-statuses')) return false;
    for (const card of root.querySelectorAll('.v4-detail-grid .v4-panel')) {
      const heading = titleOf(card);
      if (heading === 'phat hien va nguon') filterFields(card, incidentFields);
      else if (heading === 'doi chieu may ao' || heading === 'ghi chu ra soat' ||
               heading === 'danh gia phan ung') hide(card, true);
    }
    // Keep the real incident evidence panel and recorded response state.
    return true;
  }

  function updateButton() {
    const button = doc.getElementById(BUTTON_ID);
    if (!button) return;
    const label = state.compact ? 'Xem đầy đủ' : 'Chế độ demo gọn';
    if (button.textContent !== label) button.textContent = label;
    button.title = state.compact
      ? 'Hiện lại tất cả trường và tab gốc (không đổi dữ liệu)'
      : 'Chỉ ẩn thông tin phụ trong các trang chi tiết';
  }
  function addButton() {
    let button = doc.getElementById(BUTTON_ID);
    if (!button) {
      button = doc.createElement('button');
      button.id = BUTTON_ID;
      button.type = 'button';
      button.className = BUTTON_ID;
      button.addEventListener('click', () => {
        state.compact = !state.compact;
        html.dataset.n91DemoMode = state.compact ? 'compact' : 'full';
        updateButton();
      });
      doc.body.append(button);
    }
    updateButton();
  }
  function show() {
    state.scheduled = false;
    const page = currentRoute();
    const root = doc.getElementById('root');
    if (!page || !root) {
      delete html.dataset.n91DemoPage;
      doc.getElementById(BUTTON_ID)?.remove();
      return;
    }
    const matched = page.type === 'event'
      ? eventCanonical(root) || eventClassic(root)
      : incidentWorkbench(root) || incidentClassic(root);
    if (!matched) {
      delete html.dataset.n91DemoPage;
      doc.getElementById(BUTTON_ID)?.remove();
      return;
    }
    html.dataset.n91DemoPage = page.type;
    html.dataset.n91DemoMode = state.compact ? 'compact' : 'full';
    addButton();
  }
  function schedule() {
    if (state.scheduled) return;
    state.scheduled = true;
    Promise.resolve().then(show);
  }
  function start() {
    window.addEventListener('hashchange', () => {
      state.compact = true;
      schedule();
    });
    const root = doc.getElementById('root');
    if (!root) return;
    const observer = new MutationObserver(schedule);
    observer.observe(root, {childList: true, subtree: true});
    schedule();
    window.n91DetailDemoV2 = Object.freeze({
      version: '2.0', scope: 'all-event-and-incident-detail-records',
    });
  }
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();
