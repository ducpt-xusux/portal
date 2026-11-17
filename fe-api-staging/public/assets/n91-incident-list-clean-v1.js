/* N91: Incident LIST presentation-only overlay. No backend mutation or data fabrication.
 * Scope: #/incidents and #/incidents?... only. It never edits detail pages.
 * evidence_count remains the P17 persisted value, not a verified canonical join.
 */
(() => {
  'use strict';
  const TAG = '[N91-INCIDENT-LIST-V1]';
  const HIDDEN = 'n91-incident-list-v1-hidden';
  const RENAME_ATTR = 'data-n91-incident-list-original-title';
  let scheduled = false;

  const normal = (value) => String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u0111\u0110]/g, 'd')
    .replace(/\s+/g, ' ').trim().toLowerCase();

  function onIncidentList() {
    const hash = window.location.hash || '';
    const path = hash.split('?', 1)[0];
    return path === '#/incidents' || path === '#/incidents/';
  }

  function setHidden(element, shouldHide) {
    if (!element) return;
    if (element.classList.contains(HIDDEN) !== shouldHide) {
      element.classList.toggle(HIDDEN, shouldHide);
    }
  }

  function missingResponse(value) {
    const t = normal(value);
    return new Set([
      'chua xac dinh', 'khong xac dinh', 'unknown', 'unavailable',
      'n/a', 'none', 'null', 'chua co du lieu', 'khong kha dung',
    ]).has(t) || !t;
  }

  function restore() {
    for (const element of document.querySelectorAll('.' + HIDDEN)) {
      setHidden(element, false);
    }
    for (const header of document.querySelectorAll('th[' + RENAME_ATTR + ']')) {
      const previous = header.getAttribute(RENAME_ATTR);
      if (previous !== null) header.textContent = previous;
      header.removeAttribute(RENAME_ATTR);
      header.removeAttribute('title');
    }
  }

  function reconcile() {
    if (!onIncidentList()) {
      restore();
      return;
    }
    const app = document.getElementById('root');
    if (!app) return;
    // Fail closed if live markup does not have the expected column semantics.
    const tables = Array.from(app.querySelectorAll('table.v4-investigation-table'));
    for (const table of tables) {
      const headers = Array.from(table.querySelectorAll('thead > tr > th'));
      const labels = headers.map(h => normal(h.textContent));
      const detect = labels.findIndex(t => t.includes('phat hien') && t.includes('phan ung'));
      const verify = labels.findIndex(t => t.includes('xac minh nguon') && t.includes('doi chieu'));
      const evidence = labels.findIndex(t => t.startsWith('bang chung'));
      if (detect < 0 || verify < 0 || evidence < 0) continue;
      if (!(evidence < detect && detect < verify)) continue;
      const proofHead = headers[evidence];
      if (!proofHead.hasAttribute(RENAME_ATTR)) {
        proofHead.setAttribute(RENAME_ATTR, proofHead.textContent);
      }
      const label = 'B\u1eb0NG CH\u1ee8NG P17';
      if (proofHead.textContent !== label) proofHead.textContent = label;
      const explanation = 'S\u1ed1 b\u1eb1ng ch\u1ee9ng do ngu\u1ed3n ph\u00e1t hi\u1ec7n P17 ghi nh\u1eadn; kh\u00f4ng t\u1ef1 ch\u1ee9ng minh s\u1ed1 b\u1ea3n ghi Canonical Audit \u0111\u00e3 \u0111\u1ed1i chi\u1ebfu.';
      if (proofHead.getAttribute('title') !== explanation) proofHead.setAttribute('title', explanation);
      const rows = table.querySelectorAll('tbody > tr');
      for (const tr of rows) {
        const cells = Array.from(tr.children).filter(node => node.tagName === 'TD');
        if (cells.length !== headers.length) continue;
        const detectCell = cells[detect];
        const verifyCell = cells[verify];
        // Keep the incident detection state. Hide only the unknown response badge.
        for (const small of detectCell.querySelectorAll(':scope > small')) {
          setHidden(small, missingResponse(small.textContent));
        }
        // Hide live mapping metadata and the redundant historical warning in LIST only.
        // Keep 'current IP match' badge and server link, not historical identity proof.
        for (const small of verifyCell.querySelectorAll('.v4-verification > small')) {
          const t = normal(small.textContent);
          const remove = t.startsWith('neutron:') || t.startsWith('danh tinh luc su co:');
          setHidden(small, remove);
        }
        const count = cells[evidence].querySelector(':scope > strong');
        if (count && count.getAttribute('title') !== explanation) count.setAttribute('title', explanation);
      }
    }
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(() => {
      scheduled = false;
      try { reconcile(); }
      catch (error) { console.warn(TAG, 'Overlay skipped:', error?.message || error); }
    });
  }

  function init() {
    if (!document.documentElement) return;
    if (window.__n91IncidentListCleanV1) return;
    window.__n91IncidentListCleanV1 = { version: '1.0', refresh: schedule };
    const observer = new MutationObserver(schedule);
    observer.observe(document.documentElement, {subtree:true, childList:true, characterData:true});
    window.addEventListener('hashchange', schedule);
    schedule();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once:true});
  } else init();
})();
