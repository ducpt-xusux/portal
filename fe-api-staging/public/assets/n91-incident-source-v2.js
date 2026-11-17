/* N91 Incident source column V2: presentation-only, scoped to the INCIDENT LIST.
 * Never changes API, Neutron identity semantics or incident data.
 * Compatible with N91_INCIDENT_LIST_CLEAN_V1, which inspects the original header text.
 */
(() => {
  'use strict';
  const NS = 'n91-incident-source-v2';
  const HIDDEN = NS + '-hidden';
  const HEADER = NS + '-header';
  const BADGE_PREV = 'data-' + NS + '-original-badge';
  const MATCH_LABEL = 'Khớp IP';
  const HEADER_LABEL = 'XÁC MINH NGUỒN';
  let scheduled = false;

  const normalized = value => String(value ?? '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u0111\u0110]/g, 'd').replace(/\s+/g, ' ')
    .trim().toLowerCase();

  function isList() {
    const path = (location.hash || '').split('?', 1)[0].replace(/\/$/, '');
    return path === '#/incidents';
  }

  function textNode(element) {
    return Array.from(element.childNodes).find(n => n.nodeType === 3 && n.nodeValue.trim());
  }

  function restore() {
    for (const th of document.querySelectorAll('th.' + HEADER)) {
      const old = th.querySelector('[data-n91-source-v2-original-heading]');
      if (old) th.textContent = old.textContent;
      th.classList.remove(HEADER);
    }
    for (const badge of document.querySelectorAll('[' + BADGE_PREV + ']')) {
      const node = textNode(badge);
      if (node) node.nodeValue = badge.getAttribute(BADGE_PREV);
      badge.removeAttribute(BADGE_PREV);
    }
    for (const hidden of document.querySelectorAll('.' + HIDDEN)) {
      hidden.classList.remove(HIDDEN);
    }
  }

  function markHeader(th) {
    if (th.classList.contains(HEADER)) return;
    const original = th.textContent;
    if (!normalized(original).includes('doi chieu') ||
        !normalized(original).includes('xac minh nguon')) return;
    // Keep the source text in a visually hidden node: V1 still detects
    // the original column and continues to hide its previous irrelevant fields.
    const originalSpan = document.createElement('span');
    originalSpan.setAttribute('data-n91-source-v2-original-heading', '');
    originalSpan.className = HIDDEN;
    originalSpan.setAttribute('aria-hidden', 'true');
    originalSpan.textContent = original;
    const visible = document.createElement('span');
    visible.className = NS + '-visible-heading';
    visible.textContent = HEADER_LABEL;
    th.replaceChildren(originalSpan, visible);
    th.classList.add(HEADER);
  }

  function markMapping(cell) {
    const mapping = cell.querySelector('.v4-verification');
    if (!mapping) return;
    const vm = mapping.querySelector(':scope > a[href^="#/workloads/"]');
    if (!vm || !vm.textContent.trim()) return;  // No fabricated VM identity.
    const statusLine = mapping.querySelector(':scope > div');
    if (!statusLine) return;
    const badges = Array.from(statusLine.children)
      .filter(el => el.classList.contains('v4-badge'));
    if (badges.length < 1) return;
    const first = badges[0];
    const value = normalized(first.textContent);
    const alreadyAdjusted = first.hasAttribute(BADGE_PREV);
    const matched = ['khop ip hien tai', 'current ip match', 'khop ip'].includes(value);
    const freshness = badges.length > 1 ? badges[1] : null;
    if (!matched) {
      // When a React refresh changes the mapping to UNMATCHED, never keep
      // an old "Khớp IP" overlay or a hidden freshness badge.
      if (alreadyAdjusted) first.removeAttribute(BADGE_PREV);
      if (freshness) freshness.classList.remove(HIDDEN);
      return;
    }
    const isFresh = !freshness || ['da cap nhat', 'fresh', 'trong thoi han'].includes(normalized(freshness.textContent));
    if (!isFresh) {
      if (freshness) freshness.classList.remove(HIDDEN);
      // Display the stale/unknown status, rather than presenting fresh IP proof.
      return;
    }

    const node = textNode(first);
    if (node && value !== normalized(MATCH_LABEL)) {
      if (!alreadyAdjusted) first.setAttribute(BADGE_PREV, node.nodeValue);
      node.nodeValue = MATCH_LABEL;
    }
    // Suppress the redundant FRESH badge; stale/unknown remains visible.
    if (freshness) freshness.classList.add(HIDDEN);
  }

  function reconcile() {
    if (!isList()) { restore(); return; }
    const root = document.getElementById('root');
    if (!root) return;
    for (const table of root.querySelectorAll('table.v4-investigation-table')) {
      const headers = Array.from(table.querySelectorAll('thead > tr > th'));
      const ix = headers.findIndex(th => {
        const value = normalized(th.textContent);
        return value.includes('xac minh nguon') && value.includes('doi chieu');
      });
      if (ix < 0) continue; // Fail closed if page markup/semantics differs.
      markHeader(headers[ix]);
      for (const tr of table.querySelectorAll('tbody > tr')) {
        const cells = Array.from(tr.children).filter(el => el.tagName === 'TD');
        if (cells.length !== headers.length) continue;
        markMapping(cells[ix]);
      }
    }
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      try { reconcile(); }
      catch (error) { console.warn('[N91-INCIDENT-SOURCE-V2] skipped:', error?.message || error); }
    });
  }

  function init() {
    if (window.__n91IncidentSourceV2) return;
    window.__n91IncidentSourceV2 = { version: '2.0', refresh: schedule };
    new MutationObserver(schedule).observe(document.documentElement, {
      subtree: true, childList: true, characterData: true,
    });
    window.addEventListener('hashchange', schedule);
    schedule();
  }
  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
