/* DBSEC Portal 5188, presentation-only V4.
   Does not change queries, data, API, authorization, isolation or services.
   The compact view only hides secondary information; full view remains available. */
(() => {
  'use strict';
  if (window.__N91_DEMO_CLEAN_V4__) return;
  window.__N91_DEMO_CLEAN_V4__ = true;
  const BRAND = 'C\u1ed4NG QU\u1ea2N TR\u1eca B\u1ea2O M\u1eacT';
  const norm = x => String(x || '').normalize('NFC').replace(/\s+/g, ' ').trim();
  const normUpper = x => norm(x).toLocaleUpperCase('vi');
  const exact = new Map([
    ['RISK SCORE', '\u0110i\u1ec3m r\u1ee7i ro'],
    ['RISK STATUS', 'Tr\u1ea1ng th\u00e1i t\u00ednh \u0111i\u1ec3m'],
    ['CLASS T\u1ea0I L\u00daC X\u1eec L\u00dd', 'Lo\u1ea1i s\u1ef1 ki\u1ec7n'],
    ['SQL & ch\u00ednh s\u00e1ch decision', 'Truy v\u1ea5n v\u00e0 ch\u00ednh s\u00e1ch'],
    ['s\u1ef1 ki\u1ec7n projection', 'B\u1ea3n ghi s\u1ef1 ki\u1ec7n'],
    ['Gi\u1ea3i th\u00edch \u0111i\u1ec3m', 'Gi\u1ea3i th\u00edch \u0111i\u1ec3m r\u1ee7i ro'],
    ['\u0110\u1ecbnh danh v\u00e0 ngu\u1ed3n g\u1ed1c', 'Ngu\u1ed3n v\u00e0 \u0111\u1ecbnh danh'],
    ['Ngu\u1ed3n IP', 'IP ngu\u1ed3n'],
    ['received_utc / ingested_at', 'Th\u1eddi \u0111i\u1ec3m ghi nh\u1eadn'],
    ['Storage recorded \u00b7 ngu\u1ed3n', 'L\u01b0u t\u1ea1i ngu\u1ed3n'],
    ['Portal imported \u00b7 PORTAL_CLOCK', 'Portal ti\u1ebfp nh\u1eadn'],
    ['Identity status', 'Tr\u1ea1ng th\u00e1i \u0111\u1ecbnh danh'],
    ['Coverage', 'Ph\u1ea1m vi bao ph\u1ee7'],
    ['Verification', 'X\u00e1c minh'],
    ['Hash basis', 'C\u01a1 s\u1edf t\u00ednh b\u0103m'],
    ['Human r\u00e0 so\u00e1t', 'Ng\u01b0\u1eddi r\u00e0 so\u00e1t'],
    ['SHA256 n\u1ed9i dung \u00b7 upstream', 'SHA-256 n\u1ed9i dung ngu\u1ed3n'],
    ['Y\u00eau c\u1ea7u received \u00b7 ngu\u1ed3n', 'Th\u1eddi \u0111i\u1ec3m nh\u1eadn y\u00eau c\u1ea7u'],
    ['Withheld / ch\u01b0a cung c\u1ea5p', 'Ch\u01b0a cung c\u1ea5p']
  ]);
  function fixLabels() {
    const app = document.querySelector('.v4-app');
    if (!app) return;
    for (const el of app.querySelectorAll('h1,h2,h3,dt,th,.v4-detail-statuses span,.v4-event-filters label')) {
      if (el.closest('code,pre,textarea,[contenteditable="true"]')) continue;
      if (el.children.length > 0 && !el.matches('h1,h2,h3,dt,th')) continue;
      const old = norm(el.textContent);
      const next = exact.get(old);
      if (next && old !== next && !el.querySelector('button,a,input,svg')) el.textContent = next;
    }
    // The legacy events list uses an English effective-action prefix.
    for (const node of app.querySelectorAll('.v4-table td small')) {
      if (node.children.length) continue;
      const old = node.textContent;
      if (old.startsWith('Effective: ')) node.textContent = '\u00c1p d\u1ee5ng: ' + old.slice('Effective: '.length);
    }
  }
  function measureText(el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    return range.getBoundingClientRect().width;
  }
  function fixBrand() {
    const sidebar = document.querySelector('.v4-app .sidebar, .v4-app aside, .v4-sidebar, aside.sidebar, .sidebar');
    if (!sidebar) return;
    const nodes = [...sidebar.querySelectorAll('.brand-sub,.subbrand,[class*="brand"] small,[class*="brand"] p,span')];
    const matches = nodes.filter(el => {
      const val = normUpper(el.innerText || el.textContent);
      return val === BRAND || val.replace(/\s/g, '') === BRAND.replace(/\s/g, '');
    });
    let el = matches.find(node => !matches.some(other => other !== node && node.contains(other)));
    if (!el) return;
    // Only the exact known subtitle is ever rewritten (including forced BR tags).
    if (el.textContent !== BRAND || el.children.length) el.replaceChildren(document.createTextNode(BRAND));
    if (!el.classList.contains('n91-demo-brand')) el.classList.add('n91-demo-brand');
    const st = el.style;
    const set = (key, val) => { if (st.getPropertyValue(key) !== val || st.getPropertyPriority(key) !== 'important') st.setProperty(key, val, 'important'); };
    set('white-space', 'nowrap');
    set('max-width', 'none');
    set('width', 'max-content');
    set('word-break', 'normal');
    set('overflow-wrap', 'normal');
    set('letter-spacing', '0.025em');
    set('line-height', '1.15');
    const room = Math.floor(sidebar.getBoundingClientRect().right - el.getBoundingClientRect().left - 11);
    if (room <= 30) return;
    let size = 10.2;
    for (; size >= 8.6; size -= .2) {
      set('font-size', size.toFixed(1) + 'px');
      if (measureText(el) <= room) break;
    }
    if (size < 8.6) set('font-size', '8.6px');
    const measured = measureText(el);
    const scale = measured > room && measured > 0 ? (room / measured).toFixed(3) : '1';
    set('transform-origin', 'left center');
    set('transform', 'scaleX(' + scale + ')');
  }
  const keepPolicy = new Set([
    'H\u00e0nh \u0111\u1ed9ng \u00e1p d\u1ee5ng', 'K\u1ebft qu\u1ea3 x\u1eed l\u00fd',
    'Quy t\u1eafc kh\u1edbp', 'Quy t\u1eafc ch\u1eb7n', 'Phi\u00ean b\u1ea3n ch\u00ednh s\u00e1ch'
  ]);
  const keepSource = new Set([
    'M\u00e3 s\u1ef1 ki\u1ec7n', 'Th\u1ee9 t\u1ef1', 'Ph\u00e1t sinh l\u00fac',
    'IP ngu\u1ed3n', 'T\u00e0i kho\u1ea3n c\u01a1 s\u1edf d\u1eef li\u1ec7u', 'C\u01a1 s\u1edf d\u1eef li\u1ec7u'
  ]);
  function markFields(panel, keep) {
    for (const entry of panel.querySelectorAll('dl.v4-fields > div')) {
      const label = norm(entry.querySelector('dt')?.textContent);
      const extra = !keep.has(label);
      entry.classList.toggle('n91-demo-advanced-only', extra);
      // Unknown labels are preserved in the full view, never destroyed.
    }
  }
  function applyEventDetail() {
    const route = (location.hash || '').match(/^#\/events\/[^/?]+/);
    const main = document.querySelector('.v4-app main, .v4-app .v4-main');
    const page = main?.querySelector('.v4-page-content') || main;
    const grid = route && page?.querySelector('.v4-detail-grid');
    document.body.classList.toggle('n91-demo-event-detail', Boolean(grid));
    if (!grid) return;
    const panels = [...grid.querySelectorAll('section.v4-panel')];
    const heading = p => norm(p.querySelector('.panel-heading h2')?.textContent).toLocaleLowerCase('vi');
    const source = panels.find(p => heading(p).includes('ngu\u1ed3n v\u00e0 \u0111\u1ecbnh danh'));
    const policy = panels.find(p => /truy v\u1ea5n v\u00e0 ch\u00ednh s\u00e1ch|b\u1ea3n ghi s\u1ef1 ki\u1ec7n|sql &/i.test(heading(p)));
    const score = panels.find(p => heading(p).includes('gi\u1ea3i th\u00edch \u0111i\u1ec3m'));
    const incident = panels.find(p => heading(p).includes('s\u1ef1 c\u1ed1 li\u00ean quan'));
    if (!source || !policy) return; // Fail open visually when React markup differs.
    markFields(source, keepSource);
    markFields(policy, keepPolicy);
    for (const node of page.querySelectorAll('.v4-detail-statuses > div')) {
      node.classList.toggle('n91-demo-advanced-only', [...node.parentElement.children].indexOf(node) >= 2);
    }
    // Breakdown table already explains the score; three repeated totals do not.
    if (score?.querySelector('.v4-breakdown-table')) score.querySelector('dl.v4-fields')?.classList.add('n91-demo-advanced-only');
    if (incident && !incident.querySelector('.v4-link-list a')) incident.classList.add('n91-demo-advanced-only');
    policy.querySelectorAll('.v4-privacy p').forEach(x => x.classList.add('n91-demo-advanced-only'));
    policy.querySelectorAll('details.v4-json').forEach(x => x.classList.add('n91-demo-advanced-only'));
    source.querySelectorAll('details.v4-json').forEach(x => x.classList.add('n91-demo-advanced-only'));
    const extra = page.querySelector('.v4-page-heading > div > p');
    if (extra && /^[a-f\d-]{32,40}$/i.test(norm(extra.textContent))) extra.classList.add('n91-demo-advanced-only');
    // Hide a generic empty reasons section; actual reason lists remain visible.
    if (!policy.querySelector('.v4-reasons li')) {
      policy.querySelectorAll('.v4-subheading,.v4-subheading + .v4-panel-note').forEach(x => x.classList.add('n91-demo-advanced-only'));
    }
    const actions = page.querySelector('.v4-page-heading .page-actions');
    if (actions && !actions.querySelector('[data-n91-demo-expand]')) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'button secondary n91-demo-expand';
      button.setAttribute('data-n91-demo-expand', '1');
      button.setAttribute('aria-pressed', 'false');
      button.textContent = 'Xem \u0111\u1ea7y \u0111\u1ee7';
      actions.prepend(button);
    }
  }
  function cleanVNext() {
    const wb = document.getElementById('n91-unified-workbench');
    if (!wb) return;
    // The three counters and verbose provenance are redundant in the demo view.
    // The source data, P17 case evidence, legacy incidents and system status remain intact.
    const caseList = wb.querySelector('.n91u-case');
    if (caseList) {
      const head = wb.querySelector('.n91u-head:not(.n91u-headtop) h2');
      if (head && head.textContent === 'H\u1ed3 s\u01a1 c\u1ea7n xem x\u00e9t') head.textContent = 'H\u1ed3 s\u01a1 ph\u00e2n t\u00edch';
    }
    for (const p of wb.querySelectorAll('.n91u-notice')) {
      const txt = norm(p.textContent);
      if (txt.includes('Vi\u1ec7c li\u00ean k\u1ebft h\u1ed3 s\u01a1 m\u1edbi kh\u00f4ng b\u1eaft bu\u1ed9c n\u1eb1m trong 60/120 gi\u00e2y.')) {
        for (const n of p.childNodes) {
          if (n.nodeType === Node.TEXT_NODE && n.nodeValue?.includes('Vi\u1ec7c li\u00ean k\u1ebft')) n.nodeValue = n.nodeValue.replace('Vi\u1ec7c li\u00ean k\u1ebft h\u1ed3 s\u01a1 m\u1edbi kh\u00f4ng b\u1eaft bu\u1ed9c n\u1eb1m trong 60/120 gi\u00e2y.', '');
        }
      }
    }
  }
  let scheduled = false;
  function update() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      fixBrand();
      fixLabels();
      cleanVNext();
      applyEventDetail();
    });
  }
  document.addEventListener('click', event => {
    const button = event.target.closest?.('[data-n91-demo-expand]');
    if (!button) return;
    event.preventDefault();
    const expanded = !document.body.classList.contains('n91-demo-show-all');
    document.body.classList.toggle('n91-demo-show-all', expanded);
    button.textContent = expanded ? 'Thu g\u1ecdn' : 'Xem \u0111\u1ea7y \u0111\u1ee7';
    button.setAttribute('aria-pressed', String(expanded));
  });
  addEventListener('hashchange', () => {
    document.body.classList.remove('n91-demo-show-all');
    update();
  });
  addEventListener('resize', update, {passive: true});
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', update, {once: true});
  else update();
  const root = document.getElementById('root') || document.body;
  new MutationObserver(update).observe(root, {subtree: true, childList: true});
})();
