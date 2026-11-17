/* N91 single Detail toggle V1. Does not alter React or API data.
   Keep the existing title-bar action. Reuse the demo overlay's own
   mode switch when that action does not already change its state. */
(() => {
  'use strict';
  const lowerIds = [
    'n91-detail-demo-switch-v3',
    'n91-detail-demo-switch-v2',
    'n91-detail-demo-switch-v1'
  ];
  const norm = (s) => String(s || '').normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '').replace(/[đĐ]/g, 'd')
    .replace(/\s+/g, ' ').trim().toLowerCase();
  const isDetail = () => /^#\/(?:events|incidents)\/[^/?#]+(?:\?|$)/.test(location.hash || '');
  const lowerButton = () => {
    for (const id of lowerIds) {
      const btn = document.getElementById(id);
      if (btn && typeof btn.click === 'function') return btn;
    }
    return null;
  };
  const titleAction = (element) => {
    const btn = element?.closest?.('button');
    if (!btn || !btn.closest?.('#root .page-heading .page-actions, #root .v4-page-heading .page-actions')) return null;
    const text = norm(btn.textContent);
    if (!/(?:xem day du|xem gon|che bot|demo gon|thu gon|hien day du)/.test(text)) return null;
    return btn;
  };
  document.addEventListener('click', (event) => {
    if (!isDetail() || !titleAction(event.target)) return;
    const before = document.documentElement.dataset.n91DemoMode;
    const lower = lowerButton();
    if (!lower) return;
    // Let the original top button finish. If it controls the same V2/V3
    // state, do nothing. Otherwise forward exactly one click to the
    // original demo switch, retaining the original React action.
    queueMicrotask(() => {
      if (!isDetail() || !lower.isConnected) return;
      if (document.documentElement.dataset.n91DemoMode === before) {
        lower.click();
      }
    });
  }, true);
  window.n91SingleDetailToggleV1 = Object.freeze({
    version: '1.0',
    scope: 'all-event-and-incident-detail-records',
    lowerSwitchHidden: true,
  });
})();
