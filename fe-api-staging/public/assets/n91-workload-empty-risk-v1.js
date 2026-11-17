/* N91 Workload Empty Risk V1: read-only, presentation-only patch.
 * Scope: all VM detail overview routes #/workloads/<server-id>.
 * Hide ONLY the "Mức rủi ro liên quan từ sự cố gần đây" panel when the
 * original React component explicitly says no recent risk summary exists.
 * Never infer an incident, mutate any API response, or change VM operations.
 */
(() => {
  'use strict';
  const selector = 'n91-workload-risk-empty-v1';
  let scheduled = false;

  function matchesWorkloadDetail() {
    const path = (window.location.hash || '').split('?')[0];
    return /^#\/workloads\/[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\/?$/.test(path);
  }
  function normalized(value) {
    return String(value || '').normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '').replace(/[\u0111\u0110]/g, 'd')
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }
  function update() {
    scheduled = false;
    const root = document.getElementById('root');
    if (!root) return;
    const overview = root.querySelector('.v4-main section[aria-label="Overview máy ảo"]');
    if (!overview) return;
    // We operate only on the overview of a single VM, not the VM list, console,
    // security group widgets, isolation controls, or other Portal pages.
    const inScope = matchesWorkloadDetail() &&
      new URLSearchParams((location.hash.split('?')[1] || '')).get('tab') !== 'console';
    for (const panel of overview.querySelectorAll('section.v4-panel')) {
      const heading = normalized(panel.querySelector(':scope > .panel-heading h2')?.textContent);
      if (heading !== 'muc rui ro lien quan tu su co gan day') continue;
      const exposure = panel.querySelector('.v4-risk-exposure');
      const explicitEmpty = Boolean(exposure && Array.from(exposure.querySelectorAll('small'))
        .some(node => normalized(node.textContent) === 'chua co tong hop su co gan day.'));
      const actualEvidence = Boolean(panel.querySelector('a[href^="#/incidents/"]') ||
        exposure?.querySelector('strong'));
      panel.classList.toggle(selector, !!(inScope && explicitEmpty && !actualEvidence));
    }
  }
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    Promise.resolve().then(update);
  }
  function start() {
    const root = document.getElementById('root');
    if (!root) return;
    new MutationObserver(schedule).observe(root, {childList: true, subtree: true});
    window.addEventListener('hashchange', schedule);
    schedule();
    window.n91WorkloadEmptyRiskV1 = Object.freeze({scope: 'all-workload-overviews', version: '1.0'});
  }
  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', start, {once: true});
  else start();
})();
