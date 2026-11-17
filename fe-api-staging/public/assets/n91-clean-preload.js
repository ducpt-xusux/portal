/* Executed before the Portal React entrypoint. This only normalizes the visual workspace. */
try {
  if (localStorage.getItem('dbsec-source') !== 'v4') localStorage.setItem('dbsec-source', 'v4');
  if (/^#\/system\/(policies|evaluation|demo-coverage)(?:[/?]|$)/.test(location.hash)) location.replace(location.pathname + location.search + '#/system/health');
} catch (_) { /* A disabled preference store must never block sign-in. */ }
window.addEventListener('hashchange', () => {
  if (/^#\/system\/(policies|evaluation|demo-coverage)(?:[/?]|$)/.test(location.hash)) location.hash = '#/system/health';
});
