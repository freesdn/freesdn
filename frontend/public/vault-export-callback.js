// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
// Static relay only: no application startup, login, fetch, storage or logging.
(() => {
  const result = document.getElementById('result');
  const original = new URL(window.location.href);
  let message;
  try {
    // Remove code/state even when the response is rejected. Deployment access
    // logs and reverse proxies must also omit callback query strings.
    window.history.replaceState(null, '', original.pathname);
    const code = original.searchParams.get('code');
    const state = original.searchParams.get('state');
    if (original.protocol !== 'https:' || original.pathname !== '/vault-export-callback.html'
      || original.hash || original.searchParams.has('error')
      || original.searchParams.getAll('code').length !== 1 || original.searchParams.getAll('state').length !== 1
      || !code || code.length > 8192 || !state || state.length > 8192
      || /[\u0000-\u001f\u007f]/.test(code + state) || !window.opener || window.opener === window) throw new Error();
    message = { type: 'freesdn-vault-identity-v1', state, code };
    // Explicit same-origin target only. The parent additionally checks source,
    // pending state, current authority and deadline before backend exchange.
    window.opener.postMessage(message, original.origin);
    if (result) result.textContent = 'Response delivered to the original window. Check that window for the outcome; you may close this one.';
  } catch {
    if (result) result.textContent = 'Identity confirmation could not be delivered. Close this window and start a new confirmation.';
  } finally { message = undefined; }
})();
