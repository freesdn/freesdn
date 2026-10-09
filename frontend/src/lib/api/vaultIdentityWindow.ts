// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Owned OIDC confirmation window. No token, code or intent persistence. */
export const VAULT_CALLBACK_PATH = '/vault-export-callback.html';
const MESSAGE = 'freesdn-vault-identity-v1';
const opaque = (v: unknown, max: number): v is string => typeof v === 'string'
  && v.length > 0 && v.length <= max && [...v].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127);

function fail(): Error { return new Error('Identity confirmation ended. Close this window and start a new confirmation.'); }

/** Call synchronously on an explicit user click, before any network wait.
 * Only the configured same-origin static relay may answer, from this exact
 * WindowProxy and with this exact state. IdP/browser deployment still needs
 * independent acceptance (including COOP and popup restrictions).
 */
export function openVaultIdentityWindow(callbackUri: string, assertCurrent: () => void) {
  assertCurrent();
  const callback = new URL(callbackUri);
  if (callback.protocol !== 'https:' || callback.origin !== window.location.origin
    || callback.pathname !== VAULT_CALLBACK_PATH || callback.search || callback.hash
    || callback.username || callback.password) throw fail();
  const child = window.open('about:blank', '_blank', 'popup,width=560,height=720');
  if (!child) throw fail();
  let finished = false; let state: string | undefined; let wallExpiry = 0;
  const start = performance.now(); let deadline = start + 120000;
  let resolve!: (value: { state: string; code: string }) => void;
  let reject!: (reason: Error) => void;
  const result = new Promise<{ state: string; code: string }>((yes, no) => { resolve = yes; reject = no; });
  // A failure can happen while the caller is still awaiting the start HTTP
  // response. Attach a handler immediately; the original promise still rejects.
  void result.catch(() => undefined);
  let timer: ReturnType<typeof setInterval> | undefined;
  const cleanup = () => {
    window.removeEventListener('message', receive);
    if (timer !== undefined) clearInterval(timer);
    try { child.close(); } catch { /* Closing is best effort after isolation changes. */ }
    state = undefined;
  };
  const cancel = () => { if (!finished) { finished = true; cleanup(); reject(fail()); } };
  const current = () => {
    assertCurrent();
    if (finished || child.closed || performance.now() >= deadline
      || (wallExpiry > 0 && Date.now() >= wallExpiry)) throw fail();
  };
  function receive(event: MessageEvent) {
    if (finished || !state || event.origin !== callback.origin || event.source !== child) return;
    try {
      current(); const data: unknown = event.data;
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw fail();
      const value = data as Record<string, unknown>;
      if (Object.keys(value).sort().join(',') !== 'code,state,type' || value.type !== MESSAGE
        || value.state !== state || !opaque(value.code, 8192)) throw fail();
      const accepted = { state, code: value.code };
      finished = true; cleanup(); resolve(accepted);
    } catch { cancel(); }
  }
  try {
    window.addEventListener('message', receive);
    timer = setInterval(() => { try { current(); } catch { cancel(); } }, 100);
  } catch { cancel(); }
  return Object.freeze({ result, cancel,
    navigate(value: { authorize_url: string; state: string; expires_at: number }) {
      try {
        current(); if (state || !opaque(value.state, 8192)) throw fail();
        const target = new URL(value.authorize_url);
        const remaining = value.expires_at * 1000 - Date.now();
        if (target.protocol !== 'https:' || target.username || target.password || target.hash
          || target.searchParams.getAll('state').length !== 1 || target.searchParams.get('state') !== value.state
          || !Number.isSafeInteger(value.expires_at) || remaining <= 0 || remaining > 600000) throw fail();
        deadline = Math.min(deadline, performance.now() + remaining);
        wallExpiry = value.expires_at * 1000; state = value.state;
        child.location.replace(target.href);
      } catch { cancel(); throw fail(); }
    },
  });
}
