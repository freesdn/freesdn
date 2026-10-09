/// <reference types="node" />
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Execute the shipped static relay with controlled globals, not a browser. */
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
const code = readFileSync(resolve('public/vault-export-callback.js'), 'utf8');
const valid = 'https://owned-ui.example/vault-export-callback.html?code=synthetic-code&state=synthetic-state';
function run(href: string, hasOpener = true, brokenHistory = false) {
  const postMessage = vi.fn(); const text = { textContent: '' };
  const replaceState = vi.fn(() => { if (brokenHistory) throw new Error(); });
  const storage = { setItem: vi.fn(() => { throw new Error('No storage'); }) };
  const fetch = vi.fn(() => { throw new Error('No network'); });
  runInNewContext(code, { URL, document: { getElementById: () => text }, window: {
    location: { href }, history: { replaceState }, opener: hasOpener ? { postMessage } : null,
    localStorage: storage, sessionStorage: storage, fetch,
  } });
  expect(storage.setItem).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
  return { postMessage, replaceState, text };
}
describe('standalone vault callback relay', () => {
  it('scrubs query before one same-origin delivery and does not claim authentication', () => {
    const result = run(valid);
    expect(result.replaceState).toHaveBeenCalledWith(null, '', '/vault-export-callback.html');
    expect(result.postMessage).toHaveBeenCalledTimes(1);
    expect(result.postMessage).toHaveBeenCalledWith({ type: 'freesdn-vault-identity-v1', state: 'synthetic-state', code: 'synthetic-code' }, 'https://owned-ui.example');
    expect(result.replaceState.mock.invocationCallOrder[0]).toBeLessThan(result.postMessage.mock.invocationCallOrder[0]);
    expect(result.text.textContent).toContain('Check that window for the outcome');
  });
  it.each(['http', 'path', 'fragment', 'duplicate-code', 'duplicate-state', 'missing-code', 'missing-state', 'error', 'control', 'bound', 'no-opener', 'history'])('refuses %s without reflecting provider text', fault => {
    let url = valid;
    if (fault === 'http') url = url.replace('https:', 'http:'); if (fault === 'path') url = url.replace('vault-export', 'login');
    if (fault === 'fragment') url += '#secret'; if (fault === 'duplicate-code') url += '&code=other';
    if (fault === 'duplicate-state') url += '&state=other'; if (fault === 'missing-code') url = url.replace('code=synthetic-code&', '');
    if (fault === 'missing-state') url = url.replace('&state=synthetic-state', '');
    if (fault === 'error') url += '&error=private-provider-message';
    if (fault === 'control') url = url.replace('synthetic-code', 'a%0Ab');
    if (fault === 'bound') url = url.replace('synthetic-code', 'x'.repeat(8193));
    const result = run(url, fault !== 'no-opener', fault === 'history'); expect(result.postMessage).not.toHaveBeenCalled();
    expect(result.text.textContent).toContain('could not be delivered'); expect(result.text.textContent).not.toContain('synthetic');
    expect(result.text.textContent).not.toContain('private-provider-message'); expect(result.replaceState).toHaveBeenCalledTimes(1);
  });
});
