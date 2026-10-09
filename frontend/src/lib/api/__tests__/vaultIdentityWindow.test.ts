// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Controlled WindowProxy/events; actual popup/IdP/COOP acceptance is separate. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openVaultIdentityWindow } from '../vaultIdentityWindow';

const callback = 'https://owned-ui.example/vault-export-callback.html';
const state = 'synthetic-owned-state';
let listener: ((event: MessageEvent) => void) | undefined;
let child: { closed: boolean; close: ReturnType<typeof vi.fn>; location: { replace: ReturnType<typeof vi.fn> } };
let host: { location: { origin: string }; open: ReturnType<typeof vi.fn>; addEventListener: ReturnType<typeof vi.fn>; removeEventListener: ReturnType<typeof vi.fn> };
const scopes: ReturnType<typeof openVaultIdentityWindow>[] = [];
function create(check: () => void = vi.fn()) { const result = openVaultIdentityWindow(callback, check); scopes.push(result); return result; }
function begin(scope: ReturnType<typeof create>) { scope.navigate({ authorize_url: `https://owned-idp.example/authorize?state=${state}`, state, expires_at: Math.floor(Date.now() / 1000) + 100 }); }
function message(data: unknown = { type: 'freesdn-vault-identity-v1', state, code: 'synthetic-owned-code' }, source: unknown = child, origin = 'https://owned-ui.example') {
  listener?.({ data, source, origin } as MessageEvent);
}
beforeEach(() => {
  vi.useFakeTimers(); listener = undefined;
  child = { closed: false, close: vi.fn(() => { child.closed = true; }), location: { replace: vi.fn() } };
  host = { location: { origin: 'https://owned-ui.example' }, open: vi.fn(() => child),
    addEventListener: vi.fn((_name, value) => { listener = value; }),
    removeEventListener: vi.fn((_name, value) => { if (listener === value) listener = undefined; }) };
  vi.stubGlobal('window', host);
});
afterEach(() => { scopes.splice(0).forEach(scope => scope.cancel()); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('owned vault identity window', () => {
  it('opens synchronously and accepts one exact origin/source/state callback', async () => {
    const scope = create(); expect(host.open).toHaveBeenCalledWith('about:blank', '_blank', 'popup,width=560,height=720');
    expect(child.location.replace).not.toHaveBeenCalled(); begin(scope); message();
    expect(await scope.result).toEqual({ state, code: 'synthetic-owned-code' });
    expect(child.close).toHaveBeenCalledTimes(1); expect(listener).toBeUndefined();
    expect(vi.getTimerCount()).toBe(0); scope.cancel(); expect(child.close).toHaveBeenCalledTimes(1);
  });
  it.each(['http', 'other-origin', 'other-path', 'query', 'fragment', 'userinfo'])('refuses callback policy %s before opening', fault => {
    const values: Record<string, string> = { http: callback.replace('https:', 'http:'), 'other-origin': callback.replace('owned-ui', 'other'),
      'other-path': callback.replace('vault-export', 'login'), query: callback + '?next=x', fragment: callback + '#x', userinfo: callback.replace('https://', 'https://u:p@') };
    expect(() => openVaultIdentityWindow(values[fault], vi.fn())).toThrow(); expect(host.open).not.toHaveBeenCalled();
  });
  it('refuses blocked popups without installing a receiver', () => {
    host.open.mockReturnValue(null); expect(() => create()).toThrow(); expect(host.addEventListener).not.toHaveBeenCalled();
  });
  it.each(['origin', 'source', 'before-binding'])('ignores unrelated %s messages before the valid callback', async fault => {
    const scope = create(); if (fault !== 'before-binding') begin(scope);
    message(undefined, fault === 'source' ? {} : child, fault === 'origin' ? 'https://untrusted.example' : 'https://owned-ui.example');
    expect(child.close).not.toHaveBeenCalled(); if (fault === 'before-binding') begin(scope);
    message(); expect((await scope.result).state).toBe(state);
  });
  it.each(['state', 'kind', 'extra', 'missing', 'code-bound', 'code-control'])('closes on malformed trusted callback %s', async fault => {
    const scope = create(); begin(scope); const data: Record<string, unknown> = { type: 'freesdn-vault-identity-v1', state, code: 'owned-code' };
    if (fault === 'state') data.state = 'other'; if (fault === 'kind') data.type = 'login';
    if (fault === 'extra') data.proof = 'must-not-enter-ui'; if (fault === 'missing') delete data.code;
    if (fault === 'code-bound') data.code = 'x'.repeat(8193); if (fault === 'code-control') data.code = 'a\nb';
    const check = expect(scope.result).rejects.toThrow('Identity confirmation ended'); message(data); await check;
    expect(child.close).toHaveBeenCalledTimes(1); expect(listener).toBeUndefined(); expect(vi.getTimerCount()).toBe(0);
  });
  it.each(['context', 'close', 'deadline', 'wall-expiry', 'cancel'])('ends a pending callback after %s', async fault => {
    let valid = true; const scope = create(() => { if (!valid) throw new Error('private'); }); begin(scope);
    const check = expect(scope.result).rejects.toThrow('Identity confirmation ended');
    if (fault === 'context') valid = false;
    if (fault === 'close') child.closed = true;
    if (fault === 'deadline') vi.spyOn(performance, 'now').mockReturnValue(performance.now() + 200000);
    if (fault === 'wall-expiry') vi.setSystemTime(Date.now() + 200000);
    if (fault === 'cancel') scope.cancel(); else await vi.advanceTimersByTimeAsync(100);
    await check; expect(listener).toBeUndefined(); expect(vi.getTimerCount()).toBe(0);
  });
  it.each(['http', 'userinfo', 'fragment', 'state', 'duplicate', 'expired', 'long-expiry'])('refuses unsafe navigation %s and closes', fault => {
    const scope = create(); const value = { authorize_url: `https://owned-idp.example/authorize?state=${state}`, state, expires_at: Math.floor(Date.now() / 1000) + 100 };
    if (fault === 'http') value.authorize_url = value.authorize_url.replace('https:', 'http:');
    if (fault === 'userinfo') value.authorize_url = value.authorize_url.replace('https://', 'https://u:p@');
    if (fault === 'fragment') value.authorize_url += '#fragment'; if (fault === 'state') value.state = 'other';
    if (fault === 'duplicate') value.authorize_url += '&state=other';
    if (fault === 'expired') value.expires_at -= 200; if (fault === 'long-expiry') value.expires_at += 1000;
    expect(() => scope.navigate(value)).toThrow(); expect(child.location.replace).not.toHaveBeenCalled(); expect(child.close).toHaveBeenCalledTimes(1);
  });
});
