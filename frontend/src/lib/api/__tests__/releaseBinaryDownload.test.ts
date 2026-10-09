// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Controlled DOM dispatch/current store checks, not browser/cookie/server proof. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { requestReleaseBinaryDownload } from '../releaseBinaryDownload';

const config = vi.hoisted(() => ({ url: 'https://configured-api.example.invalid' }));
vi.mock('../client', () => ({ get API_URL() { return config.url; }, api: {} }));
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const org = '22222222-2222-4222-8222-222222222222';
const release = '44444444-4444-4444-8444-444444444444';
function user(): User { return { id: actor, organization_id: org, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, roles: ['admin'], permissions: ['agent:admin'],
  username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
let clicks: { href: string; target: string; rel: string; policy: string; download: string }[];
let click: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  config.url = 'https://configured-api.example.invalid'; clicks = [];
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function(this: HTMLAnchorElement) {
    clicks.push({ href: this.href, target: this.target, rel: this.rel, policy: this.referrerPolicy, download: this.download });
  });
  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('No buffered fetch is permitted'); }));
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it.each(['https://configured-api.example.invalid', 'https://configured-api.example.invalid/prefix/', '/prefix'])('uses configured API base %s with nonsecret initiating-account equality', base => {
  config.url = base; requestReleaseBinaryDownload(release);
  expect(clicks).toHaveLength(1); const url = new URL(clicks[0].href);
  expect(url.pathname).toBe(`${base.includes('prefix') ? '/prefix' : ''}/api/v1/agents/releases/${release}/binary`);
  expect(url.searchParams.get('release_actor')).toBe(actor); expect(url.searchParams.get('release_organization')).toBe(org);
  expect([...url.searchParams.keys()].sort()).toEqual(['release_actor', 'release_organization']);
  expect(url.username).toBe(''); expect(url.password).toBe(''); expect(url.hash).toBe('');
  expect(clicks[0]).toMatchObject({ target: '_blank', rel: 'noopener noreferrer', policy: 'no-referrer', download: '' });
  expect(document.querySelectorAll('a')).toHaveLength(0); expect(fetch).not.toHaveBeenCalled();
});
it('preserves platform account scope without substituting a target organization', () => {
  useAuthStore.setState({ user: { ...user(), organization_id: null } }); requestReleaseBinaryDownload(release);
  expect(new URL(clicks[0].href).searchParams.get('release_organization')).toBe('none');
});
it.each(['', '00000000-0000-0000-0000-000000000000', '../escape', 'javascript:untrusted()'])('refuses invalid release identity %s before dispatch', identity => {
  expect(() => requestReleaseBinaryDownload(identity)).toThrow(); expect(click).not.toHaveBeenCalled();
  expect(document.querySelectorAll('a')).toHaveLength(0); expect(fetch).not.toHaveBeenCalled();
});
it.each(['javascript:untrusted()', 'data:text/plain,untrusted', 'ftp://api.invalid', 'https://user:password@api.invalid',
  'https://api.invalid/?token=untrusted', 'https://api.invalid/#untrusted', 'https://api.invalid/with space'])('refuses unsafe configured base %# without opening a stored or fallback URL', base => {
  config.url = base; expect(() => requestReleaseBinaryDownload(release)).toThrow();
  expect(click).not.toHaveBeenCalled(); expect(document.querySelectorAll('a')).toHaveLength(0);
});
it.each(['logout', 'permission', 'inactive'])('refuses current %s state before native dispatch', change => {
  if (change === 'logout') useAuthStore.setState({ user: null, isAuthenticated: false });
  else if (change === 'permission') useAuthStore.setState({ hasPermission: () => false });
  else useAuthStore.setState({ user: { ...user(), is_active: false } });
  expect(() => requestReleaseBinaryDownload(release)).toThrow(); expect(click).not.toHaveBeenCalled();
});
it.each(['user', 'organization', 'cycle'])('rechecks captured authority after DOM work for %s transitions', change => {
  const append = document.body.append.bind(document.body);
  vi.spyOn(document.body, 'append').mockImplementation((...nodes) => {
    append(...nodes); useAuthStore.setState({ user: change === 'organization' ? { ...user(), organization_id: release } : { ...user(), id: release } });
    if (change === 'cycle') useAuthStore.setState({ user: user() });
  });
  expect(() => requestReleaseBinaryDownload(release)).toThrow(); expect(click).not.toHaveBeenCalled();
  expect(document.querySelectorAll('a')).toHaveLength(0);
});
it('does not claim non-issuance or retry after a click call throws', () => {
  click.mockImplementation(() => { throw new Error('synthetic-click-fault'); });
  let failure; try { requestReleaseBinaryDownload(release); } catch (error) { failure = error; }
  expect(failure).toMatchObject({ outcome: 'unconfirmed' }); expect(click).toHaveBeenCalledOnce();
  expect(String(failure)).not.toContain('synthetic-click-fault'); expect(document.querySelectorAll('a')).toHaveLength(0);
});
it('cleans up a pre-dispatch append failure and releases the action slot', () => {
  const append = vi.spyOn(document.body, 'append').mockImplementation(() => { throw new Error('synthetic-append-fault'); });
  for (let n = 0; n < 12; n += 1) expect(() => requestReleaseBinaryDownload(release)).toThrow();
  append.mockRestore(); requestReleaseBinaryDownload(release); expect(click).toHaveBeenCalledOnce();
});
it('does not retain action slots or silently repeat native requests', () => {
  for (let n = 0; n < 12; n += 1) requestReleaseBinaryDownload(release);
  expect(click).toHaveBeenCalledTimes(12); expect(fetch).not.toHaveBeenCalled(); expect(document.querySelectorAll('a')).toHaveLength(0);
});
