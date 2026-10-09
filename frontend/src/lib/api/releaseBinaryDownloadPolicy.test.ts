// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** DOM authority and dispatch boundaries; real referrer/page behavior is checked in Chromium. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { requestReleaseBinaryDownload } from './releaseBinaryDownload';

const config = vi.hoisted(() => ({ url: '' }));
vi.mock('./client', () => ({ get API_URL() { return config.url; }, api: {} }));
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const org = '22222222-2222-4222-8222-222222222222';
const release = '44444444-4444-4444-8444-444444444444';
function user(): User { return { id: actor, organization_id: org, role: 'org_admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, roles: ['org_admin'], permissions: ['agent:admin'],
  username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
let click: ReturnType<typeof vi.spyOn>;
let calls: { href: string; native: boolean; policyAtClick: string | undefined }[];
let ownedMeta: HTMLMetaElement | undefined;
let initialMetaCount: number;
beforeEach(() => {
  config.url = ''; calls = []; ownedMeta = undefined;
  initialMetaCount = document.querySelectorAll('meta[name="referrer"]').length;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true });
  click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function(this: HTMLAnchorElement) {
    const policies = [...document.querySelectorAll<HTMLMetaElement>('meta[name="referrer"]')];
    calls.push({ href: this.href, native: this.hasAttribute('download'), policyAtClick: policies[policies.length - 1]?.content });
  });
  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Native binary bytes must not be buffered'); }));
});
afterEach(() => { ownedMeta?.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
it.each(['', '/prefix'])('uses native same-origin delivery with an explicit no-referrer policy for %s', base => {
  config.url = base; requestReleaseBinaryDownload(release);
  expect(calls).toHaveLength(1); expect(calls[0]).toMatchObject({ native: true, policyAtClick: 'no-referrer' });
  const url = new URL(calls[0].href); expect(url.origin).toBe(window.location.origin);
  expect([...url.searchParams.keys()]).toEqual(['release_actor', 'release_organization']);
  expect(url.searchParams.get('release_actor')).toBe(actor); expect(url.searchParams.get('release_organization')).toBe(org);
  expect(document.querySelectorAll('a')).toHaveLength(0);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
  expect(fetch).not.toHaveBeenCalled();
});
it('preserves cross-origin browser navigation without forcing an attribute download', () => {
  config.url = 'https://different-api.example.invalid'; requestReleaseBinaryDownload(release);
  expect(calls).toHaveLength(1); expect(calls[0].native).toBe(false);
  expect(new URL(calls[0].href).origin).toBe(config.url);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
  expect(fetch).not.toHaveBeenCalled();
});
it('establishes a fresh policy even when a weaker policy is already present', () => {
  ownedMeta = document.createElement('meta'); ownedMeta.name = 'referrer'; ownedMeta.content = 'unsafe-url'; document.head.append(ownedMeta);
  requestReleaseBinaryDownload(release);
  expect(calls[0]).toMatchObject({ native: true, policyAtClick: 'no-referrer' });
  expect(ownedMeta.content).toBe('unsafe-url'); expect(ownedMeta.isConnected).toBe(true);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount + 1);
});
it.each(['user', 'organization', 'cycle'])('refuses authority changed during document-policy work: %s', change => {
  const append = document.head.append.bind(document.head);
  vi.spyOn(document.head, 'append').mockImplementation((...nodes) => {
    append(...nodes); useAuthStore.setState({ user: change === 'organization' ? { ...user(), organization_id: release } : { ...user(), id: release } });
    if (change === 'cycle') useAuthStore.setState({ user: user() });
  });
  expect(() => requestReleaseBinaryDownload(release)).toThrow(); expect(click).not.toHaveBeenCalled();
  expect(document.querySelectorAll('a')).toHaveLength(0);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
});
it('releases DOM and action state when policy insertion throws after appending', () => {
  const append = document.head.append.bind(document.head);
  const fault = vi.spyOn(document.head, 'append').mockImplementation((...nodes) => { append(...nodes); throw new Error('owned-policy-insertion-fault'); });
  for (let n = 0; n < 12; n += 1) expect(() => requestReleaseBinaryDownload(release)).toThrow();
  expect(click).not.toHaveBeenCalled(); expect(document.querySelectorAll('a')).toHaveLength(0);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
  fault.mockRestore(); requestReleaseBinaryDownload(release); expect(click).toHaveBeenCalledOnce();
});
it('retains unconfirmed outcome after attempted native dispatch throws', () => {
  click.mockImplementation(() => { throw new Error('owned-native-dispatch-fault'); });
  let failure; try { requestReleaseBinaryDownload(release); } catch (error) { failure = error; }
  expect(failure).toMatchObject({ outcome: 'unconfirmed' }); expect(click).toHaveBeenCalledOnce();
  expect(document.querySelectorAll('a')).toHaveLength(0);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
});
it('keeps explicit repeated gestures distinct without retaining metadata or buffering bytes', () => {
  for (let n = 0; n < 12; n += 1) requestReleaseBinaryDownload(release);
  expect(click).toHaveBeenCalledTimes(12); expect(calls.every(row => row.native && row.policyAtClick === 'no-referrer')).toBe(true);
  expect(document.querySelectorAll('a')).toHaveLength(0);
  expect(document.querySelectorAll('meta[name="referrer"]')).toHaveLength(initialMetaCount);
  expect(fetch).not.toHaveBeenCalled();
});
