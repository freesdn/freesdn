// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Exact response parsing and actual captured Axios transport; no live server. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { type InternalAxiosRequestConfig } from 'axios';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { captureReleasePromotion } from '../releasePromotionClient';
import { decodeReleasePromotion, ReleaseCatalogueError } from '../releaseCatalogueCodec';

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
function record() { return { id: release, version: '26.1', platform: 'linux', agent_type: 'daemon',
  download_url: 'javascript:untrusted()', checksum_sha256: 'a'.repeat(64), signature: 'synthetic-not-verified',
  file_size: 1, release_notes: 'שלום🙂', min_backend_version: '', is_latest: true, is_prerelease: false,
  published_at: '2026-01-01T01:02:03.000004Z', download_count: 0 }; }
function response(config: InternalAxiosRequestConfig, data: unknown = JSON.stringify(record())) {
  return { config, data, status: 200, statusText: 'OK', headers: {} };
}
let originalAdapter: typeof api.defaults.adapter;
const actions: ReturnType<typeof captureReleasePromotion>[] = [];
function action(id = release) { const value = captureReleasePromotion(id); actions.push(value); return value; }
beforeEach(() => {
  originalAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  document.cookie = 'freesdn_csrf=owned-promotion-csrf; path=/';
});
afterEach(() => {
  actions.splice(0).forEach(value => value.dispose()); api.defaults.adapter = originalAdapter;
  vi.restoreAllMocks(); document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

it('decodes the exact legacy promotion response as a frozen observation without interpreting stored URL or signature', () => {
  const result = decodeReleasePromotion(JSON.stringify(record()), release);
  expect(result).toEqual(record()); expect(Object.isFrozen(result)).toBe(true);
  expect(result.download_url).toBe('javascript:untrusted()'); expect(result.signature).toBe('synthetic-not-verified');
  expect(result).not.toHaveProperty('organization_id');
});
it.each([
  { id: actor }, { id: '00000000-0000-0000-0000-000000000000' }, { is_latest: false }, { is_latest: 'true' },
  { platform: 'unknown' }, { agent_type: 'unknown' }, { version: '' }, { version: ' ' },
  { checksum_sha256: 'a'.repeat(64) + '\n' }, { checksum_sha256: 'A'.repeat(64) },
  { signature: null }, { signature: '' }, { signature: 'x'.repeat(4097) },
  { release_notes: '🙂'.repeat(20001) }, { download_url: 'x'.repeat(501) },
  { published_at: '2026-02-31T01:02:03Z' }, { published_at: '2026-01-01T01:02:03' },
  { file_size: -1 }, { download_count: 2147483648 }, { organization_id: org }, { unknown: true },
])('refuses incompatible promotion response fields %#', patch => {
  expect(() => decodeReleasePromotion(JSON.stringify({ ...record(), ...patch }), release)).toThrow(ReleaseCatalogueError);
});
it.each(['signature', 'is_latest', 'published_at'])('requires the response field %s', field => {
  const value: Record<string, unknown> = record(); delete value[field];
  expect(() => decodeReleasePromotion(JSON.stringify(value), release)).toThrow(ReleaseCatalogueError);
});
it.each(['duplicate', 'bom', 'exponent', 'oversized', 'array', 'object'])('refuses incompatible raw promotion text %s', kind => {
  const valid = JSON.stringify(record());
  const raw = kind === 'duplicate' ? valid.replace('"is_latest":true', '"is_latest":false,"is_latest":true')
    : kind === 'bom' ? '\ufeff' + valid : kind === 'exponent' ? valid.replace('"file_size":1', '"file_size":1e0')
      : kind === 'oversized' ? ' '.repeat(128 * 1024) + valid : kind === 'array' ? `[${valid}]` : record();
  expect(() => decodeReleasePromotion(raw, release)).toThrow(ReleaseCatalogueError);
});
it('permits the existing maximum Unicode notes as an observation', () => {
  const value = { ...record(), release_notes: '🙂'.repeat(20000) };
  expect(decodeReleasePromotion(JSON.stringify(value), release).release_notes).toBe(value.release_notes);
});
it('captures a release synchronously and sends exactly one bodyless paired-context mutation', async () => {
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config)); api.defaults.adapter = adapter;
  let selected = release; const value = action(selected); selected = actor;
  expect(adapter).not.toHaveBeenCalled(); expect(value.releaseId).toBe(release); expect(selected).toBe(actor);
  const result = await value.execute(); expect(result.id).toBe(release); expect(Object.isFrozen(result)).toBe(true);
  const config = adapter.mock.calls[0][0]; expect(config.url).toBe(`/agents/releases/${release}/promote`);
  expect(config.method).toBe('patch'); expect(config.data).toBeUndefined();
  expect(config.headers.get('X-CSRF-Token')).toBe('owned-promotion-csrf');
  expect(config.headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
  expect(config.headers.get('X-FreeSDN-Release-Organization')).toBe(org);
  await expect(value.execute()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(adapter).toHaveBeenCalledOnce();
});
it.each(['wrong-id', 'missing-latest', 'duplicate', 'object'])('does not turn an invalid acknowledgment into success or retry: %s', async kind => {
  const value = record(); const raw = kind === 'wrong-id' ? JSON.stringify({ ...value, id: actor })
    : kind === 'missing-latest' ? JSON.stringify({ ...value, is_latest: false })
      : kind === 'duplicate' ? JSON.stringify(value).replace('"is_latest":true', '"is_latest":true,"is_latest":true') : value;
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config, raw)); api.defaults.adapter = adapter;
  const scope = action(); await expect(scope.execute()).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await expect(scope.execute()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(adapter).toHaveBeenCalledOnce();
});
it.each(['user', 'organization', 'cycle'])('refuses queued promotion after %s change', async kind => {
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config)); api.defaults.adapter = adapter;
  const scope = action(); const original = user();
  useAuthStore.setState({ user: kind === 'organization' ? { ...original, organization_id: release } : { ...original, id: release } });
  if (kind === 'cycle') useAuthStore.setState({ user: original });
  await expect(scope.execute()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(adapter).not.toHaveBeenCalled();
});
it('refuses late acknowledgment after context change even when its response is valid', async () => {
  let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return response(config); }); api.defaults.adapter = adapter;
  const pending = action().execute(); const rejected = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(adapter).toHaveBeenCalledOnce()); useAuthStore.setState({ user: { ...user(), id: release } });
  finish(); await rejected; expect(adapter).toHaveBeenCalledOnce();
});
it('refuses an already aborted attempt without issuing a mutation', async () => {
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config)); api.defaults.adapter = adapter;
  const controller = new AbortController(); controller.abort();
  await expect(action().execute(controller.signal)).rejects.toMatchObject({ outcome: 'not-issued' }); expect(adapter).not.toHaveBeenCalled();
});
