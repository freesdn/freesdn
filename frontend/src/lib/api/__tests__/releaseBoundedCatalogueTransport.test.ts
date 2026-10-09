// @vitest-environment native-fetch
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual Axios fetch adapter with controlled WHATWG Responses/streams.
 * No external HTTP request, browser cookie policy or deployed proxy is tested.
 */
import axios from 'axios';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginReleaseOperationAction, ReleaseTransportError } from '../releaseOperationTransport';
import { CATALOGUE_BODY_BYTES, CATALOGUE_BODY_MILLISECONDS } from '../releaseCatalogueBody';
import type { ReleaseCataloguePosition } from '../releaseCatalogueCodec';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const release = '44444444-4444-4444-8444-444444444444';
const stamp = '2026-01-01T01:02:03.000004Z';
const encoder = new TextEncoder();
const scopes: ReturnType<typeof beginReleaseOperationAction>[] = [];
const interceptors: number[] = [];
let originalAdapter: typeof api.defaults.adapter;
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
function user(): User {
  return { id: actor, organization_id: organization, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function action() { const scope = beginReleaseOperationAction(); scopes.push(scope); return scope; }
function body(limit = 50) { return JSON.stringify({ items: [{ id: release, organization_id: organization,
  version: '26.1', platform: 'linux', agent_type: 'daemon', download_url: 'https://artifact.invalid/not-verified',
  checksum_sha256: 'a'.repeat(64), signature: null, file_size: 1, release_notes: 'שלום🙂', min_backend_version: '',
  is_latest: false, is_prerelease: false, published_at: stamp, download_count: 0 }],
  limit, has_more: false, next_published_at: null, next_id: null }); }
function response(data: BodyInit | null = body(), status = 200, extra: Record<string, string> = {}) {
  return new Response(data, { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store', ...extra } });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function controlledStream() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, cancel });
  return { stream, cancel, controller };
}
function change(kind: string) {
  const old = user();
  useAuthStore.setState({ user: kind === 'organization' ? { ...old, organization_id: release } : { ...old, id: release } });
  if (kind === 'cycle') useAuthStore.setState({ user: old });
}
beforeEach(() => {
  originalAdapter = api.defaults.adapter;
  // Prove the new route does not silently fall back to the default XHR adapter.
  api.defaults.adapter = vi.fn(() => { throw new Error('default adapter must not execute'); });
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true });
  fetchMock = vi.fn<typeof fetch>(async () => response());
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  scopes.splice(0).forEach(scope => scope.dispose());
  interceptors.splice(0).forEach(id => api.interceptors.request.eject(id));
  api.defaults.adapter = originalAdapter;
  vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});

it('uses real fetch streaming and validates a frozen observation with paired context', async () => {
  const page = await action().cataloguePage();
  expect(page.items[0].release_notes).toBe('שלום🙂');
  expect(Object.isFrozen(page) && Object.isFrozen(page.items) && Object.isFrozen(page.items[0])).toBe(true);
  expect(fetchMock).toHaveBeenCalledOnce();
  const request = fetchMock.mock.calls[0][0] as Request;
  expect(request.url).toMatch(/\/api\/v1\/agents\/release-catalogue\?limit=50$/);
  expect(request.method).toBe('GET'); expect(request.credentials).toBe('include');
  expect(request.cache).toBe('no-store'); expect(request.redirect).toBe('error');
  expect(request.headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
  expect(request.headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
  expect(api.defaults.adapter).not.toHaveBeenCalled();
});

it('captures position and filters before an interceptor waits', async () => {
  const gate = deferred<void>(); const waiting = vi.fn();
  interceptors.push(api.interceptors.request.use(async config => { waiting(); await gate.promise; return config; }));
  const position = { limit: 2, before_id: '55555555-5555-4555-8555-555555555555', before_published_at: stamp };
  const filters = { platform: 'Linux' };
  fetchMock.mockImplementation(async () => response(body(2)));
  const pending = action().cataloguePage(position, filters);
  await vi.waitFor(() => expect(waiting).toHaveBeenCalledOnce());
  position.limit = 1; position.before_id = actor; filters.platform = 'windows'; gate.resolve();
  expect((await pending).limit).toBe(2);
  const url = new URL((fetchMock.mock.calls[0][0] as Request).url);
  expect(url.searchParams.get('limit')).toBe('2'); expect(url.searchParams.get('platform')).toBe('Linux');
  expect(url.searchParams.get('before_id')).toBe('55555555-5555-4555-8555-555555555555');
});

it.each(['user', 'organization', 'cycle'])('refuses queued page after %s transition', kind => {
  const scope = action(); change(kind);
  expect(() => scope.cataloguePage()).toThrow(ReleaseTransportError);
  expect(fetchMock).not.toHaveBeenCalled();
});

it.each(['user', 'organization', 'cycle'])('refuses late headers after %s transition and cancels unused stream', async kind => {
  const gate = deferred<Response>(); const source = controlledStream();
  fetchMock.mockReturnValue(gate.promise);
  const pending = action().cataloguePage();
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  change(kind); gate.resolve(response(source.stream)); await failure;
  await vi.waitFor(() => expect(source.cancel).toHaveBeenCalledOnce());
  expect(fetchMock).toHaveBeenCalledOnce();
});

it.each(['user', 'organization', 'cycle'])('refuses body after %s transition without returning stale rows', async kind => {
  const source = controlledStream(); fetchMock.mockResolvedValue(response(source.stream));
  const pending = action().cataloguePage();
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  source.controller.enqueue(encoder.encode('{"items":'));
  change(kind); await failure;
  await vi.waitFor(() => expect(source.cancel).toHaveBeenCalledOnce());
});

it.each([401, 409, 503])('refuses HTTP %i without refresh, replay or retained Axios body', async status => {
  fetchMock.mockResolvedValue(response('{"private":"details"}', status));
  const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
  const error = await action().cataloguePage().catch(value => value);
  expect(error).toBeInstanceOf(ReleaseTransportError);
  expect(error).toMatchObject({ outcome: 'unconfirmed', status });
  expect(error).not.toHaveProperty('config'); expect(error).not.toHaveProperty('response');
  expect(String(error)).not.toContain('details');
  expect(fetchMock).toHaveBeenCalledOnce(); expect(refresh).not.toHaveBeenCalled();
});

it.each<{ headers: Record<string, string> }>([
  { headers: { 'Content-Type': 'text/html' } },
  { headers: { 'Cache-Control': 'public, max-age=100' } },
  { headers: { 'Content-Length': String(CATALOGUE_BODY_BYTES + 1) } },
  { headers: { 'Content-Length': '1e6' } },
])('refuses incompatible headers without consuming the body: $headers', async ({ headers }) => {
  const source = controlledStream(); fetchMock.mockResolvedValue(response(source.stream, 200, headers));
  await expect(action().cataloguePage()).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(source.cancel).toHaveBeenCalledOnce());
});

it.each(['{"items":[],"items":[]}', '{"private":"unknown shape"}', '\ufeff{}'])('refuses invalid protocol text %#', async raw => {
  fetchMock.mockResolvedValue(response(raw));
  const error = await action().cataloguePage().catch(value => value);
  expect(error).toBeInstanceOf(ReleaseTransportError); expect(error).not.toHaveProperty('cause');
  expect(String(error)).not.toContain('unknown shape'); expect(fetchMock).toHaveBeenCalledOnce();
});

it('keeps action busy through body validation and permits a later deliberate read', async () => {
  const source = controlledStream(); fetchMock.mockResolvedValueOnce(response(source.stream));
  const scope = action(); const pending = scope.cataloguePage();
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  expect(() => scope.cataloguePage()).toThrow(ReleaseTransportError);
  source.controller.enqueue(encoder.encode(body())); source.controller.close(); await pending;
  await scope.cataloguePage(); expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('bounds actual streamed bytes even without a content-length header', async () => {
  const source = controlledStream(); fetchMock.mockResolvedValue(response(source.stream));
  const pending = action().cataloguePage();
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  source.controller.enqueue(new Uint8Array(CATALOGUE_BODY_BYTES + 1));
  await failure; await vi.waitFor(() => expect(source.cancel).toHaveBeenCalledOnce());
});

it.each([
  { value: { limit: 0 } }, { value: { limit: 101 } }, { value: { limit: true } },
  { value: { limit: 1, before_id: release } }, { value: { limit: 1, before_published_at: stamp } },
  { value: { limit: 1, before_id: release, before_published_at: '2026-02-31T00:00:00Z' } },
  { value: { limit: 1, organization_id: organization } },
])('refuses invalid position before issuing a request: $value', ({ value }) => {
  expect(() => action().cataloguePage(value as unknown as ReleaseCataloguePosition)).toThrow(ReleaseTransportError);
  expect(fetchMock).not.toHaveBeenCalled();
});

it.each(['fetch', 'ReadableStream'])('refuses missing %s instead of falling back', async name => {
  const scope = action(); vi.stubGlobal(name, undefined);
  await expect(scope.cataloguePage()).rejects.toMatchObject({ outcome: 'not-issued' });
  expect(fetchMock).not.toHaveBeenCalled(); expect(api.defaults.adapter).not.toHaveBeenCalled();
});

it('refuses a pre-aborted caller synchronously', () => {
  const controller = new AbortController(); controller.abort();
  expect(() => action().cataloguePage({ limit: 50 }, {}, controller.signal)).toThrow(ReleaseTransportError);
  expect(fetchMock).not.toHaveBeenCalled();
});

it('aborts an active body when caller cancels and frees action for deliberate inspection', async () => {
  const source = controlledStream(); fetchMock.mockResolvedValueOnce(response(source.stream));
  const controller = new AbortController(); const scope = action();
  const pending = scope.cataloguePage({ limit: 50 }, {}, controller.signal);
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce()); controller.abort(); await failure;
  await vi.waitFor(() => expect(source.cancel).toHaveBeenCalledOnce());
  await scope.cataloguePage(); expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('bounds an interceptor stall and refuses later dispatch without prewarming or retry', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
  const gate = deferred<void>(); const waiting = vi.fn();
  interceptors.push(api.interceptors.request.use(async config => { waiting(); await gate.promise; return config; }));
  const pending = action().cataloguePage();
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
  await vi.advanceTimersByTimeAsync(0); expect(waiting).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(CATALOGUE_BODY_MILLISECONDS); await failure;
  gate.resolve(); await vi.advanceTimersByTimeAsync(0);
  expect(fetchMock).not.toHaveBeenCalled();
});

it('bounds a stalled body and requests stream cleanup under the original fixed deadline', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
  const source = controlledStream(); fetchMock.mockResolvedValue(response(source.stream));
  const pending = action().cataloguePage();
  const failure = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
  await vi.advanceTimersByTimeAsync(0); expect(fetchMock).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(CATALOGUE_BODY_MILLISECONDS); await failure;
  await vi.advanceTimersByTimeAsync(0); expect(source.cancel).toHaveBeenCalledOnce();
  scopes.splice(0).forEach(scope => scope.dispose()); expect(vi.getTimerCount()).toBe(0);
});


it('fixture provides an empty native Response byte stream and preserves DOM presentation', async () => {
  const empty = new Response('');
  expect(empty.body).toBeInstanceOf(ReadableStream);
  expect(await empty.text()).toBe('');
  expect(document.createElement('button').tagName).toBe('BUTTON');
});
it('fixture native request signal follows a real native AbortController', () => {
  const controller = new AbortController();
  const request = new Request('https://fixture.invalid/never-fetched', { signal: controller.signal });
  expect(request.signal.aborted).toBe(false); controller.abort(); expect(request.signal.aborted).toBe(true);
  expect(fetchMock).not.toHaveBeenCalled();
});
it('fixture native Response preserves supplied stream bytes without eager materialization', async () => {
  let control!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({ start(value) { control = value; } });
  const result = new Response(stream); expect(result.body).toBe(stream);
  const reader = result.body!.getReader(); const pending = reader.read();
  control.enqueue(new Uint8Array([226, 130, 172])); control.close();
  expect(await pending).toEqual({ done: false, value: new Uint8Array([226, 130, 172]) });
  expect(await reader.read()).toEqual({ done: true, value: undefined }); reader.releaseLock();
  expect(fetchMock).not.toHaveBeenCalled();
});
