// @vitest-environment native-fetch
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual panel, transport, Axios fetch adapter, streamed body and decoder.
 * Controlled fetch/auth/DOM; not browser HTTP, cookies, SQL or deployment proof.
 */
import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import en from '../../../../public/locales/en/agents.json';
import es from '../../../../public/locales/es/agents.json';
import zh from '../../../../public/locales/zh/agents.json';
import { ReleaseCataloguePanel } from '../ReleaseCataloguePanel';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const other = '33333333-3333-4333-8333-333333333333';
const stamp = '2026-01-01T01:02:03.000004Z';
const locales = { en, es, zh }; const i18n = createInstance();
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let originalAdapter: typeof api.defaults.adapter;
function user(): User { return { id: actor, organization_id: organization, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'],
  email: 'owned@example.invalid', username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
function identity(n = 900) { return `44444444-4444-4444-8444-${String(n).padStart(12, '0')}`; }
function row(n = 900) { return { id: identity(n), organization_id: organization, version: `visible-version-${n}`,
  platform: 'linux', agent_type: 'daemon', download_url: 'javascript:untrusted()', checksum_sha256: 'a'.repeat(64),
  signature: '<svg onload="untrusted()">', file_size: 1, release_notes: '<img src=x onerror=untrusted()>',
  min_backend_version: '', is_latest: false, is_prerelease: false, published_at: stamp, download_count: 0 }; }
function body(limit = 50, more = false, start = 900, empty = false) {
  const items = empty ? [] : Array.from({ length: more ? limit : 1 }, (_, i) => row(start - i));
  return { items, limit, has_more: more, next_id: more ? items[items.length - 1].id : null,
    next_published_at: more ? stamp : null };
}
function response(value: unknown = body(), status = 200) { return new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store' },
}); }
function mount() { return render(<I18nextProvider i18n={i18n}><ReleaseCataloguePanel /></I18nextProvider>); }
function load() { fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.loadFirst })); }
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }
function deferred<T>() { let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function transition(kind: string) {
  if (kind === 'permission') useAuthStore.setState({ hasPermission: () => false });
  else if (kind === 'logout') useAuthStore.setState({ user: null, isAuthenticated: false });
  else useAuthStore.setState({ user: { ...user(), ...(kind === 'organization' ? { organization_id: other } : { id: other }) } });
  if (kind === 'cycle') useAuthStore.setState({ user: user() });
}
beforeAll(async () => { await i18n.init({ lng: 'en', fallbackLng: 'en', defaultNS: 'agents',
  resources: Object.fromEntries(Object.entries(locales).map(([language, messages]) => [language, { agents: messages }])),
  interpolation: { escapeValue: false }, react: { useSuspense: false } }); });
beforeEach(async () => {
  await i18n.changeLanguage('en');
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  originalAdapter = api.defaults.adapter;
  api.defaults.adapter = vi.fn(() => { throw new Error('default adapter must not run'); });
  fetchMock = vi.fn<typeof fetch>(async request => response(body(Number(new URL((request as Request).url).searchParams.get('limit')))));
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { cleanup(); api.defaults.adapter = originalAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('requires an explicit load even through StrictMode remount effects', () => {
  render(<StrictMode><I18nextProvider i18n={i18n}><ReleaseCataloguePanel /></I18nextProvider></StrictMode>);
  expect(fetchMock).not.toHaveBeenCalled(); expect(screen.getByRole('status')).toHaveTextContent(en.ReleaseCataloguePanel.notices.initial);
});
it('loads real streamed observations with paired identity and renders metadata without executable links or HTML', async () => {
  const page = mount(); load(); await screen.findByText('visible-version-900');
  const request = fetchMock.mock.calls[0][0] as Request;
  expect(request.method).toBe('GET'); expect(request.headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
  expect(request.headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
  expect(screen.getByText(identity())).toBeInTheDocument();
  expect(screen.getByText('javascript:untrusted()')).toBeInTheDocument();
  expect(screen.getByText('<img src=x onerror=untrusted()>')).toBeInTheDocument();
  expect(page.container.querySelectorAll('a,img,svg,script')).toHaveLength(0);
  expect(screen.getByText(en.ReleaseCataloguePanel.signature)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: en.ReleaseCataloguePanel.next })).toBeDisabled();
  expect(fetchMock).toHaveBeenCalledOnce(); expect(api.defaults.adapter).not.toHaveBeenCalled();
});
it('advances with exact paired cursor and filters and replaces rather than accumulates page rows', async () => {
  fetchMock.mockImplementation(async request => {
    const u = new URL((request as Request).url); const next = u.searchParams.has('before_id');
    return response(body(10, !next, next ? 800 : 900));
  });
  mount(); change(en.ReleaseCataloguePanel.platform, 'linux'); change(en.ReleaseCataloguePanel.agentType, 'daemon');
  change(en.ReleaseCataloguePanel.pageSize, '10'); load(); await screen.findByText('visible-version-891');
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.next })); await screen.findByText('visible-version-800');
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  const u = new URL((fetchMock.mock.calls[1][0] as Request).url);
  expect(Object.fromEntries(u.searchParams)).toEqual({ limit: '10', platform: 'linux', agent_type: 'daemon',
    before_id: identity(891), before_published_at: stamp });
  load(); await screen.findByText('visible-version-900');
  expect(new URL((fetchMock.mock.calls[2][0] as Request).url).searchParams.has('before_id')).toBe(false);
});
it.each(['platform', 'agentType', 'pageSize'] as const)('clears rows on %s edit without an automatic request', async key => {
  mount(); load(); await screen.findByText('visible-version-900');
  change(en.ReleaseCataloguePanel[key], { platform: 'windows', agentType: 'desktop', pageSize: '25' }[key]);
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(en.ReleaseCataloguePanel.notices.filterChanged);
  expect(fetchMock).toHaveBeenCalledOnce(); load(); await screen.findByText('visible-version-900');
  expect(new URL((fetchMock.mock.calls[1][0] as Request).url).searchParams.has('before_id')).toBe(false);
});
it('keeps load and filter controls disabled for the entire body lifetime and cancels the reader', async () => {
  const cancelled = vi.fn(); let streamController!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({ start(c) { streamController = c; }, cancel: cancelled });
  fetchMock.mockResolvedValue(new Response(stream, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }));
  mount(); load(); await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  streamController.enqueue(new TextEncoder().encode('{"items":'));
  expect(screen.getByRole('button', { name: en.ReleaseCataloguePanel.loadFirst })).toBeDisabled();
  expect(screen.getByLabelText(en.ReleaseCataloguePanel.platform)).toBeDisabled(); load(); expect(fetchMock).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.cancel }));
  await waitFor(() => expect(cancelled).toHaveBeenCalledOnce());
  expect(screen.getByRole('status')).toHaveTextContent(en.ReleaseCataloguePanel.notices.cancelled);
  expect(screen.getByRole('button', { name: en.ReleaseCataloguePanel.loadFirst })).toBeEnabled();
});
it('aborts on unmount and ignores late headers', async () => {
  const gate = deferred<Response>(); fetchMock.mockReturnValue(gate.promise);
  const view = mount(); load(); await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  const request = fetchMock.mock.calls[0][0] as Request; view.unmount(); expect(request.signal.aborted).toBe(true);
  await act(async () => { gate.resolve(response()); }); expect(fetchMock).toHaveBeenCalledOnce();
});
it.each(['user', 'organization', 'permission', 'logout', 'cycle'])('clears an already displayed page on %s change without refetching', async kind => {
  mount(); load(); await screen.findByText('visible-version-900');
  act(() => transition(kind));
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(en.ReleaseCataloguePanel.notices.contextChanged);
  expect(fetchMock).toHaveBeenCalledOnce();
});
it.each(['user', 'organization', 'cycle'])('refuses late page results after %s context transition', async kind => {
  const gate = deferred<Response>(); fetchMock.mockReturnValue(gate.promise);
  mount(); load(); await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  act(() => transition(kind)); await act(async () => { gate.resolve(response()); });
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(en.ReleaseCataloguePanel.notices.contextChanged);
  expect(fetchMock).toHaveBeenCalledOnce();
});
it('does not let cancelled late output replace a subsequent deliberately loaded page', async () => {
  const first = deferred<Response>(); fetchMock.mockReturnValueOnce(first.promise).mockResolvedValueOnce(response(body(50, false, 700)));
  mount(); load(); await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.cancel }));
  load(); await screen.findByText('visible-version-700'); await act(async () => { first.resolve(response()); });
  expect(screen.getByText('visible-version-700')).toBeInTheDocument();
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument(); expect(fetchMock).toHaveBeenCalledTimes(2);
});
it.each([401, 409, 503])('shows a generic failure for HTTP %i without automatic retry or stale rows', async status => {
  mount(); load(); await screen.findByText('visible-version-900');
  fetchMock.mockResolvedValue(response({ private: 'synthetic-error-marker' }, status)); load();
  expect(await screen.findByRole('alert')).toHaveTextContent(en.ReleaseCataloguePanel.notices.failed);
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  expect(screen.queryByText(/synthetic-error-marker/)).not.toBeInTheDocument(); expect(fetchMock).toHaveBeenCalledTimes(2);
});
it('refuses a duplicate-key wire body without rendering partial rows', async () => {
  const raw = JSON.stringify(body()).replace('"limit":50', '"limit":50,"limit":50');
  fetchMock.mockResolvedValue(new Response(raw, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }));
  mount(); load(); await screen.findByRole('alert'); expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledOnce();
});
it('refuses loading without current permission before any fetch', async () => {
  useAuthStore.setState({ hasPermission: () => false }); mount(); load(); await screen.findByRole('alert');
  expect(fetchMock).not.toHaveBeenCalled();
});
it.each(['en', 'es', 'zh'] as const)('uses complete %s labels and renders an empty validated page', async language => {
  await i18n.changeLanguage(language); const labels = locales[language].ReleaseCataloguePanel;
  expect(Object.keys(labels).sort()).toEqual(Object.keys(en.ReleaseCataloguePanel).sort());
  expect(Object.keys(labels.notices).sort()).toEqual(Object.keys(en.ReleaseCataloguePanel.notices).sort());
  expect(Object.keys(labels.columns).sort()).toEqual(Object.keys(en.ReleaseCataloguePanel.columns).sort());
  fetchMock.mockResolvedValue(response(body(50, false, 900, true))); mount();
  expect(screen.getByRole('heading', { name: labels.title })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: labels.loadFirst })); expect(await screen.findByText(labels.empty)).toBeVisible();
  expect(screen.getByRole('button', { name: labels.next })).toBeDisabled();
});
