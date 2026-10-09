// @vitest-environment native-fetch
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual panel, transport, Axios fetch adapter, streamed body and decoder.
 * Controlled fetch/auth/DOM; not browser HTTP, cookies, SQL or deployment proof.
 */
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
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
let click: ReturnType<typeof vi.spyOn>;
let destinations: string[];
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
  destinations = [];
  click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function(this: HTMLAnchorElement) { destinations.push(this.href); });
  originalAdapter = api.defaults.adapter;
  api.defaults.adapter = vi.fn(() => { throw new Error('default adapter must not run'); });
  fetchMock = vi.fn<typeof fetch>(async request => response(body(Number(new URL((request as Request).url).searchParams.get('limit')))));
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { cleanup(); api.defaults.adapter = originalAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('requests verified server bytes only on a deliberate download click, never the stored URL', async () => {
  mount(); expect(click).not.toHaveBeenCalled(); load(); await screen.findByText('visible-version-900');
  expect(click).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.download }));
  expect(click).toHaveBeenCalledOnce(); const url = new URL(destinations[0]);
  expect(url.pathname).toBe(`/api/v1/agents/releases/${identity()}/binary`);
  expect(url.searchParams.get('release_actor')).toBe(actor); expect(url.searchParams.get('release_organization')).toBe(organization);
  expect(destinations[0]).not.toContain('javascript:'); expect(fetchMock).toHaveBeenCalledOnce(); expect(api.defaults.adapter).not.toHaveBeenCalled();
  expect(screen.getByText(en.ReleaseCataloguePanel.downloadNotices.requested)).toBeVisible();
  expect(document.querySelectorAll('a')).toHaveLength(0);
});
it('does not offer binary actions before an observation exists', () => {
  mount(); expect(screen.queryByRole('button', { name: en.ReleaseCataloguePanel.download })).not.toBeInTheDocument();
  expect(fetchMock).not.toHaveBeenCalled(); expect(click).not.toHaveBeenCalled();
});
it.each(['user', 'organization', 'permission', 'logout', 'cycle'])('clears download actions and dispatch notices on %s change', async kind => {
  mount(); load(); await screen.findByText('visible-version-900'); fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.download }));
  expect(click).toHaveBeenCalledOnce(); act(() => transition(kind));
  expect(screen.queryByRole('button', { name: en.ReleaseCataloguePanel.download })).not.toBeInTheDocument();
  expect(screen.queryByText(en.ReleaseCataloguePanel.downloadNotices.requested)).not.toBeInTheDocument();
  expect(click).toHaveBeenCalledOnce(); expect(fetchMock).toHaveBeenCalledOnce();
});
it('refuses a saved row handler during an A-B-A transition before React commits the cleared display', async () => {
  mount(); load(); await screen.findByText('visible-version-900'); const button = screen.getByRole('button', { name: en.ReleaseCataloguePanel.download });
  act(() => { transition('cycle'); fireEvent.click(button); });
  expect(click).not.toHaveBeenCalled(); expect(screen.queryByText(en.ReleaseCataloguePanel.downloadNotices.requested)).not.toBeInTheDocument();
});
it('preserves explicit download after unrelated store notification', async () => {
  mount(); load(); await screen.findByText('visible-version-900'); act(() => useAuthStore.setState({ isLoading: false }));
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.download })); expect(click).toHaveBeenCalledOnce();
});
it.each(['en', 'es', 'zh'] as const)('renders %s native-download labels and dispatch caveats', async language => {
  await i18n.changeLanguage(language); mount(); const labels = locales[language].ReleaseCataloguePanel;
  fireEvent.click(screen.getByRole('button', { name: labels.loadFirst })); await screen.findByText('visible-version-900');
  fireEvent.click(screen.getByRole('button', { name: labels.download }));
  expect(screen.getByText(labels.downloadNotices.requested)).toBeVisible(); expect(click).toHaveBeenCalledOnce();
});
it('does not restore a prior-context status when the native dispatch boundary changes account', async () => {
  click.mockImplementation(() => transition('user')); mount(); load(); await screen.findByText('visible-version-900');
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.download }));
  expect(click).toHaveBeenCalledOnce(); expect(screen.queryByText(en.ReleaseCataloguePanel.downloadNotices.requested)).not.toBeInTheDocument();
  expect(screen.queryByText('visible-version-900')).not.toBeInTheDocument();
});
it('reports uncertainty without retry or private exception content after a dispatch fault', async () => {
  click.mockImplementation(() => { throw new Error('synthetic-private-dispatch-failure'); });
  mount(); load(); await screen.findByText('visible-version-900'); fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.download }));
  expect(screen.getByText(en.ReleaseCataloguePanel.downloadNotices.unconfirmed)).toBeVisible(); expect(click).toHaveBeenCalledOnce();
  expect(screen.queryByText(/synthetic-private-dispatch-failure/)).not.toBeInTheDocument(); expect(fetchMock).toHaveBeenCalledOnce();
});
