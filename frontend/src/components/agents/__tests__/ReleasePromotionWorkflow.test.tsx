// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real component/client/Axios with controlled adapter and authentication state.
 * These are not native browser, live server or independent signature tests. */
import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import * as promotionClient from '@/lib/api/releasePromotionClient';
import en from '../../../../public/locales/en/agents.json';
import es from '../../../../public/locales/es/agents.json';
import zh from '../../../../public/locales/zh/agents.json';
import { ReleasePromotionWorkflow } from '../ReleasePromotionWorkflow';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const release = '44444444-4444-4444-8444-444444444444';
const other = '55555555-5555-4555-8555-555555555555';
const labels = en.ReleasePromotionWorkflow;
const locales = { en, es, zh }; const i18n = createInstance();
let originalAdapter: typeof api.defaults.adapter;
let adapter: ReturnType<typeof vi.fn<(config: InternalAxiosRequestConfig) => Promise<ReturnType<typeof response>>>>;
function user(): User { return { id: actor, organization_id: organization, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, roles: ['admin'], permissions: ['agent:admin'],
  username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
function record() { return { id: release, version: '<img src=x onerror=untrusted()>', platform: 'linux', agent_type: 'daemon',
  download_url: 'javascript:untrusted()', checksum_sha256: 'a'.repeat(64), signature: 'synthetic-not-verified',
  file_size: 1, release_notes: '<script>untrusted()</script>', min_backend_version: '', is_latest: true,
  is_prerelease: false, published_at: '2026-01-01T01:02:03.000004Z', download_count: 0 }; }
function response(config: InternalAxiosRequestConfig, data: unknown = JSON.stringify(record())) {
  return { config, data, status: 200, statusText: 'OK', headers: {} };
}
function deferred<T>() { let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function mount() { return render(<I18nextProvider i18n={i18n}><ReleasePromotionWorkflow /></I18nextProvider>); }
function input(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }
function prepare(id = release) { input(labels.releaseId, id); fireEvent.click(screen.getByRole('button', { name: labels.prepare })); }
function confirm() { input(labels.confirmation, release); }
function promote() { fireEvent.click(screen.getByRole('button', { name: labels.promote })); }
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
  adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config)); api.defaults.adapter = adapter;
  document.cookie = 'freesdn_csrf=owned-promotion-ui; path=/';
});
afterEach(() => {
  cleanup(); api.defaults.adapter = originalAdapter; vi.restoreAllMocks();
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

it('does not issue on StrictMode mount or local preparation and requires exact typed confirmation', () => {
  render(<StrictMode><I18nextProvider i18n={i18n}><ReleasePromotionWorkflow /></I18nextProvider></StrictMode>);
  expect(adapter).not.toHaveBeenCalled(); prepare(); expect(adapter).not.toHaveBeenCalled();
  expect(screen.getByLabelText(labels.releaseId)).toBeDisabled();
  expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled();
  input(labels.confirmation, other); expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled();
  confirm(); expect(screen.getByRole('button', { name: labels.promote })).toBeEnabled();
  expect(adapter).not.toHaveBeenCalled();
});
it('renders a validated observation as escaped metadata, not executable stored URLs or signature verification', async () => {
  const view = mount(); prepare(); confirm(); promote();
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(labels.notices.confirmed));
  expect(screen.getByText(record().version)).toBeInTheDocument();
  expect(screen.getByText(record().checksum_sha256)).toBeInTheDocument();
  expect(view.container.querySelectorAll('a,img,script,svg')).toHaveLength(0);
  expect(screen.queryByText(record().download_url)).not.toBeInTheDocument();
  expect(screen.queryByText(record().signature)).not.toBeInTheDocument();
  const request = adapter.mock.calls[0][0];
  expect(request.url).toBe(`/agents/releases/${release}/promote`); expect(request.method).toBe('patch');
  expect(request.headers.get('X-CSRF-Token')).toBe('owned-promotion-ui');
  expect(request.headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
  expect(request.headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
  promote(); expect(adapter).toHaveBeenCalledOnce(); expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled();
});
it.each(['wrong-id', 'false-latest', 'duplicate'])('leaves %s acknowledgment uncertain without partial success or automatic retry', async kind => {
  const raw = kind === 'wrong-id' ? JSON.stringify({ ...record(), id: other })
    : kind === 'false-latest' ? JSON.stringify({ ...record(), is_latest: false })
      : JSON.stringify(record()).replace('"is_latest":true', '"is_latest":true,"is_latest":true');
  adapter.mockImplementation(async config => response(config, raw)); mount(); prepare(); confirm(); promote();
  expect(await screen.findByRole('alert')).toHaveTextContent(labels.notices.unconfirmed);
  expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  promote(); expect(adapter).toHaveBeenCalledOnce(); expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled();
});
it.each([401, 409, 503])('keeps HTTP %i uncertain and does not expose raw response or replay the request', async status => {
  adapter.mockImplementation(async config => {
    const received = { ...response(config, 'synthetic-private-error'), status };
    throw new AxiosError('synthetic-private-error', 'ERR_BAD_RESPONSE', config, undefined, received);
  });
  mount(); prepare(); confirm(); promote();
  expect(await screen.findByRole('alert')).toHaveTextContent(labels.notices.unconfirmed);
  expect(screen.queryByText(/synthetic-private-error/)).not.toBeInTheDocument();
  promote(); expect(adapter).toHaveBeenCalledOnce();
});
it('requires acknowledgment before closing, clears the original selection and never retries on close', async () => {
  mount(); prepare(); confirm(); promote();
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(labels.notices.confirmed));
  const close = screen.getByRole('button', { name: labels.close }); expect(close).toBeDisabled();
  fireEvent.click(screen.getByLabelText(labels.acknowledgement)); expect(close).toBeEnabled(); fireEvent.click(close);
  expect(screen.getByLabelText(labels.releaseId)).toHaveValue(''); expect(screen.queryByLabelText(labels.confirmation)).not.toBeInTheDocument();
  expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.closed); expect(adapter).toHaveBeenCalledOnce();
});
it('keeps busy controls locked and ignores repeated promotion clicks while awaiting a response', async () => {
  const gate = deferred<void>(); adapter.mockImplementation(async config => { await gate.promise; return response(config); });
  mount(); prepare(); confirm(); promote(); await waitFor(() => expect(adapter).toHaveBeenCalledOnce());
  expect(screen.getByLabelText(labels.confirmation)).toBeDisabled(); expect(screen.getByLabelText(labels.acknowledgement)).toBeDisabled();
  expect(screen.getByRole('button', { name: labels.close })).toBeDisabled(); promote(); expect(adapter).toHaveBeenCalledOnce();
  await act(async () => { gate.resolve(); });
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(labels.notices.confirmed));
});
it('stop waiting aborts the request, retains a spent attempt and refuses late success without claiming rollback', async () => {
  const gate = deferred<void>(); adapter.mockImplementation(async config => { await gate.promise; return response(config); });
  mount(); prepare(); confirm(); promote(); await waitFor(() => expect(adapter).toHaveBeenCalledOnce());
  const request = adapter.mock.calls[0][0]; fireEvent.click(screen.getByRole('button', { name: labels.stopWaiting }));
  expect(request.signal?.aborted).toBe(true); expect(screen.getByRole('status')).toHaveTextContent(labels.notices.cancelled);
  expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled(); promote();
  await act(async () => { gate.resolve(); });
  expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.cancelled); expect(adapter).toHaveBeenCalledOnce();
});
it.each(['user', 'organization', 'permission', 'logout', 'cycle'])('clears prepared input on %s transition without mutation', kind => {
  mount(); prepare(); confirm(); act(() => transition(kind));
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.contextChanged);
  expect(screen.getByLabelText(labels.releaseId)).toHaveValue('');
  expect(screen.queryByLabelText(labels.confirmation)).not.toBeInTheDocument(); expect(adapter).not.toHaveBeenCalled();
});
it.each(['user', 'organization', 'cycle'])('discards late success after %s context transition', async kind => {
  const gate = deferred<void>(); adapter.mockImplementation(async config => { await gate.promise; return response(config); });
  mount(); prepare(); confirm(); promote(); await waitFor(() => expect(adapter).toHaveBeenCalledOnce());
  act(() => transition(kind)); await act(async () => { gate.resolve(); });
  expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.contextChanged); expect(adapter).toHaveBeenCalledOnce();
});
it('clears displayed promotion metadata immediately when the current account changes', async () => {
  mount(); prepare(); confirm(); promote(); await screen.findByText(record().version);
  act(() => transition('user')); expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.contextChanged); expect(adapter).toHaveBeenCalledOnce();
});
it('aborts on unmount and never lets a late response mutate a remounted workflow', async () => {
  const gate = deferred<void>(); adapter.mockImplementation(async config => { await gate.promise; return response(config); });
  const view = mount(); prepare(); confirm(); promote(); await waitFor(() => expect(adapter).toHaveBeenCalledOnce());
  view.unmount(); expect(adapter.mock.calls[0][0].signal?.aborted).toBe(true); mount();
  await act(async () => { gate.resolve(); });
  expect(screen.getByRole('status')).toHaveTextContent(labels.notices.initial);
  expect(screen.queryByText(record().version)).not.toBeInTheDocument(); expect(adapter).toHaveBeenCalledOnce();
});
it.each(['invalid-id', 'permission'])('refuses %s before preparing a mutation', kind => {
  if (kind === 'permission') useAuthStore.setState({ hasPermission: () => false });
  mount(); prepare(kind === 'invalid-id' ? 'not-a-uuid' : release);
  expect(screen.getByRole('alert')).toHaveTextContent(labels.notices.invalid);
  expect(screen.queryByLabelText(labels.confirmation)).not.toBeInTheDocument(); expect(adapter).not.toHaveBeenCalled();
});
it.each(['en', 'es', 'zh'] as const)('includes all %s labels and retains explicit local preparation', async language => {
  await i18n.changeLanguage(language); const local = locales[language].ReleasePromotionWorkflow;
  expect(Object.keys(local).sort()).toEqual(Object.keys(labels).sort());
  expect(Object.keys(local.notices).sort()).toEqual(Object.keys(labels.notices).sort()); mount();
  expect(screen.getByRole('heading', { name: local.title })).toBeVisible();
  input(local.releaseId, release); fireEvent.click(screen.getByRole('button', { name: local.prepare }));
  expect(screen.getByRole('status')).toHaveTextContent(local.notices.prepared);
  expect(screen.getByRole('button', { name: local.promote })).toBeDisabled(); expect(adapter).not.toHaveBeenCalled();
});

it('never labels an acknowledged request unissued when the action closes before presentation', async () => {
  // Inject resource-lifetime closure at the client/UI await boundary; the real
  // client, captured transport, adapter and response decoder still execute.
  const capture = promotionClient.captureReleasePromotion;
  vi.spyOn(promotionClient, 'captureReleasePromotion').mockImplementation(value => {
    const captured = capture(value);
    return { ...captured, async execute(signal?: AbortSignal) {
      const observation = await captured.execute(signal);
      captured.dispose();
      return observation;
    } };
  });
  mount(); prepare(); confirm(); promote();
  expect(await screen.findByRole('alert')).toHaveTextContent(labels.notices.unconfirmed);
  expect(screen.queryByText(record().version)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: labels.promote })).toBeDisabled();
  expect(adapter).toHaveBeenCalledOnce();
});
