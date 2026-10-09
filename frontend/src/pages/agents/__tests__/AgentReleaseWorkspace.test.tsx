// @vitest-environment native-fetch
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
/** Real page and four workflow components with controlled Fetch/Axios/auth.
 * No native browser, worker, SQL, real cookie or external server acceptance. */
import { StrictMode } from 'react';
import { Blob as DOMBlob, File as DOMFile } from 'happy-dom';
import { webcrypto } from 'node:crypto';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import vectors from '@/lib/api/__tests__/releaseCommitmentVectors.json';
import en from '../../../../public/locales/en/agents.json';
import es from '../../../../public/locales/es/agents.json';
import zh from '../../../../public/locales/zh/agents.json';
import { AgentReleasesPage } from '../AgentReleasesPage';

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
const document = JSON.parse(vectors[0].raw);
const locales = { en, es, zh }; const i18n = createInstance();
let previousAdapter: typeof api.defaults.adapter;
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let adapter: ReturnType<typeof vi.fn<(config: InternalAxiosRequestConfig) => Promise<ReturnType<typeof wire>>>>;
function user(): User { return { id: actor, organization_id: organization, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, roles: ['admin'], permissions: ['agent:admin'],
  username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
function row() { return { id: release, organization_id: organization, version: 'visible-catalogue-version', platform: 'linux', agent_type: 'daemon',
  download_url: 'javascript:untrusted()', checksum_sha256: 'a'.repeat(64), signature: 'synthetic-not-verified', file_size: 1,
  release_notes: '<img src=x onerror=untrusted()>', min_backend_version: '', is_latest: false, is_prerelease: false,
  published_at: '2026-01-01T01:02:03.000004Z', download_count: 0 }; }
function catalogue() { return new Response(JSON.stringify({ items: [row()], limit: 50, has_more: false,
  next_id: null, next_published_at: null }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }); }
function promoted() { const { organization_id: _organization, ...value } = row();
  return { ...value, version: 'visible-promoted-version', is_latest: true }; }
function wire(config: InternalAxiosRequestConfig, value: unknown) {
  return { config, data: JSON.stringify(value), status: 200, statusText: 'OK', headers: {} };
}
function review() { return { storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
  absence_authorizes_retry_or_cleanup: false, release_row_present: false, observed_at: '2026-01-01T00:00:01Z',
  operation: null, intent: document, intent_sha256: vectors[0].intent_sha256, deletion_target_matches: null,
  historical_observation: true, reservation_created: false, server_retains_full_intent: false,
  save_original_intent_before_mutation: true, retry_requires_identical_intent_and_current_authority: true }; }
function mount() { return render(<I18nextProvider i18n={i18n}><AgentReleasesPage /></I18nextProvider>); }
function section(kind: 'publication' | 'promotion' | 'deletion') {
  const element = window.document.querySelector<HTMLDetailsElement>(`details[data-release-workflow="${kind}"]`);
  if (!element) throw new Error('missing workflow section');
  return element;
}
function expand(kind: 'publication' | 'promotion' | 'deletion') { const element = section(kind); element.open = true; fireEvent(element, new Event('toggle')); return within(element); }
function collapse(kind: 'publication' | 'promotion' | 'deletion') { const element = section(kind); element.open = false; fireEvent(element, new Event('toggle')); }
async function importIntent(kind: 'publication' | 'deletion', language: keyof typeof locales = 'en') {
  const target = expand(kind); const labels = locales[language].ReleaseIntentRecoveryPanel;
  fireEvent.change(target.getByLabelText(labels.import), { target: { files: [new File([vectors[0].raw], 'retained.json', { type: 'application/json' })] } });
  await target.findByText(labels.verified); return target;
}
function preparePromotion() {
  const target = expand('promotion'); const labels = en.ReleasePromotionWorkflow;
  fireEvent.change(target.getByLabelText(labels.releaseId), { target: { value: release } });
  fireEvent.click(target.getByRole('button', { name: labels.prepare }));
  fireEvent.change(target.getByLabelText(labels.confirmation), { target: { value: release } });
  return target;
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
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
  previousAdapter = api.defaults.adapter; vi.stubGlobal('crypto', webcrypto);
  // Match happy-dom's real FileReader realm; keep native Fetch/Response streaming.
  vi.stubGlobal('Blob', DOMBlob); vi.stubGlobal('File', DOMFile);
  adapter = vi.fn(async config => wire(config, config.url?.endsWith('/promote') ? promoted() : review())); api.defaults.adapter = adapter;
  fetchMock = vi.fn<typeof fetch>(async () => catalogue()); vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { cleanup(); api.defaults.adapter = previousAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('mounts all workflows without network, automatic mutation or stored-URL links in StrictMode', () => {
  render(<StrictMode><I18nextProvider i18n={i18n}><AgentReleasesPage /></I18nextProvider></StrictMode>);
  expect(screen.getByRole('heading', { name: en.AgentReleasesWorkspace.title, level: 1 })).toBeVisible();
  expect(window.document.querySelectorAll('details[data-release-workflow]')).toHaveLength(3);
  expect(fetchMock).not.toHaveBeenCalled(); expect(adapter).not.toHaveBeenCalled();
  for (const kind of ['publication', 'promotion', 'deletion'] as const) { expand(kind); collapse(kind); }
  expect(fetchMock).not.toHaveBeenCalled(); expect(adapter).not.toHaveBeenCalled();
  expect(window.document.querySelectorAll('a[href^="javascript:"]')).toHaveLength(0);
});
it('loads the real bounded catalogue only on deliberate click without invoking retired APIs', async () => {
  mount(); fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.loadFirst }));
  await screen.findByText('visible-catalogue-version');
  expect((fetchMock.mock.calls[0][0] as Request).url).toContain('/agents/release-catalogue?limit=50');
  expect(adapter).not.toHaveBeenCalled(); expect(fetchMock).toHaveBeenCalledOnce();
});
it('preserves local publication form input across collapse without issuing a request', () => {
  mount(); const pub = expand('publication');
  fireEvent.change(pub.getByLabelText(en.ReleasePublicationWorkflow.version), { target: { value: 'saved-local-version' } });
  collapse('publication'); expand('deletion'); collapse('deletion'); expand('publication');
  expect(pub.getByLabelText(en.ReleasePublicationWorkflow.version)).toHaveValue('saved-local-version');
  expect(adapter).not.toHaveBeenCalled(); expect(fetchMock).not.toHaveBeenCalled();
});
it('keeps an imported original intent across collapse and another workflow preparation', async () => {
  mount(); const pub = await importIntent('publication');
  expect(pub.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
  collapse('publication'); preparePromotion(); collapse('promotion'); expand('publication');
  expect(pub.getByText(document.operation_id)).toBeVisible(); expect(pub.getByText(en.ReleaseIntentRecoveryPanel.verified)).toBeVisible();
  expect(pub.getByRole('button', { name: 'Execute reserve' })).toBeDisabled(); expect(adapter).not.toHaveBeenCalled();
});
it('does not share intent confirmation or local close state between publication and deletion recovery panels', async () => {
  mount(); const pub = await importIntent('publication'); const deletion = await importIntent('deletion');
  fireEvent.change(pub.getByLabelText(en.ReleaseIntentRecoveryPanel.confirmation), { target: { value: document.operation_id } });
  expect(deletion.getByLabelText(en.ReleaseIntentRecoveryPanel.confirmation)).toHaveValue('');
  fireEvent.click(pub.getByLabelText(en.ReleasePublicationWorkflow.acknowledgement));
  fireEvent.click(pub.getByRole('button', { name: en.ReleasePublicationWorkflow.close }));
  expect(pub.queryByText(document.operation_id)).not.toBeInTheDocument();
  expect(deletion.getByText(document.operation_id)).toBeVisible(); expect(adapter).not.toHaveBeenCalled();
});
it.each(['user', 'organization', 'permission', 'logout', 'cycle'])('clears catalogue, saved intent and prepared promotion on %s transition', async kind => {
  mount(); const pub = await importIntent('publication'); preparePromotion();
  fireEvent.click(screen.getByRole('button', { name: en.ReleaseCataloguePanel.loadFirst })); await screen.findByText('visible-catalogue-version');
  act(() => transition(kind));
  expect(screen.queryByText('visible-catalogue-version')).not.toBeInTheDocument();
  expect(pub.queryByText(document.operation_id)).not.toBeInTheDocument();
  expect(within(section('promotion')).queryByLabelText(en.ReleasePromotionWorkflow.confirmation)).not.toBeInTheDocument();
  expect(adapter).not.toHaveBeenCalled(); expect(fetchMock).toHaveBeenCalledOnce();
});
it('does not abort, duplicate or lose a promotion merely because its section is collapsed', async () => {
  const gate = deferred<void>(); adapter.mockImplementation(async config => { await gate.promise; return wire(config, promoted()); });
  mount(); const promotion = preparePromotion(); fireEvent.click(promotion.getByRole('button', { name: en.ReleasePromotionWorkflow.promote }));
  await waitFor(() => expect(adapter).toHaveBeenCalledOnce()); const request = adapter.mock.calls[0][0];
  collapse('promotion'); expand('publication'); expect(request.signal?.aborted).toBe(false);
  await act(async () => { gate.resolve(); }); expand('promotion');
  expect(await promotion.findByText('visible-promoted-version')).toBeVisible();
  expect(promotion.getByRole('button', { name: en.ReleasePromotionWorkflow.promote })).toBeDisabled();
  expect(adapter).toHaveBeenCalledOnce();
});
it('preserves an uncertain mutation latch when recovery is collapsed and reopened', async () => {
  adapter.mockImplementation(async config => {
    if (config.url?.endsWith('/review')) return wire(config, review());
    throw new AxiosError('synthetic-lost-acknowledgment', 'ERR_NETWORK', config);
  });
  mount(); const pub = await importIntent('publication');
  fireEvent.click(pub.getByRole('button', { name: en.ReleaseIntentRecoveryPanel.review })); await pub.findByText(en.ReleaseIntentRecoveryPanel.observation);
  fireEvent.change(pub.getByLabelText(en.ReleaseIntentRecoveryPanel.confirmation), { target: { value: document.operation_id } });
  fireEvent.click(pub.getByRole('button', { name: 'Execute reserve' })); await pub.findByText(en.ReleaseIntentRecoveryPanel.uncertain);
  collapse('publication'); expand('promotion'); expand('publication');
  expect(pub.getByText(en.ReleaseIntentRecoveryPanel.uncertain)).toBeVisible();
  expect(pub.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
  expect(pub.queryByText(/synthetic-lost-acknowledgment/)).not.toBeInTheDocument(); expect(adapter).toHaveBeenCalledTimes(2);
});
it.each(['en', 'es', 'zh'] as const)('renders complete %s workflow labels and translated recovery actions without network', async language => {
  await i18n.changeLanguage(language); mount(); const labels = locales[language]; const pub = await importIntent('publication', language);
  for (const group of ['ReleasePublicationWorkflow', 'ReleaseDeletionWorkflow', 'ReleaseIntentRecoveryPanel', 'AgentReleasesWorkspace'] as const) {
    expect(Object.keys(labels[group]).sort()).toEqual(Object.keys(en[group]).sort());
  }
  expect(screen.getByRole('heading', { name: labels.AgentReleasesWorkspace.title })).toBeVisible();
  expect(pub.getByRole('heading', { name: labels.ReleasePublicationWorkflow.title })).toBeVisible();
  expect(pub.getByLabelText(labels.ReleaseIntentRecoveryPanel.action)).toBeVisible();
  const button = labels.ReleaseIntentRecoveryPanel.execute.replace('{{action}}', labels.ReleaseIntentRecoveryPanel.actions.reserve);
  expect(pub.getByRole('button', { name: button })).toBeDisabled();
  expect(expand('deletion').getByLabelText(labels.ReleaseDeletionWorkflow.releaseId)).toBeVisible();
  expect(expand('promotion').getByLabelText(labels.ReleasePromotionWorkflow.releaseId)).toBeVisible();
  expect(adapter).not.toHaveBeenCalled(); expect(fetchMock).not.toHaveBeenCalled();
});
it('retranslates an existing context-change notice without reviving cleared account state', async () => {
  mount(); const pub = await importIntent('publication'); act(() => transition('user'));
  expect(pub.getByText(en.ReleasePublicationWorkflow.notices.contextChanged)).toBeVisible();
  await act(async () => { await i18n.changeLanguage('es'); });
  expect(pub.getByText(es.ReleasePublicationWorkflow.notices.contextChanged)).toBeVisible();
  expect(pub.queryByText(document.operation_id)).not.toBeInTheDocument(); expect(adapter).not.toHaveBeenCalled();
});
