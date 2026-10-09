// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import vectors from '@/lib/api/__tests__/releaseCommitmentVectors.json';
import { ReleaseIntentRecoveryPanel } from '../ReleaseIntentRecoveryPanel';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const doc = JSON.parse(vectors[0].raw);
let previousAdapter: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: doc.organization_id, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function review(exists = true) {
  return { storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
    absence_authorizes_retry_or_cleanup: false, release_row_present: false, observed_at: '2026-01-01T00:00:01Z',
    operation: exists ? { operation_id: doc.operation_id, release_id: doc.release_id, organization_id: doc.organization_id, requested_by: actor,
      last_transition_by: actor, kind: 'publish', storage_kind: 'owned', phase: 'reserved', decision: null, transition_sequence: 0,
      created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null } : null,
    intent: doc, intent_sha256: vectors[0].intent_sha256, deletion_target_matches: null, historical_observation: true,
    reservation_created: false, server_retains_full_intent: false, save_original_intent_before_mutation: true,
    retry_requires_identical_intent_and_current_authority: true };
}
function reserved() {
  return { operation_id: doc.operation_id, release_id: doc.release_id, intent_sha256: vectors[0].intent_sha256,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true,
    result: { operation_id: doc.operation_id, release_id: doc.release_id, phase: 'reserved', decision: null, created: true,
      requested_by: actor, last_transition_by: actor } };
}
function wire(config: InternalAxiosRequestConfig, value: unknown) {
  return { config, data: JSON.stringify(value), status: 200, statusText: 'OK', headers: {} };
}
function pick(label: string, raw = vectors[0].raw) {
  fireEvent.change(screen.getByLabelText(label), { target: { files: [new File([raw], 'retained.json', { type: 'application/json' })] } });
}
async function loadAndReview() {
  pick('Import saved intent');
  await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
  fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' }));
  await screen.findByText('Validated historical observation');
  fireEvent.change(screen.getByLabelText('Type the complete operation ID to confirm this action'), { target: { value: doc.operation_id } });
}
beforeEach(() => {
  previousAdapter = api.defaults.adapter; vi.stubGlobal('crypto', webcrypto);
  const BaseURL = URL;
  vi.stubGlobal('URL', class extends BaseURL { static createObjectURL() { return 'blob:owned-recovery-test'; } static revokeObjectURL() { return undefined; } });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  api.defaults.adapter = async config => wire(config, config.url?.includes('intents/review') ? review() : reserved());
});
afterEach(() => { cleanup(); api.defaults.adapter = previousAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('deliberate release recovery panel', () => {
  it('does not execute on mount or download, and enables a single mutation only after readback, review and confirmation', async () => {
    const prepare = vi.fn(() => vectors[0].raw);
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => wire(config, config.url?.includes('intents/review') ? review() : reserved()));
    api.defaults.adapter = adapter; render(<ReleaseIntentRecoveryPanel prepareIntent={prepare} />);
    expect(prepare).not.toHaveBeenCalled(); expect(adapter).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Use prepared intent' }));
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Download original intent' }));
    expect(screen.getByText(/Download initiated/)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled(); expect(adapter).not.toHaveBeenCalled();
    pick('Verify saved intent file'); await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
    fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await screen.findByText('Validated historical observation');
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Type the complete operation ID to confirm this action'), { target: { value: doc.operation_id } });
    fireEvent.click(screen.getByRole('button', { name: 'Execute reserve' }));
    await waitFor(() => expect(adapter).toHaveBeenCalledTimes(2));
    await screen.findByText('Validated historical observation');
    expect(adapter.mock.calls[1][0].url).toMatch(/\/reserve$/);
  });
  it('imports an original document after reopening but still requires exact server review', async () => {
    render(<ReleaseIntentRecoveryPanel />); pick('Import saved intent');
    await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
    expect(screen.getByText(doc.operation_id)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    expect(screen.getByText(/Review the exact retained intent/)).toBeVisible();
  });
  it('refuses malformed imports without rendering their contents or sending HTTP', async () => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => wire(config, review())); api.defaults.adapter = adapter;
    render(<ReleaseIntentRecoveryPanel />); pick('Import saved intent', '{"synthetic-private-marker":');
    expect(await screen.findByRole('alert')).toHaveTextContent('intent file could not be verified');
    expect(screen.queryByText(/synthetic-private-marker/)).not.toBeInTheDocument(); expect(adapter).not.toHaveBeenCalled();
  });
  it('removes the old document and observation from the UI when the actor context changes', async () => {
    render(<ReleaseIntentRecoveryPanel />); await loadAndReview();
    useAuthStore.setState({ user: { ...user(), id: doc.release_id } });
    await screen.findByText(/account context changed or this session expired/);
    expect(screen.queryByText(doc.operation_id)).not.toBeInTheDocument();
    expect(screen.queryByText('Validated historical observation')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Execute reserve' })).not.toBeInTheDocument();
  });
  it('leaves an uncertain mutation disabled and never displays or replays the backend error body', async () => {
    let mutations = 0;
    api.defaults.adapter = async config => {
      if (config.url?.includes('intents/review')) return wire(config, review());
      mutations += 1;
      throw new AxiosError('synthetic-private-marker', 'ERR_BAD_REQUEST', config, undefined,
        { ...wire(config, { detail: '<img src=x onerror=alert(1)>' }), status: 503 });
    };
    render(<ReleaseIntentRecoveryPanel />); await loadAndReview(); fireEvent.click(screen.getByRole('button', { name: 'Execute reserve' }));
    await screen.findByText(/A mutation outcome is unconfirmed/);
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled(); expect(mutations).toBe(1);
    expect(screen.queryByText(/synthetic-private-marker|onerror=alert/)).not.toBeInTheDocument();
  });
  it('does not enable publication or cleanup merely because no history was observed', async () => {
    api.defaults.adapter = async config => wire(config, review(false));
    render(<ReleaseIntentRecoveryPanel />); await loadAndReview();
    expect(screen.getByText(/No operation history was observed/)).toBeVisible();
    fireEvent.change(screen.getByLabelText('Release action'), { target: { value: 'publish' } });
    expect(screen.getByRole('button', { name: 'Execute publish' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Release action'), { target: { value: 'cleanup' } });
    expect(screen.getByRole('button', { name: 'Execute cleanup' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Release action'), { target: { value: 'reserve' } });
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeEnabled();
  });
  it('aborts a pending file import when unmounted without adopting or sending work afterward', async () => {
    const abort = vi.spyOn(FileReader.prototype, 'abort');
    vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(() => undefined);
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => wire(config, review())); api.defaults.adapter = adapter;
    const page = render(<ReleaseIntentRecoveryPanel />); pick('Import saved intent'); page.unmount();
    await waitFor(() => expect(abort).toHaveBeenCalled()); expect(adapter).not.toHaveBeenCalled();
  });
});
