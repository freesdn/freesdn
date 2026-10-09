// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import { decodeReleaseIntent } from '@/lib/api/releaseOperationCodec';
import vectors from '@/lib/api/__tests__/releaseCommitmentVectors.json';
import { ReleaseDeletionWorkflow } from '../ReleaseDeletionWorkflow';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
// Real component/composer/retention/codec/crypto; controlled auth store, HTTP,
// DOM and file picker. No actual browser save, backend, SQL or IdP claim.
const actor = '11111111-1111-4111-8111-111111111111';
const vector = vectors[5];
const document = decodeReleaseIntent(vector.raw);
let previousAdapter: typeof api.defaults.adapter;
let calls: InternalAxiosRequestConfig[];
let saved: Blob | undefined;
let journal: boolean;
function user(): User { return { id: actor, organization_id: document.organization_id, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'],
  email: 'owned@example.invalid', username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }
function pick(label: string, raw = vector.raw) {
  fireEvent.change(screen.getByLabelText(label), { target: { files: [new File([raw], 'retained.json')] } });
}
function review() { return { intent: document, intent_sha256: vector.intent_sha256,
  operation: journal ? { operation_id: document.operation_id, release_id: document.release_id,
    organization_id: document.organization_id, requested_by: actor, last_transition_by: actor, kind: 'delete',
    storage_kind: 'owned', phase: 'reserved', decision: null, transition_sequence: 0,
    created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null } : null,
  storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
  absence_authorizes_retry_or_cleanup: false, release_row_present: true, observed_at: '2026-01-01T00:00:01Z',
  deletion_target_matches: true, historical_observation: true, reservation_created: false,
  server_retains_full_intent: false, save_original_intent_before_mutation: true,
  retry_requires_identical_intent_and_current_authority: true }; }
function wire(config: InternalAxiosRequestConfig, value: unknown) {
  return { config, data: JSON.stringify(value), headers: {}, status: 200, statusText: 'OK' };
}
function respond(config: InternalAxiosRequestConfig) {
  if (config.method === 'get' || config.url?.endsWith('/review')) return wire(config, review());
  journal = true;
  const deletion = config.url?.endsWith('/delete');
  return wire(config, { operation_id: document.operation_id, release_id: document.release_id, intent_sha256: vector.intent_sha256,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true,
    result: { operation_id: document.operation_id, release_id: document.release_id, phase: deletion ? 'decided' : 'reserved',
      decision: deletion ? 'deleted' : null, newly_changed: true, cleanup_disposition: deletion ? 'pending-owned-verification' : 'preserve-live',
      bytes_removed: false, cleanup_authorized: false } });
}
function start() {
  change('Release UUID to remove', document.release_id);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare deletion intent' }));
}
async function prepareAndAdopt() {
  start(); await screen.findByText(/Deletion intent prepared from a read-only/);
  fireEvent.click(screen.getByRole('button', { name: 'Use prepared intent' }));
}
async function reviewSaved() {
  pick('Verify saved intent file'); await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
  fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await screen.findByText('Validated historical observation');
  change('Type the complete operation ID to confirm this action', document.operation_id);
}
function bytes(blob: Blob): Promise<ArrayBuffer> { return new Promise((resolve, reject) => {
  const reader = new FileReader(); reader.onerror = () => reject(new Error('fixture file read failed'));
  reader.onload = () => resolve(reader.result as ArrayBuffer); reader.readAsArrayBuffer(blob);
}); }
beforeEach(() => {
  saved = undefined; calls = []; journal = false; previousAdapter = api.defaults.adapter;
  vi.stubGlobal('crypto', webcrypto);
  expect(document.operation_id).toBe('33333333-3333-4333-8333-333333333333');
  vi.spyOn(crypto, 'randomUUID').mockReturnValue('33333333-3333-4333-8333-333333333333');
  const BaseURL = URL; vi.stubGlobal('URL', class extends BaseURL {
    static createObjectURL(blob: Blob) { saved = blob; return 'blob:owned-deletion-workflow'; }
    static revokeObjectURL() { return undefined; }
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  api.defaults.adapter = async config => { calls.push(config); return respond(config); };
});
afterEach(() => { cleanup(); api.defaults.adapter = previousAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('deliberate deletion preparation and recovery workflow', () => {
  it('requires separate save readback, exact review, typed identity and explicit reserve then delete clicks', async () => {
    render(<ReleaseDeletionWorkflow />); expect(calls).toHaveLength(0); await prepareAndAdopt();
    expect(calls).toHaveLength(1); expect(calls[0].method).toBe('get');
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Download original intent' })); expect(saved).toBeDefined();
    expect(decodeReleaseIntent(new TextDecoder().decode(await bytes(saved!)))).toEqual(document);
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled(); expect(calls).toHaveLength(1);
    pick('Verify saved intent file'); await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await screen.findByText('Validated historical observation');
    expect(calls).toHaveLength(2); expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled();
    change('Type the complete operation ID to confirm this action', document.operation_id);
    change('Release action', 'delete'); expect(screen.getByRole('button', { name: 'Execute delete' })).toBeDisabled();
    change('Release action', 'reserve'); fireEvent.click(screen.getByRole('button', { name: 'Execute reserve' }));
    await screen.findByText('Validated historical observation');
    expect(calls).toHaveLength(3); expect(calls[2].url).toMatch(/\/reserve$/);
    expect(JSON.parse(calls[2].data as string)).toEqual(document);
    change('Release action', 'delete'); expect(screen.getByRole('button', { name: 'Execute delete' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Execute delete' })); await screen.findByText('Validated historical observation');
    expect(calls).toHaveLength(4); expect(calls[3].url).toMatch(/\/delete$/);
    expect(JSON.parse(calls[3].data as string)).toEqual(document);
    expect(calls.some(call => call.url?.endsWith('/cleanup'))).toBe(false);
  });
  it.each(['actor', 'organization', 'permission', 'ABA'])(
    'clears preparation and suppresses a late response after %s context change', async which => {
      let finish!: () => void;
      api.defaults.adapter = async config => { calls.push(config); await new Promise<void>(resolve => { finish = resolve; }); return respond(config); };
      render(<ReleaseDeletionWorkflow />); start(); await waitFor(() => expect(calls).toHaveLength(1));
      expect(screen.getByLabelText('Release UUID to remove')).toBeDisabled(); expect(screen.getByLabelText('Import saved intent')).toBeDisabled();
      act(() => {
        if (which === 'permission') useAuthStore.setState({ hasPermission: () => false });
        else useAuthStore.setState({ user: { ...user(), ...(which === 'organization'
          ? { organization_id: '33333333-3333-4333-8333-333333333333' } : { id: document.release_id }) } });
        if (which === 'ABA') useAuthStore.setState({ user: user() });
      });
      expect(calls[0].signal?.aborted).toBe(true);
      await act(async () => { finish(); });
      expect(screen.getByText(/Account context changed/)).toBeVisible();
      expect(screen.getByLabelText('Release UUID to remove')).toHaveValue('');
      expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
      expect(calls).toHaveLength(1);
    });
  it('invalidates unadopted preparation on target edit without fetching another target automatically', async () => {
    render(<ReleaseDeletionWorkflow />); start(); await screen.findByRole('button', { name: 'Use prepared intent' });
    change('Release UUID to remove', actor);
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument(); expect(calls).toHaveLength(1);
  });
  it('cancels a pending read without adopting late output or issuing a server cancellation', async () => {
    let finish!: () => void;
    api.defaults.adapter = async config => { calls.push(config); await new Promise<void>(resolve => { finish = resolve; }); return respond(config); };
    render(<ReleaseDeletionWorkflow />); start(); await waitFor(() => expect(calls).toHaveLength(1));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel deletion preparation' })); expect(calls[0].signal?.aborted).toBe(true);
    await act(async () => { finish(); }); await screen.findByText(/Deletion preparation did not complete/);
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument(); expect(calls).toHaveLength(1);
  });
  it('aborts preparation on unmount without a late mutation', async () => {
    let finish!: () => void;
    api.defaults.adapter = async config => { calls.push(config); await new Promise<void>(resolve => { finish = resolve; }); return respond(config); };
    const page = render(<ReleaseDeletionWorkflow />); start(); await waitFor(() => expect(calls).toHaveLength(1));
    page.unmount(); expect(calls[0].signal?.aborted).toBe(true); await act(async () => { finish(); }); expect(calls).toHaveLength(1);
  });
  it.each([401, 503])('sanitizes preparation HTTP %s and never refreshes or retries', async status => {
    api.defaults.adapter = async config => { calls.push(config); throw new AxiosError('synthetic-private-marker', 'ERR_BAD_RESPONSE', config,
      undefined, { ...wire(config, { detail: 'synthetic-private-marker' }), status }); };
    render(<ReleaseDeletionWorkflow />); start(); await screen.findByText(/Deletion preparation did not complete/);
    expect(calls).toHaveLength(1); expect(screen.queryByText(/synthetic-private-marker/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
  });
  it('refuses an absent target rather than displaying a prepared deletion', async () => {
    api.defaults.adapter = async config => { calls.push(config); return wire(config, { ...review(), release_row_present: false, deletion_target_matches: false }); };
    render(<ReleaseDeletionWorkflow />); start(); await screen.findByText(/Deletion preparation did not complete/);
    expect(calls).toHaveLength(1); expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
  });
  it('rejects a malformed target without sending HTTP', async () => {
    render(<ReleaseDeletionWorkflow />); change('Release UUID to remove', '../../unrelated');
    fireEvent.click(screen.getByRole('button', { name: 'Prepare deletion intent' }));
    await screen.findByText(/Deletion preparation did not complete/); expect(calls).toHaveLength(0);
  });
  it('locks an imported original intent against replacement without sending a preparation request', async () => {
    render(<ReleaseDeletionWorkflow />); pick('Import saved intent');
    await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
    expect(screen.getByText(document.operation_id)).toBeVisible(); expect(calls).toHaveLength(0);
    expect(screen.getByLabelText('Release UUID to remove')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Prepare deletion intent' })).toBeDisabled();
    expect(screen.getByLabelText('Import saved intent')).toBeDisabled();
    pick('Import saved intent', vectors[0].raw);
    expect(screen.getByText(document.operation_id)).toBeVisible(); expect(calls).toHaveLength(0);
  });
  it('requires acknowledgment to close local state and sends no cancellation or cleanup', async () => {
    render(<ReleaseDeletionWorkflow />); await prepareAndAdopt();
    expect(screen.getByRole('button', { name: 'Close local deletion workflow' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I have kept any original intent/));
    fireEvent.click(screen.getByRole('button', { name: 'Close local deletion workflow' }));
    expect(screen.queryByText(document.operation_id)).not.toBeInTheDocument();
    expect(screen.getByText(/Server operations and uncertain outcomes are unchanged/)).toBeVisible();
    expect(screen.getByLabelText('Release UUID to remove')).toHaveValue(''); expect(calls).toHaveLength(1);
  });
  it('refuses local close while an exact server review is pending', async () => {
    let finish!: () => void;
    render(<ReleaseDeletionWorkflow />); await prepareAndAdopt(); fireEvent.click(screen.getByLabelText(/I have kept any original intent/));
    api.defaults.adapter = async config => { calls.push(config); await new Promise<void>(resolve => { finish = resolve; }); return respond(config); };
    fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await waitFor(() => expect(calls).toHaveLength(2));
    expect(screen.getByRole('button', { name: 'Close local deletion workflow' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Close local deletion workflow' }));
    expect(screen.getByText(document.operation_id)).toBeVisible(); await act(async () => { finish(); });
    await screen.findByText('Validated historical observation'); expect(screen.getByRole('button', { name: 'Close local deletion workflow' })).toBeEnabled();
  });
  it('retains an uncertain deletion for inspection without replay or automatic cleanup', async () => {
    render(<ReleaseDeletionWorkflow />); await prepareAndAdopt(); await reviewSaved();
    fireEvent.click(screen.getByRole('button', { name: 'Execute reserve' })); await screen.findByText('Validated historical observation');
    api.defaults.adapter = async config => { calls.push(config); throw new AxiosError('synthetic-private-marker', 'ERR_BAD_RESPONSE', config,
      undefined, { ...wire(config, {}), status: 503 }); };
    change('Release action', 'delete'); fireEvent.click(screen.getByRole('button', { name: 'Execute delete' }));
    await screen.findByText(/A mutation outcome is unconfirmed/);
    expect(screen.getByRole('button', { name: 'Execute delete' })).toBeDisabled();
    change('Release action', 'cleanup'); expect(screen.getByRole('button', { name: 'Execute cleanup' })).toBeDisabled();
    expect(screen.getByText(document.operation_id)).toBeVisible(); expect(screen.queryByText(/synthetic-private-marker/)).not.toBeInTheDocument();
    expect(calls).toHaveLength(4); expect(calls.filter(call => call.url?.endsWith('/delete'))).toHaveLength(1);
    expect(calls.some(call => call.url?.endsWith('/cleanup'))).toBe(false);
  });
});
