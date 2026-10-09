// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type InternalAxiosRequestConfig } from 'axios';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '@/lib/api/client';
import { hashReleasePayload } from '@/lib/api/releasePayloadHash';
import { decodeReleaseIntent, releaseIntentCommitment, type ReleaseIntentDocument } from '@/lib/api/releaseOperationCodec';
import vectors from '@/lib/api/__tests__/releaseCommitmentVectors.json';
import { ReleasePublicationWorkflow } from '../ReleasePublicationWorkflow';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
// This tests real composer/retention/UI and wire decoding around controlled
// worker/HTTP boundaries, not actual browser workers, crypto or server auth.
vi.mock('@/lib/api/releasePayloadHash', async original => {
  const actual = await original<typeof import('@/lib/api/releasePayloadHash')>();
  return { ...actual, hashReleasePayload: vi.fn() };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
function user(): User { return { id: actor, organization_id: organization, role: 'admin', is_active: true,
  is_superuser: false, is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'],
  email: 'owned@example.invalid', username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
let saved: Blob | undefined;
let previousAdapter: typeof api.defaults.adapter;
let calls: InternalAxiosRequestConfig[];
let exists: boolean;
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }
function pick(label: string, file: File) { fireEvent.change(screen.getByLabelText(label), { target: { files: [file] } }); }
function fillOwned() { change('Release version', '1.2.3'); change('Release notes', 'captured notes'); pick('Binary to prepare', new File(['abc'], 'agent.bin')); }
function fillExternal() {
  change('Release storage', 'external'); change('Release version', '2.3.4');
  change('External download URL', 'https://updates.example.invalid/agent'); change('External SHA-256', 'b'.repeat(64)); change('External size in bytes', '10737418240');
}
function bytes(blob: Blob): Promise<ArrayBuffer> { return new Promise((resolve, reject) => {
  const reader = new FileReader(); reader.onerror = () => reject(new Error('fixture file read failed'));
  reader.onload = () => resolve(reader.result as ArrayBuffer); reader.readAsArrayBuffer(blob);
}); }
async function downloaded(): Promise<{ raw: string; document: ReleaseIntentDocument }> {
  fireEvent.click(screen.getByRole('button', { name: 'Download original intent' })); expect(saved).toBeDefined();
  const raw = new TextDecoder().decode(await bytes(saved!)); return { raw, document: decodeReleaseIntent(raw) };
}
function wire(config: InternalAxiosRequestConfig, value: unknown) { return { config, data: JSON.stringify(value), status: 200, statusText: 'OK', headers: {} }; }
function operation(document: ReleaseIntentDocument) { return { operation_id: document.operation_id, release_id: document.release_id,
  organization_id: document.organization_id, requested_by: actor, last_transition_by: actor, kind: document.kind,
  storage_kind: document.kind === 'publish' ? document.storage_kind : 'owned', phase: 'reserved', decision: null,
  transition_sequence: 0, created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null }; }
async function respond(config: InternalAxiosRequestConfig) {
  const raw = typeof config.data === 'string' ? config.data : (config.data as FormData).get('intent') as string;
  const document = decodeReleaseIntent(raw); const commitment = await releaseIntentCommitment(document);
  if (config.url?.endsWith('/review')) return wire(config, { intent: document, intent_sha256: commitment,
    operation: exists ? operation(document) : null, release_row_present: false, deletion_target_matches: null,
    observed_at: '2026-01-01T00:00:01Z', historical_observation: true, reservation_created: false, server_retains_full_intent: false,
    save_original_intent_before_mutation: true, retry_requires_identical_intent_and_current_authority: true,
    storage_checked: false, all_artifact_references_checked: false, authorization_granted: false, absence_authorizes_retry_or_cleanup: false });
  const result = config.url?.endsWith('/upload') ? { operation_id: document.operation_id, release_id: document.release_id,
    phase: 'prepared', requested_by: actor, last_transition_by: actor, publication_or_storage_authorized: false }
    : { operation_id: document.operation_id, release_id: document.release_id, phase: 'reserved', decision: null,
      created: true, requested_by: actor, last_transition_by: actor };
  return wire(config, { operation_id: document.operation_id, release_id: document.release_id, intent_sha256: commitment,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true, result });
}
async function prepared() {
  fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
  await screen.findByText(/Intent prepared locally/); fireEvent.click(screen.getByRole('button', { name: 'Use prepared intent' }));
}
async function reviewed(raw: string) {
  pick('Verify saved intent file', new File([raw], 'retained.json'));
  await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
  fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await screen.findByText('Validated historical observation');
  change('Type the complete operation ID to confirm this action', decodeReleaseIntent(raw).operation_id);
}
beforeEach(() => {
  saved = undefined; calls = []; exists = false; previousAdapter = api.defaults.adapter; vi.stubGlobal('crypto', webcrypto);
  const BaseURL = URL; vi.stubGlobal('URL', class extends BaseURL {
    static createObjectURL(blob: Blob) { saved = blob; return 'blob:workflow-test'; } static revokeObjectURL() { return undefined; }
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  vi.mocked(hashReleasePayload).mockReset().mockResolvedValue('a'.repeat(64));
  api.defaults.adapter = async config => { calls.push(config); return respond(config); };
});
afterEach(() => { cleanup(); api.defaults.adapter = previousAdapter; vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('publication preparation through retained-intent workflow', () => {
  it('does nothing on mount and cannot close local state without acknowledgment', () => {
    render(<ReleasePublicationWorkflow />); expect(hashReleasePayload).not.toHaveBeenCalled(); expect(calls).toHaveLength(0);
    expect(screen.getByRole('button', { name: 'Close local workflow' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
  });
  it('requires file retention and review before reserve, then uploads the original captured snapshot', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); await prepared();
    expect(calls).toHaveLength(0); expect(screen.getByRole('button', { name: 'Prepare release intent' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
    const { raw, document } = await downloaded(); expect(document.metadata).toMatchObject({ filename: 'agent.bin', checksum_sha256: 'a'.repeat(64), file_size: 3, is_latest: true, release_notes: 'captured notes' });
    expect(screen.getByRole('button', { name: 'Execute reserve' })).toBeDisabled(); await reviewed(raw);
    fireEvent.click(screen.getByRole('button', { name: 'Execute reserve' })); await waitFor(() => expect(calls).toHaveLength(2));
    await screen.findByText('Validated historical observation'); change('Release action', 'upload');
    expect(screen.getByText(/A binary snapshot is selected/)).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Execute upload' }));
    await waitFor(() => expect(calls).toHaveLength(3)); await screen.findByText('Validated historical observation');
    const body = calls[2].data as FormData; expect(decodeReleaseIntent(body.get('intent') as string)).toEqual(document);
    expect(new TextDecoder().decode(await bytes(body.get('file') as Blob))).toBe('abc');
    expect(calls.map(c => c.url)).toEqual(['/agents/release-operation-intents/review', `/agents/release-operations/${document.operation_id}/reserve`, `/agents/release-operations/${document.operation_id}/upload`]);
  });
  it('composes external metadata without a worker or URL request', async () => {
    render(<ReleasePublicationWorkflow />); fillExternal(); await prepared(); const { document } = await downloaded();
    expect(document).toMatchObject({ storage_kind: 'external', metadata: { file_size: 10737418240, filename: null, checksum_sha256: 'b'.repeat(64) } });
    expect(hashReleasePayload).not.toHaveBeenCalled(); expect(calls).toHaveLength(0);
  });
  it.each(['missing-file', 'bad-version', 'too-many-notes', 'bad-url', 'bad-checksum', 'fractional-size', 'exponent-size', 'oversize'])(
    'refuses %s before any worker or server request', async which => {
      render(<ReleasePublicationWorkflow />); fillOwned();
      if (which === 'missing-file') fireEvent.change(screen.getByLabelText('Binary to prepare'), { target: { files: [] } });
      if (which === 'bad-version') change('Release version', '../bad');
      if (which === 'too-many-notes') change('Release notes', 'x'.repeat(20001));
      if (['bad-url', 'bad-checksum', 'fractional-size', 'exponent-size', 'oversize'].includes(which)) {
        fillExternal();
        if (which === 'bad-url') change('External download URL', 'javascript:alert(1)');
        if (which === 'bad-checksum') change('External SHA-256', 'g'.repeat(64));
        if (which === 'fractional-size') change('External size in bytes', '1.5');
        if (which === 'exponent-size') change('External size in bytes', '1e3');
        if (which === 'oversize') change('External size in bytes', '10737418241');
      }
      fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' })); await screen.findByText(/Intent preparation did not complete/);
      expect(hashReleasePayload).not.toHaveBeenCalled(); expect(calls).toHaveLength(0);
    });
  it('preserves complete Unicode notes and all explicit publication options', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); change('Release notes', '🎉'.repeat(20000)); change('Release platform', 'windows'); change('Agent type', 'desktop');
    change('Minimum backend version', '26.09.1'); fireEvent.click(screen.getByLabelText('Prerelease')); fireEvent.click(screen.getByLabelText('Make latest after publication'));
    await prepared(); const { document } = await downloaded(); expect(document.metadata).toMatchObject({ release_notes: '🎉'.repeat(20000), platform: 'windows', agent_type: 'desktop', min_backend_version: '26.09.1', is_prerelease: true, is_latest: false });
  });
  it('uses the current organization for an org admin despite scripted readonly-field changes', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); change('Target organization UUID (empty means platform)', '33333333-3333-4333-8333-333333333333');
    await prepared(); expect((await downloaded()).document.organization_id).toBe(organization);
  });
  it.each(['platform', 'other-organization'])(
    'records a superuser explicit %s target without claiming authority', async which => {
      useAuthStore.setState({ user: { ...user(), is_superuser: true } }); render(<ReleasePublicationWorkflow />); fillOwned();
      const target = which === 'platform' ? '' : '33333333-3333-4333-8333-333333333333'; change('Target organization UUID (empty means platform)', target);
      await prepared(); expect((await downloaded()).document.organization_id).toBe(target || null); expect(calls).toHaveLength(0);
    });
  it.each(['actor', 'organization', 'permission', 'ABA'])(
    'clears form and aborts late hash output after %s transition', async which => {
      let resolve!: (digest: string) => void; let signal: AbortSignal | undefined;
      vi.mocked(hashReleasePayload).mockImplementation((_blob, options) => { signal = options.signal; return new Promise(r => { resolve = r; }); });
      render(<ReleasePublicationWorkflow />); fillOwned(); fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
      expect(screen.getByLabelText('Import saved intent')).toBeDisabled();
      if (which === 'permission') useAuthStore.setState({ hasPermission: () => false });
      else useAuthStore.setState({ user: { ...user(), ...(which === 'organization' ? { organization_id: '33333333-3333-4333-8333-333333333333' } : { id: '44444444-4444-4444-8444-444444444444' }) } });
      if (which === 'ABA') useAuthStore.setState({ user: user() });
      await screen.findByText(/Account context changed/); expect(signal?.aborted).toBe(true); resolve('a'.repeat(64));
      await waitFor(() => expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument());
      expect(screen.getByLabelText('Release version')).toHaveValue(''); expect(calls).toHaveLength(0);
    });
  it('cancels local hashing and never adopts a late result or leaks the native error', async () => {
    let reject!: (reason: Error) => void; let signal: AbortSignal | undefined;
    vi.mocked(hashReleasePayload).mockImplementation((_blob, options) => { signal = options.signal; return new Promise((_resolve, r) => { reject = r; }); });
    render(<ReleasePublicationWorkflow />); fillOwned(); fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel local preparation' })); expect(signal?.aborted).toBe(true); reject(new Error('synthetic-private-native-path'));
    await screen.findByText(/Intent preparation did not complete/); expect(screen.queryByText(/synthetic-private-native-path/)).not.toBeInTheDocument(); expect(calls).toHaveLength(0);
  });
  it('aborts pending preparation on unmount and ignores its eventual result', async () => {
    let resolve!: (digest: string) => void; let signal: AbortSignal | undefined;
    vi.mocked(hashReleasePayload).mockImplementation((_blob, options) => { signal = options.signal; return new Promise(r => { resolve = r; }); });
    const page = render(<ReleasePublicationWorkflow />); fillOwned(); fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
    page.unmount(); expect(signal?.aborted).toBe(true); resolve('a'.repeat(64)); expect(calls).toHaveLength(0);
  });
  it('invalidates a prepared but unadopted document when fields are edited', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
    await screen.findByRole('button', { name: 'Use prepared intent' }); change('Release notes', 'new notes');
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument(); expect(calls).toHaveLength(0);
  });
  it('locks imported intent against accidental replacement and does not attach an unrelated prepared binary', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); fireEvent.click(screen.getByRole('button', { name: 'Prepare release intent' }));
    await screen.findByRole('button', { name: 'Use prepared intent' }); pick('Import saved intent', new File([vectors[0].raw], 'original.json'));
    await screen.findByText('Matching intent file read back and verified. Keep your saved copy.');
    expect(screen.getByRole('button', { name: 'Prepare release intent' })).toBeDisabled(); expect(screen.getByLabelText('Import saved intent')).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Use prepared intent' })).not.toBeInTheDocument();
    pick('Import saved intent', new File([vectors[1].raw], 'replacement.json'));
    expect(screen.getByText(decodeReleaseIntent(vectors[0].raw).operation_id)).toBeVisible();
    exists = true; fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await screen.findByText('Validated historical observation');
    change('Type the complete operation ID to confirm this action', decodeReleaseIntent(vectors[0].raw).operation_id); change('Release action', 'upload');
    expect(screen.getByRole('button', { name: 'Execute upload' })).toBeDisabled();
  });
  it('requires acknowledgment to close retained local state and issues no cancellation command', async () => {
    render(<ReleasePublicationWorkflow />); fillOwned(); await prepared(); const { document } = await downloaded();
    expect(screen.getByRole('button', { name: 'Close local workflow' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I have kept any original intent/)); fireEvent.click(screen.getByRole('button', { name: 'Close local workflow' }));
    expect(screen.queryByText(document.operation_id)).not.toBeInTheDocument(); expect(screen.getByLabelText('Release version')).toHaveValue('');
    expect(screen.getByText(/Retained server operations and any uncertain outcomes are unchanged/)).toBeVisible(); expect(calls).toHaveLength(0);
  });
  it('does not close the local workflow while a server review is pending', async () => {
    let release!: () => void; api.defaults.adapter = async config => { calls.push(config); await new Promise<void>(r => { release = r; }); return respond(config); };
    render(<ReleasePublicationWorkflow />); pick('Import saved intent', new File([vectors[0].raw], 'original.json'));
    await screen.findByText('Matching intent file read back and verified. Keep your saved copy.'); fireEvent.click(screen.getByLabelText(/I have kept any original intent/));
    fireEvent.click(screen.getByRole('button', { name: 'Review exact intent' })); await waitFor(() => expect(calls).toHaveLength(1));
    expect(screen.getByRole('button', { name: 'Close local workflow' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Close local workflow' }));
    expect(screen.getByText(decodeReleaseIntent(vectors[0].raw).operation_id)).toBeVisible(); release(); await screen.findByText('Validated historical observation');
    expect(screen.getByRole('button', { name: 'Close local workflow' })).toBeEnabled();
  });
});
