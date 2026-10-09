// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginReleaseIntentRetention, importReleaseIntentFile, ReleaseIntentFileError, type ReleaseIntentRetention } from '../releaseIntentRetention';
import vectors from './releaseCommitmentVectors.json';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const doc = JSON.parse(vectors[0].raw);
const sessions: ReleaseIntentRetention[] = [];
const revoked = vi.fn();
let savedBlob: Blob | undefined;
let previousAdapter: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: doc.organization_id, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function session() { const value = beginReleaseIntentRetention(vectors[0].raw); sessions.push(value); return value; }
function file(raw = vectors[0].raw) { return new File([raw], 'retained.json', { type: 'application/json' }); }
function status() {
  return { storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
    absence_authorizes_retry_or_cleanup: false, release_row_present: false, observed_at: '2026-01-01T00:00:01Z',
    operation: { operation_id: doc.operation_id, release_id: doc.release_id, organization_id: doc.organization_id, requested_by: actor,
      last_transition_by: actor, kind: 'publish', storage_kind: 'owned', phase: 'reserved', decision: null, transition_sequence: 0,
      created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null } };
}
function review(exists = true) {
  return { ...status(), operation: exists ? status().operation : null, intent: doc, intent_sha256: vectors[0].intent_sha256,
    deletion_target_matches: null, historical_observation: true, reservation_created: false, server_retains_full_intent: false,
    save_original_intent_before_mutation: true, retry_requires_identical_intent_and_current_authority: true };
}
function reserved() {
  return { operation_id: doc.operation_id, release_id: doc.release_id, intent_sha256: vectors[0].intent_sha256,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true,
    result: { operation_id: doc.operation_id, release_id: doc.release_id, phase: 'reserved', decision: null, created: false,
      requested_by: actor, last_transition_by: actor } };
}
function response(config: InternalAxiosRequestConfig, value: unknown) {
  return { config, data: JSON.stringify(value), status: 200, statusText: 'OK', headers: {} };
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); previousAdapter = api.defaults.adapter; savedBlob = undefined; revoked.mockClear();
  const BaseURL = URL;
  vi.stubGlobal('URL', class extends BaseURL {
    static createObjectURL(blob: Blob) { savedBlob = blob; return 'blob:owned-intent-test'; }
    static revokeObjectURL(url: string) { revoked(url); }
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  api.defaults.adapter = async config => response(config, config.url?.includes('intents/review') ? review() : config.method === 'get' ? status() : reserved());
});
afterEach(() => {
  sessions.splice(0).forEach(value => value.dispose()); api.defaults.adapter = previousAdapter;
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers();
});

describe('explicit retained intent readback', () => {
  it('does not treat download dispatch as a save; only matching file readback satisfies retention', async () => {
    const value = session(); const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => response(config, review())); api.defaults.adapter = adapter;
    value.download(); expect(savedBlob?.size).toBe(new TextEncoder().encode(vectors[0].raw).byteLength);
    expect(value.getState()).toMatchObject({ downloadIssued: true, fileVerified: false });
    expect(() => value.captureMutation('reserve', doc.operation_id)).toThrow();
    expect(adapter).not.toHaveBeenCalled(); await value.verifySelectedFile(file());
    expect(value.getState()).toMatchObject({ fileVerified: true, reviewed: false });
    expect(adapter).not.toHaveBeenCalled();
  });
  it('imports an equivalent complete saved document without normalizing its raw export spelling', async () => {
    const raw = JSON.stringify(doc, null, 3);
    const value = await importReleaseIntentFile(file(raw)); sessions.push(value);
    expect(value.getState()).toMatchObject({ fileVerified: true, reviewed: false, document: doc });
    value.download();
    const selected = new File([savedBlob!], 'saved-again.json');
    await value.verifySelectedFile(selected);
    expect(selected.size).toBe(new TextEncoder().encode(raw).byteLength);
  });
  it.each(['empty', 'oversize', 'invalid-utf8', 'bom', 'bad-json', 'duplicate-key', 'lone-surrogate', 'different-document', 'unknown-field'])(
    'refuses selected file %s without retaining a verification or exposing its contents', async which => {
      const value = session(); let selected = file();
      if (which === 'empty') selected = file('');
      if (which === 'oversize') selected = file(' '.repeat(307201));
      if (which === 'invalid-utf8') selected = new File([new Uint8Array([0xc3, 0x28])], 'synthetic-sensitive-name');
      if (which === 'bom') selected = file('\ufeff' + vectors[0].raw);
      if (which === 'bad-json') selected = file('{"synthetic-private-marker":');
      if (which === 'duplicate-key') selected = file(vectors[0].raw.replace('{', '{"kind":"delete",'));
      if (which === 'lone-surrogate') selected = file(JSON.stringify({ ...doc, metadata: { ...doc.metadata, release_notes: '\ud800' } }));
      if (which === 'different-document') selected = file(vectors[3].raw);
      if (which === 'unknown-field') selected = file(JSON.stringify({ ...doc, authority: 'synthetic-private-marker' }));
      const failure = await value.verifySelectedFile(selected).catch(error => error);
      expect(failure).toBeInstanceOf(ReleaseIntentFileError);
      expect(String(failure)).not.toMatch(/synthetic-private-marker|synthetic-sensitive-name/);
      expect(failure).not.toHaveProperty('cause'); expect(value.getState()).toMatchObject({ fileVerified: false });
    });
  it.each(['verify-user', 'verify-org', 'verify-cycle', 'import-user'])(
    'refuses a file completion after %s context change and never revives the old session', async which => {
      const value = session(); const reader = vi.spyOn(FileReader.prototype, 'readAsArrayBuffer');
      const pending = which === 'import-user' ? importReleaseIntentFile(file()) : value.verifySelectedFile(file());
      const refused = expect(pending).rejects.toThrow(ReleaseIntentFileError);
      expect(reader).toHaveBeenCalledTimes(1);
      useAuthStore.setState({ user: which === 'verify-org' ? { ...user(), organization_id: doc.release_id } : { ...user(), id: doc.release_id } });
      if (which === 'verify-cycle') useAuthStore.setState({ user: user() });
      await refused; expect(value.getState()).toEqual({ closed: true });
    });
  it('bounds a stalled document reader without sending a release request', async () => {
    vi.useFakeTimers(); vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(() => undefined);
    const value = session(); const pending = value.verifySelectedFile(file());
    const refused = expect(pending).rejects.toThrow(ReleaseIntentFileError);
    await vi.advanceTimersByTimeAsync(10001); await refused;
    expect(value.getState()).toMatchObject({ busy: false, fileVerified: false });
  });
  it.each(['before', 'during'])('refuses file verification cancelled %s reading', async when => {
    const value = session(); const controller = new AbortController(); if (when === 'before') controller.abort();
    const pending = value.verifySelectedFile(file(), controller.signal); const refused = expect(pending).rejects.toThrow(ReleaseIntentFileError);
    controller.abort(); await refused; expect(value.getState()).toMatchObject({ fileVerified: false, busy: false });
  });
  it('invalidates an earlier verification when a newly selected file does not match', async () => {
    const value = session(); await value.verifySelectedFile(file()); expect(value.getState()).toMatchObject({ fileVerified: true });
    await expect(value.verifySelectedFile(file(vectors[3].raw))).rejects.toThrow();
    expect(value.getState()).toMatchObject({ fileVerified: false });
  });
  it('requires matching readback, exact server review and typed operation confirmation before mutation', async () => {
    const value = session(); await value.verifySelectedFile(file());
    expect(() => value.captureMutation('reserve', doc.operation_id)).toThrow();
    await value.captureReview().execute(); expect(() => value.captureMutation('reserve', actor)).toThrow();
    expect(await value.captureMutation('reserve', doc.operation_id).execute()).toEqual(reserved());
  });
  it('requires retained history after an uncertain mutation and never uses absence to clear that requirement', async () => {
    const value = session(); await value.verifySelectedFile(file()); await value.captureReview().execute();
    let attempted = 0;
    api.defaults.adapter = async config => {
      if (config.url?.includes('intents/review')) return response(config, review(false));
      if (config.method === 'get') return response(config, status());
      attempted += 1;
      throw new AxiosError('synthetic-private-error', 'ERR_BAD_REQUEST', config, undefined, { ...response(config, {}), status: 503 });
    };
    await expect(value.captureMutation('reserve', doc.operation_id).execute()).rejects.toMatchObject({ outcome: 'unconfirmed' });
    expect(() => value.captureMutation('reserve', doc.operation_id)).toThrow();
    await value.captureReview().execute(); expect(value.getState()).toMatchObject({ inspectionRequired: true, journalObserved: false });
    expect(() => value.captureMutation('reserve', doc.operation_id)).toThrow();
    await value.captureInspection().execute(); expect(value.getState()).toMatchObject({ inspectionRequired: false, journalObserved: true });
    const explicit = value.captureMutation('reserve', doc.operation_id); explicit.dispose();
    expect(attempted).toBe(1);
  });
  it('does not substitute a status-only observation for full intent review', async () => {
    const value = session(); await value.verifySelectedFile(file()); await value.captureInspection().execute();
    expect(value.getState()).toMatchObject({ reviewed: false, journalObserved: true });
    expect(() => value.captureMutation('reserve', doc.operation_id)).toThrow();
  });
  it('revokes retained download URLs and conceals metadata when the account context closes', () => {
    const value = session(); const observed = vi.fn(); value.subscribe(observed); value.download();
    useAuthStore.setState({ isAuthenticated: false, user: null });
    expect(value.getState()).toEqual({ closed: true }); expect(revoked).toHaveBeenCalledWith('blob:owned-intent-test');
    expect(observed).toHaveBeenCalled(); expect(() => value.download()).toThrow();
  });
});
