// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Planned actual Axios/Zustand/WebCrypto cases; adapters replace HTTP only. */
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { captureReleaseRequest, type ReleaseRequestSelection } from '../releaseOperationClient';
import vectors from './releaseCommitmentVectors.json';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const doc = JSON.parse(vectors[0].raw);
const captured: ReturnType<typeof captureReleaseRequest>[] = [];
let previousAdapter: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: organization, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function capture(selection: ReleaseRequestSelection = { kind: 'command', rawIntent: vectors[0].raw, action: 'reserve' }) {
  const value = captureReleaseRequest(selection); captured.push(value); return value;
}
function body(prepared = false) {
  return { operation_id: doc.operation_id, release_id: doc.release_id, intent_sha256: vectors[0].intent_sha256,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true,
    result: { operation_id: doc.operation_id, release_id: doc.release_id, requested_by: actor, last_transition_by: actor,
      ...(prepared ? { phase: 'prepared', publication_or_storage_authorized: false }
        : { phase: 'reserved', decision: null, created: true }) } };
}
function wire(config: InternalAxiosRequestConfig, value: unknown = body()): AxiosResponse {
  return { config, data: JSON.stringify(value), headers: {}, status: 200, statusText: 'OK' };
}
function status() {
  return { storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
    absence_authorizes_retry_or_cleanup: false, release_row_present: false, observed_at: '2026-01-01T00:00:01Z',
    operation: { operation_id: doc.operation_id, release_id: doc.release_id, organization_id: organization, requested_by: actor,
      last_transition_by: actor, kind: 'publish', storage_kind: 'owned', phase: 'reserved', decision: null, transition_sequence: 0,
      created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null } };
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  previousAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
});
afterEach(() => {
  captured.splice(0).forEach(action => action.dispose());
  api.defaults.adapter = previousAdapter;
  vi.restoreAllMocks(); vi.unstubAllGlobals();
});

describe('fully captured deliberate release request', () => {
  it('captures raw document and command before queueing, without issuing a request or rewriting metadata', async () => {
    const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
    const input: ReleaseRequestSelection = { kind: 'command', rawIntent: vectors[0].raw, action: 'reserve' };
    const action = capture(input);
    input.rawIntent = vectors[3].raw; input.action = 'publish';
    expect(adapter).not.toHaveBeenCalled();
    expect(action.snapshot.originalIntent).toBe(vectors[0].raw);
    expect(Object.isFrozen(action.snapshot.document?.metadata)).toBe(true);
    const result = await action.execute();
    expect(result).toEqual(body());
    expect(adapter).toHaveBeenCalledTimes(1);
    expect(adapter.mock.calls[0][0].data).toBe(vectors[0].raw);
    expect(adapter.mock.calls[0][0].url).toMatch(/\/reserve$/);
    await expect(action.execute()).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it('captures immutable binary contents without reading the full file or following later selection changes', async () => {
    const adapter = vi.fn(async config => wire(config, body(true))); api.defaults.adapter = adapter;
    const file = new Blob(['abc']); const read = vi.spyOn(file, 'arrayBuffer');
    const input: ReleaseRequestSelection = { kind: 'upload', rawIntent: vectors[0].raw, file };
    const action = capture(input); input.file = new Blob(['xyz']); input.rawIntent = vectors[3].raw;
    const result = await action.execute(); expect(result).toEqual(body(true));
    expect(read).not.toHaveBeenCalled();
    const form = adapter.mock.calls[0][0].data as FormData;
    expect([...form.keys()]).toEqual(['intent', 'file']); expect(form.get('intent')).toBe(vectors[0].raw);
    // Read only the three-byte test part independently; never a production-sized buffer.
    const bytes = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject;
      reader.readAsText(form.get('file') as Blob);
    });
    expect(bytes).toBe('abc');
  });
  it.each(['malformed', 'kind-action', 'size', 'external-upload'])(
    'refuses invalid captured selection %s before any queue or HTTP request', which => {
      const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
      const selection: ReleaseRequestSelection = which === 'size' || which === 'external-upload'
        ? { kind: 'upload', rawIntent: vectors[which === 'size' ? 0 : 3].raw, file: new Blob(['wrong']) }
        : { kind: 'command', rawIntent: which === 'malformed' ? '{' : vectors[5].raw, action: 'publish' };
      expect(() => capture(selection)).toThrow(); expect(adapter).not.toHaveBeenCalled();
      // Refusals must dispose their context subscription/admission slot.
      for (let i = 0; i < 8; i += 1) capture();
    });
  it.each(['actor-before-hash', 'actor-during-hash', 'cancel-during-hash', 'crypto-unavailable'])(
    'does not issue captured work after %s', async which => {
      const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
      const action = capture(); const controller = new AbortController();
      const original = crypto.subtle.digest.bind(crypto.subtle);
      let finish: () => void = () => undefined;
      const waiting = vi.fn();
      if (which === 'actor-before-hash') useAuthStore.setState({ user: { ...user(), id: doc.release_id } });
      else vi.spyOn(crypto.subtle, 'digest').mockImplementation(async (algorithm, data) => {
        if (which === 'crypto-unavailable') throw new Error('synthetic-secret-context');
        await new Promise<void>(resolve => { finish = resolve; waiting(); });
        return original(algorithm, data);
      });
      const pending = action.execute(controller.signal);
      const refused = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
      if (which === 'actor-during-hash' || which === 'cancel-during-hash') {
        await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(1));
        if (which === 'actor-during-hash') useAuthStore.setState({ user: { ...user(), organization_id: doc.release_id } });
        else controller.abort();
        // Let both actual SHA operations finish; the caller rechecks before HTTP.
        finish(); await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(2)); finish();
      }
      await refused; expect(adapter).not.toHaveBeenCalled();
    });
  it('reports unconfirmed after context changes during response commitment verification', async () => {
    const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
    const original = crypto.subtle.digest.bind(crypto.subtle);
    let count = 0; let finish: () => void = () => undefined; const waiting = vi.fn();
    vi.spyOn(crypto.subtle, 'digest').mockImplementation(async (algorithm, data) => {
      count += 1;
      if (count === 3) await new Promise<void>(resolve => { finish = resolve; waiting(); });
      return original(algorithm, data);
    });
    const action = capture(); const pending = action.execute();
    const refused = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(waiting).toHaveBeenCalledOnce());
    useAuthStore.setState({ user: { ...user(), id: doc.release_id } }); finish();
    await refused; expect(adapter).toHaveBeenCalledTimes(1);
  });
  it.each(['wrong-digest', 'missing-safety', 'duplicate-wire', 'malformed-wire', 'object-instead-of-wire'])(
    'retains an uncertain outcome after HTTP success with %s; never replays and permits bound inspection', async which => {
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
        if (config.method === 'get') return wire(config, status());
        const value = JSON.parse(JSON.stringify(body()));
        if (which === 'wrong-digest') value.intent_sha256 = 'f'.repeat(64);
        if (which === 'missing-safety') delete value.authorization_granted;
        const response = wire(config, value);
        if (which === 'duplicate-wire') response.data = response.data.replace('{', '{"authorization_granted":true,');
        if (which === 'malformed-wire') response.data = '{"synthetic-sensitive-marker":';
        if (which === 'object-instead-of-wire') response.data = value;
        return response;
      }); api.defaults.adapter = adapter;
      const refresh = vi.spyOn(axios, 'post'); const action = capture();
      const error = await action.execute().catch(value => value);
      expect(error).toMatchObject({ outcome: 'unconfirmed' }); expect(error).not.toHaveProperty('cause');
      expect(String(error)).not.toContain('synthetic-sensitive-marker');
      await expect(action.execute()).rejects.toMatchObject({ outcome: 'not-issued' });
      expect(adapter).toHaveBeenCalledTimes(1); expect(refresh).not.toHaveBeenCalled();
      expect(await action.inspect()).toEqual(status()); expect(adapter).toHaveBeenCalledTimes(2);
    });
  it.each([401, 409, 503])('never retries HTTP %s and never labels the response as rollback', async statusCode => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError('private-body', 'ERR_BAD_REQUEST', config, undefined, { ...wire(config), status: statusCode });
    }); api.defaults.adapter = adapter;
    const refresh = vi.spyOn(axios, 'post'); const action = capture();
    await expect(action.execute()).rejects.toMatchObject({ outcome: 'unconfirmed', status: statusCode });
    expect(adapter).toHaveBeenCalledTimes(1); expect(refresh).not.toHaveBeenCalled();
  });
});

describe('captured read-only review choices', () => {
  it.each(['review', 'inspect', 'deletion-review'] as const)(
    'validates %s without reserving, mutating or granting future authority', async kind => {
      const vector = vectors[kind === 'deletion-review' ? 5 : 0];
      const value = kind === 'inspect' ? status() : { ...status(), operation: null, intent: JSON.parse(vector.raw),
        intent_sha256: vector.intent_sha256, deletion_target_matches: kind === 'deletion-review' ? true : null,
        historical_observation: true, reservation_created: false, server_retains_full_intent: false,
        save_original_intent_before_mutation: true, retry_requires_identical_intent_and_current_authority: true };
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => wire(config, value)); api.defaults.adapter = adapter;
      const selection: ReleaseRequestSelection = kind === 'review' ? { kind, rawIntent: vector.raw }
        : kind === 'inspect' ? { kind, operationId: doc.operation_id }
          : { kind, operationId: doc.operation_id, releaseId: doc.release_id };
      const action = capture(selection);
      if (selection.kind !== 'review') selection.operationId = actor;
      if (selection.kind === 'deletion-review') selection.releaseId = actor;
      expect(await action.execute()).toEqual(value);
      expect(adapter).toHaveBeenCalledTimes(1);
      expect(adapter.mock.calls[0][0].method).toBe(kind === 'review' ? 'post' : 'get');
      if (kind !== 'review') expect(adapter.mock.calls[0][0].url).toContain(doc.operation_id);
      expect(value.authorization_granted).toBe(false);
    });
});
