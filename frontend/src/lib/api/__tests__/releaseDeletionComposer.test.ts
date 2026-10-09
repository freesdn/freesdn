// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Planned real Axios/Zustand/WebCrypto contracts; HTTP alone is adapted. */
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { captureReleaseDeletion } from '../releaseDeletionComposer';
import vectors from './releaseCommitmentVectors.json';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const doc = JSON.parse(vectors[5].raw);
const captured: ReturnType<typeof captureReleaseDeletion>[] = [];
let previousAdapter: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: organization, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function capture(releaseId = doc.release_id) {
  const value = captureReleaseDeletion(releaseId); captured.push(value); return value;
}
function review(index = 5) {
  return { intent: JSON.parse(vectors[index].raw), intent_sha256: vectors[index].intent_sha256,
    operation: null, storage_checked: false, all_artifact_references_checked: false, authorization_granted: false,
    absence_authorizes_retry_or_cleanup: false, release_row_present: true, observed_at: '2026-01-01T00:00:01Z',
    deletion_target_matches: true, historical_observation: true, reservation_created: false,
    server_retains_full_intent: false, save_original_intent_before_mutation: true,
    retry_requires_identical_intent_and_current_authority: true };
}
function wire(config: InternalAxiosRequestConfig, value: unknown = review()): AxiosResponse {
  return { config, data: JSON.stringify(value), headers: {}, status: 200, statusText: 'OK' };
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  vi.spyOn(crypto, 'randomUUID').mockReturnValue(doc.operation_id);
  previousAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
});
afterEach(() => {
  captured.splice(0).forEach(action => action.dispose());
  api.defaults.adapter = previousAdapter;
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers();
});

describe('captured deletion-intent preparation', () => {
  it.each([5, 6, 7])('retains exact validated server metadata from vector %s without mutation', async index => {
    const adapter = vi.fn(async config => wire(config, review(index))); api.defaults.adapter = adapter;
    const action = capture();
    expect(adapter).not.toHaveBeenCalled();
    expect(() => action.getIntent()).toThrow();
    expect(Object.isFrozen(action.snapshot)).toBe(true);
    await action.execute();
    expect(JSON.parse(action.getIntent())).toEqual(JSON.parse(vectors[index].raw));
    expect(adapter).toHaveBeenCalledTimes(1);
    const request = adapter.mock.calls[0][0];
    expect(request.method).toBe('get');
    expect(request.url).toBe(`/agents/releases/${doc.release_id}/deletion-intent/${doc.operation_id}`);
    expect(request.data).toBeUndefined();
    await expect(action.execute()).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it.each(['bad-identity', 'zero', 'no-permission', 'logged-out'])(
    'refuses invalid initiation %s without HTTP or leaking admission', which => {
      const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
      if (which === 'no-permission') useAuthStore.setState({ hasPermission: () => false });
      if (which === 'logged-out') useAuthStore.setState({ isAuthenticated: false });
      expect(() => capture(which === 'bad-identity' ? '../../other' : which === 'zero'
        ? '00000000-0000-0000-0000-000000000000' : doc.release_id)).toThrow();
      expect(adapter).not.toHaveBeenCalled();
      useAuthStore.setState({ isAuthenticated: true, hasPermission: () => true });
      for (let n = 0; n < 8; n += 1) capture();
    });
  it.each(['not-matched', 'missing-row', 'wrong-commitment', 'wrong-release', 'wrong-kind', 'malformed'])(
    'does not expose an actionable intent after %s', async which => {
      const value = review();
      if (which === 'not-matched') value.deletion_target_matches = false;
      if (which === 'missing-row') value.release_row_present = false;
      if (which === 'wrong-commitment') value.intent_sha256 = 'f'.repeat(64);
      if (which === 'wrong-release') value.intent.release_id = actor;
      if (which === 'wrong-kind') value.intent = JSON.parse(vectors[0].raw);
      const adapter = vi.fn(async config => which === 'malformed'
        ? { ...wire(config), data: '{' } : wire(config, value)); api.defaults.adapter = adapter;
      const action = capture();
      await expect(action.execute()).rejects.toMatchObject({ outcome: 'unconfirmed' });
      expect(() => action.getIntent()).toThrow();
      await expect(action.execute()).rejects.toMatchObject({ outcome: 'not-issued' });
      expect(adapter).toHaveBeenCalledTimes(1);
      for (let n = 0; n < 8; n += 1) capture();
    });
  it.each(['account', 'cancel'])(
    'never reveals a late server response after %s', async which => {
      let finish: () => void = () => undefined;
      const adapter = vi.fn(async config => {
        await new Promise<void>(resolve => { finish = resolve; }); return wire(config);
      }); api.defaults.adapter = adapter;
      const controller = new AbortController(); const action = capture();
      const pending = action.execute(controller.signal);
      const refused = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
      await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
      if (which === 'account') {
        useAuthStore.setState({ user: { ...user(), id: doc.release_id } });
        useAuthStore.setState({ user: user() });
      } else controller.abort();
      finish(); await refused;
      expect(() => action.getIntent()).toThrow(); expect(adapter).toHaveBeenCalledTimes(1);
    });
  it('refuses delayed use and clears its retained view on disposal', async () => {
    const adapter = vi.fn(async config => wire(config)); api.defaults.adapter = adapter;
    const action = capture(); await action.execute(); expect(action.getIntent()).toBeTruthy();
    action.dispose(); action.dispose();
    expect(() => action.getIntent()).toThrow();
    await expect(action.execute()).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).toHaveBeenCalledTimes(1);
    for (let n = 0; n < 8; n += 1) capture();
  });
  it.each([401, 503])('does not refresh or retry HTTP %s', async status => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError('owned-private-response', 'ERR_BAD_RESPONSE', config, undefined, { ...wire(config), status });
    }); api.defaults.adapter = adapter;
    const refresh = vi.spyOn(axios, 'post'); const action = capture();
    await expect(action.execute()).rejects.toMatchObject({ outcome: 'unconfirmed', status });
    expect(() => action.getIntent()).toThrow();
    expect(adapter).toHaveBeenCalledTimes(1); expect(refresh).not.toHaveBeenCalled();
  });
});
