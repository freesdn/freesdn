// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { captureReleasePublication, type ReleasePublicationDraft } from '../releasePublicationComposer';
import { decodeReleaseIntent } from '../releaseOperationCodec';
import { hashReleasePayload } from '../releasePayloadHash';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
// Builder lifetime tests use a controlled hash await. Actual hash correctness
// is separate; neither suite constitutes browser/server upload acceptance.
vi.mock('../releasePayloadHash', async original => {
  const actual = await original<typeof import('../releasePayloadHash')>();
  return { ...actual, hashReleasePayload: vi.fn() };
});
const organization = '22222222-2222-4222-8222-222222222222';
function user(): User { return { id: '11111111-1111-4111-8111-111111111111', organization_id: organization,
  role: 'admin', is_active: true, is_superuser: false, is_org_admin: true, mfa_enabled: false,
  permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid', username: 'owned',
  first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' }; }
function input(): ReleasePublicationDraft { return { organization_id: organization, storage_kind: 'owned',
  file: new File(['abc'], 'agent.bin'), version: '1.2.3+test', platform: 'linux', agent_type: 'daemon',
  release_notes: 'Original 🎉 note', min_backend_version: '', is_prerelease: false, is_latest: true }; }
function external(): ReleasePublicationDraft { const owned = input(); const { file: _file, ...fields } = owned as Extract<ReleasePublicationDraft, { storage_kind: 'owned' }>;
  return { ...fields, storage_kind: 'external', download_url: 'https://updates.example.invalid/binary', checksum_sha256: 'b'.repeat(64), file_size: 10737418240 }; }
const scopes: ReturnType<typeof captureReleasePublication>[] = [];
function capture(value = input()) { const result = captureReleasePublication(value); scopes.push(result); return result; }
let previousAdapter: typeof api.defaults.adapter;
let requests = vi.fn();
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); requests = vi.fn(); previousAdapter = api.defaults.adapter;
  api.defaults.adapter = async () => { requests(); throw new Error('No HTTP belongs in composition'); };
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  vi.mocked(hashReleasePayload).mockReset().mockResolvedValue('a'.repeat(64));
});
afterEach(() => { scopes.splice(0).forEach(s => s.dispose()); api.defaults.adapter = previousAdapter; vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
describe('captured new publication intent', () => {
  it('binds original metadata and file snapshot before hashing and issues no HTTP', async () => {
    const form = input(); const value = capture(form);
    expect(() => value.getIntent()).toThrow(); expect(hashReleasePayload).not.toHaveBeenCalled();
    form.version = '9.9.9'; form.release_notes = 'changed';
    if (form.storage_kind === 'owned') form.file = new File(['different'], 'replacement.bin');
    await value.execute(); const document = decodeReleaseIntent(value.getIntent());
    expect(document.metadata).toMatchObject({ version: '1.2.3+test', filename: 'agent.bin', file_size: 3,
      checksum_sha256: 'a'.repeat(64), release_notes: 'Original 🎉 note', is_latest: true });
    expect(document.metadata.download_url).toBe(`/api/v1/agents/releases/${document.release_id}/binary`);
    expect(document.operation_id).not.toBe(document.release_id); expect(value.getPayload()?.size).toBe(3);
    await expect(value.execute()).rejects.toThrow(); expect(hashReleasePayload).toHaveBeenCalledOnce(); expect(requests).not.toHaveBeenCalled();
  });
  it('preserves external metadata without fetching, hashing or implying remote-byte verification', async () => {
    const form = external(); const value = capture(form); await value.execute();
    expect(decodeReleaseIntent(value.getIntent()).metadata).toMatchObject({ filename: null, file_size: 10737418240, checksum_sha256: 'b'.repeat(64) });
    expect(value.getPayload()).toBeUndefined(); expect(hashReleasePayload).not.toHaveBeenCalled(); expect(requests).not.toHaveBeenCalled();
  });
  it('preserves full 20000 Unicode code-point notes', async () => {
    const form = input(); form.release_notes = '🎉'.repeat(20000); const value = capture(form); await value.execute();
    expect(decodeReleaseIntent(value.getIntent()).metadata.release_notes).toBe(form.release_notes);
  });
  it.each(['bad-org', 'bad-version', 'too-many-notes', 'surrogate', 'nul', 'bad-platform', 'bad-kind', 'bad-filename', 'oversize', 'bad-checksum', 'bad-url'])(
    'refuses %s form input before a hash worker is requested', which => {
      let form: unknown = input(); const record = form as Record<string, unknown>;
      if (which === 'bad-org') record.organization_id = 'not-an-id';
      if (which === 'bad-version') record.version = '../unsafe';
      if (which === 'too-many-notes') record.release_notes = 'a'.repeat(20001);
      if (which === 'surrogate') record.release_notes = '\ud800';
      if (which === 'nul') record.release_notes = '\0';
      if (which === 'bad-platform') record.platform = 'other';
      if (which === 'bad-kind') record.storage_kind = 'legacy';
      if (which === 'bad-filename') record.file = new File(['a'], '../unsafe.bin');
      if (which === 'oversize') { const file = new File(['a'], 'large.bin'); Object.defineProperty(file, 'size', { value: 524288001 }); record.file = file; }
      if (which === 'bad-checksum') form = { ...external(), checksum_sha256: 'f'.repeat(63) };
      if (which === 'bad-url') form = { ...external(), download_url: 'http://updates.example.invalid/binary' };
      expect(() => captureReleasePublication(form as ReleasePublicationDraft)).toThrow(); expect(hashReleasePayload).not.toHaveBeenCalled(); expect(requests).not.toHaveBeenCalled();
    });
  it.each(['user', 'organization', 'ABA', 'permission'])(
    'permanently closes a queued composition after %s change', async which => {
      const value = capture(); const original = user();
      if (which === 'permission') useAuthStore.setState({ hasPermission: () => false });
      else useAuthStore.setState({ user: { ...original, ...(which === 'organization'
        ? { organization_id: '33333333-3333-4333-8333-333333333333' }
        : { id: '44444444-4444-4444-8444-444444444444' }) } });
      if (which === 'ABA') useAuthStore.setState({ user: original });
      await expect(value.execute()).rejects.toThrow(); expect(() => value.getIntent()).toThrow(); expect(hashReleasePayload).not.toHaveBeenCalled();
    });
  it('aborts an in-flight hash on account change and refuses late completion', async () => {
    let resolve!: (hash: string) => void; let signal: AbortSignal | undefined;
    vi.mocked(hashReleasePayload).mockImplementation((_blob, options) => { signal = options.signal; return new Promise(r => { resolve = r; }); });
    const value = capture(); const pending = value.execute(); void pending.catch(() => undefined);
    useAuthStore.setState({ user: { ...user(), is_active: false } }); expect(signal?.aborted).toBe(true);
    resolve('a'.repeat(64)); await expect(pending).rejects.toThrow(); expect(() => value.getIntent()).toThrow(); expect(requests).not.toHaveBeenCalled();
  });
  it('does not expose a placeholder or partial intent after hash failure', async () => {
    vi.mocked(hashReleasePayload).mockRejectedValue(new Error('synthetic private pathname'));
    const value = capture(); await expect(value.execute()).rejects.toMatchObject({ message: expect.not.stringContaining('private') });
    expect(() => value.getIntent()).toThrow(); expect(() => value.getPayload()).toThrow(); expect(requests).not.toHaveBeenCalled();
  });
  it('closes and clears access after disposal even when hashing already completed', async () => {
    const value = capture(); await value.execute(); value.dispose(); expect(() => value.getIntent()).toThrow(); expect(() => value.getPayload()).toThrow();
  });
  it('refuses an expired captured form without launching a worker', async () => {
    vi.useFakeTimers(); const value = capture(); await vi.advanceTimersByTimeAsync(600000);
    await expect(value.execute()).rejects.toThrow(); expect(hashReleasePayload).not.toHaveBeenCalled();
  });
  it('propagates deliberate cancellation to the owned hash and hides late output', async () => {
    let resolve!: (hash: string) => void; let signal: AbortSignal | undefined;
    vi.mocked(hashReleasePayload).mockImplementation((_blob, options) => { signal = options.signal; return new Promise(r => { resolve = r; }); });
    const value = capture(); const controller = new AbortController(); const pending = value.execute(controller.signal); void pending.catch(() => undefined);
    controller.abort(); expect(signal?.aborted).toBe(true); resolve('a'.repeat(64));
    await expect(pending).rejects.toThrow(); expect(() => value.getIntent()).toThrow(); expect(requests).not.toHaveBeenCalled();
  });
});
