// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { backupGuestType, hypervisorApi } from '../hypervisor';
import { api } from '../client';

vi.mock('../client', () => ({ api: { post: vi.fn().mockResolvedValue({ data: {} }), delete: vi.fn().mockResolvedValue({ data: {} }) } }));
beforeEach(() => vi.clearAllMocks());

describe('recovery intent transport', () => {
  it('replays a manual backup with the same ID and exact backup settings', async () => {
    const body = { request_id: crypto.randomUUID(), storage: 'pbs', mode: 'snapshot', compress: 'zstd' };
    vi.mocked(api.post).mockRejectedValueOnce(new Error('Response lost'));
    await expect(hypervisorApi.runBackup('controller', 'pve1', 'lxc', 101, body)).rejects.toThrow('Response lost');
    await hypervisorApi.runBackup('controller', 'pve1', 'lxc', 101, body);
    expect(vi.mocked(api.post).mock.calls.map((c) => c[1])).toEqual([{ ...body, force: true }, { ...body, force: true }]);
  });

  it('keeps snapshot create options bound to one intent', async () => {
    const body = { request_id: crypto.randomUUID(), snapname: 'safe', vmstate: true };
    await hypervisorApi.createSnapshot('controller', 'pve1', 'qemu', 101, body);
    await hypervisorApi.createSnapshot('controller', 'pve1', 'qemu', 101, body);
    expect(vi.mocked(api.post).mock.calls.map((c) => c[1])).toEqual([{ ...body, force: true }, { ...body, force: true }]);
  });

  it('preserves rollback confirmation as a separate gate from force and intent', async () => {
    const key = crypto.randomUUID();
    await hypervisorApi.rollbackSnapshot('controller', 'pve1', 'qemu', 101, 'safe', key);
    expect(api.post).toHaveBeenCalledWith(expect.stringContaining('/snapshots/safe/rollback'), { request_id: key, force: true }, { params: { confirmed: true } });
  });

  it('sends deletion intent and explicit confirmation without relying on a DELETE body', async () => {
    const key = crypto.randomUUID();
    await hypervisorApi.deleteSnapshot('controller', 'pve1', 'lxc', 101, 'safe', key);
    expect(api.delete).toHaveBeenCalledWith(expect.stringContaining('/snapshots/safe'), { params: { request_id: key, force: true, confirmed: true } });
  });

  it('reuses restore staging IDs without authorizing apply or adding private flags to the payload', async () => {
    const key = crypto.randomUUID();
    const payload = { node: 'pve1', vm_type: 'lxc' as const, archive: 'pbs:backup/ct/101/2026-09-16T03:04:05Z', vmid: 202, start: false, unique: true };
    await hypervisorApi.stageBackupRestore('controller', payload, key);
    await hypervisorApi.stageBackupRestore('controller', payload, key);
    const expected = { request_id: key, payload, target_id: '202' };
    expect(vi.mocked(api.post).mock.calls.map((c) => c[1])).toEqual([expected, expected]);
    expect(payload).not.toHaveProperty('request_id');
    expect(expected).not.toHaveProperty('force');
    expect(expected).not.toHaveProperty('confirmed');
  });

  it.each([
    ['pbs:backup/ct/101/2026-09-16T03:04:05Z', 'pbs-ct', 'lxc'],
    ['pbs:backup/ct/101/2026-09-16T03:04:05Z', undefined, 'lxc'],
    ['pbs:backup/vm/101/2026-09-16T03:04:05Z', 'pbs-vm', 'qemu'],
    ['local:backup/vzdump-lxc-101.tar.zst', undefined, 'lxc'],
    ['local:backup/vzdump-qemu-101.vma.zst', undefined, 'qemu'],
  ])('identifies guest type for %s', (archive, format, expected) => {
    expect(backupGuestType(archive, format)).toBe(expected);
  });
});
