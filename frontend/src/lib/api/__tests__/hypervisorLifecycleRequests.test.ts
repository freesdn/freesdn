// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { hypervisorApi } from '../hypervisor';
import { api } from '../client';

vi.mock('../client', () => ({ api: { post: vi.fn().mockResolvedValue({ data: {} }) } }));
beforeEach(() => vi.clearAllMocks());

describe('durable clone and migration requests', () => {
  it('reuses a clone intent across response loss, retaining its options', async () => {
    const body = { request_id: crypto.randomUUID(), newid: 202, name: 'copied', full: false };
    vi.mocked(api.post).mockRejectedValueOnce(new Error('Response lost'));
    await expect(hypervisorApi.cloneVM('controller', 'pve1', 'qemu', 101, body)).rejects.toThrow('Response lost');
    await hypervisorApi.cloneVM('controller', 'pve1', 'qemu', 101, body);
    const calls = vi.mocked(api.post).mock.calls;
    expect(calls[0][1]).toEqual({ ...body, force: true });
    expect(calls[1][1]).toEqual(calls[0][1]);
  });

  it('retains explicit container restart consent and its request ID on replay', async () => {
    const body = { request_id: crypto.randomUUID(), target: 'pve2', online: false, restart: true };
    await hypervisorApi.migrateVM('controller', 'pve1', 'lxc', 101, body);
    await hypervisorApi.migrateVM('controller', 'pve1', 'lxc', 101, body);
    expect(vi.mocked(api.post).mock.calls.map((call) => call[1])).toEqual([
      { ...body, force: true }, { ...body, force: true },
    ]);
  });

  it('does not silently consent to downtime or enable live container migration', async () => {
    await hypervisorApi.migrateVM('controller', 'pve1', 'lxc', 101, { target: 'pve2' });
    const body = vi.mocked(api.post).mock.calls[0][1];
    expect(body).not.toHaveProperty('restart');
    expect(body).not.toHaveProperty('online');
    expect(body).toHaveProperty('request_id', expect.any(String));
  });

  it('preserves all per-target IDs while replaying a partially returned mixed batch', async () => {
    const targets = ['qemu', 'lxc'].map((vm_type, index) => ({ node: 'pve1', vm_type, vmid: 101 + index, request_id: crypto.randomUUID() }));
    const body = { targets, target_node: 'pve2', online: true, restart: false };
    await hypervisorApi.bulkMigrate('controller', body);
    await hypervisorApi.bulkMigrate('controller', body);
    expect(vi.mocked(api.post).mock.calls.map((call) => call[1])).toEqual([
      { ...body, force: true }, { ...body, force: true },
    ]);
    expect(body).not.toHaveProperty('force');
  });
});
