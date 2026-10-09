// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { hypervisorApi } from '../hypervisor';
import { api } from '../client';

vi.mock('../client', () => ({ api: { post: vi.fn().mockResolvedValue({ data: {} }) } }));

beforeEach(() => vi.clearAllMocks());

describe('durable hypervisor power requests', () => {
  it('keeps a caller-provided intent ID unchanged across retries', async () => {
    const key = crypto.randomUUID();
    await hypervisorApi.vmAction('controller', 'pve1', 'qemu', 101, 'reboot', key);
    await hypervisorApi.vmAction('controller', 'pve1', 'qemu', 101, 'reboot', key);
    const calls = vi.mocked(api.post).mock.calls;
    expect(calls[0][1]).toEqual({ action: 'reboot', request_id: key, force: true });
    expect(calls[1][1]).toEqual(calls[0][1]);
  });

  it('gives independent operator actions different IDs', async () => {
    await hypervisorApi.vmAction('controller', 'pve1', 'qemu', 101, 'start');
    await hypervisorApi.vmAction('controller', 'pve1', 'qemu', 101, 'start');
    const calls = vi.mocked(api.post).mock.calls;
    expect(calls[0][1]).not.toEqual(calls[1][1]);
    expect(calls[0][1]).toHaveProperty('request_id', expect.any(String));
  });

  it('preserves per-target IDs when resuming a partial bulk request', async () => {
    const targets = [101, 102].map((vmid) => ({ node: 'pve1', vm_type: 'qemu', vmid, request_id: crypto.randomUUID() }));
    await hypervisorApi.bulkAction('controller', { targets, action: 'shutdown' });
    expect(vi.mocked(api.post).mock.calls[0][1]).toEqual({ targets, action: 'shutdown', force: true });
  });

  it('sends the explicit apply gate without inventing deletion review IDs', async () => {
    const body = { targets: [{ node: 'pve1', vm_type: 'qemu', vmid: 101, request_id: 'reviewed-request', expected_digest: 'a'.repeat(40) }], action: 'delete' };
    await hypervisorApi.bulkAction('controller', body);
    expect(api.post).toHaveBeenCalledWith('/hypervisor/controllers/controller/bulk-action', { ...body, force: true }, { params: { confirmed: true } });
    expect(body).not.toHaveProperty('force');
  });

  it('can generate intent IDs without the secure-context randomUUID API', async () => {
    const unavailable = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('Unavailable on LAN HTTP'); });
    try {
      await hypervisorApi.vmAction('controller', 'pve1', 'qemu', 101, 'start');
      expect(vi.mocked(api.post).mock.calls[0][1]).toHaveProperty('request_id', expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/));
      expect(unavailable).not.toHaveBeenCalled();
    } finally {
      unavailable.mockRestore();
    }
  });
});
