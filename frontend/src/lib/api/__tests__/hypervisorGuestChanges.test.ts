// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../client';
import { hypervisorApi, reviewedDiskBytes, reviewedGuestDigest } from '../hypervisor';

vi.mock('../client', () => ({ api: { put: vi.fn(), post: vi.fn() } }));
beforeEach(() => vi.clearAllMocks());

describe('reviewed guest requests', () => {
  it('keeps resize review and intent unchanged after a lost response', async () => {
    const body = { request_id: crypto.randomUUID(), expected_digest: 'a'.repeat(40), disk: 'rootfs', size: '+10G', current_size_bytes: 32 * 1024 ** 3 };
    vi.mocked(api.put).mockRejectedValueOnce(new Error('Response lost')).mockResolvedValueOnce({ data: {} });
    await expect(hypervisorApi.resizeDisk('controller', 'pve1', 'lxc', 101, body)).rejects.toThrow('Response lost');
    await hypervisorApi.resizeDisk('controller', 'pve1', 'lxc', 101, body);
    expect(vi.mocked(api.put).mock.calls[1]).toEqual(vi.mocked(api.put).mock.calls[0]);
    expect(vi.mocked(api.put).mock.calls[0][1]).toEqual({ ...body, force: true });
    expect(body).not.toHaveProperty('force');
  });

  it('does not equate force with destructive template consent', async () => {
    const body = { request_id: crypto.randomUUID(), expected_digest: 'a'.repeat(40), confirmed: false };
    await hypervisorApi.convertToTemplate('controller', 'pve1', 'qemu', 101, body);
    expect(vi.mocked(api.post).mock.calls[0][1]).toEqual({ ...body, force: true, confirmed: false });
  });

  it.each([
    ['local:disk,size=32G', 32 * 1024 ** 3],
    ['local:disk,size=1.5T,backup=1', 1.5 * 1024 ** 4],
    ['local:disk,size=1024M', 1024 ** 3],
    ['local:disk,size=44040192K', 42 * 1024 ** 3],
    ['local:disk,size=2', 2 * 1024 ** 3],
    ['local:disk,size=999999999999999T', null],
    ['local:disk,size=32G,media=cdrom', null],
    ['local:disk', null],
    ['local:disk,size=0G', null],
  ])('reads the actual disk review from %s', (rootfs, expected) => {
    expect(reviewedDiskBytes({ rootfs }, 'rootfs')).toBe(expected);
  });

  it('refuses missing or malformed provider review data', () => {
    expect(reviewedDiskBytes({ scsi0: { size: '32G' } }, 'scsi0')).toBeNull();
    expect(reviewedGuestDigest({})).toBeNull();
    expect(reviewedGuestDigest({ digest: 'not-a-digest' })).toBeNull();
    expect(reviewedGuestDigest({ digest: 'a'.repeat(40) })).toBe('a'.repeat(40));
  });
});
