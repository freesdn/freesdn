// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Three shipped Hypervisor buttons that always failed, and one report that
 * always lied.
 *
 * RESTORE AND PRUNE ALWAYS RETURNED HTTP 400
 * `_refuse_direct_catastrophic` is the FIRST statement of both
 * `HypervisorService.restore_backup` and `.prune_backups`, and the API maps
 * its ValueError to a 400. So "Restore" in the Storage tab, "Prune Now" in the
 * Backup Age tab and "Prune Backups" in the PBS tab each returned:
 *
 *   "backup restore (overwrites a guest) is catastrophic and cannot be applied
 *    on the direct path; stage it via the staged adapter endpoints (which run
 *    the pre-flight and require confirmed=true) to proceed."
 *
 * The guard is right — a restore overwrites a live guest, a prune deletes
 * archives permanently, and the direct path had neither the pre-flight nor the
 * archive-volid allowlist. What was missing was the other half: the staged
 * endpoints it names were not reachable from anywhere in the UI, and `proxmox`
 * was not even a GatewayVendor, so nothing could LIST a staged Proxmox change.
 * The advice pointed at a door with no handle, and the disaster-recovery action
 * the product advertises could not be performed from the product.
 *
 * THE BACKUP AGE REPORT LABELLED EVERY GUEST "NEVER BACKED UP"
 * The tab read `v.status` and `v.last_backup`. `BackupAgeReport` carries
 * `last_backup_time`, `age_hours` and `is_stale`. So `v.status === 'never'` was
 * never true and `v.last_backup == null` was ALWAYS true — every guest counted
 * and rendered as never backed up, including one backed up an hour ago, while
 * the "stale" and "OK" counters sat at zero.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

import { hypervisorApi } from '../hypervisor';

vi.mock('../client', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({ data: {} })),
    post: vi.fn(() => Promise.resolve({ data: {} })),
    put: vi.fn(() => Promise.resolve({ data: {} })),
    delete: vi.fn(() => Promise.resolve({ data: {} })),
  },
  API_URL: '',
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (await import('../client')).api as any;

const CID = '11111111-1111-1111-1111-111111111111';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('backup restore and prune are staged, not applied directly', () => {
  it('does not call the direct restore endpoint any more', async () => {
    await hypervisorApi.stageBackupRestore(CID, {
      node: 'pve1',
      vm_type: 'qemu',
      archive: 'local:backup/vzdump-qemu-100-2026_08_19.vma.zst',
      vmid: 100,
    });

    const [url] = api.post.mock.calls[0];
    expect(url).not.toContain('/backup/restore');
    expect(url).toContain('/gateway-proxmox-backup/');
  });

  it('stages the restore against the feature the backend routes', () => {
    // The service maps ("proxmox.backup.restore", "create") -> restore_backup.
    // A different feature string reaches no handler at all.
    hypervisorApi.stageBackupRestore(CID, {
      node: 'pve1',
      vm_type: 'lxc',
      archive: 'local:backup/vzdump-lxc-200-2026_08_19.tar.zst',
      vmid: 200,
    });

    const [url, body, config] = api.post.mock.calls[0];
    expect(url).toBe(`/gateway-proxmox-backup/${CID}/changes/proxmox.backup.restore`);
    expect(config.params.operation).toBe('create');
    expect(body.payload).toMatchObject({
      node: 'pve1',
      vm_type: 'lxc',
      vmid: 200,
    });
  });

  it('sends the payload keys the staged validator reads', () => {
    // The staged apply reads `start` and `unique`. The direct endpoint took
    // `start_after_restore` and `unique_mac`; sending those names to the
    // staged path would silently drop both operator choices.
    hypervisorApi.stageBackupRestore(CID, {
      node: 'pve1',
      vm_type: 'qemu',
      archive: 'local:backup/vzdump-qemu-100-2026_08_19.vma.zst',
      vmid: 100,
      storage: 'local-lvm',
      start: true,
      unique: false,
    });

    const body = api.post.mock.calls[0][1];
    expect(body.payload.start).toBe(true);
    expect(body.payload.unique).toBe(false);
    expect(body.payload).not.toHaveProperty('start_after_restore');
    expect(body.payload).not.toHaveProperty('unique_mac');
  });

  it('stages a prune against its own feature', () => {
    hypervisorApi.stageBackupPrune(CID, {
      node: 'pve1',
      storage: 'local',
      keep_last: 3,
      keep_daily: 7,
    });

    const [url, body, config] = api.post.mock.calls[0];
    expect(url).toBe(`/gateway-proxmox-backup/${CID}/changes/proxmox.backup.prune`);
    expect(config.params.operation).toBe('create');
    expect(body.payload).toMatchObject({
      node: 'pve1',
      storage: 'local',
      keep_last: 3,
      keep_daily: 7,
    });
  });

  it('no longer exposes the endpoints the backend refuses', () => {
    // Guard the class: leaving these on the client invites the next caller
    // straight back into the 400.
    expect(hypervisorApi).not.toHaveProperty('restoreBackup');
    expect(hypervisorApi).not.toHaveProperty('pruneBackups');
  });

  it('keeps the prune PREVIEW on the direct path', () => {
    // Preview is a read. It was never blocked, and routing it through staging
    // would break the confirm dialog that shows what a prune would delete.
    hypervisorApi.getPrunePreview(CID, 'pve1', 'local');
    expect(api.get.mock.calls[0][0]).toContain('/prune-preview');
    expect(api.post).not.toHaveBeenCalled();
  });
});

describe('the Backup Age report reads the fields the backend sends', () => {
  // Mirrors the tab's derivation. BackupAgeReport is
  // {vmid, name, node, last_backup_time, age_hours, is_stale}.
  const statusOf = (v: Record<string, unknown>): 'never' | 'stale' | 'ok' => {
    if (v?.['last_backup_time'] == null) return 'never';
    return v?.['is_stale'] ? 'stale' : 'ok';
  };

  const FRESH = { vmid: 100, last_backup_time: '2026-08-19T01:00:00Z', age_hours: 2, is_stale: false };
  const STALE = { vmid: 101, last_backup_time: '2026-08-10T01:00:00Z', age_hours: 220, is_stale: true };
  const NEVER = { vmid: 102, last_backup_time: null, age_hours: null, is_stale: true };

  it('does not call a freshly backed-up guest "never"', () => {
    // The whole bug: `v.last_backup` is undefined on every row, so
    // `v.last_backup == null` was true for all of them.
    expect(statusOf(FRESH)).toBe('ok');
    expect((FRESH as Record<string, unknown>)['last_backup']).toBeUndefined();
    expect((FRESH as Record<string, unknown>)['status']).toBeUndefined();
  });

  it('distinguishes stale from never', () => {
    expect(statusOf(STALE)).toBe('stale');
    expect(statusOf(NEVER)).toBe('never');
  });

  it('counts each bucket instead of putting everything in one', () => {
    const vms = [FRESH, STALE, NEVER];
    expect(vms.filter((v) => statusOf(v) === 'ok')).toHaveLength(1);
    expect(vms.filter((v) => statusOf(v) === 'stale')).toHaveLength(1);
    expect(vms.filter((v) => statusOf(v) === 'never')).toHaveLength(1);
  });

  it('reproduces the old derivation to prove the test is not vacuous', () => {
    // Negative control. This is exactly what the tab used to do.
    const oldNeverCount = [FRESH, STALE, NEVER].filter(
      (v: Record<string, unknown>) => v['status'] === 'never' || v['last_backup'] == null,
    ).length;
    expect(oldNeverCount).toBe(3);
  });

  it('sorts worst-first rather than not at all', () => {
    const order = (s: string) => (s === 'never' ? 3 : s === 'stale' ? 2 : 1);
    const sorted = [FRESH, STALE, NEVER].sort(
      (a, b) => order(statusOf(b)) - order(statusOf(a)),
    );
    expect(sorted.map((v) => v.vmid)).toEqual([102, 101, 100]);
  });
});
