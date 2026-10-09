// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';
import { backupAgeCounts, backupAgeStatus } from './backupAge';

describe('backup observations presented to an operator', () => {
  const fresh = { vmid: 100, last_backup_time: '2026-09-14T12:00:00Z', is_stale: false };
  const stale = { vmid: 101, last_backup_time: '2026-09-01T12:00:00Z', is_stale: true };
  const missing = { vmid: 102, last_backup_time: null, is_stale: true };

  it('does not add stale archives to the green count from an older server', () => {
    const legacy = { vms: [fresh, stale, missing], total_vms: 3, backed_up: 2, stale: 1, never_backed_up: 1 };
    expect(backupAgeCounts(legacy)).toEqual({ total: 3, ok: 1, stale: 1, never: 1, unknown: 0 });
  });

  it('does not render an incomplete missing observation as never backed up', () => {
    expect(backupAgeStatus(missing, false)).toBe('unknown');
    expect(backupAgeStatus({ ...stale, status: 'unknown', is_stale: null }, false)).toBe('unknown');
  });

  it('preserves positive archive evidence during partial outages', () => {
    expect(backupAgeStatus(fresh, false)).toBe('ok');
  });

  it('does not turn an unknown stale flag into OK', () => {
    expect(backupAgeStatus({ ...fresh, is_stale: null })).toBe('unknown');
  });

  it('honors a measured zero fresh count', () => {
    expect(backupAgeCounts({ vms: [fresh], fresh: 0 }).ok).toBe(0);
  });
});
