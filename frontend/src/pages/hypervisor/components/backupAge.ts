// SPDX-License-Identifier: AGPL-3.0-only
export interface BackupAgeGuest {
  vmid: number;
  status?: string;
  last_backup_time?: string | number | null;
  age_hours?: number | null;
  is_stale?: boolean | null;
}

export type BackupAgeStatus = 'ok' | 'stale' | 'never' | 'unknown';

export function backupAgeStatus(guest: BackupAgeGuest, complete = true): BackupAgeStatus {
  switch (guest.status) {
    case 'current': return 'ok';
    case 'stale': return 'stale';
    case 'missing': return 'never';
    case 'unknown': return 'unknown';
  }
  // Compatibility with earlier servers: a timestamp with explicit freshness
  // is useful evidence. A missing/unknown measurement cannot become green.
  if (guest.last_backup_time != null && guest.is_stale === false) return 'ok';
  if (!complete) return 'unknown';
  if (guest.last_backup_time == null) return 'never';
  return guest.is_stale === true ? 'stale' : 'unknown';
}

export function backupAgeCounts(report: {
  vms?: BackupAgeGuest[];
  total_vms?: number;
  fresh?: number;
  stale?: number;
  never_backed_up?: number;
  unknown?: number;
  complete?: boolean;
}) {
  const guests = report.vms ?? [];
  const count = (status: BackupAgeStatus) => guests.filter(
    (guest) => backupAgeStatus(guest, report.complete ?? true) === status,
  ).length;
  return {
    total: report.total_vms ?? guests.length,
    // Legacy `backed_up` includes stale archives, so it is never the OK count.
    ok: report.fresh ?? count('ok'),
    stale: report.stale ?? count('stale'),
    never: report.never_backed_up ?? count('never'),
    unknown: report.unknown ?? count('unknown'),
  };
}
