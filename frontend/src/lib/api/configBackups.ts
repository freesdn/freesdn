// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Database (pg-backup) status and network device configuration backups.
 *
 * Every configuration the server returns here is REDACTED: secret-looking values
 * arrive as `[redacted:<fingerprint>]`. The unredacted export is a separate,
 * audited, super-admin-only download that this module deliberately does not wrap.
 */
import { api } from './client';

const enc = encodeURIComponent;

export type DatabaseBackupState =
  | 'healthy'
  | 'unencrypted'
  | 'pending'
  | 'unknown'
  | 'disabled'
  | 'failing'
  | 'stale';

export interface DatabaseBackupStatus {
  state: DatabaseBackupState;
  severity: 'ok' | 'warning' | 'critical';
  enabled: boolean | null;
  encrypted: boolean | null;
  reason: string | null;
  last_success_at: string | null;
  max_age_seconds: number | null;
  checked_at: string;
  setup_command: string | null;
}

export interface ConfigBackupTarget {
  id: string;
  source_kind: string;
  source_id: string;
  vendor: string;
  display_name: string;
  site_id: string | null;
  enabled: boolean;
  interval_hours: number;
  retention_versions: number;
  next_due_at: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_changed_at: string | null;
  last_status: string;
  last_error_code: string | null;
  consecutive_failures: number;
  capture_running: boolean;
  latest_version: number | null;
  latest_captured_at: string | null;
}

export interface ConfigSnapshot {
  id: string;
  version: number;
  captured_at: string;
  format: string;
  size_bytes: number;
  trigger: string;
  summary: { added: number; removed: number } | null;
}

export interface ConfigDiff {
  target_id: string;
  from_version: number | null;
  to_version: number;
  redacted: boolean;
  lines: string[];
  truncated: boolean;
  added: number;
  removed: number;
}

/** What PATCH /config-backups/{id} accepts: either field, or both. */
export interface ConfigBackupTargetUpdate {
  enabled?: boolean;
  /** Hours between captures, 6 to 168 (the backend's INTERVAL_HOURS_RANGE). */
  interval_hours?: number;
}

export const databaseBackupApi = {
  status: () => api.get<DatabaseBackupStatus>('/backups/database-status').then((r) => r.data),
};

export const configBackupApi = {
  list: () => api.get<ConfigBackupTarget[]>('/config-backups/').then((r) => r.data),
  versions: (targetId: string) =>
    api.get<ConfigSnapshot[]>(`/config-backups/${enc(targetId)}/versions/`).then((r) => r.data),
  diff: (targetId: string, version: number) =>
    api
      .get<ConfigDiff>(`/config-backups/${enc(targetId)}/versions/${enc(String(version))}/diff`)
      .then((r) => r.data),
  capture: (targetId: string) => api.post(`/config-backups/${enc(targetId)}/capture`),
  /** Change a device's backup schedule; answers with the updated target. */
  update: (targetId: string, change: ConfigBackupTargetUpdate) =>
    api.patch<ConfigBackupTarget>(`/config-backups/${enc(targetId)}`, change).then((r) => r.data),
};
