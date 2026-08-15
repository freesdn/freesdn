// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway system API client
 * ====================================
 *
 * Talks to /api/v1/gateway-system/*. Covers:
 *   - Controller-level: backups, SMTP, notifications, SSL cert,
 *     admins, global settings, maintenance window, cloud-access.
 *   - Site-level: time/NTP, LED schedule, reboot schedules,
 *     notifications subscription.
 *   - Monitoring: SNMP and syslog exporters (site-scoped).
 *
 * Reads run live. Writes are staged. Backup downloads stream raw bytes.
 */

import { isDemoMode } from '@/demo/mode';

import { api, API_URL } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type SystemFeature =
  | 'system.backup'
  | 'system.backup.restore'
  | 'system.smtp'
  | 'system.smtp.test'
  | 'system.notifications'
  | 'system.ssl_cert'
  | 'system.admin'
  | 'system.global'
  | 'system.maintenance'
  | 'system.cloud_access'
  | 'site.time'
  | 'site.led_schedule'
  | 'site.reboot_schedule'
  | 'site.notifications'
  | 'monitoring.snmp'
  | 'monitoring.syslog';

export type ControllerConfigName =
  | 'smtp'
  | 'notifications'
  | 'ssl_cert'
  | 'global'
  | 'maintenance'
  | 'cloud_access';

export type SiteConfigName =
  | 'time'
  | 'led_schedule'
  | 'notifications'
  | 'snmp'
  | 'syslog';

const ctrlPrefix = (controllerId: string) =>
  `/gateway-system/${controllerId}`;

const sitePrefix = (controllerId: string, siteId: string) =>
  `/gateway-system/${controllerId}/sites/${siteId}`;

export const gatewaySystemApi = {
  // ── Reads ─────────────────────────────────────────────────────────
  getControllerConfig: (
    controllerId: string,
    configName: ControllerConfigName,
  ) =>
    api.get(`${ctrlPrefix(controllerId)}/configs/${configName}`),

  listBackups: (controllerId: string) =>
    api.get(`${ctrlPrefix(controllerId)}/backups`),

  /** Returns the absolute URL for the operator's "Download" button.
   *
   * Both ``controllerId`` and ``backupId`` are URL-encoded to defend
   * against future callers that might pass non-UUID strings, and the
   * full ``API_URL`` prefix is included so the link works in dev
   * setups where the frontend and backend are on different origins.
   */
  backupDownloadUrl: (controllerId: string, backupId: string) =>
    isDemoMode
      ? '#'
      : `${API_URL}/api/v1/gateway-system/${encodeURIComponent(controllerId)}` +
        `/backups/${encodeURIComponent(backupId)}/download`,

  listAdmins: (controllerId: string) =>
    api.get(`${ctrlPrefix(controllerId)}/admins`),

  getSiteConfig: (
    controllerId: string,
    siteId: string,
    configName: SiteConfigName,
  ) =>
    api.get(`${sitePrefix(controllerId, siteId)}/configs/${configName}`),

  listRebootSchedules: (controllerId: string, siteId: string) =>
    api.get(`${sitePrefix(controllerId, siteId)}/reboot-schedules`),

  // ── Writes (staged) ───────────────────────────────────────────────
  stageController: (
    controllerId: string,
    feature: SystemFeature,
    operation: ChangeOperation,
    body: PendingChangeRequest,
  ) =>
    api.post<PendingChangeResponse>(
      `${ctrlPrefix(controllerId)}/changes/${feature}`,
      body,
      { params: { operation } },
    ),

  stageSite: (
    controllerId: string,
    siteId: string,
    feature: SystemFeature,
    operation: ChangeOperation,
    body: PendingChangeRequest,
  ) =>
    api.post<PendingChangeResponse>(
      `${sitePrefix(controllerId, siteId)}/changes/${feature}`,
      body,
      { params: { operation } },
    ),

  listPending: (
    controllerId: string,
    params?: {
      feature_prefix?: string;
      status?: string;
      limit?: number;
    },
  ) =>
    api.get<PendingChangeResponse[]>(
      `${ctrlPrefix(controllerId)}/changes`,
      { params },
    ),
};
