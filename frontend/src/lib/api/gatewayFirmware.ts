// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway firmware API client
 * ======================================
 *
 * Talks to /api/v1/gateway-firmware/*. Reads pull live firmware state
 * from the Omada controller. Writes (single device upgrade, batch,
 * schedule CRUD) are staged in the same adapter_pending_changes table
 * the gateway-VPN endpoints use; they never push live unless an
 * operator explicitly applies them.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

// NOTE: ``Firmware*Response`` shapes below are hand-typed because
// the backend endpoints return untyped ``dict[str, Any]``. Migrating
// them to OpenAPI-generated types requires defining Pydantic
// response models on the backend first, tracked as a follow-up.
// In the meantime, the loose ``[k: string]: unknown`` index signature
// is the honest interface (the controller may add fields).

// ── Firmware-specific feature codes ────────────────────────────────────

export type FirmwareFeature =
  | 'firmware.upgrade'           // payload: {device_mac, version?}
  | 'firmware.upgrade.batch'     // payload: {macs[], version?}
  | 'firmware.schedule';         // payload: schedule config (see Omada docs)

// ── Response types ─────────────────────────────────────────────────────

export interface FirmwareDeviceInfoResponse {
  controller_id: string;
  site_id: string;
  device_mac: string;
  info: {
    currentVersion?: string;
    upgradeAvailable?: boolean;
    latestVersion?: string;
    releaseNotes?: string;
    checksum?: string;
    [k: string]: unknown;
  };
  fetched_at: string;
}

export interface FirmwareAvailableResponse {
  controller_id: string;
  site_id: string;
  model: string | null;
  items: Array<{
    model?: string;
    version?: string;
    releaseDate?: string;
    releaseNotes?: string;
    [k: string]: unknown;
  }>;
  fetched_at: string;
}

export interface FirmwareScheduleListResponse {
  controller_id: string;
  site_id: string;
  items: Array<{
    id?: string;
    name?: string;
    deviceModels?: string[];
    deviceMacs?: string[];
    cron?: string;
    timeOfDay?: string;
    timezone?: string;
    stableOnly?: boolean;
    [k: string]: unknown;
  }>;
  fetched_at: string;
}

export interface FirmwareHistoryResponse {
  controller_id: string;
  site_id: string;
  items: Array<{
    deviceMac?: string;
    fromVersion?: string;
    toVersion?: string;
    status?: string;
    startedAt?: string;
    completedAt?: string;
    [k: string]: unknown;
  }>;
  fetched_at: string;
}

// ── Path helpers ───────────────────────────────────────────────────────

const sitePrefix = (controllerId: string, siteId: string) =>
  `/gateway-firmware/${controllerId}/sites/${siteId}`;

// ── API surface ────────────────────────────────────────────────────────

export const gatewayFirmwareApi = {
  /** Live firmware info for one device (current + available upgrade). */
  getDevice: (controllerId: string, siteId: string, deviceMac: string) =>
    api.get<FirmwareDeviceInfoResponse>(
      `${sitePrefix(controllerId, siteId)}/devices/${deviceMac}`,
    ),

  /** Firmware images available for adopted devices on this site. */
  getAvailable: (
    controllerId: string,
    siteId: string,
    params?: { model?: string },
  ) =>
    api.get<FirmwareAvailableResponse>(
      `${sitePrefix(controllerId, siteId)}/available`,
      { params },
    ),

  /** List configured auto-upgrade schedules. */
  listSchedules: (controllerId: string, siteId: string) =>
    api.get<FirmwareScheduleListResponse>(
      `${sitePrefix(controllerId, siteId)}/schedules`,
    ),

  /** Recent upgrade attempts (success / fail / in-progress). */
  getHistory: (
    controllerId: string,
    siteId: string,
    params?: { limit?: number },
  ) =>
    api.get<FirmwareHistoryResponse>(
      `${sitePrefix(controllerId, siteId)}/history`,
      { params },
    ),

  /**
   * Stage a firmware change (upgrade now, batch upgrade, schedule CRUD).
   * The change waits in the staging queue until applied.
   */
  stageChange: (
    controllerId: string,
    siteId: string,
    feature: FirmwareFeature,
    operation: ChangeOperation,
    body: PendingChangeRequest,
  ) =>
    api.post<PendingChangeResponse>(
      `${sitePrefix(controllerId, siteId)}/changes/${feature}`,
      body,
      { params: { operation } },
    ),

  /** List pending firmware changes. */
  listPendingChanges: (
    controllerId: string,
    siteId: string,
    params?: { status?: string; limit?: number },
  ) =>
    api.get<PendingChangeResponse[]>(
      `${sitePrefix(controllerId, siteId)}/changes`,
      { params },
    ),
};
