// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway bulk-ops + cloning + templates API client
 * ============================================================
 *
 * Talks to /api/v1/gateway-bulk/*. Reads pull live data from the Omada
 * controller. Writes (bulk device/client/SSID ops, site clone, templates)
 * are staged via core.adapter_pending_changes and never push to the
 * controller unless an operator explicitly applies them with force=true
 * AND OMADA_READ_ONLY is off.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type BulkFeature =
  | 'bulk.device.adopt'
  | 'bulk.device.forget'
  | 'bulk.device.reboot'
  | 'bulk.device.factory_reset'
  | 'bulk.device.locate'
  | 'bulk.device.move_site'
  | 'bulk.ssid.set_state'
  | 'bulk.client.block'
  | 'bulk.client.unblock'
  | 'bulk.client.kick'
  | 'site.clone'
  | 'site.template.export'
  | 'site.template.apply'
  | 'site.template.delete';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-bulk/${controllerId}/sites/${siteId}`;

export const gatewayBulkApi = {
  listTemplates: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/templates`),

  stage: (
    controllerId: string,
    siteId: string,
    feature: BulkFeature,
    operation: ChangeOperation,
    body: PendingChangeRequest,
  ) =>
    api.post<PendingChangeResponse>(
      `${prefix(controllerId, siteId)}/changes/${feature}`,
      body,
      { params: { operation } },
    ),

  listPending: (
    controllerId: string,
    siteId: string,
    params?: { status?: string; limit?: number },
  ) =>
    api.get<PendingChangeResponse[]>(
      `${prefix(controllerId, siteId)}/changes`,
      { params },
    ),
};
