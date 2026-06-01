// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway switch advanced API client
 * ==============================================
 *
 * Talks to /api/v1/gateway-switch-advanced/*. Covers sFlow,
 * mirror sessions, LLDP-MED, QinQ, per-port jumbo, PoE budget,
 * voice VLAN per-switch, MSTP. Reads live; writes stage.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type SwitchAdvancedFeature =
  | 'switch.sflow'
  | 'switch.mirror'
  | 'switch.lldp_med'
  | 'switch.qinq'
  | 'switch.port.jumbo'
  | 'switch.poe_budget'
  | 'switch.voice_vlan'
  | 'switch.mstp';

export type PerSwitchConfig =
  | 'sflow'
  | 'lldp_med'
  | 'qinq'
  | 'poe_budget'
  | 'voice_vlan'
  | 'mstp';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-switch-advanced/${controllerId}/sites/${siteId}`;

export const gatewaySwitchAdvancedApi = {
  getSwitchConfig: (
    controllerId: string,
    siteId: string,
    switchMac: string,
    configName: PerSwitchConfig,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/switches/${switchMac}/configs/${configName}`,
    ),

  listMirrorSessions: (
    controllerId: string,
    siteId: string,
    switchMac: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/switches/${switchMac}/mirror-sessions`,
    ),

  getPerPortJumbo: (
    controllerId: string,
    siteId: string,
    switchMac: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/switches/${switchMac}/per-port-jumbo`,
    ),

  stage: (
    controllerId: string,
    siteId: string,
    feature: SwitchAdvancedFeature,
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
