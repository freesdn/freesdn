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

/**
 * Feature codes the staging applier actually routes.
 *
 * These MUST match the `_APPLY` keys in
 * `app/services/adapter_omada_switch_advanced.py` verbatim. A code that
 * is not a key stages fine (the endpoint only checks the `switch.`
 * prefix) and then raises 400 `no applier for ...` at apply time, i.e.
 * it fails only after an operator has queued and confirmed the change.
 * Three codes were wrong: `switch.mirror`, `switch.port.jumbo` and
 * `switch.voice_vlan` are `switch.mirror_session`,
 * `switch.per_port_jumbo` and `switch.voice_vlan_per_switch` server-side.
 */
export type SwitchAdvancedFeature =
  | 'switch.sflow'
  | 'switch.mirror_session'
  | 'switch.lldp_med'
  | 'switch.qinq'
  | 'switch.per_port_jumbo'
  | 'switch.poe_budget'
  | 'switch.voice_vlan_per_switch'
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

  /**
   * Per-port jumbo-frame override.
   *
   * The route is `.../switches/{mac}/ports/{port_id}/jumbo-frame`. This
   * used to build `.../switches/{mac}/per-port-jumbo`, a path the backend
   * has never served, and it omitted `portId` entirely, so the first
   * caller to wire it up would have got a 404 in production. The repo's
   * `scripts/check_api_contract.py` could not catch it: its call regex
   * only matches path literals that start with `/`, and every function
   * here opens with the `${prefix(...)}` template hole.
   */
  getPerPortJumbo: (
    controllerId: string,
    siteId: string,
    switchMac: string,
    portId: number,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/switches/${switchMac}/ports/${portId}/jumbo-frame`,
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
