// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway firewall depth:
 * URL filter, app control, port forwarding, DMZ, 1:1 NAT, UPnP,
 * attack defense, ALG, IDS/IPS.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type FirewallCollection =
  | 'url_filter'
  | 'app_filter'
  | 'app_categories'
  | 'port_forward'
  | 'one_to_one_nat'
  | 'upnp_mappings'
  | 'ids_ips_events';

export type FirewallConfig =
  | 'dmz'
  | 'upnp'
  | 'attack_defense'
  | 'alg'
  | 'ids_ips';

export type FirewallFeature =
  | 'firewall.urlfilter.rule'
  | 'firewall.appfilter.rule'
  | 'firewall.port_forward'
  | 'firewall.dmz'
  | 'firewall.one_to_one_nat'
  | 'firewall.upnp'
  | 'firewall.upnp.mapping'
  | 'firewall.attack_defense'
  | 'firewall.alg'
  | 'firewall.ids_ips'
  | 'firewall.ids_ips.signatures';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-firewall/${controllerId}/sites/${siteId}`;

export const gatewayFirewallApi = {
  list: (
    controllerId: string,
    siteId: string,
    collection: FirewallCollection,
  ) => api.get(`${prefix(controllerId, siteId)}/lists/${collection}`),

  getConfig: (controllerId: string, siteId: string, name: FirewallConfig) =>
    api.get(`${prefix(controllerId, siteId)}/configs/${name}`),

  stage: (
    controllerId: string,
    siteId: string,
    feature: FirewallFeature,
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
