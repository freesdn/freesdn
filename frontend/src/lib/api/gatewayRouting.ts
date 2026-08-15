// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway advanced routing API client
 * ==============================================
 *
 * Talks to /api/v1/gateway-routing/*. VRRP, IPv6 static routes, BGP,
 * routing table. Reads live; writes stage.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type RoutingFeature =
  | 'routing.vrrp'
  | 'routing.ipv6_static'
  | 'routing.bgp';

export type RoutingRead =
  | 'vrrp'
  | 'ipv6_static'
  | 'bgp'
  | 'bgp_neighbors'
  | 'routing_table';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-routing/${controllerId}/sites/${siteId}`;

export const gatewayRoutingApi = {
  get: (
    controllerId: string,
    siteId: string,
    what: RoutingRead,
    params?: { family?: 'ipv4' | 'ipv6' },
  ) =>
    api.get(`${prefix(controllerId, siteId)}/${what}`, { params }),

  stage: (
    controllerId: string,
    siteId: string,
    feature: RoutingFeature,
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
