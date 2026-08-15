// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway hotspot deeper API client
 * =============================================
 *
 * Talks to /api/v1/gateway-hotspot/*. Hotspot operators, SMS gateway,
 * form-auth fields per portal, free-auth policies. Reads live;
 * writes stage.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type HotspotFeature =
  | 'hotspot.operator'
  | 'hotspot.sms_gateway'
  | 'hotspot.sms_gateway.test'
  | 'hotspot.form_auth_fields'
  | 'hotspot.free_auth_policy';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-hotspot/${controllerId}/sites/${siteId}`;

export const gatewayHotspotApi = {
  listOperators: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/operators`),

  getSmsGateway: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/sms-gateway`),

  getFormFields: (
    controllerId: string,
    siteId: string,
    portalId: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/portals/${portalId}/form-fields`,
    ),

  listFreeAuthPolicies: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/free-auth-policies`),

  stage: (
    controllerId: string,
    siteId: string,
    feature: HotspotFeature,
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
