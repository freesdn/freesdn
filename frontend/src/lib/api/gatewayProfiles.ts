// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway profiles / object catalog.
 *
 * Reusable objects referenced by URL filter, app control, bandwidth
 * control, captive portal, RADIUS-backed SSIDs, and 802.1X. Reads run
 * live; writes are staged.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type ProfileType =
  | 'mac_groups'
  | 'domain_groups'
  | 'oui_profiles'
  | 'time_ranges'
  | 'rate_limit_profiles'
  | 'ppsk_profiles'
  | 'radius_profiles'
  | 'ldap_profiles';

export type ProfileFeature =
  | 'profile.mac_group'
  | 'profile.domain_group'
  | 'profile.oui'
  | 'profile.time_range'
  | 'profile.rate_limit'
  | 'profile.ppsk'
  | 'profile.radius'
  | 'profile.ldap';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-profiles/${controllerId}/sites/${siteId}`;

export const gatewayProfilesApi = {
  list: (controllerId: string, siteId: string, type: ProfileType) =>
    api.get(`${prefix(controllerId, siteId)}/${type}`),

  get: (
    controllerId: string,
    siteId: string,
    type: ProfileType,
    profileId: string,
  ) => api.get(`${prefix(controllerId, siteId)}/${type}/${profileId}`),

  stage: (
    controllerId: string,
    siteId: string,
    feature: ProfileFeature,
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
