// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway WiFi advanced:
 * WLAN-group / SSID advanced knobs, MAC filter, surveillance VLAN,
 * walled garden, voucher templates, 6 GHz radio, locate-AP.
 */

import { api } from './client';
import type {
  ChangeOperation,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

export type WifiFeature =
  | 'wifi.wlan_group.advanced'
  | 'wifi.ssid.advanced'
  | 'wifi.ssid.mac_filter'
  | 'wifi.surveillance_vlan'
  | 'wifi.walled_garden'
  | 'wifi.voucher_template'
  | 'wifi.radio_6ghz'
  | 'wifi.locate_ap'
  | 'wifi.wids_wips'
  | 'wifi.mesh_detail'
  | 'wifi.regulatory'
  | 'wifi.dfs'
  | 'wifi.channel_pilot'
  | 'wifi.channel_pilot.run';

export type WifiConfigName =
  | 'wids_wips'
  | 'mesh_detail'
  | 'regulatory'
  | 'dfs'
  | 'channel_pilot';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-wifi/${controllerId}/sites/${siteId}`;

export const gatewayWifiApi = {
  getWlanGroup: (controllerId: string, siteId: string, wlanId: string) =>
    api.get(`${prefix(controllerId, siteId)}/wlan-groups/${wlanId}`),

  getSsid: (
    controllerId: string,
    siteId: string,
    wlanId: string,
    ssidId: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/wlan-groups/${wlanId}/ssids/${ssidId}`,
    ),

  getSurveillanceVlan: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/surveillance-vlan`),

  listWalledGarden: (
    controllerId: string,
    siteId: string,
    portalId: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/portals/${portalId}/walled-garden`,
    ),

  listVoucherTemplates: (
    controllerId: string,
    siteId: string,
    portalId: string,
  ) =>
    api.get(
      `${prefix(controllerId, siteId)}/portals/${portalId}/voucher-templates`,
    ),

  getConfig: (
    controllerId: string,
    siteId: string,
    configName: WifiConfigName,
  ) =>
    api.get(`${prefix(controllerId, siteId)}/configs/${configName}`),

  listWidsWipsEvents: (
    controllerId: string,
    siteId: string,
    params?: { limit?: number },
  ) =>
    api.get(`${prefix(controllerId, siteId)}/wids-wips/events`, { params }),

  stage: (
    controllerId: string,
    siteId: string,
    feature: WifiFeature,
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
