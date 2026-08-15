// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway VPN API client
 * =================================
 *
 * Talks to /api/v1/gateway-vpn/* endpoints. Reads run live against the
 * Omada controller. Writes never touch the controller, they are STAGED
 * in core.adapter_pending_changes and only push to live if an operator
 * explicitly applies them with force=true AND OMADA_READ_ONLY is off.
 *
 * The intended UX: every "save" button on a VPN form calls
 * ``stageChange`` and shows the staged item in a "Pending changes"
 * panel. The Apply button on a pending change calls ``applyChange``
 * with ``{force: true}``. Both safety nets must be down for a write
 * to reach the live device.
 */

import { api } from './client';
import type { ApiSchemas } from './generated';
import type {
  ChangeOperation,
  ChangeStatus,
  PendingChangeRequest,
  PendingChangeResponse,
} from './gatewayCommon';

// ── Types sourced from the backend OpenAPI spec ────────────────────────
//
// Re-exported (rather than duplicated) so a backend signature change
// fails tsc here. Run ``npm run gen:api`` after a backend change to
// refresh the generated types.

// Protocol literal, projected from the response schema's inline enum.
export type VPNProtocol = ApiSchemas['VPNStatusResponse']['protocol'];

// Staging envelope, re-export so callers can import either path.
export type {
  ChangeOperation,
  ChangeStatus,
  PendingChangeRequest,
  PendingChangeResponse,
};

// Backend doesn't emit ``VPNFeature`` as a standalone schema (each
// staging endpoint accepts ``feature: str``), so this stays a hand-
// maintained literal until we ship a typed feature enum on the server.
// Keep in sync with backend services/gateway_vpn.py:_APPLY.
export type VPNFeature =
  | 'vpn.ipsec.config'
  | 'vpn.ipsec.policy'
  | 'vpn.openvpn.config'
  | 'vpn.openvpn.user'
  | 'vpn.l2tp.config'
  | 'vpn.l2tp.user'
  | 'vpn.pptp.config'
  | 'vpn.pptp.user'
  | 'vpn.wireguard.config'
  | 'vpn.wireguard.peer'
  | 'vpn.sslvpn.config'
  | 'vpn.sslvpn.user'
  | 'vpn.gre.tunnel';

// ── Response shapes, generated ────────────────────────────────────────

export type GatewayVPNListResponse = ApiSchemas['GatewayVPNListResponse'];
export type GatewayVPNDetailResponse = ApiSchemas['GatewayVPNDetailResponse'];
export type VPNStatusResponse = ApiSchemas['VPNStatusResponse'];
export type ApplyPendingChangeRequest = ApiSchemas['ApplyPendingChangeRequest'];

// ── Path helpers ───────────────────────────────────────────────────────

// All path-segment interpolations in this file (controller IDs, site IDs,
// VPN protocol, feature, change ID) flow through this, never let raw
// values land in a URL.
const enc = (segment: string) => encodeURIComponent(String(segment ?? ''));

const sitePrefix = (controllerId: string, siteId: string) =>
  `/gateway-vpn/${enc(controllerId)}/sites/${enc(siteId)}`;

// ── API surface ────────────────────────────────────────────────────────

export const gatewayVpnApi = {
  // ── Live reads ──────────────────────────────────────────────────────

  /** Read live protocol-level config (e.g. IPsec global, OpenVPN server). */
  getProtocolConfig: (
    controllerId: string,
    siteId: string,
    protocol: VPNProtocol,
  ) =>
    api.get<GatewayVPNDetailResponse>(
      `${sitePrefix(controllerId, siteId)}/${enc(protocol)}/config`,
    ),

  /** Read live status for a protocol (active tunnels, peers, traffic). */
  getProtocolStatus: (
    controllerId: string,
    siteId: string,
    protocol: VPNProtocol,
  ) =>
    api.get<VPNStatusResponse>(
      `${sitePrefix(controllerId, siteId)}/${enc(protocol)}/status`,
    ),

  /** List users for protocols that have one (openvpn / l2tp / pptp / sslvpn). */
  listProtocolUsers: (
    controllerId: string,
    siteId: string,
    protocol: 'openvpn' | 'l2tp' | 'pptp' | 'sslvpn',
  ) =>
    api.get<GatewayVPNListResponse>(
      `${sitePrefix(controllerId, siteId)}/${enc(protocol)}/users`,
    ),

  /** List configured IPsec policies (site-to-site + client). */
  listIPsecPolicies: (controllerId: string, siteId: string) =>
    api.get<GatewayVPNListResponse>(
      `${sitePrefix(controllerId, siteId)}/ipsec/policies`,
    ),

  /** List WireGuard peers. */
  listWireguardPeers: (controllerId: string, siteId: string) =>
    api.get<GatewayVPNListResponse>(
      `${sitePrefix(controllerId, siteId)}/wireguard/peers`,
    ),

  /** List GRE tunnels. */
  listGreTunnels: (controllerId: string, siteId: string) =>
    api.get<GatewayVPNListResponse>(
      `${sitePrefix(controllerId, siteId)}/gre/tunnels`,
    ),

  // ── Stage writes (always safe) ──────────────────────────────────────

  /**
   * Stage a write. Does NOT touch the controller, the change appears
   * in ``listPendingChanges`` and waits for an explicit apply.
   */
  stageChange: (
    controllerId: string,
    siteId: string,
    feature: VPNFeature,
    operation: ChangeOperation,
    body: PendingChangeRequest,
  ) =>
    api.post<PendingChangeResponse>(
      `${sitePrefix(controllerId, siteId)}/changes/${enc(feature)}`,
      body,
      { params: { operation } },
    ),

  /** List pending changes for a site (filterable by feature prefix / status). */
  listPendingChanges: (
    controllerId: string,
    siteId: string,
    params?: {
      feature_prefix?: string;
      status?: ChangeStatus;
      limit?: number;
    },
  ) =>
    api.get<PendingChangeResponse[]>(
      `${sitePrefix(controllerId, siteId)}/changes`,
      { params },
    ),

  /** Discard a pending change without applying it. */
  discardChange: (changeId: string) =>
    api.post<PendingChangeResponse>(
      `/gateway-vpn/changes/${enc(changeId)}/discard`,
    ),

  /**
   * Push a staged change to the live controller.
   *
   * Refused unless ``OMADA_READ_ONLY=false`` server-side AND
   * ``body.force === true``. Both must be set to apply.
   */
  applyChange: (changeId: string, body: ApplyPendingChangeRequest) =>
    api.post<PendingChangeResponse>(
      `/gateway-vpn/changes/${enc(changeId)}/apply`,
      body,
    ),
};
