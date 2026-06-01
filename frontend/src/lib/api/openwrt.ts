// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, OpenWrt gateway API client.
 *
 * Drives the ``/gateway-openwrt/{cid}/*`` read endpoints. The
 * underlying adapter has full CRUD via ubus / UCI but write
 * endpoints will land in follow-up commits, the read surface
 * is enough to render the gateway detail page.
 *
 * URL layout:
 *
 *   GET /gateway-openwrt/{cid}/device-info
 *   GET /gateway-openwrt/{cid}/interfaces
 *   GET /gateway-openwrt/{cid}/firewall-rules
 *   GET /gateway-openwrt/{cid}/port-forwards
 *   GET /gateway-openwrt/{cid}/dhcp-leases
 *   GET /gateway-openwrt/{cid}/dhcp-static-mappings
 *   GET /gateway-openwrt/{cid}/arp-table
 *   GET /gateway-openwrt/{cid}/summary
 */
import { api } from './client';

const enc = (segment: string) => encodeURIComponent(String(segment ?? ''));

export interface OpenWrtDeviceInfo {
  hostname: string;
  model: string;
  version: string;
  kernel: string;
  uptime: number;
  memory: { total: number; free: number; available: number; cached: number; buffered: number };
  load: number[];
}

export interface OpenWrtInterface {
  name: string;
  device?: string;
  status?: string;
  enabled?: boolean;
  proto?: string;
  ipv4_address?: string;
  ipv4_subnet?: string | number;
  ipv4_gateway?: string | null;
  ipv6_address?: string | null;
  mac_address?: string | null;
  mtu?: number | null;
  is_wan?: boolean;
  is_lan?: boolean;
  is_bridge?: boolean;
  dns_servers?: string[];
  rx_bytes?: number;
  tx_bytes?: number;
  // Other UCI / ubus fields passed through
  [k: string]: unknown;
}

export interface OpenWrtFirewallRule {
  uci_name?: string;
  name?: string;
  src?: string;
  dest?: string;
  target?: string;
  proto?: string;
  enabled?: boolean;
  [k: string]: unknown;
}

export interface OpenWrtPortForward {
  uci_name?: string;
  name?: string;
  src?: string;
  src_dport?: string;
  dest?: string;
  dest_ip?: string;
  dest_port?: string;
  proto?: string;
  enabled?: boolean;
  [k: string]: unknown;
}

export interface OpenWrtDhcpLease {
  mac_address?: string;
  ip_address?: string;
  hostname?: string;
  expires?: number;
  status?: string;
  [k: string]: unknown;
}

export interface OpenWrtArpEntry {
  mac?: string;
  ip?: string;
  interface?: string;
  [k: string]: unknown;
}

export interface OpenWrtListEnvelope<T> {
  controller_id: string;
  items: T[];
  count?: number;
  fetched_at: string;
}

export const openwrtApi = {
  getDeviceInfo: (cid: string) =>
    api.get<{ controller_id: string; info: OpenWrtDeviceInfo; fetched_at: string }>(
      `/gateway-openwrt/${enc(cid)}/device-info`,
    ),

  listInterfaces: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtInterface>>(
      `/gateway-openwrt/${enc(cid)}/interfaces`,
    ),

  listFirewallRules: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtFirewallRule>>(
      `/gateway-openwrt/${enc(cid)}/firewall-rules`,
    ),

  listPortForwards: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtPortForward>>(
      `/gateway-openwrt/${enc(cid)}/port-forwards`,
    ),

  listDhcpLeases: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtDhcpLease>>(
      `/gateway-openwrt/${enc(cid)}/dhcp-leases`,
    ),

  listDhcpStaticMappings: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtDhcpLease>>(
      `/gateway-openwrt/${enc(cid)}/dhcp-static-mappings`,
    ),

  listArpTable: (cid: string) =>
    api.get<OpenWrtListEnvelope<OpenWrtArpEntry>>(
      `/gateway-openwrt/${enc(cid)}/arp-table`,
    ),

  getSummary: (cid: string) =>
    api.get<{ controller_id: string; summary: Record<string, unknown>; fetched_at: string }>(
      `/gateway-openwrt/${enc(cid)}/summary`,
    ),

  // ── Stage-only writes ─────────────────────────────────────────────────
  // Each call records a pending row in ``omada_pending_changes``. The
  // PendingChangesDrawer (already in the gateway header) drives the
  // apply through the shared ``/gateway-vpn/changes/{id}/apply`` path.

  stageFirewallRule: (
    cid: string,
    operation: 'create' | 'update' | 'delete',
    payload: Record<string, unknown>,
    targetId?: string,
  ) =>
    api.post<{ id: string; status: string }>(
      `/gateway-openwrt-firewall/${enc(cid)}/changes/openwrt.firewall.rule?operation=${operation}`,
      { payload, target_id: targetId ?? null },
    ),

  stagePortForward: (
    cid: string,
    operation: 'create' | 'update' | 'delete',
    payload: Record<string, unknown>,
    targetId?: string,
  ) =>
    api.post<{ id: string; status: string }>(
      `/gateway-openwrt-firewall/${enc(cid)}/changes/openwrt.firewall.port_forward?operation=${operation}`,
      { payload, target_id: targetId ?? null },
    ),

  stageDhcpStaticHost: (
    cid: string,
    operation: 'create' | 'update' | 'delete',
    payload: Record<string, unknown>,
    targetId?: string,
  ) =>
    api.post<{ id: string; status: string }>(
      `/gateway-openwrt-dhcp/${enc(cid)}/changes/openwrt.dhcp.static_host?operation=${operation}`,
      { payload, target_id: targetId ?? null },
    ),
};
