// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, MikroTik (RouterOS) gateway API client.
 *
 * Mirrors the structure of ``gateway.ts`` but targets the typed
 * ``/gateway-mikrotik-*`` endpoints. Every write is staged via the
 * shared pending-changes pattern (the backend prefixes each domain
 * with ``mikrotik.<domain>.*`` and locks the feature namespace at the
 * stage endpoint).
 *
 * URL layout (backend prefixes use hyphens, not slashes):
 *
 *   GET   /gateway-mikrotik-system/{cid}/info | services | files | logs
 *   POST  /gateway-mikrotik-system/{cid}/changes/{feature}?operation=...
 *   GET   /gateway-mikrotik-interfaces/{cid}/ethernet | bridges | vlans | ...
 *   POST  /gateway-mikrotik-interfaces/{cid}/changes/{feature}?operation=...
 *   GET   /gateway-mikrotik-ip/{cid}/addresses | pools | arp
 *   POST  /gateway-mikrotik-ip/{cid}/changes/{feature}?operation=...
 *   GET   /gateway-mikrotik-routing/{cid}/routes | ospf/... | bgp/...
 *   POST  /gateway-mikrotik-routing/{cid}/changes/{feature}?operation=...
 *   GET   /gateway-mikrotik-dhcp/{cid}/servers | leases | networks
 *   POST  /gateway-mikrotik-dhcp/{cid}/changes/{feature}?operation=...
 *   GET   /gateway-mikrotik-firewall/{cid}/filter | nat | mangle | address-lists
 *   POST  /gateway-mikrotik-firewall/{cid}/changes/{feature}?operation=...
 *
 * Reads run live; writes return a ``PendingChangeResponse`` that the
 * operator applies via the shared ``/gateway-vpn/changes/{id}/apply``
 * endpoint (already in ``gateway.ts``).
 */
import { api } from './client';

// Helper to encode path segments safely.
const enc = (segment: string) => encodeURIComponent(String(segment ?? ''));

// ─── Shared envelope shapes ────────────────────────────────────────────

/**
 * Every list endpoint returns this envelope; ``items`` is the row
 * collection RouterOS returned (post-redaction). RouterOS REST has no
 * native pagination, so the backend trims after fetching everything.
 */
export interface MikroTikListResponse<T> {
  controller_id: string;
  items: T[];
  fetched_at: string;
  limit: number;
  offset: number;
  total: number;
}

/**
 * Singleton response shape · for endpoints that return a single row
 * (e.g. ``/system/identity``, ``/snmp`` settings). Re-used by
 * backup-metadata + neighbor-discovery-settings reads.
 */
export interface MikroTikSingletonResponse<T> {
  controller_id: string;
  item: T;
  fetched_at: string;
}

/** Payload for the stage endpoint · matches ``PendingChangeRequest``. */
export interface MikroTikChangeRequest {
  payload?: Record<string, unknown>;
  target_id?: string | null;
  notes?: string | null;
}

/** Response from the stage endpoint · matches ``PendingChangeResponse``. */
export interface MikroTikPendingChange {
  id: string;
  organization_id: string;
  controller_id: string | null;
  site_id: string | null;
  feature: string;
  operation: string;
  status: string;
  payload: Record<string, unknown>;
  target_id: string | null;
  notes: string | null;
  created_at: string;
  applied_at: string | null;
  applied_response: Record<string, unknown> | null;
  error: string | null;
  actor_id: string | null;
}

export type MikroTikOperation = 'create' | 'update' | 'delete';

// RouterOS REST surfaces row fields as kebab-case strings. We model
// every per-row interface as a permissive Record with the keys we
// know about typed concretely, plus a string-indexed fallback so a
// firmware quirk that adds new keys doesn't break compilation.

// ─── System domain ─────────────────────────────────────────────────────

/** ``/system/identity`` row · just a name. */
export interface MikroTikIdentity {
  name?: string;
  [key: string]: unknown;
}

/** ``/system/resource`` · CPU / RAM / uptime / version / board. */
export interface MikroTikResource {
  uptime?: string;
  version?: string;
  'build-time'?: string;
  'factory-software'?: string;
  'free-memory'?: string | number;
  'total-memory'?: string | number;
  cpu?: string;
  'cpu-count'?: string | number;
  'cpu-frequency'?: string | number;
  'cpu-load'?: string | number;
  'free-hdd-space'?: string | number;
  'total-hdd-space'?: string | number;
  'write-sect-since-reboot'?: string | number;
  'write-sect-total'?: string | number;
  'bad-blocks'?: string;
  'architecture-name'?: string;
  'board-name'?: string;
  platform?: string;
  [key: string]: unknown;
}

/** ``/system/routerboard`` · hardware metadata. */
export interface MikroTikRouterboard {
  routerboard?: string | boolean;
  model?: string;
  'serial-number'?: string;
  'firmware-type'?: string;
  'factory-firmware'?: string;
  'current-firmware'?: string;
  'upgrade-firmware'?: string;
  [key: string]: unknown;
}

/** ``/system/clock`` · time + timezone + (optionally) NTP servers. */
export interface MikroTikClock {
  time?: string;
  date?: string;
  'time-zone-name'?: string;
  'time-zone-autodetect'?: string | boolean;
  'dst-active'?: string | boolean;
  [key: string]: unknown;
}

export interface MikroTikSystemHealth {
  name?: string;
  value?: string;
  type?: string;
  [key: string]: unknown;
}

export interface MikroTikSystemInfoResponse {
  controller_id: string;
  identity: MikroTikIdentity;
  resource: MikroTikResource;
  routerboard: MikroTikRouterboard;
  license: Record<string, unknown>;
  clock: MikroTikClock;
  health: MikroTikSystemHealth[];
  packages: Array<Record<string, unknown>>;
  fetched_at: string;
}

// ─── Interfaces domain ─────────────────────────────────────────────────

export interface MikroTikEthernetInterface {
  '.id'?: string;
  name?: string;
  'default-name'?: string;
  'mac-address'?: string;
  mtu?: string | number;
  'l2mtu'?: string | number;
  disabled?: string | boolean;
  running?: string | boolean;
  'rx-byte'?: string | number;
  'tx-byte'?: string | number;
  'rx-packet'?: string | number;
  'tx-packet'?: string | number;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikBridgeInterface {
  '.id'?: string;
  name?: string;
  'mac-address'?: string;
  protocol?: string;
  mtu?: string | number;
  disabled?: string | boolean;
  running?: string | boolean;
  'vlan-filtering'?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

/**
 * Wireless interfaces come from the general ``/interface`` list filtered
 * by ``type`` (RouterOS has no dedicated /interface/wireless rows in
 * REST for RouterOS 7+; the wireless package may not be installed).
 * Treated as a generic interface row.
 */
export interface MikroTikGenericInterface {
  '.id'?: string;
  name?: string;
  type?: string;
  'mac-address'?: string;
  mtu?: string | number;
  disabled?: string | boolean;
  running?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

// ─── IP domain ─────────────────────────────────────────────────────────

export interface MikroTikIPAddress {
  '.id'?: string;
  address?: string;
  network?: string;
  interface?: string;
  'actual-interface'?: string;
  disabled?: string | boolean;
  dynamic?: string | boolean;
  invalid?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikIPPool {
  '.id'?: string;
  name?: string;
  ranges?: string;
  'next-pool'?: string;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikRoute {
  '.id'?: string;
  'dst-address'?: string;
  gateway?: string;
  'pref-src'?: string;
  distance?: string | number;
  scope?: string | number;
  'target-scope'?: string | number;
  'routing-table'?: string;
  'suppress-hw-offload'?: string | boolean;
  active?: string | boolean;
  static?: string | boolean;
  dynamic?: string | boolean;
  disabled?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

// ─── DHCP domain ───────────────────────────────────────────────────────

export interface MikroTikDHCPServer {
  '.id'?: string;
  name?: string;
  interface?: string;
  'address-pool'?: string;
  'lease-time'?: string;
  disabled?: string | boolean;
  invalid?: string | boolean;
  authoritative?: string | boolean;
  'add-arp'?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikDHCPLease {
  '.id'?: string;
  address?: string;
  'mac-address'?: string;
  'client-id'?: string;
  'address-lists'?: string;
  server?: string;
  'dhcp-option'?: string;
  status?: string;
  'expires-after'?: string;
  'last-seen'?: string;
  'active-address'?: string;
  'active-mac-address'?: string;
  'active-client-id'?: string;
  'active-server'?: string;
  'host-name'?: string;
  dynamic?: string | boolean;
  blocked?: string | boolean;
  disabled?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikDHCPNetwork {
  '.id'?: string;
  address?: string;
  gateway?: string;
  netmask?: string | number;
  'dns-server'?: string;
  'domain'?: string;
  'next-server'?: string;
  comment?: string;
  [key: string]: unknown;
}

// ─── Firewall domain ───────────────────────────────────────────────────

export interface MikroTikFirewallFilterRule {
  '.id'?: string;
  chain?: string;
  action?: string;
  protocol?: string;
  'src-address'?: string;
  'dst-address'?: string;
  'src-port'?: string;
  'dst-port'?: string;
  'in-interface'?: string;
  'out-interface'?: string;
  'connection-state'?: string;
  log?: string | boolean;
  'log-prefix'?: string;
  disabled?: string | boolean;
  dynamic?: string | boolean;
  invalid?: string | boolean;
  bytes?: string | number;
  packets?: string | number;
  comment?: string;
  [key: string]: unknown;
}

export interface MikroTikFirewallNATRule {
  '.id'?: string;
  chain?: string;
  action?: string;
  protocol?: string;
  'src-address'?: string;
  'dst-address'?: string;
  'src-port'?: string;
  'dst-port'?: string;
  'in-interface'?: string;
  'out-interface'?: string;
  'to-addresses'?: string;
  'to-ports'?: string;
  disabled?: string | boolean;
  dynamic?: string | boolean;
  invalid?: string | boolean;
  bytes?: string | number;
  packets?: string | number;
  comment?: string;
  [key: string]: unknown;
}

// ─── DNS domain ────────────────────────────────────────────────────────

/** ``/ip/dns`` singleton settings row. */
export interface MikroTikDNSSettings {
  servers?: string;
  'dynamic-servers'?: string;
  'use-doh-server'?: string;
  'verify-doh-cert'?: string | boolean;
  'allow-remote-requests'?: string | boolean;
  'max-udp-packet-size'?: string | number;
  'query-server-timeout'?: string;
  'query-total-timeout'?: string;
  'cache-size'?: string | number;
  'cache-max-ttl'?: string;
  'cache-used'?: string | number;
  [key: string]: unknown;
}

/** ``/ip/dns/static`` row. */
export interface MikroTikDNSStaticEntry {
  '.id'?: string;
  name?: string;
  type?: string;
  address?: string;
  cname?: string;
  'mx-preference'?: string | number;
  'mx-exchange'?: string;
  text?: string;
  ttl?: string;
  'regexp'?: string;
  comment?: string;
  disabled?: string | boolean;
  dynamic?: string | boolean;
  [key: string]: unknown;
}

/** ``/ip/dns/cache`` row · read-only. */
export interface MikroTikDNSCacheEntry {
  '.id'?: string;
  name?: string;
  data?: string;
  type?: string;
  ttl?: string;
  static?: string | boolean;
  [key: string]: unknown;
}

// ─── VPN domain (L2TP / PPTP / SSTP) ───────────────────────────────────

/**
 * ``/interface/l2tp-server/server`` singleton row. RouterOS exposes
 * the server config as a single row; the L2TP secrets live in the
 * shared ``/ppp/secret`` collection with ``service="l2tp"`` filtering
 * applied client-side.
 *
 * NOTE `ipsec-secret` is intentionally NOT declared here on
 * the *read* shape. The backend must redact the secret on GET; if the
 * adapter ever regresses and returns it, the strict type forces a
 * compile-time error rather than silently surfacing the secret into a
 * password input where DevTools can read it. The write path passes the
 * field through `Record<string, unknown>`, so this restriction only
 * applies to reads.
 */
export interface MikroTikL2TPServer {
  enabled?: string | boolean;
  'max-mtu'?: string | number;
  'max-mru'?: string | number;
  'mrru'?: string;
  authentication?: string;
  'keepalive-timeout'?: string;
  'default-profile'?: string;
  'use-ipsec'?: string | boolean;
  caller?: string;
  'one-session-per-host'?: string | boolean;
  [key: string]: unknown;
}

/** ``/interface/pptp-server/server`` singleton row · deprecated. */
export interface MikroTikPPTPServer {
  enabled?: string | boolean;
  'max-mtu'?: string | number;
  'max-mru'?: string | number;
  'mrru'?: string;
  authentication?: string;
  'keepalive-timeout'?: string;
  'default-profile'?: string;
  'one-session-per-host'?: string | boolean;
  [key: string]: unknown;
}

/** ``/ppp/secret`` row · shared L2TP / PPTP / PPPoE secrets. */
export interface MikroTikPPPSecret {
  '.id'?: string;
  name?: string;
  password?: string;
  service?: string;
  profile?: string;
  'local-address'?: string;
  'remote-address'?: string;
  'caller-id'?: string;
  'last-logged-out'?: string;
  comment?: string;
  disabled?: string | boolean;
  [key: string]: unknown;
}

/** ``/certificate`` row · read-only display for SSTP server. */
export interface MikroTikCertificate {
  '.id'?: string;
  name?: string;
  'common-name'?: string;
  subject?: string;
  issuer?: string;
  'serial-number'?: string;
  'fingerprint'?: string;
  'invalid-before'?: string;
  'invalid-after'?: string;
  trusted?: string | boolean;
  'private-key'?: string | boolean;
  ca?: string | boolean;
  [key: string]: unknown;
}

// ─── Hotspot domain ────────────────────────────────────────────────────

/** ``/ip/hotspot`` row (per-interface captive portal server). */
export interface MikroTikHotspotServer {
  '.id'?: string;
  name?: string;
  interface?: string;
  'address-pool'?: string;
  profile?: string;
  'idle-timeout'?: string;
  disabled?: string | boolean;
  invalid?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

/** ``/ip/hotspot/user/profile`` row (rate / quota template). */
export interface MikroTikHotspotUserProfile {
  '.id'?: string;
  name?: string;
  'rate-limit'?: string;
  'session-timeout'?: string;
  'idle-timeout'?: string;
  'keepalive-timeout'?: string;
  'shared-users'?: string | number;
  'mac-cookie-timeout'?: string;
  'address-pool'?: string;
  'address-list'?: string;
  default?: string | boolean;
  [key: string]: unknown;
}

/** ``/ip/hotspot/active`` row · read-only session. */
export interface MikroTikHotspotActive {
  '.id'?: string;
  user?: string;
  address?: string;
  'mac-address'?: string;
  'login-by'?: string;
  uptime?: string;
  'session-time-left'?: string;
  'idle-time'?: string;
  'bytes-in'?: string | number;
  'bytes-out'?: string | number;
  'packets-in'?: string | number;
  'packets-out'?: string | number;
  server?: string;
  comment?: string;
  [key: string]: unknown;
}

// ─── Queues domain ─────────────────────────────────────────────────────

/** ``/queue/simple`` row · target + max-limit + priority. */
export interface MikroTikSimpleQueue {
  '.id'?: string;
  name?: string;
  target?: string;
  'max-limit'?: string;
  'burst-limit'?: string;
  'burst-threshold'?: string;
  'burst-time'?: string;
  'limit-at'?: string;
  priority?: string | number;
  parent?: string;
  queue?: string;
  'packet-marks'?: string;
  'total-bytes'?: string | number;
  bytes?: string | number;
  packets?: string | number;
  disabled?: string | boolean;
  dynamic?: string | boolean;
  invalid?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

/** ``/queue/tree`` row · HTB tree node (read-only display). */
export interface MikroTikQueueTree {
  '.id'?: string;
  name?: string;
  parent?: string;
  'packet-mark'?: string;
  'queue'?: string;
  priority?: string | number;
  'max-limit'?: string;
  'limit-at'?: string;
  'burst-limit'?: string;
  'burst-threshold'?: string;
  'burst-time'?: string;
  disabled?: string | boolean;
  invalid?: string | boolean;
  bytes?: string | number;
  packets?: string | number;
  comment?: string;
  [key: string]: unknown;
}

// ─── Firmware lifecycle types ─────────────────────────────────

/**
 * ``/system/package/update`` row · shape returned by
 * MikroTikClient.get_update_status. ``status`` mirrors the RouterOS
 * field exactly so operators see the real RouterOS state machine.
 */
export interface MikroTikFirmwareStatus {
  channel?: string;
  'installed-version'?: string;
  'latest-version'?: string;
  status?: string;
  'last-checked'?: string;
  'last-error'?: string;
  [key: string]: unknown;
}

export interface MikroTikFirmwareStatusResponse {
  controller_id: string;
  item: MikroTikFirmwareStatus;
  fetched_at: string;
}

/** ``/system/package`` row · one installed package. */
export interface MikroTikPackage {
  '.id'?: string;
  name?: string;
  version?: string;
  'build-time'?: string;
  disabled?: string | boolean;
  'scheduled'?: string;
  'scheduled-action'?: string;
  [key: string]: unknown;
}

// ─── Backup types ─────────────────────────────────────────────

/** ``/file`` row filtered to .backup / .rsc files. */
export interface MikroTikBackupFile {
  '.id'?: string;
  name?: string;
  size?: string | number;
  type?: string;
  'creation-time'?: string;
  [key: string]: unknown;
}

/** Backup file content · base64 for binary, plain string for .rsc. */
export interface MikroTikBackupContent {
  controller_id: string;
  name: string;
  content: string;
  encoding: 'base64' | 'utf-8';
  size: number;
  fetched_at: string;
}

// ─── Topology / neighbor types ────────────────────────────────

/** ``/ip/neighbor`` row · discovered neighbor on any protocol. */
export interface MikroTikNeighbor {
  '.id'?: string;
  interface?: string;
  address?: string;
  'address4'?: string;
  'address6'?: string;
  'mac-address'?: string;
  identity?: string;
  platform?: string;
  version?: string;
  board?: string;
  'system-caps'?: string;
  'system-caps-enabled'?: string;
  'system-description'?: string;
  'interface-name'?: string;
  'discovered-by'?: string;
  age?: string;
  uptime?: string;
  [key: string]: unknown;
}

/** ``/ip/neighbor/discovery-settings`` singleton. */
export interface MikroTikNeighborDiscoverySettings {
  protocol?: string;
  'discover-interface-list'?: string;
  [key: string]: unknown;
}

/** ``/interface/lldp/interface`` per-interface LLDP state. */
export interface MikroTikLldpInterface {
  '.id'?: string;
  interface?: string;
  'system-name'?: string;
  'port-id'?: string;
  'management-address'?: string;
  'chassis-id'?: string;
  'capabilities'?: string;
  [key: string]: unknown;
}

/** Single node in the topology graph. */
export interface MikroTikTopologyNode {
  id: string;
  label: string;
  type: 'device' | 'neighbor';
  platform?: string;
  version?: string;
  address?: string;
  'mac-address'?: string;
}

/** Edge between nodes · protocol-coloured client-side. */
export interface MikroTikTopologyEdge {
  id: string;
  source: string;
  target: string;
  protocol: string; // lldp | cdp | mndp | other
  interface?: string;
}

export interface MikroTikTopologyResponse {
  controller_id: string;
  nodes: MikroTikTopologyNode[];
  edges: MikroTikTopologyEdge[];
  fetched_at: string;
}

// ─── SNMP CRUD types ──────────────────────────────────────────

/** ``/snmp/trap-target`` row, community + version + address. */
export interface MikroTikSnmpTrapTarget {
  '.id'?: string;
  address?: string;
  port?: string | number;
  version?: string;
  community?: string;
  comment?: string;
  disabled?: string | boolean;
  [key: string]: unknown;
}

/**
 * ``/snmp/community`` v3-user row · auth + encryption protocol metadata
 * ONLY. Passwords are write-only and never appear in the read response;
 * the frontend must never display or log them.
 */
export interface MikroTikSnmpV3User {
  '.id'?: string;
  name?: string;
  // RouterOS read path emits 'auth-protocol' (hyphenated short form).
  'auth-protocol'?: string;
  'authentication-protocol'?: string;
  'encryption-protocol'?: string;
  addresses?: string;
  'read-access'?: string | boolean;
  'write-access'?: string | boolean;
  comment?: string;
  [key: string]: unknown;
}

// ─── API surface ───────────────────────────────────────────────────────

/**
 * Stage a write against a MikroTik domain. ``feature`` MUST start with
 * the domain prefix (e.g. ``mikrotik.firewall.filter_rule``), the
 * backend rejects mismatches at 400.
 */
function stageChange(
  domain:
    | 'system'
    | 'interfaces'
    | 'ip'
    | 'routing'
    | 'dhcp'
    | 'firewall'
    | 'dns'
    | 'vpn'
    | 'hotspot'
    | 'queues'
    | 'security',
  controllerId: string,
  feature: string,
  operation: MikroTikOperation,
  body: MikroTikChangeRequest,
) {
  return api.post<MikroTikPendingChange>(
    `/gateway-mikrotik-${domain}/${enc(controllerId)}/changes/${enc(feature)}`,
    body,
    { params: { operation } },
  );
}

export const mikrotikApi = {
  // ── System ───────────────────────────────────────────────────────
  getSystemInfo: (controllerId: string) =>
    api.get<MikroTikSystemInfoResponse>(
      `/gateway-mikrotik-system/${enc(controllerId)}/info`,
    ),

  /**
   * Stage an identity-name change. The backend ``_APPLY`` table does
   * not currently include ``mikrotik.system.identity``; the stage
   * endpoint will accept it (feature-prefix matches) but apply will
   * fail with 400 "no applier" until the adapter is wired. This is the
   * documented stage-only path, apply is a follow-up.
   */
  stageIdentityUpdate: (controllerId: string, name: string) =>
    stageChange('system', controllerId, 'mikrotik.system.identity', 'update', {
      payload: { name },
    }),

  /**
   * Stage an NTP-servers change. Same caveat as identity, feature is
   * a documented extension point; apply requires adapter support.
   */
  stageNtpUpdate: (
    controllerId: string,
    primary: string | null,
    secondary: string | null,
  ) =>
    stageChange('system', controllerId, 'mikrotik.system.ntp', 'update', {
      payload: {
        'primary-ntp': primary ?? '',
        'secondary-ntp': secondary ?? '',
      },
    }),

  // ── Interfaces ───────────────────────────────────────────────────
  getEthernet: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikEthernetInterface>>(
      `/gateway-mikrotik-interfaces/${enc(controllerId)}/ethernet`,
    ),

  getBridges: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikBridgeInterface>>(
      `/gateway-mikrotik-interfaces/${enc(controllerId)}/bridges`,
    ),

  /**
   * Wireless interfaces don't have a dedicated endpoint, they're
   * filtered out of the general ``/list`` response client-side.
   */
  getAllInterfaces: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikGenericInterface>>(
      `/gateway-mikrotik-interfaces/${enc(controllerId)}/list`,
    ),

  /**
   * Bridge create/update/delete · maps to ``mikrotik.interfaces.bridge``.
   * The backend's _APPLY only ships VLAN sub-interface + bridge-vlan
   * + toggle currently; bridge CRUD is an extension point staged with
   * the same conventions as the rest of the domain.
   */
  createBridge: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange(
      'interfaces',
      controllerId,
      'mikrotik.interfaces.bridge',
      'create',
      { payload },
    ),

  updateBridge: (
    controllerId: string,
    bridgeId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange(
      'interfaces',
      controllerId,
      'mikrotik.interfaces.bridge',
      'update',
      { target_id: bridgeId, payload },
    ),

  deleteBridge: (controllerId: string, bridgeId: string) =>
    stageChange(
      'interfaces',
      controllerId,
      'mikrotik.interfaces.bridge',
      'delete',
      { target_id: bridgeId },
    ),

  /** Toggle any interface · maps to ``mikrotik.interfaces.toggle``. */
  toggleInterface: (
    controllerId: string,
    interfaceId: string,
    enabled: boolean,
  ) =>
    stageChange(
      'interfaces',
      controllerId,
      'mikrotik.interfaces.toggle',
      'create',
      { target_id: interfaceId, payload: { enabled } },
    ),

  // ── IP (addresses + pools) ───────────────────────────────────────
  getIPAddresses: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikIPAddress>>(
      `/gateway-mikrotik-ip/${enc(controllerId)}/addresses`,
    ),

  getIPPools: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikIPPool>>(
      `/gateway-mikrotik-ip/${enc(controllerId)}/pools`,
    ),

  /** IP address create · RouterOS doesn't expose a stable PATCH for
   *  ``/ip/address`` rows; renumber is delete-then-recreate. */
  createIPAddress: (
    controllerId: string,
    payload: { address: string; interface: string; comment?: string },
  ) =>
    stageChange('ip', controllerId, 'mikrotik.ip.address', 'create', {
      payload,
    }),

  deleteIPAddress: (controllerId: string, addressId: string) =>
    stageChange('ip', controllerId, 'mikrotik.ip.address', 'delete', {
      target_id: addressId,
    }),

  createIPPool: (
    controllerId: string,
    payload: { name: string; ranges: string; comment?: string },
  ) =>
    stageChange('ip', controllerId, 'mikrotik.ip.pool', 'create', { payload }),

  updateIPPool: (
    controllerId: string,
    poolId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('ip', controllerId, 'mikrotik.ip.pool', 'update', {
      target_id: poolId,
      payload,
    }),

  deleteIPPool: (controllerId: string, poolId: string) =>
    stageChange('ip', controllerId, 'mikrotik.ip.pool', 'delete', {
      target_id: poolId,
    }),

  // ── Routing (static routes live here, NOT in /ip) ────────────────
  getRoutes: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikRoute>>(
      `/gateway-mikrotik-routing/${enc(controllerId)}/routes`,
    ),

  createRoute: (
    controllerId: string,
    payload: {
      'dst-address': string;
      gateway: string;
      distance?: number | string;
      comment?: string;
    },
  ) =>
    stageChange('routing', controllerId, 'mikrotik.routing.static_route', 'create', {
      payload,
    }),

  updateRoute: (
    controllerId: string,
    routeId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('routing', controllerId, 'mikrotik.routing.static_route', 'update', {
      target_id: routeId,
      payload,
    }),

  deleteRoute: (controllerId: string, routeId: string) =>
    stageChange('routing', controllerId, 'mikrotik.routing.static_route', 'delete', {
      target_id: routeId,
    }),

  // ── DHCP ─────────────────────────────────────────────────────────
  getDHCPServers: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikDHCPServer>>(
      `/gateway-mikrotik-dhcp/${enc(controllerId)}/servers`,
    ),

  getDHCPLeases: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikDHCPLease>>(
      `/gateway-mikrotik-dhcp/${enc(controllerId)}/leases`,
    ),

  getDHCPNetworks: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikDHCPNetwork>>(
      `/gateway-mikrotik-dhcp/${enc(controllerId)}/networks`,
    ),

  createDHCPServer: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.server', 'create', {
      payload,
    }),

  updateDHCPServer: (
    controllerId: string,
    serverId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.server', 'update', {
      target_id: serverId,
      payload,
    }),

  deleteDHCPServer: (controllerId: string, serverId: string) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.server', 'delete', {
      target_id: serverId,
    }),

  /**
   * "Make static" from a dynamic lease · creates a new static lease
   * with the lease's MAC and IP. Backend feature is
   * ``mikrotik.dhcp.lease_static`` create.
   */
  makeLeaseStatic: (
    controllerId: string,
    lease: { 'mac-address'?: string; address?: string; server?: string; 'host-name'?: string; comment?: string },
  ) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.lease_static', 'create', {
      payload: {
        'mac-address': lease['mac-address'] ?? '',
        address: lease.address ?? '',
        server: lease.server ?? '',
        comment: lease.comment ?? lease['host-name'] ?? '',
      },
    }),

  createStaticLease: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.lease_static', 'create', {
      payload,
    }),

  updateStaticLease: (
    controllerId: string,
    leaseId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.lease_static', 'update', {
      target_id: leaseId,
      payload,
    }),

  deleteStaticLease: (controllerId: string, leaseId: string) =>
    stageChange('dhcp', controllerId, 'mikrotik.dhcp.lease_static', 'delete', {
      target_id: leaseId,
    }),

  // ── Firewall ─────────────────────────────────────────────────────
  getFilterRules: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikFirewallFilterRule>>(
      `/gateway-mikrotik-firewall/${enc(controllerId)}/filter`,
    ),

  getNATRules: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikFirewallNATRule>>(
      `/gateway-mikrotik-firewall/${enc(controllerId)}/nat`,
    ),

  createFilterRule: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.filter_rule', 'create', {
      payload,
    }),

  updateFilterRule: (
    controllerId: string,
    ruleId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.filter_rule', 'update', {
      target_id: ruleId,
      payload,
    }),

  deleteFilterRule: (controllerId: string, ruleId: string) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.filter_rule', 'delete', {
      target_id: ruleId,
    }),

  /**
   * Reorder filter rules · stages a ``mikrotik.firewall.filter_reorder``
   * change with the full ordered ID array. The applier wiring is a
   * follow-up, staging succeeds today, apply requires adapter work.
   */
  reorderFilterRules: (controllerId: string, orderedIds: string[]) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.filter_reorder', 'update', {
      payload: { order: orderedIds },
    }),

  createNATRule: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.nat_rule', 'create', {
      payload,
    }),

  updateNATRule: (
    controllerId: string,
    ruleId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.nat_rule', 'update', {
      target_id: ruleId,
      payload,
    }),

  deleteNATRule: (controllerId: string, ruleId: string) =>
    stageChange('firewall', controllerId, 'mikrotik.firewall.nat_rule', 'delete', {
      target_id: ruleId,
    }),

  // ── DNS ──────────────────────────────────────────────────────────
  getDNSSettings: (controllerId: string) =>
    api.get<{ controller_id: string; item: MikroTikDNSSettings; fetched_at: string }>(
      `/gateway-mikrotik-dns/${enc(controllerId)}/settings`,
    ),

  getDNSStatic: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikDNSStaticEntry>>(
      `/gateway-mikrotik-dns/${enc(controllerId)}/static`,
    ),

  getDNSCache: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikDNSCacheEntry>>(
      `/gateway-mikrotik-dns/${enc(controllerId)}/cache`,
    ),

  createDNSStatic: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('dns', controllerId, 'mikrotik.dns.static', 'create', {
      payload,
    }),

  updateDNSStatic: (
    controllerId: string,
    entryId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('dns', controllerId, 'mikrotik.dns.static', 'update', {
      target_id: entryId,
      payload,
    }),

  deleteDNSStatic: (controllerId: string, entryId: string) =>
    stageChange('dns', controllerId, 'mikrotik.dns.static', 'delete', {
      target_id: entryId,
    }),

  // ── VPN (L2TP / PPTP / SSTP) ─────────────────────────────────────
  getL2TPServer: (controllerId: string) =>
    api.get<{ controller_id: string; item: MikroTikL2TPServer; fetched_at: string }>(
      `/gateway-mikrotik-vpn/${enc(controllerId)}/l2tp/server`,
    ),

  getPPTPServer: (controllerId: string) =>
    api.get<{ controller_id: string; item: MikroTikPPTPServer; fetched_at: string }>(
      `/gateway-mikrotik-vpn/${enc(controllerId)}/pptp/server`,
    ),

  /**
   * Singleton L2TP server settings update. Maps to
   * ``mikrotik.vpn.l2tp_server`` (no target_id; payload is the full
   * PATCH body for ``/interface/l2tp-server/server``).
   */
  updateL2TPServer: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('vpn', controllerId, 'mikrotik.vpn.l2tp_server', 'update', {
      payload,
    }),

  /**
   * Singleton PPTP server settings update. Maps to
   * ``mikrotik.vpn.pptp_server``. Deprecated protocol, flagged in
   * the UI with a "deprecated" badge but kept available for legacy
   * deployments that still depend on it.
   */
  updatePPTPServer: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('vpn', controllerId, 'mikrotik.vpn.pptp_server', 'update', {
      payload,
    }),

  // ── Hotspot ──────────────────────────────────────────────────────
  getHotspotServers: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikHotspotServer>>(
      `/gateway-mikrotik-hotspot/${enc(controllerId)}/servers`,
    ),

  getHotspotUserProfiles: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikHotspotUserProfile>>(
      `/gateway-mikrotik-hotspot/${enc(controllerId)}/user-profiles`,
    ),

  getHotspotActive: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikHotspotActive>>(
      `/gateway-mikrotik-hotspot/${enc(controllerId)}/active`,
    ),

  createHotspotServer: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.server', 'create', {
      payload,
    }),

  updateHotspotServer: (
    controllerId: string,
    serverId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.server', 'update', {
      target_id: serverId,
      payload,
    }),

  deleteHotspotServer: (controllerId: string, serverId: string) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.server', 'delete', {
      target_id: serverId,
    }),

  createHotspotUserProfile: (
    controllerId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.user_profile', 'create', {
      payload,
    }),

  updateHotspotUserProfile: (
    controllerId: string,
    profileId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.user_profile', 'update', {
      target_id: profileId,
      payload,
    }),

  deleteHotspotUserProfile: (controllerId: string, profileId: string) =>
    stageChange('hotspot', controllerId, 'mikrotik.hotspot.user_profile', 'delete', {
      target_id: profileId,
    }),

  /**
   * Disconnect an active hotspot session. RouterOS exposes this as a
   * ``delete`` on ``/ip/hotspot/active`` rows, the corresponding
   * MikroTikClient method (``delete_hotspot_active``) isn't wired yet,
   * so we surface this as a deferred TODO and the UI
   * disables the button when the active row has no ``.id``. Once the
   * adapter exposes ``mikrotik.hotspot.active_disconnect`` we can
   * call it through here without UI churn.
   */
  // (intentionally unimplemented for now, see deferred list)

  // ── Queues ───────────────────────────────────────────────────────
  getSimpleQueues: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikSimpleQueue>>(
      `/gateway-mikrotik-queues/${enc(controllerId)}/simple`,
    ),

  getQueueTree: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikQueueTree>>(
      `/gateway-mikrotik-queues/${enc(controllerId)}/tree`,
    ),

  createSimpleQueue: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('queues', controllerId, 'mikrotik.queues.simple', 'create', {
      payload,
    }),

  updateSimpleQueue: (
    controllerId: string,
    queueId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('queues', controllerId, 'mikrotik.queues.simple', 'update', {
      target_id: queueId,
      payload,
    }),

  deleteSimpleQueue: (controllerId: string, queueId: string) =>
    stageChange('queues', controllerId, 'mikrotik.queues.simple', 'delete', {
      target_id: queueId,
    }),

  // ─── Firmware lifecycle ──────────────────────────────────
  // Routes live on the existing /gateway-mikrotik-system domain.
  // Adapter methods exist in the client; the HTTP route wiring is a
  // known backend gap, so these calls return 404 until the routes ship.
  // Backend returns a bare firmware-status dict (not a {item} envelope).
  getFirmwareStatus: (controllerId: string) =>
    api.get<MikroTikFirmwareStatus>(
      `/gateway-mikrotik-system/${enc(controllerId)}/firmware/status`,
    ),

  checkFirmwareUpdates: (controllerId: string) =>
    stageChange('system', controllerId, 'mikrotik.system.firmware.check', 'update', {
      payload: {},
    }),

  setFirmwareChannel: (controllerId: string, channel: string) =>
    stageChange('system', controllerId, 'mikrotik.system.firmware.channel', 'update', {
      payload: { channel },
    }),

  downloadFirmwareUpdate: (controllerId: string) =>
    stageChange('system', controllerId, 'mikrotik.system.firmware.download', 'update', {
      payload: {},
    }),

  installFirmwareUpdate: (controllerId: string) =>
    stageChange('system', controllerId, 'mikrotik.system.firmware.install', 'update', {
      payload: {},
    }),

  cancelFirmwareDownload: (controllerId: string) =>
    stageChange('system', controllerId, 'mikrotik.system.firmware.cancel', 'update', {
      payload: {},
    }),

  // Backend returns a bare packages array (not an {items} envelope).
  getInstalledPackages: (controllerId: string) =>
    api.get<MikroTikPackage[]>(
      `/gateway-mikrotik-system/${enc(controllerId)}/packages`,
    ),

  enablePackage: (controllerId: string, name: string) =>
    stageChange('system', controllerId, 'mikrotik.system.package.enable', 'update', {
      target_id: name,
      payload: { name },
    }),

  disablePackage: (controllerId: string, name: string) =>
    stageChange('system', controllerId, 'mikrotik.system.package.disable', 'update', {
      target_id: name,
      payload: { name },
    }),

  uninstallPackage: (controllerId: string, name: string) =>
    stageChange('system', controllerId, 'mikrotik.system.package.uninstall', 'delete', {
      target_id: name,
      payload: { name },
    }),

  // ─── Config backup / restore ─────────────────────────────
  // Backend returns a bare backups array (not an {items} envelope).
  listMikrotikBackups: (controllerId: string) =>
    api.get<MikroTikBackupFile[]>(
      `/gateway-mikrotik-system/${enc(controllerId)}/backup/list`,
    ),

  getBackupMetadata: (controllerId: string, name: string) =>
    api.get<MikroTikSingletonResponse<MikroTikBackupFile>>(
      `/gateway-mikrotik-system/${enc(controllerId)}/backup/metadata/${enc(name)}`,
    ),

  // Backend streams raw bytes (not a JSON {content,encoding} envelope), so
  // fetch the response as a blob and save resp.data directly.
  downloadBackupContent: (controllerId: string, name: string) =>
    api.get<Blob>(
      `/gateway-mikrotik-system/${enc(controllerId)}/backup/download/${enc(name)}`,
      { responseType: 'blob' },
    ),

  createBinaryBackup: (controllerId: string, name: string, password?: string) =>
    stageChange('system', controllerId, 'mikrotik.system.backup.create_binary', 'create', {
      payload: password ? { name, password } : { name },
    }),

  exportTextConfig: (
    controllerId: string,
    comment: string,
    encrypted: boolean,
  ) =>
    stageChange('system', controllerId, 'mikrotik.system.backup.export_text', 'create', {
      payload: { comment, encrypted },
    }),

  uploadBackupContent: (
    controllerId: string,
    name: string,
    content: string,
  ) =>
    stageChange('system', controllerId, 'mikrotik.system.backup.upload', 'create', {
      payload: { name, content },
    }),

  deleteMikrotikBackup: (controllerId: string, name: string) =>
    stageChange('system', controllerId, 'mikrotik.system.backup.delete', 'delete', {
      target_id: name,
      payload: { name },
    }),

  restoreMikrotikBackup: (
    controllerId: string,
    name: string,
    password?: string,
  ) =>
    stageChange('system', controllerId, 'mikrotik.system.backup.restore', 'update', {
      target_id: name,
      payload: password ? { name, password } : { name },
    }),

  // ─── Topology / neighbor discovery ───────────────────────
  // Backend returns a bare neighbors array (not an {items} envelope).
  getNeighbors: (controllerId: string) =>
    api.get<MikroTikNeighbor[]>(
      `/gateway-mikrotik-system/${enc(controllerId)}/neighbors`,
    ),

  // Backend returns a bare settings dict (not a {item} envelope).
  getNeighborDiscoverySettings: (controllerId: string) =>
    api.get<MikroTikNeighborDiscoverySettings>(
      `/gateway-mikrotik-system/${enc(controllerId)}/neighbors/settings`,
    ),

  updateNeighborDiscoverySettings: (
    controllerId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('system', controllerId, 'mikrotik.system.neighbor.settings', 'update', {
      payload,
    }),

  getLldpInterfaces: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikLldpInterface>>(
      `/gateway-mikrotik-system/${enc(controllerId)}/lldp`,
    ),

  buildTopology: (controllerId: string) =>
    api.get<MikroTikTopologyResponse>(
      `/gateway-mikrotik-system/${enc(controllerId)}/topology`,
    ),

  // ─── SNMP CRUD (trap-targets + SNMPv3 users) ─────────────
  // Lives on /gateway-mikrotik-security/{cid}/snmp/*, read endpoints
  // for /settings and /communities already exist. Trap targets and
  // SNMPv3 users are newly added.
  getSnmpTrapTargets: (controllerId: string) =>
    api.get<MikroTikListResponse<MikroTikSnmpTrapTarget>>(
      `/gateway-mikrotik-security/${enc(controllerId)}/snmp/trap-targets`,
    ),

  addSnmpTrapTarget: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.trap_target', 'create', {
      payload,
    }),

  updateSnmpTrapTarget: (
    controllerId: string,
    targetId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.trap_target', 'update', {
      target_id: targetId,
      payload,
    }),

  removeSnmpTrapTarget: (controllerId: string, targetId: string) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.trap_target', 'delete', {
      target_id: targetId,
    }),

  // Backend returns a bare SNMPv3-user array (not an {items} envelope).
  getSnmpV3Users: (controllerId: string) =>
    api.get<MikroTikSnmpV3User[]>(
      `/gateway-mikrotik-security/${enc(controllerId)}/snmp/v3-users`,
    ),

  /**
   * Add a SNMPv3 user. ``payload`` MUST never round-trip through the
   * read path, auth-password and privacy-password are write-only and
   * the GET endpoint returns the user list without password fields.
   */
  addSnmpV3User: (controllerId: string, payload: Record<string, unknown>) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.v3_user', 'create', {
      payload,
    }),

  /**
   * Update an existing SNMPv3 user. Same write-only contract as add,
   * passwords are only sent on update if the operator typed a new value.
   */
  updateSnmpV3User: (
    controllerId: string,
    userId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.v3_user', 'update', {
      target_id: userId,
      payload,
    }),

  deleteSnmpV3User: (controllerId: string, userId: string) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.v3_user', 'delete', {
      target_id: userId,
    }),

  updateSnmpSettings: (
    controllerId: string,
    payload: Record<string, unknown>,
  ) =>
    stageChange('security', controllerId, 'mikrotik.security.snmp.settings', 'update', {
      payload,
    }),
};

export type MikroTikApi = typeof mikrotikApi;
