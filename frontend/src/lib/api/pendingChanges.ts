// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Pending Changes API client
 * ====================================
 *
 * Talks to the staging endpoints that back the Pending Changes drawer
 * on ``GatewayDetailPage``. All gateway vendors (mikrotik, pfsense,
 * opnsense, openwrt) write into the SAME ``adapter_pending_changes``
 * table, but the LIST endpoint is split per feature domain because
 * each domain checks a different permission tier.
 *
 * Strategy:
 *   - ``listChangesForGateway`` fans out to every known per-domain list
 *     endpoint for the vendor in parallel via ``Promise.allSettled``
 *     and merges the results. Domains the operator lacks permission
 *     for fail silently (we don't want a missing permission on one
 *     module to hide pending writes the operator DID stage in another).
 *   - ``applyChange`` and ``discardChange`` are unified, the backend
 *     resolves the right service by ``change.feature`` prefix.
 *
 * Re-uses generated types so a backend signature change fails tsc here.
 * Run ``npm run gen:api`` after a backend change to refresh.
 */

import { AxiosError } from 'axios';

import { api } from './client';
import type {
  ChangeStatus,
  PendingChangeResponse,
} from './gatewayCommon';
import type { ApiSchemas } from './generated';

// ── Re-exports ─────────────────────────────────────────────────────────

export type { ChangeStatus, PendingChangeResponse };
export type ApplyPendingChangeRequest =
  ApiSchemas['ApplyPendingChangeRequest'];

// ── Path safety ────────────────────────────────────────────────────────

const enc = (segment: string) => encodeURIComponent(String(segment ?? ''));

// ── Vendor → domain map ────────────────────────────────────────────────
//
// Each entry is a ``/gateway-<vendor>-<domain>`` route segment. The
// path ``${segment}/${controllerId}/changes`` is the per-domain list
// endpoint. Keep these in sync with the backend ``endpoints/`` folder.
//
// The merge query targets the union of these segments and ignores any
// 4xx/5xx response, so adding or removing a backend domain is safe,
// missing routes drop out of the response without crashing the UI.

const MIKROTIK_DOMAINS = [
  'system',
  'interfaces',
  'ip',
  'dhcp',
  'firewall',
  'dns',
  'vpn',
  'hotspot',
  'queues',
  'routing',
  'security',
  'capsman',
  'ppp',
] as const;

const PFSENSE_DOMAINS = [
  'system',
  'interfaces',
  'firewall',
  'nat',
  'dhcp',
  'dns',
  'routing',
  'vpn',
  'services',
  'diagnostics',
] as const;

const OPNSENSE_DOMAINS = [
  'system',
  'interfaces',
  'firewall',
  'nat',
  'dhcp',
  'dns',
  'routing',
  'vpn',
  'services',
  'shaper',
  'ids',
  'cron',
  'diagnostics',
] as const;

// OpenWrt per-domain stage endpoints. DHCP endpoint serves
// both ``openwrt.dhcp.*`` and ``openwrt.dns.*`` features (single domain
// in the FE fanout, dnsmasq owns both). Each adapter write self-applies
// at the OpenWrt box (uci_commit + service reload) so no separate apply
// feature is needed.
const OPENWRT_DOMAINS = ['firewall', 'dhcp'] as const;

// UniFi per-domain stage endpoints landed in the stage-and-apply
// build-out. UniFi is a Controller (in ``core.controllers``)
// not a Gateway (in ``firewall.gateway_connections``), but the
// polymorphic resolver accepts either id shape and the drawer keys its
// fanout on the ``gateway-<vendor>-<domain>`` URL prefix, uniform with
// the MikroTik/pfSense/OPNsense fleet.
const UNIFI_DOMAINS = [
  'clients',
  'devices',
  'wlans',
  'networks',
  'firewall',
  'traffic',
  'dns',
  // The remaining six per-domain routers. Omitting them meant a change
  // staged on any of these tabs (routing/VPN/switch/port-profiles/
  // WLAN-groups/radios) never surfaced in the Pending-Changes drawer, so
  // it could be STAGED but never reviewed or APPLIED. Segments must match
  // the backend ``gateway-unifi-<segment>`` router prefixes verbatim
  // (note the hyphenated ``port-profiles`` / ``wlan-groups``).
  'routing',
  'vpn',
  'switch',
  'port-profiles',
  'wlan-groups',
  'radios',
  'radius',
  'hotspot',
] as const;

// FreePBX per-domain stage endpoints. These map to the
// ``gateway-freepbx-<domain>`` routers; their staged features namespace
// under ``pbx.<domain>.*`` (the by-gateway fast path maps freepbx -> pbx.).
const FREEPBX_DOMAINS = [
  'extensions',
  'trunks',
  'ring-groups',
  'queues',
  'ivr',
  'inbound-routes',
] as const;

export type GatewayVendor =
  | 'mikrotik'
  | 'pfsense'
  | 'opnsense'
  | 'openwrt'
  | 'unifi'
  | 'freepbx';

function domainsForVendor(vendor: GatewayVendor): readonly string[] {
  switch (vendor) {
    case 'mikrotik':
      return MIKROTIK_DOMAINS;
    case 'pfsense':
      return PFSENSE_DOMAINS;
    case 'opnsense':
      return OPNSENSE_DOMAINS;
    case 'openwrt':
      return OPENWRT_DOMAINS;
    case 'unifi':
      return UNIFI_DOMAINS;
    case 'freepbx':
      return FREEPBX_DOMAINS;
  }
}

function vendorPrefix(vendor: GatewayVendor): string {
  switch (vendor) {
    case 'mikrotik':
      return 'gateway-mikrotik';
    case 'pfsense':
      return 'gateway-pfsense';
    case 'opnsense':
      return 'gateway-opnsense';
    case 'openwrt':
      return 'gateway-openwrt';
    case 'unifi':
      return 'gateway-unifi';
    case 'freepbx':
      return 'gateway-freepbx';
  }
}

// ── Listing ────────────────────────────────────────────────────────────

export interface ListChangesParams {
  /** Status filter, backend default is ``pending``. Pass ``"all"`` to skip the filter. */
  status?: ChangeStatus | 'all';
  /** Per-domain row cap; merged results may exceed this. Defaults to 200. */
  limit?: number;
}

/**
 * Fetch all pending/applied/failed changes for a gateway across every
 * known feature domain for its vendor.
 *
 * Resilient: a failing domain endpoint (404, 403, 500) does not abort
 * the whole list, its rows are simply absent. This matches operator
 * expectation: "show me what I've staged on this box" must work even
 * if one module is broken.
 */
export async function listChangesForGateway(
  vendor: GatewayVendor,
  gatewayId: string,
  params: ListChangesParams = {},
): Promise<PendingChangeResponse[]> {
  const domains = domainsForVendor(vendor);
  if (domains.length === 0) return [];

  const queryParams: Record<string, string | number> = { vendor };
  if (params.status) {
    queryParams.status = params.status;
  }
  if (params.limit) queryParams.limit = params.limit;

  // Fast path: a single batched endpoint
  // returns every domain's staged rows in one SQL query via a
  // feature-prefix LIKE. Replaces the per-domain fanout (up to 13
  // HTTP calls per drawer open for MikroTik). The per-domain
  // ``/gateway-{vendor}-{domain}/changes`` endpoints remain for
  // drilldown views and as a fallback on 404/500 here.
  try {
    const resp = await api.get<PendingChangeResponse[]>(
      `/gateway-vpn/changes/by-gateway/${enc(gatewayId)}`,
      { params: queryParams },
    );
    // Server already orders desc; no merge needed.
    return resp.data;
  } catch {
    // Fall back to the historical per-domain fanout. The fast-path
    // endpoint is recent; on a backend that doesn't have
    // it yet, this preserves correctness while we wait for the
    // deploy to roll out.
    return _listChangesByDomainFanout(vendor, gatewayId, params);
  }
}

async function _listChangesByDomainFanout(
  vendor: GatewayVendor,
  gatewayId: string,
  params: ListChangesParams,
): Promise<PendingChangeResponse[]> {
  const domains = domainsForVendor(vendor);
  if (domains.length === 0) return [];

  const prefix = vendorPrefix(vendor);
  const queryParams: Record<string, string | number> = {};
  if (params.status && params.status !== 'all') {
    queryParams.status = params.status;
  }
  if (params.limit) queryParams.limit = params.limit;

  const results = await Promise.allSettled(
    domains.map((domain) =>
      api.get<PendingChangeResponse[]>(
        `/${prefix}-${enc(domain)}/${enc(gatewayId)}/changes`,
        { params: queryParams },
      ),
    ),
  );

  const merged: PendingChangeResponse[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const change of r.value.data) {
      if (seen.has(change.id)) continue;
      seen.add(change.id);
      merged.push(change);
    }
  }
  // Newest first, staging service already orders desc within a domain,
  // but the merge reshuffles by domain order.
  merged.sort((a, b) => b.created_at.localeCompare(a.created_at));
  return merged;
}

// ── Mutate ─────────────────────────────────────────────────────────────

/**
 * Push a staged change to the live device.
 *
 * Forces ``{force: true}`` server-side, there is no UI opt-out for the
 * force flag because the drawer is the ONLY apply path. The other half
 * of the dual-gate (``OMADA_READ_ONLY=false``) is environment-only.
 *
 * ``confirmed`` is the operator's deliberate sign-off for a CATASTROPHIC or
 * destructive change (any delete, plus device restart/disable/upgrade and
 * client forget). The vendor pre-flights refuse such ops unless the apply
 * carries it; the drawer surfaces a confirm dialog for those changes and
 * passes ``confirmed: true`` only after the operator acknowledges. A
 * non-destructive apply omits it and stays one-click.
 */
export function applyChange(changeId: string, opts?: { confirmed?: boolean }) {
  return api.post<PendingChangeResponse>(
    `/gateway-vpn/changes/${enc(changeId)}/apply`,
    { force: true, confirmed: opts?.confirmed ?? false },
  );
}

/** Discard a staged change without applying it. */
export function discardChange(changeId: string) {
  return api.post<PendingChangeResponse>(
    `/gateway-vpn/changes/${enc(changeId)}/discard`,
  );
}

// ── Staging (FreePBX) ───────────────────────────────────────────────────

export type FreePBXDomain =
  | 'extensions'
  | 'trunks'
  | 'ring-groups'
  | 'queues'
  | 'ivr'
  | 'inbound-routes';

export interface StagePbxChangeParams {
  /** ``voip.pbx`` row id. */
  pbxId: string;
  /** URL domain segment, e.g. ``extensions`` -> /gateway-freepbx-extensions. */
  domain: FreePBXDomain;
  /** Dotted feature, e.g. ``pbx.extension.update``. */
  feature: string;
  operation: 'create' | 'update' | 'delete';
  /** Config payload to push on apply (omit for delete). */
  payload?: Record<string, unknown>;
  /** Entity id for update / delete (omit for create). */
  targetId?: string | null;
  /** Free-text change note. */
  notes?: string | null;
}

/**
 * Stage a FreePBX config change. Records a pending row — never touches the
 * live PBX. The operator applies it later via the Pending Changes drawer
 * (which rides the ADAPTER_READ_ONLY + force dual-gate).
 */
export function stagePbxChange(p: StagePbxChangeParams) {
  return api.post<PendingChangeResponse>(
    `/gateway-freepbx-${p.domain}/${enc(p.pbxId)}/changes/${enc(p.feature)}`,
    {
      payload: p.payload ?? {},
      target_id: p.targetId ?? null,
      notes: p.notes ?? null,
    },
    { params: { operation: p.operation } },
  );
}

// ── Error helpers ──────────────────────────────────────────────────────

export interface ApplyErrorInfo {
  status: number | null;
  /** Best-effort human message extracted from the response body. */
  message: string;
  /** True if the backend rejected because ``OMADA_READ_ONLY=true``. */
  isReadOnly: boolean;
  /** True if the operator lacks the role/permission for this feature. */
  isForbidden: boolean;
  /** RouterOS / vendor adapter's own response, if surfaced. */
  vendorError?: string;
}

/**
 * Normalize an axios error from ``applyChange`` into the fields the
 * drawer renders. Keeps the parsing logic in one place so the
 * read-only banner and the per-row failure message stay in sync.
 */
export function describeApplyError(err: unknown): ApplyErrorInfo {
  const info: ApplyErrorInfo = {
    status: null,
    message: 'Apply failed',
    isReadOnly: false,
    isForbidden: false,
  };

  if (!(err instanceof AxiosError)) {
    if (err instanceof Error) info.message = err.message;
    return info;
  }

  info.status = err.response?.status ?? null;
  const data = err.response?.data as
    | {
        detail?: string | { msg?: string }[];
        applied_response?: { error?: string };
      }
    | undefined;

  // Pydantic returns ``detail`` as a list of validation errors; FastAPI
  // HTTPException returns ``detail`` as a string. Handle both.
  let detail: string | undefined;
  if (typeof data?.detail === 'string') {
    detail = data.detail;
  } else if (Array.isArray(data?.detail) && data.detail[0]?.msg) {
    detail = data.detail[0].msg;
  }
  if (detail) info.message = detail;

  if (info.status === 403) {
    info.isForbidden = true;
    // Backend can surface the read-only gate as either the legacy
    // ``OMADA_READ_ONLY`` env name, the broader ``ADAPTER_READ_ONLY``,
    // or the plain "read-only" / "read only" phrasing from a pydantic
    // / role-check rejection. All three should light up the banner.
    if (
      detail &&
      /OMADA_READ_ONLY|ADAPTER_READ_ONLY|read[- _]only/i.test(detail)
    ) {
      info.isReadOnly = true;
    }
  }

  // 502 carries the RouterOS-side rejection in applied_response.error
  if (info.status === 502 && data?.applied_response?.error) {
    info.vendorError = data.applied_response.error;
  }

  return info;
}
