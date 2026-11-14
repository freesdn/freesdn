// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The capability maturity record the demo serves at /capabilities/maturity.
 *
 * A COPY of backend/app/core/capability_maturity.py (the single source of
 * truth), because the static demo has no backend. Without it the demo answered
 * that route with the generic empty-list stub, and every maturity badge fell
 * back to Experimental: Backup & Restore (Stable) and SSO (Beta) included.
 * src/demo/__tests__/capabilityMaturityParity.test.ts fails when this copy and
 * the backend record disagree, so update both together.
 */
import type { CapabilityMaturityMap } from '@/lib/api/capabilities';

export const demoCapabilityMaturity: CapabilityMaturityMap = {
  backup_restore: {
    maturity: "stable",
    title: "Backup & Restore",
    notes:
      "Audited E2E; disaster-recovery drills proven (config + secrets survive restore and decrypt; first-install restore verified in a real browser).",
  },
  adapter_maturity: {
    maturity: "stable",
    title: "Adapter maturity honesty",
    notes:
      "Verified/Experimental badges driven by a single source of truth; VERIFIED requires real-hardware evidence and is never self-claimed.",
  },
  sso: {
    maturity: "beta",
    title: "SSO / OAuth2 / SAML / LDAP",
    notes:
      "OIDC verified live end-to-end against a real IdP (Keycloak): discovery, code exchange, JWKS signature + nonce + state checks, single-use replay defense, and tier-capped JIT provisioning. LDAP is implemented and unit-tested but not yet live-verified; SAML is intentionally disabled (501) pending an XSW-safe assertion validator.",
  },
  wifi_radius: {
    maturity: "beta",
    title: "WiFi / SSID / RADIUS / 802.1X",
    notes:
      "FreeSDN side verified: the RADIUS shared secret is encrypted at rest, and a WPA-Enterprise SSID change stages through the dual-gate to the exact correct Omada call (update_ssid_advanced -> PATCH .../ssids/{id}) without touching the controller. The live apply to real AP/RADIUS hardware is not yet exercised end-to-end.",
  },
  ztp: {
    maturity: "experimental",
    title: "Zero-touch provisioning",
    notes:
      "Adoption pipeline implemented (AdapterResult-honest); not yet proven E2E across the full provision→verify path on real gear.",
  },
  automation: {
    maturity: "experimental",
    title: "Automation engine",
    notes:
      "Event/manual triggers and notify/alert/camera/fabric/llm actions work and are honesty-gated; no full real-world vertical proven E2E yet.",
  },
  collector: {
    maturity: "beta",
    title: "Observability collector (SNMP/syslog/NetFlow)",
    notes:
      "Syslog ingest verified live end-to-end (external UDP → allowlist → source-IP→device resolution → parse → store) via the dedicated `collector` compose service. SNMP-trap and NetFlow share the same receiver/store path (unit-tested; not yet fired live). Syslog and traps now also publish `collector.syslog.received` / `collector.trap.received` onto the event bus, so an automation rule can act on them, severity-floored at warning and rate-capped per source; still BETA because that bridge has not been fired live against real gear.",
  },
  access_control: {
    maturity: "experimental",
    title: "Physical access control",
    notes:
      "Door/credential management works; physical door CONTROL refuses with 501 until a real door-controller adapter is added. Ships disabled by default.",
  },
  storage: {
    maturity: "experimental",
    title: "Storage (TrueNAS)",
    notes:
      "Reads are live-validated against a real appliance and cover pools, datasets, snapshots, disks, SMART, alerts and data-protection coverage. Reads, health rollup, the force gate, and snapshot create/delete are now VALIDATED LIVE against a real 26.0 appliance over Tailscale. Dataset create and scrub start are staged and dual-gated but not yet fired live. The backup destination is validated live end-to-end: save, restore, verify and PRUNE. The middleware has no file-delete on any version, so each backup is its own child dataset and retention destroys the dataset -- proven against the real box, space reclaimed. Snapshot rollback and dataset delete (the operator-facing staged ops) stay withheld pending a confirmation flow that names what they destroy.",
  },
  vpn: {
    maturity: "experimental",
    title: "VPN / overlay",
    notes:
      "Security audited (🟢); the live-tunnel soak against real infrastructure is still pending; do not assume the data path is proven.",
  },
  voip_freepbx_write: {
    maturity: "experimental",
    title: "FreePBX configuration writes",
    notes:
      "Reads are live-validated. The write transport is implemented: extension, ring-group and inbound-route creation was proven live once, without a recorded cassette; other entities are tested against mocks only.",
  },
  audit_log: {
    maturity: "beta",
    title: "Security audit trail",
    notes:
      "Auth + account-admin events now write a tamper-evident trail; broader per-domain CRUD coverage is still in progress.",
  },
  fabric: {
    maturity: "beta",
    title: "Fabric (universal interconnect)",
    notes:
      "Built through the visual builder; real cross-app verticals are only lightly exercised live.",
  },
  websocket: {
    maturity: "beta",
    title: "Real-time (WebSocket)",
    notes:
      "Works; reconnect behaviour at scale is not yet proven.",
  },
  plugins: {
    maturity: "beta",
    title: "External plugin system",
    notes:
      "Sandbox is hygiene, NOT a security boundary, by design; treat plugins like installing a Python package.",
  },
};
