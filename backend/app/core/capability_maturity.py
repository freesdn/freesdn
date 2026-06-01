# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Capability maturity — the honest feature-readiness record, in the product.
=========================================================================

The capability-level sibling of ``app/adapters/maturity.py``. THE single source
of truth for "how proven is this *feature*?", so the UI / docs / README never
present a capability as production-ready when it has only ever been *assumed* to
work end-to-end. This is the in-product half of the FEATURE-READINESS matrix and
exists for one reason: the VPN lesson — we nearly shipped "ready" over a feature
that had never run live.

Honesty rules (mirror the adapter record + the readiness rubric):

* **STABLE is earned, never assumed** — granted here only for a capability that
  has been verified end-to-end against real infrastructure (🟢 in the matrix).
* **EXPERIMENTAL = built but UNVERIFIED end-to-end** (🔴 — the danger zone). It
  works in code/tests but has not been proven live; surface it as such.
* **BETA = works, partially verified** (🟡) — real evidence with known gaps.
* **Anything not listed defaults to EXPERIMENTAL** — the safe, non-overselling
  default, so a new capability is never silently presented as production-ready.

Owner-reviewed: promote a capability (→ BETA / STABLE) here only when the
evidence is real, exactly as the adapter record requires hardware evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CapabilityMaturity(StrEnum):
    """Honest readiness of a user-facing capability."""

    STABLE = "stable"  # 🟢 audited E2E against real infra
    BETA = "beta"  # 🟡 works, real evidence, known gaps
    EXPERIMENTAL = "experimental"  # 🔴 built but UNVERIFIED end-to-end


@dataclass(frozen=True)
class CapabilityInfo:
    """A capability's honest maturity + a human title and note."""

    maturity: CapabilityMaturity
    title: str
    notes: str = ""


_STABLE = CapabilityMaturity.STABLE
_BETA = CapabilityMaturity.BETA
_EXPERIMENTAL = CapabilityMaturity.EXPERIMENTAL

# capability id -> honest maturity. Absent ⇒ EXPERIMENTAL (see ``get_capability_maturity``).
# Mirrors the FEATURE-READINESS matrix; keep it HONEST — promote only on evidence.
CAPABILITY_MATURITY: dict[str, CapabilityInfo] = {
    # ── 🟢 STABLE — audited end-to-end with linked evidence ──
    "backup_restore": CapabilityInfo(
        _STABLE,
        "Backup & Restore",
        "Audited E2E; disaster-recovery drills proven (config + secrets survive "
        "restore and decrypt; first-install restore verified in a real browser).",
    ),
    "adapter_maturity": CapabilityInfo(
        _STABLE,
        "Adapter maturity honesty",
        "Verified/Experimental badges driven by a single source of truth; VERIFIED "
        "requires real-hardware evidence and is never self-claimed.",
    ),
    # ── 🔴 EXPERIMENTAL — built but UNVERIFIED end-to-end (the danger zone) ──
    "sso": CapabilityInfo(
        _BETA,
        "SSO / OAuth2 / SAML / LDAP",
        "OIDC verified live end-to-end against a real IdP (Keycloak): discovery, "
        "code exchange, JWKS signature + nonce + state checks, single-use replay "
        "defense, and tier-capped JIT provisioning. LDAP is implemented and "
        "unit-tested but not yet live-verified; SAML is intentionally disabled "
        "(501) pending an XSW-safe assertion validator.",
    ),
    "wifi_radius": CapabilityInfo(
        _BETA,
        "WiFi / SSID / RADIUS / 802.1X",
        "FreeSDN side verified: the RADIUS shared secret is encrypted at rest, and "
        "a WPA-Enterprise SSID change stages through the dual-gate to the exact "
        "correct Omada call (update_ssid_advanced -> PATCH .../ssids/{id}) without "
        "touching the controller. The live apply to real AP/RADIUS hardware is not "
        "yet exercised end-to-end.",
    ),
    "ztp": CapabilityInfo(
        _EXPERIMENTAL,
        "Zero-touch provisioning",
        "Adoption pipeline implemented (AdapterResult-honest); not yet proven E2E "
        "across the full provision→verify path on real gear.",
    ),
    "automation": CapabilityInfo(
        _EXPERIMENTAL,
        "Automation engine",
        "Event/manual triggers and notify/alert/camera/fabric/llm actions work and "
        "are honesty-gated; no full real-world vertical proven E2E yet.",
    ),
    "collector": CapabilityInfo(
        _BETA,
        "Observability collector (SNMP/syslog/NetFlow)",
        "Syslog ingest verified live end-to-end (external UDP → allowlist → "
        "source-IP→device resolution → parse → store) via the dedicated `collector` "
        "compose service. SNMP-trap and NetFlow share the same receiver/store path "
        "(unit-tested; not yet fired live).",
    ),
    "access_control": CapabilityInfo(
        _EXPERIMENTAL,
        "Physical access control",
        "Door/credential management works; physical door CONTROL refuses with 501 "
        "until a real door-controller adapter is added. Ships disabled by default.",
    ),
    "vpn": CapabilityInfo(
        _EXPERIMENTAL,
        "VPN / overlay",
        "Security audited (🟢); the live-tunnel soak against real infrastructure is "
        "still pending — do not assume the data path is proven.",
    ),
    "voip_freepbx_write": CapabilityInfo(
        _EXPERIMENTAL,
        "FreePBX configuration writes",
        "Reads are live-validated; the configuration-WRITE transport is stubbed — "
        "writes are not yet functional.",
    ),
    # ── 🟡 BETA — works, real evidence, known gaps ──
    "audit_log": CapabilityInfo(
        _BETA,
        "Security audit trail",
        "Auth + account-admin events now write a tamper-evident trail; broader "
        "per-domain CRUD coverage is still in progress.",
    ),
    "fabric": CapabilityInfo(
        _BETA,
        "Fabric (universal interconnect)",
        "Built through the visual builder; real cross-app verticals are only "
        "lightly exercised live.",
    ),
    "websocket": CapabilityInfo(
        _BETA,
        "Real-time (WebSocket)",
        "Works; reconnect behaviour at scale is not yet proven.",
    ),
    "plugins": CapabilityInfo(
        _BETA,
        "External plugin system",
        "Sandbox is hygiene, NOT a security boundary, by design — treat plugins "
        "like installing a Python package.",
    ),
}


def get_capability_maturity(capability_id: str) -> CapabilityInfo:
    """Honest maturity for a capability id.

    This record is authoritative. Anything not listed defaults to EXPERIMENTAL:
    STABLE/BETA are never assumed, so a forgotten or brand-new capability is never
    silently presented as production-ready.
    """
    return CAPABILITY_MATURITY.get(
        capability_id,
        CapabilityInfo(_EXPERIMENTAL, capability_id.replace("_", " ").title()),
    )
