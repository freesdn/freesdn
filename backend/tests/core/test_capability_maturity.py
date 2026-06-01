# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: the capability-maturity record is the in-product half of the
FEATURE-READINESS honesty rule (B1).

The 🔴 "built but unverified end-to-end" capabilities must read EXPERIMENTAL, the
default for anything unlisted must be EXPERIMENTAL (never silently presented as
production-ready), the earned ones read STABLE, and the 🔴 *modules* must carry
``is_beta`` so the Modules settings page badges them.
"""

from __future__ import annotations

from app.core.capability_maturity import (
    CAPABILITY_MATURITY,
    CapabilityMaturity,
    get_capability_maturity,
)


def test_unknown_capability_defaults_to_experimental():
    # The safe, non-overselling default — a forgotten/new capability is never
    # silently STABLE.
    assert get_capability_maturity("a_brand_new_thing").maturity is CapabilityMaturity.EXPERIMENTAL


def test_danger_zone_capabilities_are_experimental():
    # Still 🔴 — built but UNVERIFIED end-to-end. Promote one here only on real
    # evidence (live E2E / staged proof), never to look more finished than it is.
    for cap in (
        "ztp",
        "automation",
        "access_control",
        "vpn",
        "voip_freepbx_write",
    ):
        assert get_capability_maturity(cap).maturity is CapabilityMaturity.EXPERIMENTAL, cap


def test_verified_capabilities_are_beta():
    # Promoted 🔴→🟡 on real evidence: collector (live syslog ingest E2E), sso
    # (live OIDC E2E vs a real IdP + tamper tests), wifi_radius (staged-only
    # dual-gate + secret-at-rest + exact Omada-call proof). Each carries an
    # honest note naming what is NOT yet covered.
    for cap in ("collector", "sso", "wifi_radius"):
        assert get_capability_maturity(cap).maturity is CapabilityMaturity.BETA, cap


def test_earned_capabilities_are_stable():
    assert get_capability_maturity("backup_restore").maturity is CapabilityMaturity.STABLE
    assert get_capability_maturity("adapter_maturity").maturity is CapabilityMaturity.STABLE


def test_every_record_has_a_human_title():
    for cap_id, info in CAPABILITY_MATURITY.items():
        assert info.title, cap_id


def test_nonstable_modules_carry_the_beta_flag():
    # `is_beta` is the binary "show a non-stable badge on the Modules page" flag,
    # orthogonal to the 3-level capability maturity: both a BETA module (collector)
    # and an EXPERIMENTAL one (access_control) legitimately carry it.
    from app.modules.access_control.module import AccessControlModule
    from app.modules.collector.module import CollectorModule

    assert CollectorModule.get_manifest().is_beta is True
    assert AccessControlModule.get_manifest().is_beta is True
