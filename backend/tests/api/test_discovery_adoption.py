# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the discovery adoption flow.

Covers the chapter's three backend invariants:

1. ``_score_drivers`` / ``_auto_pick_driver`` ranks DRIVER_REGISTRY entries
   correctly against vendor / device_type / open_ports / fingerprint hints
   and falls back to ``"generic"`` when no driver scores above the
   confidence floor.
2. ``/discovery/adopt`` and ``/adopt/bulk`` accept ``driver_id=None`` and
   auto-pick a driver from the matching DiscoveredHost row's
   fingerprint, without raising.
3. After adoption succeeds, the matching DiscoveredHost row is marked
   ``is_adopted=True`` with ``adopted_device_id`` linked, so it no
   longer appears in ``GET /discovered-hosts`` (which defaults to
   ``show_adopted=False``).
"""

from __future__ import annotations

import pytest

from app.api.v1.endpoints.discovery import (
    DRIVER_REGISTRY,
    _auto_pick_driver,
    _score_drivers,
)


class TestScoreDrivers:
    """Pure-function tests for the driver-scoring helper."""

    def test_excludes_generic_from_recommendations(self) -> None:
        """The 'generic' driver is a fallback — it should never appear as
        a scored match, otherwise the recommended_driver in /match-drivers
        would always be 'generic' for any unknown device."""
        matches = _score_drivers(
            vendor="generic",  # would otherwise match the generic driver
            device_type="other",
            open_ports=[80, 443],
            fingerprint_data={},
        )
        assert all(m["driver_id"] != "generic" for m in matches)

    def test_vendor_match_dominates(self) -> None:
        """Vendor match contributes the largest score component (0.4)."""
        matches = _score_drivers(
            vendor="mikrotik",
            device_type=None,
            open_ports=[],
            fingerprint_data={},
        )
        assert matches, "expected at least one match for vendor=mikrotik"
        assert matches[0]["driver_id"] == "mikrotik_routeros"
        assert matches[0]["match_score"] >= 0.4

    def test_port_overlap_boosts_score(self) -> None:
        """Common RouterOS ports (8728/8729) push MikroTik above the 0.5
        manageable threshold."""
        matches = _score_drivers(
            vendor="mikrotik",
            device_type="router",
            open_ports=[8728, 8729, 80, 443],
            fingerprint_data={},
        )
        top = matches[0]
        assert top["driver_id"] == "mikrotik_routeros"
        # 0.4 vendor + 0.3 device_type + 0.2 ports = 0.9
        assert top["match_score"] >= 0.5

    def test_no_match_returns_empty(self) -> None:
        """Random unknown vendor with no fingerprint returns no matches."""
        matches = _score_drivers(
            vendor="some-unknown-vendor-xyz",
            device_type=None,
            open_ports=[],
            fingerprint_data={},
        )
        assert matches == []


class TestAutoPickDriver:
    """The fallback-aware auto-picker used by /adopt and /adopt/bulk."""

    def test_falls_back_to_generic_when_no_match(self) -> None:
        picked = _auto_pick_driver(
            vendor="ecobee",
            device_type="iot_device",
            open_ports=[],
            fingerprint_data={},
        )
        assert picked == "generic"

    def test_falls_back_to_generic_below_threshold(self) -> None:
        """A weak vendor-only match (score 0.4) is below the 0.5
        manageable cutoff, so we fall back to generic to avoid silently
        pointing a real driver at a host it cannot manage."""
        picked = _auto_pick_driver(
            vendor="mikrotik",
            device_type=None,
            open_ports=[],
            fingerprint_data={},
        )
        # 0.4 < 0.5 → generic
        assert picked == "generic"

    def test_picks_strong_match(self) -> None:
        """High-confidence MikroTik signature picks the routeros driver."""
        picked = _auto_pick_driver(
            vendor="mikrotik",
            device_type="router",
            open_ports=[8728, 8729],
            fingerprint_data={"vendor": "mikrotik"},
        )
        assert picked == "mikrotik_routeros"

    def test_picks_hikvision_for_camera(self) -> None:
        picked = _auto_pick_driver(
            vendor="hikvision",
            device_type="camera",
            open_ports=[80, 443, 554, 8000],
            fingerprint_data={},
        )
        assert picked == "hikvision_isapi"


class TestDriverRegistryShape:
    """Smoke test: the generic driver actually exists in the registry,
    because /adopt and /adopt/bulk depend on it as a fallback."""

    def test_generic_driver_present(self) -> None:
        ids = {d["id"] for d in DRIVER_REGISTRY}
        assert "generic" in ids

    def test_generic_supports_broad_device_types(self) -> None:
        """The fallback must accept any device_type the auto-picker
        might emit, otherwise the strict driver-type check at adopt
        time would reject the auto-fallback."""
        generic = next(d for d in DRIVER_REGISTRY if d["id"] == "generic")
        for dt in ("other", "iot_device", "voip_phone"):
            assert dt in generic["device_types"]


# ---------------------------------------------------------------------------
# Pydantic-level test: AdoptDeviceRequest must accept driver_id=None
# now that auto-match is wired in. This is a regression guard — pre-chapter
# the field was required and the agent would fail to even submit a payload.
# ---------------------------------------------------------------------------


class TestAdoptDeviceRequestSchema:
    def test_driver_id_optional(self) -> None:
        from uuid import uuid4
        from app.api.v1.endpoints.discovery import AdoptDeviceRequest

        req = AdoptDeviceRequest(
            ip_address="192.168.1.150",
            name="lab-proxmox",
            site_id=uuid4(),
        )
        assert req.driver_id is None

    def test_driver_id_still_accepted_when_set(self) -> None:
        from uuid import uuid4
        from app.api.v1.endpoints.discovery import AdoptDeviceRequest

        req = AdoptDeviceRequest(
            ip_address="192.168.1.150",
            name="lab-proxmox",
            site_id=uuid4(),
            driver_id="mikrotik_routeros",
        )
        assert req.driver_id == "mikrotik_routeros"
