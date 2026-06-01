# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada adapter — replay against REAL recorded controller payloads.

These cassettes were captured from a real Omada controller (see
tests/fixtures_harness/README.md). They exercise the adapter's parsing /
normalization against the device's *actual* responses, so a vendor field
rename or restructure breaks here instead of slipping past a hand-written mock.

Cassettes live in the off-repo recordings folder (FREESDN_CASSETTE_DIR); when
absent (public CI / contributor machines) these tests SKIP, never fail.
Assertions are STRUCTURAL only (counts/types/normalization) — never real device
values — so this shipped test file carries no lab fingerprints.

Record: FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo dir> against the
live controller (the recorder builds the adapter from the stored controller).
"""

from __future__ import annotations

import re

import pytest

from app.adapters.base import DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette

_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


async def _adapter():
    """Omada adapter for record (from live controller) or replay (dummy params)."""
    return await cassette_adapter(
        "omada",
        host="https://omada.invalid",
        username="replay",
        password="replay",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        mode="local",
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("omada/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    assert len(devices) >= 1  # the real device list parsed (not silently emptied)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type
        if d.mac_address:
            assert _MAC_RE.match(d.mac_address), f"unnormalized MAC: {d.mac_address!r}"


@pytest.mark.asyncio
async def test_get_sites_parses_real_payload() -> None:
    with use_cassette("omada/get_sites", verify_ssl=False):
        async with await _adapter() as adapter:
            sites = await adapter.get_sites()
    assert isinstance(sites, list)
    assert len(sites) >= 1
    assert all(isinstance(s, dict) for s in sites)


@pytest.mark.asyncio
async def test_get_switches_parses_real_payload() -> None:
    with use_cassette("omada/get_switches", verify_ssl=False):
        async with await _adapter() as adapter:
            switches = await adapter.get_switches()
    assert isinstance(switches, list)
    assert all(isinstance(s, dict) for s in switches)


@pytest.mark.asyncio
async def test_get_access_points_degrades_gracefully() -> None:
    # On this controller version the AP endpoint returns "Unsupported request
    # path"; the adapter must degrade to an empty list, not raise. This cassette
    # locks in that real version-compat behavior.
    with use_cassette("omada/get_access_points", verify_ssl=False):
        async with await _adapter() as adapter:
            aps = await adapter.get_access_points()
    assert isinstance(aps, list)


@pytest.mark.asyncio
async def test_get_clients_parses_real_payload() -> None:
    with use_cassette("omada/get_clients", verify_ssl=False):
        async with await _adapter() as adapter:
            clients = await adapter.get_clients()
    assert isinstance(clients, list)
    assert len(clients) >= 1  # real client list parsed
    for c in clients[:20]:
        assert isinstance(c, dict)
        assert "mac" in c or "mac_address" in c


@pytest.mark.asyncio
async def test_get_firmware_overview_parses_real_payload() -> None:
    with use_cassette("omada/get_firmware_overview", verify_ssl=False):
        async with await _adapter() as adapter:
            overview = await adapter.get_firmware_overview()
    assert isinstance(overview, dict)
    assert overview  # non-empty normalized firmware summary
