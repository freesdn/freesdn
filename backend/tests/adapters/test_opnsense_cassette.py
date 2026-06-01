# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OPNsense adapter — replay against REAL recorded firewall payloads.

Cassettes captured from a real OPNsense firewall (see fixtures_harness/README).
They exercise the adapter's parsing/normalization against the device's *actual*
responses. Cassettes live off-repo (FREESDN_CASSETTE_DIR); absent → tests SKIP.
Assertions are STRUCTURAL only — no real device values — so this file ships clean.

Record: FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo dir> in your lab
(the recorder builds the adapter from the stored OPNsense controller).
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    """OPNsense adapter for record (from live controller) or replay (dummy params).
    The adapter maps username->api_key, password->api_secret."""
    # Bare host (no scheme) — the OPNsense adapter builds https://{host}:{port}
    # itself; a scheme here would leak into the request path and miss the cassette.
    return await cassette_adapter(
        "opnsense",
        host="opnsense.invalid",
        username="replay",
        password="replay",
        port=443,
        use_ssl=True,
        verify_ssl=False,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("opnsense/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type


# Bedrock reads that MUST succeed against any supported OPNsense.
@pytest.mark.parametrize(
    "cassette,method",
    [
        ("opnsense/get_system_info", "get_system_info"),
        ("opnsense/get_firmware_info", "get_firmware_info"),
    ],
)
@pytest.mark.asyncio
async def test_bedrock_reads_succeed(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert isinstance(result, AdapterResult)
    assert result.success is True  # parsed the real payload into a success envelope


# Reads whose availability varies by OPNsense version/plugins: assert the adapter
# returns a normalized AdapterResult (success OR graceful-degrade), never crashes.
@pytest.mark.parametrize(
    "cassette,method",
    [
        ("opnsense/get_gateway_status", "get_gateway_status"),
        ("opnsense/get_firewall_rules", "get_firewall_rules"),
        ("opnsense/get_dhcp_leases", "get_dhcp_leases"),
    ],
)
@pytest.mark.asyncio
async def test_version_varying_reads_return_envelope(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert isinstance(result, AdapterResult)  # normalized, didn't raise on a 404/missing-MVC
