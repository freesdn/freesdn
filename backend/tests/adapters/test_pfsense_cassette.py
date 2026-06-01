# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""pfSense adapter — replay against REAL recorded payloads (or VM).

Record (lab/VM): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus
either a connected pfSense controller, or the universal env path
FREESDN_RECORD_HOST/USERNAME/PASSWORD (ideal for a free pfSense CE VM).
Cassettes live off-repo; absent → SKIP. Assertions are STRUCTURAL only.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    # pfSense maps username->api_key, password->api_secret; builds https://{host}:{port}.
    return await cassette_adapter(
        "pfsense",
        host="pfsense.invalid",
        username="replay",
        password="replay",
        port=443,
        use_ssl=True,
        verify_ssl=False,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("pfsense/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("pfsense/get_firmware_info", "get_firmware_info"),
        ("pfsense/get_gateway_status", "get_gateway_status"),
        ("pfsense/get_interfaces", "get_interfaces"),
        ("pfsense/get_firewall_rules", "get_firewall_rules"),
        ("pfsense/get_dhcp_leases", "get_dhcp_leases"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    # Normalized envelope/collection — parsed the real payload, never crashed.
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
