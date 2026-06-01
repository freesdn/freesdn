# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""MikroTik adapter — replay against REAL recorded RouterOS payloads (or CHR VM).

Record (lab/VM): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus a
connected MikroTik controller, or FREESDN_RECORD_HOST/USERNAME/PASSWORD (ideal
for a free RouterOS CHR VM with the REST API enabled). Absent → SKIP. Structural
assertions only.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    return await cassette_adapter(
        "mikrotik",
        host="mikrotik.invalid",
        username="replay",
        password="replay",
        port=443,
        use_ssl=True,
        verify_ssl=False,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("mikrotik/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("mikrotik/get_interfaces", "get_interfaces"),
        ("mikrotik/get_firewall_rules", "get_firewall_rules"),
        ("mikrotik/get_dhcp_leases", "get_dhcp_leases"),
        ("mikrotik/get_arp_table", "get_arp_table"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
