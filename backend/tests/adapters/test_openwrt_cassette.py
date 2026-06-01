# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OpenWrt adapter — replay against REAL recorded ubus payloads (or x86 VM).

Record (lab/VM): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus a
connected OpenWrt gateway, or FREESDN_RECORD_HOST/USERNAME/PASSWORD (ideal for a
free OpenWrt x86 VM with luci/uhttpd-mod-ubus installed). Absent → SKIP.
Structural assertions only.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    # OpenWrt ubus over uhttpd; port→scheme (80=http, 443=https) inside the client.
    return await cassette_adapter(
        "openwrt",
        host="openwrt.invalid",
        username="replay",
        password="replay",
        port=80,
        verify_ssl=False,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("openwrt/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("openwrt/get_device_summary", "get_device_summary"),
        ("openwrt/get_dhcp_leases", "get_dhcp_leases"),
        ("openwrt/get_arp_table", "get_arp_table"),
        ("openwrt/get_disk_usage", "get_disk_usage"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
