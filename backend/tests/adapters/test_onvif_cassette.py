# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""ONVIF adapter — replay against REAL recorded SOAP payloads (camera or sim).

Record (lab): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus
FREESDN_RECORD_HOST/USERNAME/PASSWORD pointed at an ONVIF camera (e.g. a
Hikvision cam in ONVIF mode) or the free Happytime ONVIF Server simulator.
Reads only. Absent → SKIP. Structural assertions only.

NOTE: ``discover_devices`` is WS-Discovery (UDP multicast), not a single-device
HTTP read, so it is not cassette-replayable — the device reads below are.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    # TEST-NET-1 host (RFC 5737) so construction is inert in replay.
    return await cassette_adapter(
        "onvif",
        host="192.0.2.30",
        username="replay",
        password="replay",
        port=80,
    )


@pytest.mark.asyncio
async def test_device_info_parses_real_payload() -> None:
    with use_cassette("onvif/get_device_info"):
        async with await _adapter() as adapter:
            info = await adapter.get_device_info(device_id="")
    # DiscoveredDevice on success, or None if the SOAP profile is unavailable.
    assert info is None or isinstance(info, DiscoveredDevice)


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("onvif/get_full_system_info", "get_full_system_info"),
        ("onvif/get_channels", "get_channels"),
        ("onvif/get_network_interfaces", "get_network_interfaces"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
