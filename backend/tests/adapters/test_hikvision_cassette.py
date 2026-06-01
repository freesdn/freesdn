# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hikvision adapter — replay against REAL recorded ISAPI payloads.

Record (lab): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus
FREESDN_RECORD_HOST/USERNAME/PASSWORD pointed at a real NVR/camera. Reads only
(read-only-first on prod). Absent → SKIP. Structural assertions only.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    # TEST-NET-1 host (RFC 5737) so construction passes the SSRF guard in replay.
    return await cassette_adapter(
        "hikvision",
        host="192.0.2.10",
        username="replay",
        password="replay",
        port=80,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("hikvision/discover_devices"):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("hikvision/get_full_system_info", "get_full_system_info"),
        ("hikvision/get_channels", "get_channels"),
        ("hikvision/get_event_state", "get_event_state"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
