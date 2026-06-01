# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Proxmox adapter — replay against REAL recorded PVE payloads.

Record (lab): FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> plus the
connected Proxmox controller (PVEAuditor token), or
FREESDN_RECORD_HOST/USERNAME/PASSWORD. Reads only — Proxmox is the owner's
mission-critical cluster (read-only-first). Absent → SKIP. Structural assertions.
"""

from __future__ import annotations

import pytest

from app.adapters.base import AdapterResult, DiscoveredDevice
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette


async def _adapter():
    # Proxmox API token auth: username=user@realm!tokenid, password=secret.
    return await cassette_adapter(
        "proxmox",
        host="proxmox.invalid",
        username="replay@pam!replay",
        password="replay",
        port=8006,
        use_ssl=True,
        verify_ssl=False,
    )


@pytest.mark.asyncio
async def test_discover_devices_parses_real_payload() -> None:
    with use_cassette("proxmox/discover_devices", verify_ssl=False):
        async with await _adapter() as adapter:
            devices = await adapter.discover_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert isinstance(d, DiscoveredDevice)
        assert d.device_type


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("proxmox/get_all_vms", "get_all_vms"),
        ("proxmox/get_ceph_status", "get_ceph_status"),
        ("proxmox/get_backup_jobs", "get_backup_jobs"),
    ],
)
@pytest.mark.asyncio
async def test_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette, verify_ssl=False):
        async with await _adapter() as adapter:
            result = await getattr(adapter, method)()
    assert result is not None
    assert isinstance(result, (AdapterResult, dict, list))
