# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from __future__ import annotations

import pytest

from app.adapters.capabilities import Capability
from app.adapters.unifi_protect.adapter import UniFiProtectAdapter


@pytest.mark.asyncio
async def test_nvr_and_camera_inventory_uses_real_capabilities():
    adapter = UniFiProtectAdapter("protect.example.invalid", "synthetic-user", "synthetic-password")
    adapter._bootstrap = {
        "nvr": {"mac": "02:00:00:00:00:01", "name": "Test NVR", "host": "192.0.2.1"},
        "cameras": [
            {
                "mac": "02:00:00:00:00:02",
                "name": "PTZ",
                "host": "192.0.2.2",
                "isConnected": True,
                "featureFlags": {"hasMotionZones": True, "hasPanTilt": True},
            },
            {
                "mac": "02:00:00:00:00:03",
                "name": "Fixed",
                "host": "192.0.2.3",
                "isConnected": False,
            },
        ],
    }
    try:
        devices = await adapter.discover_devices()
    finally:
        await adapter.disconnect()
    assert len(devices) == 3
    assert devices[0].capabilities == [Capability.CAMERA_STREAM_RTSP]
    assert set(devices[1].capabilities) == {
        Capability.CAMERA_STREAM_RTSP,
        Capability.CAMERA_MOTION_DETECTION,
        Capability.CAMERA_PTZ,
    }
    assert devices[1].device_type == "camera_ptz" and devices[1].status == "online"
    assert devices[2].capabilities == [Capability.CAMERA_STREAM_RTSP]
    assert devices[2].status == "offline"
