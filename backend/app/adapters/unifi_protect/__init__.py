# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — UniFi Protect adapter.

Adapter for the UniFi Protect controller (Ubiquiti's camera platform).
Mirrors the camera-adapter contract that ``HikvisionAdapter`` and
``ONVIFAdapter`` already satisfy so the cameras module's
``_create_camera_adapter(vendor=...)`` dispatcher can route to UniFi
Protect alongside Hikvision and ONVIF.

UniFi Protect is a separate application from UniFi Network. Both can
run on the same UniFi OS device (UDM Pro, Cloud Key, UOS Server LXC).
The adapter probes ``/proxy/protect/api/bootstrap`` to detect whether
Protect is installed on the target host; if the endpoint returns the
UOS HTML shell (not JSON), the adapter raises
:class:`UniFiProtectNotInstalledError` so operators get a clean error
instead of a confusing parse failure.
"""

from app.adapters.unifi_protect.adapter import (
    UniFiProtectAdapter,
    UniFiProtectNotInstalledError,
)

__all__ = [
    "UniFiProtectAdapter",
    "UniFiProtectNotInstalledError",
]
