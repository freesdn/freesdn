# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — TrueNAS adapter package.

The TrueNAS adapter exposes read-only inventory and health for
TrueNAS SCALE (22.x+) and CORE (13.x+) appliances. Write support
(dataset/share/snapshot mutation) is deferred to a follow-up
chapter.

Public surface::

    from app.adapters.truenas import TrueNASAdapter, TrueNASClient
"""

from app.adapters.truenas.adapter import TrueNASAdapter
from app.adapters.truenas.client import TrueNASAPIError, TrueNASClient

__all__ = [
    "TrueNASAdapter",
    "TrueNASClient",
    "TrueNASAPIError",
]
