# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OpenWRT Adapter Package
====================================

ubus JSON-RPC adapter for OpenWRT routers and firewalls.
"""

from app.adapters.openwrt.adapter import OpenWRTAdapter

__all__ = ["OpenWRTAdapter"]
