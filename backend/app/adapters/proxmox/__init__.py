# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Proxmox VE Adapter
================================

Adapter for Proxmox Virtual Environment hypervisor management.
Supports cluster, node, VM, container, and storage operations.
"""

from app.adapters.proxmox.adapter import ProxmoxAdapter

__all__ = ["ProxmoxAdapter"]
