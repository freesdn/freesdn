# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Firewall Module
=======================

Network security functionality including:
- Firewall rule management
- NAT configuration
- VPN management
- IDS/IPS
- Traffic monitoring
"""

from app.modules.firewall.module import FirewallModule
from app.modules.firewall.service import (
    FirewallError,
    FirewallService,
)

__all__ = [
    "FirewallModule",
    "FirewallService",
    "FirewallError",
]
