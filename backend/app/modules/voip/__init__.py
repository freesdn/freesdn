# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN VoIP Module
===================

GDMS-style IP phone fleet management:
- Fleet dashboard & device lifecycle
- Network discovery (ARP, SIP, HTTP)
- Zero-touch provisioning & config templates
- PBX integration (FreePBX, UCM)
- Extensions, ring groups, CDR
- Firmware tracking & compliance
"""

from app.modules.voip.module import VoIPModule
from app.modules.voip.service import (
    DiscoveryScanNotFoundError,
    PBXNotFoundError,
    PhoneNotFoundError,
    VoIPError,
    VoIPService,
)

__all__ = [
    "VoIPModule",
    "VoIPService",
    "VoIPError",
    "PhoneNotFoundError",
    "PBXNotFoundError",
    "DiscoveryScanNotFoundError",
]
