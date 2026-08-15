# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Access Control Module
=============================

Physical access control functionality including:
- Door/reader management
- Card/credential management
- Access schedules
- Access event logs
- Anti-passback
"""

from app.modules.access_control.module import AccessControlModule
from app.modules.access_control.service import (
    AccessControlError,
    AccessControlService,
)

__all__ = [
    "AccessControlModule",
    "AccessControlService",
    "AccessControlError",
]
