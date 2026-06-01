# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Setup Wizard
==========================

First-run setup wizard for configuring FreeSDN.

Steps:
1. Welcome  — Check system requirements
2. Database — Verify database connection
3. Admin    — Create admin user
4. Organization — Create first organization + default site
5. Modules  — Select and enable modules
6. Controllers — Add device controllers (optional)
7. Complete — Finish setup, optionally install sample data
"""

from app.setup.api import router
from app.setup.schemas import (
    AdminCreateRequest,
    AdminCreateResponse,
    ControllerAddRequest,
    ControllerAddResponse,
    ControllerTestResult,
    ControllerTypeInfo,
    DatabaseCheckResponse,
    ModuleOption,
    ModuleSelectionRequest,
    ModuleSelectionResponse,
    OrganizationCreateRequest,
    OrganizationCreateResponse,
    SampleDataRequest,
    SampleDataResponse,
    SetupCompleteRequest,
    SetupCompleteResponse,
    SetupStatus,
    SetupStep,
    SetupSummary,
    SystemRequirement,
    WelcomeResponse,
)
from app.setup.service import SetupService

__all__ = [
    "router",
    "SetupService",
    # Schemas
    "SetupStatus",
    "SetupStep",
    "SystemRequirement",
    "WelcomeResponse",
    "DatabaseCheckResponse",
    "AdminCreateRequest",
    "AdminCreateResponse",
    "OrganizationCreateRequest",
    "OrganizationCreateResponse",
    "ModuleOption",
    "ModuleSelectionRequest",
    "ModuleSelectionResponse",
    "ControllerTypeInfo",
    "ControllerAddRequest",
    "ControllerAddResponse",
    "ControllerTestResult",
    "SetupCompleteRequest",
    "SetupCompleteResponse",
    "SetupSummary",
    "SampleDataRequest",
    "SampleDataResponse",
]
