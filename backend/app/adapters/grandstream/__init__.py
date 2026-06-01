# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter Package
===========================================

IP phone fleet adapter for Grandstream GRP, GXP, GXV, DP, and HT series.
Provides per-phone HTTP management + XML provisioning.
"""

from app.adapters.grandstream.adapter import GrandstreamAdapter
from app.adapters.grandstream.client import GrandstreamPhoneClient
from app.adapters.grandstream.exceptions import (
    GrandstreamApiError,
    GrandstreamAuthError,
    GrandstreamConnectionError,
    GrandstreamError,
    GrandstreamProvisioningError,
    GrandstreamTimeoutError,
)
from app.adapters.grandstream.provisioner import GrandstreamProvisioner

__all__ = [
    "GrandstreamAdapter",
    "GrandstreamPhoneClient",
    "GrandstreamProvisioner",
    "GrandstreamError",
    "GrandstreamConnectionError",
    "GrandstreamAuthError",
    "GrandstreamApiError",
    "GrandstreamProvisioningError",
    "GrandstreamTimeoutError",
]
