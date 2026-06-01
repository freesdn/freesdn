# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter Package
======================================

PBX brain adapter for FreePBX/Asterisk integration.
Uses three communication channels:
- AMI (Asterisk Manager Interface) for events + admin commands
- ARI (Asterisk REST Interface) for real-time call control
- FreePBX REST API for high-level configuration CRUD
"""

from app.adapters.freepbx.adapter import FreePBXAdapter
from app.adapters.freepbx.ami_client import AMIClient, AMIMessage
from app.adapters.freepbx.ari_client import ARIClient
from app.adapters.freepbx.exceptions import (
    AMIAuthError,
    AMIConnectionError,
    AMITimeoutError,
    ARIAuthError,
    ARIConnectionError,
    FreePBXApiError,
    FreePBXAuthError,
    FreePBXConnectionError,
    FreePBXError,
)
from app.adapters.freepbx.rest_client import FreePBXRestClient

__all__ = [
    "FreePBXAdapter",
    "AMIClient",
    "AMIMessage",
    "ARIClient",
    "FreePBXRestClient",
    "FreePBXError",
    "FreePBXConnectionError",
    "FreePBXAuthError",
    "FreePBXApiError",
    "AMIConnectionError",
    "AMIAuthError",
    "AMITimeoutError",
    "ARIConnectionError",
    "ARIAuthError",
]
