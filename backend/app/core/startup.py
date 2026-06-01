# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Startup subsystem health tracking.

This module is intentionally separate from app.main to avoid circular imports
(health.py needs to read subsystem status, but main.py imports the API router).
"""

# Tracks subsystem health after startup. Keys: subsystem name, Values: "healthy" or "degraded"
SUBSYSTEM_STATUS: dict[str, str] = {}
