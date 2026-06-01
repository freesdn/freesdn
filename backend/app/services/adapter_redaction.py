# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-feature secret redaction (compat shim)
========================================================

The redaction helper lives in :mod:`app.core.redaction` so adapter
modules can import it at load time without triggering the
``app.services`` package init (which transitively imports
discovery → which imports adapters → circular load deadlock at
startup).

This module is a thin re-export so the ~50 existing call sites that
import from ``app.services.adapter_redaction`` keep working. New
callers should import directly from :mod:`app.core.redaction`.
"""

from __future__ import annotations

from app.core.redaction import redact_list, redact_secrets

__all__ = ["redact_secrets", "redact_list"]
