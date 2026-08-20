# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Application Package
==============================

FreeSDN - Unified Network Management Platform
"""

# Single source of truth for the running version and license, shipped inside
# the ``app`` package so it is importable even in the production image (which
# runs from copied source with no installed distribution metadata). Everything
# else derives from these: ``settings.APP_VERSION`` / ``settings.APP_LICENSE``
# read them, and a config test asserts ``pyproject.toml`` matches ``__version__``
# so the packaging version and the runtime version can never silently drift.
__version__ = "26.08.2"
__license__ = "AGPL-3.0-only"
