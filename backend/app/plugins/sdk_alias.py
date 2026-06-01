# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Runtime alias: make ``import freesdn_sdk`` resolve to the real SDK.

Plugin authors develop against the published **freesdn-sdk** stub package
(``pip install freesdn-sdk``) and write ``from freesdn_sdk import FreeSDNPlugin``
for IDE/type-check/offline-test support. Inside FreeSDN there is no separate
``freesdn_sdk`` package — the *real* implementations live in
``app.plugins.sdk``. This module wires the dev-time import name to the runtime
implementations in ``sys.modules`` so the SAME plugin code runs unmodified in
both worlds.

The loader calls :func:`install_freesdn_sdk_alias` before exec'ing a plugin
module. It is idempotent and intentionally process-wide (the backend itself
never imports ``freesdn_sdk``, so aliasing it can't shadow a real dependency).
"""

from __future__ import annotations

import sys
import types

_INSTALLED_FLAG = "__freesdn_runtime_alias__"


def install_freesdn_sdk_alias() -> None:
    """Register ``freesdn_sdk`` (+ ``.base`` / ``.context``) in sys.modules,
    re-exporting the runtime implementations from ``app.plugins.*``. Idempotent."""
    existing = sys.modules.get("freesdn_sdk")
    if existing is not None and getattr(existing, _INSTALLED_FLAG, False):
        return

    from app.plugins.sdk import (
        AlertSDK,
        DeviceSDK,
        EventSDK,
        FreeSDNPlugin,
        PluginContext,
        PluginHTTPClient,
        PluginSettingsSDK,
    )

    pkg = types.ModuleType("freesdn_sdk")
    pkg.FreeSDNPlugin = FreeSDNPlugin
    pkg.PluginContext = PluginContext
    pkg.DeviceSDK = DeviceSDK
    pkg.AlertSDK = AlertSDK
    pkg.EventSDK = EventSDK
    pkg.PluginSettingsSDK = PluginSettingsSDK
    pkg.PluginHTTPClient = PluginHTTPClient

    # Best-effort extras that live elsewhere in core; never fail the alias if a
    # symbol is unavailable — the load-critical surface is the classes above.
    try:
        from app.plugins.schema import PluginManifest

        pkg.PluginManifest = PluginManifest
    except Exception:  # pragma: no cover - defensive
        pass
    try:
        from app.plugins.sandbox import PluginSecurityError

        pkg.PluginSecurityError = PluginSecurityError
    except Exception:  # pragma: no cover - defensive
        pass
    try:
        from app.core.events import Event, EventCategory, EventPriority

        pkg.Event = Event
        pkg.EventCategory = EventCategory
        pkg.EventPriority = EventPriority
    except Exception:  # pragma: no cover - defensive
        pass

    setattr(pkg, _INSTALLED_FLAG, True)

    # Submodules so ``from freesdn_sdk.base import FreeSDNPlugin`` and
    # ``from freesdn_sdk.context import PluginContext`` (used by the stub's
    # own internals + type-only imports) resolve too.
    base = types.ModuleType("freesdn_sdk.base")
    base.FreeSDNPlugin = FreeSDNPlugin
    setattr(base, _INSTALLED_FLAG, True)

    ctx = types.ModuleType("freesdn_sdk.context")
    ctx.PluginContext = PluginContext
    ctx.DeviceSDK = DeviceSDK
    ctx.AlertSDK = AlertSDK
    ctx.EventSDK = EventSDK
    ctx.PluginSettingsSDK = PluginSettingsSDK
    ctx.PluginHTTPClient = PluginHTTPClient
    setattr(ctx, _INSTALLED_FLAG, True)

    pkg.base = base
    pkg.context = ctx

    sys.modules["freesdn_sdk"] = pkg
    sys.modules["freesdn_sdk.base"] = base
    sys.modules["freesdn_sdk.context"] = ctx
