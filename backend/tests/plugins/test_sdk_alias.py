# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The dev-SDK <-> runtime-SDK reconciliation.

Plugin authors write ``from freesdn_sdk import FreeSDNPlugin`` against the
published stub package. At runtime the loader aliases ``freesdn_sdk`` to the
real ``app.plugins.sdk`` impls, so the SAME plugin code loads and subclasses
the real BaseModule-backed base (and thus passes the loader's issubclass
check). These tests pin that contract.
"""
from __future__ import annotations

import sys

from app.plugins.sdk import FreeSDNPlugin as RuntimeFreeSDNPlugin
from app.plugins.sdk import PluginContext as RuntimePluginContext
from app.plugins.sdk_alias import install_freesdn_sdk_alias


def test_alias_maps_freesdn_sdk_to_runtime() -> None:
    install_freesdn_sdk_alias()
    import freesdn_sdk  # noqa: PLC0415 — import AFTER the alias is installed

    assert freesdn_sdk.FreeSDNPlugin is RuntimeFreeSDNPlugin
    assert freesdn_sdk.PluginContext is RuntimePluginContext
    # The runtime base is BaseModule-backed (not the dev stub).
    assert RuntimeFreeSDNPlugin.__mro__[1].__name__ == "BaseModule"


def test_plugin_authored_against_dev_import_passes_loader_check() -> None:
    """A plugin written `from freesdn_sdk import FreeSDNPlugin` must satisfy the
    loader's `issubclass(cls, app.plugins.sdk.FreeSDNPlugin)` validation."""
    install_freesdn_sdk_alias()
    from freesdn_sdk import FreeSDNPlugin  # noqa: PLC0415

    class AuthoredPlugin(FreeSDNPlugin):
        pass

    assert issubclass(AuthoredPlugin, RuntimeFreeSDNPlugin)


def test_alias_submodules_resolve() -> None:
    install_freesdn_sdk_alias()
    from freesdn_sdk.base import FreeSDNPlugin as BaseImport  # noqa: PLC0415
    from freesdn_sdk.context import PluginContext as CtxImport  # noqa: PLC0415

    assert BaseImport is RuntimeFreeSDNPlugin
    assert CtxImport is RuntimePluginContext
    assert "freesdn_sdk" in sys.modules


def test_alias_is_idempotent() -> None:
    install_freesdn_sdk_alias()
    first = sys.modules["freesdn_sdk"]
    install_freesdn_sdk_alias()
    assert sys.modules["freesdn_sdk"] is first


def test_dev_stub_api_matches_runtime() -> None:
    """Parity guard: every public lifecycle/extension method the dev stub
    declares must exist on the runtime base, so a plugin authored against the
    stub finds the same surface at runtime. (Catches stub<->runtime drift.)"""
    # The hooks + extension points the published stub promises authors.
    promised = [
        "on_install",
        "on_start",
        "on_upgrade",
        "on_uninstall",
        "get_router",
        "register_automation_trigger",
        "register_automation_action",
        "register_ai_tool",
        "emit_event",
    ]
    missing = [name for name in promised if not hasattr(RuntimeFreeSDNPlugin, name)]
    assert not missing, f"runtime FreeSDNPlugin is missing dev-SDK surface: {missing}"
