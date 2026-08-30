# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A setting the code reads must be a setting the operator can set.

``Settings`` is configured with ``extra="ignore"``, so an environment variable
that does not correspond to a declared field is silently discarded. Code that
reaches for one with ``getattr(settings, "NAME", default)`` therefore always gets
the default, whatever the operator put in their ``.env``, and nothing warns.

That is not hypothetical. ``AI_PROVIDER_PROXY_HOSTS`` was read that way, was
documented on the AI-assistant page AND in the configuration reference, and was
named in the 400 body the API returns when it rejects a provider host -- so the
error message told the operator to set a variable that could not work. Two more
had the same shape: ``FRONTEND_URL`` (the password-reset link fell back to a CORS
origin or localhost) and ``ALLOW_PRIVATE_CONTROLLER_HOSTS`` (a UniFi hardening
guard that defaulted permissive at the call site and could never be turned on).

The ``getattr`` form is legitimate -- it keeps a module importable when a field
is optional -- so this does not ban it. It requires the field to exist.
"""

from __future__ import annotations

import ast
import pathlib

from app.core.config import Settings

#: Local variables that happen to be named ``settings``. The ONVIF adapter reads
#: camera IMAGING settings off a device response with exactly this shape, and
#: those keys are vendor field names, not FreeSDN configuration.
_NOT_THE_CONFIG_OBJECT = {
    "app/adapters/onvif/adapter.py",
}


def _app_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2] / "app"


def _getattr_settings_names() -> list[tuple[str, int, str]]:
    """Every ``getattr(settings, "NAME", ...)`` in the app tree."""
    found: list[tuple[str, int, str]] = []
    root = _app_root()
    for path in root.rglob("*.py"):
        rel = path.relative_to(root.parent).as_posix()
        if rel in _NOT_THE_CONFIG_OBJECT:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "settings"
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                found.append((rel, node.lineno, node.args[1].value))
    return found


def test_every_setting_read_with_getattr_is_declared() -> None:
    """Fails before the fix on AI_PROVIDER_PROXY_HOSTS, FRONTEND_URL and
    ALLOW_PRIVATE_CONTROLLER_HOSTS."""
    declared = set(Settings.model_fields)
    undeclared = [
        f"{rel}:{lineno} reads settings.{name}"
        for rel, lineno, name in _getattr_settings_names()
        if name not in declared
    ]
    assert not undeclared, (
        "these settings are read but never declared on Settings, and "
        'model_config sets extra="ignore" -- so the operator\'s value is '
        "discarded and the default always wins:\n  " + "\n  ".join(undeclared)
    )


def test_the_probe_actually_finds_call_sites() -> None:
    """Guard against the scan silently matching nothing.

    A detector that finds zero call sites passes forever and proves nothing.
    """
    assert len(_getattr_settings_names()) >= 3, (
        "the getattr(settings, ...) scan found almost nothing; the AST shape it "
        "matches has probably changed and this test is no longer checking anything"
    )
