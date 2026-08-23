# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The plugin capability vocabulary, and the consent it is supposed to represent.

Three things have to agree about what a plugin may do: the manifest it
declares, the dialog the operator approves, and the check the SDK runs. They
did not.

  * ``PluginPermission.code`` accepted any string. A manifest could declare
    ``superuser`` and it rendered in the consent dialog as a real permission
    while enforcing nothing. Consent that names a boundary which does not exist
    is worse than no consent.
  * A near-miss went the other way: ``device.read`` (singular) is not a
    capability, so the plugin installed cleanly and failed at first use.
  * The caller mapping lived separately in sdk.py and had drifted.
    ``alerts.write`` mapped to ``alert:write``, WHICH IS NOT A PERMISSION
    ANYWHERE IN FREESDN. site_admin carries ``alert:create`` and
    ``alert:update`` and is precisely the role that drives a plugin route, and
    the guard refused it.

Verified live: a site_admin invoking a plugin route that raises an alert got a
PermissionError before this and succeeds now.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS
from app.plugins.capabilities import (
    CAPABILITIES,
    MUTATING_CAPABILITIES,
    core_permissions_for,
    is_known,
    known_codes,
)


def _holds(role_permissions: list[str], permission: str) -> bool:
    """Mirror of CurrentUser.has_permission for a plain role grant list."""
    if "*" in role_permissions or permission in role_permissions:
        return True
    return f"{permission.split(':')[0]}:*" in role_permissions


# ── the vocabulary is real ───────────────────────────────────────


def _freesdn_permission_vocabulary() -> set[str]:
    """Every permission string FreeSDN actually uses.

    Two sources, because either alone is incomplete. Role grants miss
    ``device:write``, which no role names literally (site_admin holds
    ``device:*``) but which endpoint guards require. Endpoint guards miss
    permissions only ever granted, never guarded. ``alert:write`` appears in
    NEITHER, which is exactly what made it invented.
    """
    vocabulary: set[str] = set()
    for granted in DEFAULT_ROLE_PERMISSIONS.values():
        vocabulary.update(p for p in granted if not p.endswith(":*") and p != "*")

    endpoints = pathlib.Path(__file__).resolve().parents[2] / "app" / "api" / "v1" / "endpoints"
    guard = re.compile(r'"([a-z_]+:[a-z_]+)"')
    for py in endpoints.rglob("*.py"):
        vocabulary.update(guard.findall(py.read_text(encoding="utf-8", errors="replace")))
    return vocabulary


def test_every_mapped_core_permission_actually_exists():
    """
    The headline bug. ``alert:write`` was mapped and exists nowhere in FreeSDN,
    so the capability was refused for every caller not covered by a wildcard --
    including site_admin, which holds alert:create and alert:update.
    """
    vocabulary = _freesdn_permission_vocabulary()
    assert "device:read" in vocabulary, "the harvest is broken, not the mapping"
    assert "alert:write" not in vocabulary, "alert:write now exists; the mapping may be revisited"

    invented = sorted(
        perm
        for capability in CAPABILITIES.values()
        for perm in capability.core_permissions
        if perm not in vocabulary
    )
    assert not invented, (
        f"capabilities map onto permissions FreeSDN does not define: {invented}. "
        "Such a permission is held by nobody, so the capability is unreachable "
        "for any caller not covered by a wildcard grant."
    )


def test_a_site_admin_can_exercise_the_alert_write_capability():
    """
    The concrete regression. site_admin holds alert:create and alert:update and
    is the role most likely to be driving a plugin route.
    """
    site_admin = DEFAULT_ROLE_PERMISSIONS["site_admin"]
    accepted = core_permissions_for("alerts.write")
    assert any(_holds(site_admin, perm) for perm in accepted), (
        f"site_admin ({sorted(p for p in site_admin if p.startswith('alert'))}) "
        f"cannot satisfy alerts.write ({sorted(accepted)})"
    )


def test_a_viewer_still_cannot_write():
    """The guard has to keep refusing, or the fix traded one bug for a worse one."""
    viewer = DEFAULT_ROLE_PERMISSIONS["viewer"]
    for code in ("alerts.write", "devices.register", "devices.stage"):
        accepted = core_permissions_for(code)
        assert not any(_holds(viewer, perm) for perm in accepted), (
            f"viewer can now satisfy {code}; that is a privilege escalation"
        )


def test_every_capability_is_caller_gated():
    """
    An ungated capability would let a plugin do something on behalf of a caller
    who could not do it directly, which is the whole of.
    """
    ungated = sorted(c.code for c in CAPABILITIES.values() if not c.core_permissions)
    assert not ungated, f"capabilities with no caller gate: {ungated}"


def test_mutating_capabilities_are_labelled():
    """The consent dialog leads with these; a miscategorised one reads as read-only."""
    unknown = MUTATING_CAPABILITIES - set(CAPABILITIES)
    assert not unknown, f"MUTATING_CAPABILITIES names codes that do not exist: {sorted(unknown)}"
    for code in CAPABILITIES:
        looks_mutating = code.endswith((".write", ".register", ".stage"))
        assert (code in MUTATING_CAPABILITIES) == looks_mutating, (
            f"{code} is {'not ' if looks_mutating else ''}marked mutating"
        )


def test_every_capability_has_a_summary_written_for_an_operator():
    for capability in CAPABILITIES.values():
        assert capability.summary.strip(), f"{capability.code} has no summary"
        assert capability.summary.endswith("."), f"{capability.code} summary is not a sentence"
        assert len(capability.summary) > 20, f"{capability.code} summary says nothing useful"


# ── the manifest validator refuses what the SDK cannot enforce ───


@pytest.mark.parametrize(
    "code", ["superuser", "device.read", "devices.write", "", "firewall.admin"]
)
def test_an_unknown_capability_is_refused_at_parse_time(code):
    """
    Refused before install, not at first use. ``devices.write`` is in this list
    on purpose: it was renamed to ``devices.register`` because it read as "may
    change devices" and only ever meant "may create an inventory record".
    """
    from pydantic import ValidationError

    from app.plugins.schema import PluginManifest

    with pytest.raises(ValidationError) as excinfo:
        PluginManifest(
            id="probe-plugin",
            name="Probe",
            version="1.0.0",
            class_name="ProbePlugin",
            permissions=[{"code": code, "name": "anything"}],
        )
    assert "Unknown plugin capability" in str(excinfo.value)


@pytest.mark.parametrize("code", sorted(CAPABILITIES))
def test_every_known_capability_parses(code):
    from app.plugins.schema import PluginManifest

    manifest = PluginManifest(
        id="probe-plugin",
        name="Probe",
        version="1.0.0",
        class_name="ProbePlugin",
        permissions=[{"code": code, "name": "anything"}],
    )
    assert [p.code for p in manifest.permissions] == [code]


def test_the_sdk_and_the_validator_read_the_same_vocabulary():
    """
    The drift that caused the alert:write bug was two copies of one mapping.
    There must be exactly one, and sdk.py must not have grown a private table.
    """
    import inspect

    from app.plugins import sdk

    source = inspect.getsource(sdk)
    assert "_CAPABILITY_CORE_PERMISSION" not in source, (
        "sdk.py has a private capability mapping again; use app.plugins.capabilities"
    )
    assert "core_permissions_for" in source, "sdk.py no longer reads the shared vocabulary"

    for code in known_codes():
        assert is_known(code)
