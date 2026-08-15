# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""RBAC catalog parity guard.

Regression test for the class of bug where an endpoint enforces a permission
string (via ``require_permissions`` / ``require_any_permission``) that is
granted to NO role in ``DEFAULT_ROLE_PERMISSIONS`` except the super_admin
wildcard — so every delegated role (admin/org_admin/site_admin/operator/
viewer) silently gets 403 on that whole surface.

That is exactly what happened to the network surface: 244 guards across 29
files enforced ``network:read``/``network:write``, which no role granted, so
only super_admin could use switch/AP/VLAN/WiFi/PoE management.

This test statically collects every literal permission passed to those
dependency factories and asserts each resolves to at least one NON-super_admin
role, using the same matching rules as ``CurrentUser.has_permission`` (exact,
``resource:*`` colon wildcard, ``module.*`` dot wildcard).
"""
from __future__ import annotations

import re
from pathlib import Path

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS

APP_DIR = Path(__file__).resolve().parents[2] / "app"

# Permissions intentionally reserved for super_admin only (documented
# exceptions). Add here — with a reason — if an endpoint legitimately gates on
# a permission no delegated role should ever hold.
SUPER_ADMIN_ONLY: set[str] = set()

# require_permissions("a", "b") / require_any_permission("a", "b") — capture the
# parenthesised literal args.
_CALL = re.compile(
    r"require_(?:permissions|any_permission)\(\s*((?:[\"'][^\"']+[\"'])(?:\s*,\s*[\"'][^\"']+[\"'])*)",
)
_LITERAL = re.compile(r"[\"']([^\"']+)[\"']")


def _matches_has_permission(perm: str, perms: list[str]) -> bool:
    """Mirror CurrentUser.has_permission (minus the super_admin shortcut)."""
    if "*" in perms or perm in perms:
        return True
    colon = perm.split(":")
    if len(colon) == 2 and f"{colon[0]}:*" in perms:
        return True
    dot = perm.split(".")
    if len(dot) == 2 and f"{dot[0]}.*" in perms:
        return True
    return False


def _granted_to_a_delegated_role(perm: str) -> bool:
    for role, perms in DEFAULT_ROLE_PERMISSIONS.items():
        if role == "super_admin":
            continue
        if _matches_has_permission(perm, perms):
            return True
    return False


def _collect_enforced_permissions() -> set[str]:
    found: set[str] = set()
    for py in APP_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for call in _CALL.finditer(text):
            for lit in _LITERAL.findall(call.group(1)):
                found.add(lit)
    return found


def test_every_enforced_permission_reaches_a_delegated_role() -> None:
    enforced = _collect_enforced_permissions()
    assert enforced, "no require_permissions/require_any_permission literals found — regex broke?"

    unreachable = sorted(
        p
        for p in enforced
        if p not in SUPER_ADMIN_ONLY and not _granted_to_a_delegated_role(p)
    )
    assert not unreachable, (
        "These permission strings are enforced by endpoints but granted to NO "
        "non-super_admin role — every delegated role gets 403 on those routes. "
        "Add the permission to the right roles in DEFAULT_ROLE_PERMISSIONS (or, "
        "if intentionally super_admin-only, to SUPER_ADMIN_ONLY here): "
        f"{unreachable}"
    )


def test_network_surface_is_reachable_by_admin_tiers() -> None:
    """Direct guard for the specific bug this test was born from."""
    for role in ("admin", "org_admin", "site_admin"):
        perms = DEFAULT_ROLE_PERMISSIONS[role]
        assert _matches_has_permission("network:write", perms), f"{role} cannot write network"
        assert _matches_has_permission("network:read", perms), f"{role} cannot read network"
    for role in ("operator", "viewer"):
        perms = DEFAULT_ROLE_PERMISSIONS[role]
        assert _matches_has_permission("network:read", perms), f"{role} cannot read network"
        assert not _matches_has_permission("network:write", perms), f"{role} should be read-only on network"
