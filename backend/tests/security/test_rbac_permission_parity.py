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

Second half of the same class, added 2026-08-18
-----------------------------------------------
HTTP guards are not the only place a permission is enforced. Every Fabric
``Operation`` declares one via ``Operation(permission=...)`` in
``app/modules/*/module.py``, and the negotiator, the ``/fabric`` endpoint and
the AI tool bridge all gate on it. Scanning only ``require_permissions`` call
sites therefore missed that half entirely, and it had gone the same way:
**15 Operation permissions across 5 modules (ai, backup, hypervisor, network,
storage) were granted to no role at all**, so the whole Fabric surface for
those modules answered "permission denied" to every delegated role.

The network module is the sharpest illustration. Its colon-style
``network:read``/``network:write`` were fixed when this test was written,
while its dot-style ``network.view``/``network.manage`` Operations sat
unreachable right beside them, because the guard could not see them.

One more trap, pinned below: ``has_permission`` expands a dot wildcard only
for **two-part** codes (``if len(dot_parts) == 2``), so ``network.*`` does NOT
grant ``network.vlan.manage``. Three-part codes must be granted in full, which
is why ``collector.flows.read`` has always been spelled out rather than
written as ``collector.*``. ``_matches_has_permission`` mirrors that rule
exactly; a checker that loops over every prefix looks right and reports a
false pass.
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


# Operation(permission="...") in a module manifest. This carries the same
# enforcement weight as an endpoint guard: fabric/negotiator.py,
# endpoints/fabric.py and fabric/ai_bridge.py all check it before dispatch.
_OP_PERMISSION = re.compile(r"permission=[\"']([^\"']+)[\"']")

MODULES_DIR = APP_DIR / "modules"


def _collect_fabric_operation_permissions() -> dict[str, set[str]]:
    """Map each declared Operation permission to the module files declaring it."""
    found: dict[str, set[str]] = {}
    for py in MODULES_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for perm in _OP_PERMISSION.findall(text):
            found.setdefault(perm, set()).add(str(py.relative_to(APP_DIR.parent)))
    return found


def test_every_enforced_permission_reaches_a_delegated_role() -> None:
    enforced = _collect_enforced_permissions()
    assert enforced, "no require_permissions/require_any_permission literals found — regex broke?"

    unreachable = sorted(
        p for p in enforced if p not in SUPER_ADMIN_ONLY and not _granted_to_a_delegated_role(p)
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
        assert not _matches_has_permission("network:write", perms), (
            f"{role} should be read-only on network"
        )


def test_every_fabric_operation_permission_reaches_a_delegated_role() -> None:
    """
    The half this guard could not see. A Fabric Operation whose permission is
    granted to nobody is not a latent risk, it is a dead feature: the module
    ships, the operation is registered and advertised in the catalog, and every
    delegated role is refused at the negotiator.
    """
    declared = _collect_fabric_operation_permissions()
    assert declared, "no Operation(permission=...) declarations found - regex broke?"

    unreachable = {
        perm: sorted(files)
        for perm, files in declared.items()
        if perm not in SUPER_ADMIN_ONLY and not _granted_to_a_delegated_role(perm)
    }
    assert not unreachable, (
        "These Fabric Operation permissions are granted to NO non-super_admin role, "
        "so those operations are unreachable for every delegated role. Add them to "
        "DEFAULT_ROLE_PERMISSIONS (or to SUPER_ADMIN_ONLY here, with a reason): "
        f"{unreachable}"
    )


def test_three_part_permissions_are_granted_in_full_not_by_wildcard() -> None:
    """
    ``has_permission`` expands a dot wildcard only for two-part codes, so a
    three-part code "covered" by ``module.*`` is granted to nobody. That reads
    as covered in review, which is what makes it worth a test.
    """
    declared = _collect_fabric_operation_permissions()
    nested = [p for p in declared if p.count(".") >= 2]
    assert nested, "expected at least one three-part permission (e.g. network.vlan.manage)"

    for perm in nested:
        holders = [
            role
            for role, perms in DEFAULT_ROLE_PERMISSIONS.items()
            if role != "super_admin" and perm in perms
        ]
        assert holders, (
            f"{perm!r} has three parts, so no dot wildcard can grant it - it must be "
            "listed verbatim in DEFAULT_ROLE_PERMISSIONS for every role that needs it"
        )


def test_matching_helper_mirrors_the_real_wildcard_rule() -> None:
    """
    This file is only as good as its model of has_permission. Pin the two-part
    limit so the helper cannot drift more permissive than the product and start
    passing grants the app will actually refuse.
    """
    assert _matches_has_permission("network.view", ["network.*"])
    assert not _matches_has_permission("network.vlan.manage", ["network.*"]), (
        "helper is more permissive than CurrentUser.has_permission, which expands "
        "a dot wildcard only for two-part codes"
    )
    assert _matches_has_permission("network.vlan.manage", ["network.vlan.manage"])


def test_the_five_modules_that_were_unreachable_stay_reachable() -> None:
    """Direct guard for the specific instances found on 2026-08-18."""
    expected = {
        "storage.view": ("admin", "org_admin", "site_admin", "operator", "viewer"),
        "storage.write": ("admin", "org_admin", "site_admin"),
        "hypervisor.view": ("admin", "org_admin", "site_admin", "operator", "viewer"),
        "hypervisor.manage_vms": ("admin", "org_admin", "site_admin"),
        "network.view": ("admin", "org_admin", "site_admin", "operator", "viewer"),
        "network.vlan.manage": ("admin", "org_admin", "site_admin"),
        "backup.view": ("admin", "org_admin", "site_admin", "operator", "viewer"),
        "ai.chat": ("admin", "org_admin", "site_admin", "operator"),
    }
    for perm, roles in expected.items():
        for role in roles:
            assert _matches_has_permission(perm, DEFAULT_ROLE_PERMISSIONS[role]), (
                f"{role} lost {perm}"
            )


def test_read_only_roles_did_not_gain_a_fabric_write() -> None:
    """The fix widened reads. It must not have widened writes on the way past."""
    writes = (
        "storage.write",
        "hypervisor.manage_vms",
        "hypervisor.manage_nodes",
        "hypervisor.manage_snapshots",
        "network.manage",
        "network.vlan.manage",
        "network.wifi.manage",
        "backup.schedule",
        "backup.settings",
    )
    for role in ("operator", "viewer", "guest"):
        perms = DEFAULT_ROLE_PERMISSIONS[role]
        for write in writes:
            assert not _matches_has_permission(write, perms), f"{role} gained {write}"
