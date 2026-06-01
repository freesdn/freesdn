# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""RBAC contract tests.

Validates that:
1. Every role used in the system exists in DEFAULT_ROLE_PERMISSIONS
2. Role hierarchy is correct (super_admin > admin > org_admin > site_admin > operator > viewer > guest)
3. has_permission() handles both colon and dot wildcards correctly
4. UserResponse includes auth fields (permissions, is_superuser, is_org_admin)
5. Dangerous permissions are denied to low-privilege roles
6. Module permissions are granted to admin
"""

import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.core.dependencies import (
    DEFAULT_ROLE_PERMISSIONS,
    ROLE_HIERARCHY,
    CurrentUser,
    validate_role_assignment,
)

# ===================================================================
# Helpers
# ===================================================================

def _make_current_user(role: str) -> CurrentUser:
    """Build a minimal CurrentUser with the default permissions for *role*."""
    user = MagicMock()
    user.id = uuid.uuid4()
    user.organization_id = uuid.uuid4()
    user.role = role
    user.is_active = True
    perms = DEFAULT_ROLE_PERMISSIONS.get(role, [])
    return CurrentUser(user=user, permissions=perms)


def _expand_permissions(perms: list[str]) -> set[str]:
    """Expand wildcard entries so subset comparisons work.

    Both ``resource:*`` and ``module.*`` are expanded into the union of
    all concrete permissions seen across every role for that resource/module.
    A bare ``*`` expands to every concrete permission in the entire map.
    """
    # Collect every concrete (non-wildcard) permission across all roles
    all_concrete: set[str] = set()
    for role_perms in DEFAULT_ROLE_PERMISSIONS.values():
        for p in role_perms:
            if p != "*" and not p.endswith(":*") and not p.endswith(".*"):
                all_concrete.add(p)

    expanded: set[str] = set()
    for p in perms:
        if p == "*":
            expanded |= all_concrete
        elif p.endswith(":*"):
            prefix = p[:-1]  # "device:"
            expanded |= {c for c in all_concrete if c.startswith(prefix)}
            expanded.add(p)  # keep the wildcard itself too
        elif p.endswith(".*"):
            prefix = p[:-1]  # "cameras."
            expanded |= {c for c in all_concrete if c.startswith(prefix)}
            expanded.add(p)
        else:
            expanded.add(p)
    return expanded


# ===================================================================
# Test 1: All expected roles exist
# ===================================================================

EXPECTED_ROLES = [
    "super_admin",
    "admin",
    "org_admin",
    "site_admin",
    "operator",
    "viewer",
    "guest",
]


@pytest.mark.parametrize("role", EXPECTED_ROLES)
def test_role_exists_in_defaults(role: str) -> None:
    assert role in DEFAULT_ROLE_PERMISSIONS, (
        f"Role '{role}' missing from DEFAULT_ROLE_PERMISSIONS"
    )


@pytest.mark.parametrize("role", EXPECTED_ROLES)
def test_role_exists_in_hierarchy(role: str) -> None:
    assert role in ROLE_HIERARCHY, (
        f"Role '{role}' missing from ROLE_HIERARCHY"
    )


# ===================================================================
# Test 2: Role hierarchy — each role has <= permissions of the one above
# ===================================================================

def test_role_hierarchy_levels_are_strictly_decreasing() -> None:
    """ROLE_HIERARCHY numeric levels must decrease down the chain."""
    for i in range(1, len(EXPECTED_ROLES)):
        higher = EXPECTED_ROLES[i - 1]
        lower = EXPECTED_ROLES[i]
        assert ROLE_HIERARCHY[higher] > ROLE_HIERARCHY[lower], (
            f"{higher} ({ROLE_HIERARCHY[higher]}) should be higher "
            f"than {lower} ({ROLE_HIERARCHY[lower]})"
        )


def test_role_permission_superset() -> None:
    """Each role's expanded permissions should be a superset of the next
    lower role's expanded permissions (excluding super_admin which uses '*').
    """
    # Start from admin (index 1) because super_admin uses bare '*'
    for i in range(2, len(EXPECTED_ROLES)):
        higher = EXPECTED_ROLES[i - 1]
        lower = EXPECTED_ROLES[i]
        higher_exp = _expand_permissions(DEFAULT_ROLE_PERMISSIONS[higher])
        lower_exp = _expand_permissions(DEFAULT_ROLE_PERMISSIONS[lower])
        extra = lower_exp - higher_exp
        assert lower_exp.issubset(higher_exp), (
            f"'{lower}' has permissions not in '{higher}': {extra}"
        )


# ===================================================================
# Test 3: Super admin has wildcard
# ===================================================================

def test_super_admin_has_wildcard() -> None:
    assert "*" in DEFAULT_ROLE_PERMISSIONS["super_admin"]


def test_super_admin_has_permission_for_anything() -> None:
    cu = _make_current_user("super_admin")
    assert cu.has_permission("device:read")
    assert cu.has_permission("cameras.manage")
    assert cu.has_permission("nonexistent:thing")


# ===================================================================
# Test 4: Guest has minimal permissions
# ===================================================================

def test_guest_minimal() -> None:
    perms = DEFAULT_ROLE_PERMISSIONS["guest"]
    assert len(perms) <= 10, (
        f"Guest should have very few permissions, got {len(perms)}: {perms}"
    )


# ===================================================================
# Test 5: Critical permissions exist for expected roles
# ===================================================================

@pytest.mark.parametrize("role,permission", [
    # admin — full access to core resources
    ("admin", "device:read"),
    ("admin", "device:write"),
    ("admin", "device:delete"),
    ("admin", "alert:read"),
    ("admin", "vpn:read"),
    ("admin", "agent:read"),
    ("admin", "settings:read"),
    # org_admin — broad but not full admin
    ("org_admin", "device:read"),
    ("org_admin", "alert:read"),
    ("org_admin", "site:read"),
    ("org_admin", "vpn:read"),
    # site_admin — read + some write
    ("site_admin", "device:read"),
    ("site_admin", "alert:read"),
    ("site_admin", "config:read"),
    # operator — read + limited update
    ("operator", "device:read"),
    ("operator", "device:update"),
    ("operator", "alert:read"),
    # viewer — read-only
    ("viewer", "device:read"),
    ("viewer", "site:read"),
    ("viewer", "alert:read"),
    ("viewer", "analytics:read"),
    # guest — bare minimum
    ("guest", "site:read"),
    ("guest", "device:read"),
    ("guest", "event:read"),
])
def test_role_has_expected_permission(role: str, permission: str) -> None:
    cu = _make_current_user(role)
    assert cu.has_permission(permission), (
        f"Role '{role}' should have permission '{permission}'"
    )


# ===================================================================
# Test 6: Dangerous permissions NOT given to low roles
# ===================================================================

@pytest.mark.parametrize("role,permission", [
    ("viewer", "device:delete"),
    ("viewer", "device:write"),
    ("viewer", "device:update"),
    ("viewer", "user:create"),
    ("guest", "device:write"),
    ("guest", "device:delete"),
    ("guest", "user:create"),
    ("guest", "user:delete"),
    ("guest", "settings:write"),
    ("guest", "controller:write"),
    ("operator", "user:delete"),
    ("operator", "user:create"),
    ("operator", "settings:write"),
])
def test_role_lacks_dangerous_permission(role: str, permission: str) -> None:
    cu = _make_current_user(role)
    assert not cu.has_permission(permission), (
        f"Role '{role}' should NOT have '{permission}'"
    )


# ===================================================================
# Test 7: UserResponse includes auth fields
# ===================================================================

def test_user_response_has_auth_fields() -> None:
    from app.schemas.core import UserResponse

    fields = UserResponse.model_fields
    assert "permissions" in fields, "UserResponse missing 'permissions' field"
    assert "is_superuser" in fields, "UserResponse missing 'is_superuser' field"
    assert "is_org_admin" in fields, "UserResponse missing 'is_org_admin' field"


def test_user_response_auth_field_defaults() -> None:
    """The auth fields should have sensible defaults."""
    from app.schemas.core import UserResponse

    info = UserResponse.model_fields
    assert info["is_superuser"].default is False
    assert info["is_org_admin"].default is False
    assert info["permissions"].default_factory is not None  # list factory


# ===================================================================
# Test 8: Module permissions are covered for admin
# ===================================================================

@pytest.mark.parametrize("permission", [
    "cameras.view",
    "cameras.manage",
    "cameras.playback",
    "firewall.view",
    "firewall.manage_rules",
    "gateway.view",
    "gateway.manage_vlans",
    "voip.view",
    "access.view",
])
def test_module_permission_granted_to_admin(permission: str) -> None:
    """Every module permission should be accessible to the admin role."""
    cu = _make_current_user("admin")
    assert cu.has_permission(permission), (
        f"Admin role should have module permission '{permission}'"
    )


# ===================================================================
# Test 9: No empty role definitions
# ===================================================================

def test_no_empty_roles() -> None:
    for role, perms in DEFAULT_ROLE_PERMISSIONS.items():
        assert len(perms) > 0, f"Role '{role}' has no permissions"


# ===================================================================
# Test 10: has_permission wildcard matching
# ===================================================================

class TestHasPermissionWildcards:
    """Verify that CurrentUser.has_permission() resolves wildcards for both
    colon-separated (core) and dot-separated (module) permission styles.
    """

    def test_colon_wildcard_matches(self) -> None:
        """'device:*' should match 'device:read', 'device:write', etc."""
        cu = _make_current_user("admin")  # admin has 'device:*'
        assert cu.has_permission("device:read")
        assert cu.has_permission("device:write")
        assert cu.has_permission("device:delete")
        assert cu.has_permission("device:reboot")

    def test_dot_wildcard_matches(self) -> None:
        """'cameras.*' should match 'cameras.view', 'cameras.manage', etc."""
        cu = _make_current_user("admin")  # admin has 'cameras.*'
        assert cu.has_permission("cameras.view")
        assert cu.has_permission("cameras.manage")
        assert cu.has_permission("cameras.playback")
        assert cu.has_permission("cameras.ptz")

    def test_exact_match_without_wildcard(self) -> None:
        """Operator has explicit 'device:read' (not 'device:*')."""
        cu = _make_current_user("operator")
        assert cu.has_permission("device:read")
        assert cu.has_permission("device:update")
        # operator does NOT have device:write or device:delete
        assert not cu.has_permission("device:write")
        assert not cu.has_permission("device:delete")

    def test_no_cross_resource_match(self) -> None:
        """'device:*' should NOT match 'user:read'."""
        cu = _make_current_user("site_admin")  # has device:* but not user:*
        assert cu.has_permission("device:read")
        assert not cu.has_permission("user:create")

    def test_nonexistent_permission_denied(self) -> None:
        """Completely unknown permissions should be denied for non-superadmin."""
        cu = _make_current_user("viewer")
        assert not cu.has_permission("warp_drive:engage")
        assert not cu.has_permission("flux.capacitor")


# ===================================================================
# Test 11: has_any_permission / has_all_permissions
# ===================================================================

class TestCompositePermissions:
    def test_has_any_permission_true(self) -> None:
        cu = _make_current_user("viewer")
        assert cu.has_any_permission(["device:read", "device:delete"])

    def test_has_any_permission_false(self) -> None:
        cu = _make_current_user("guest")
        assert not cu.has_any_permission(["device:delete", "user:create"])

    def test_has_all_permissions_true(self) -> None:
        cu = _make_current_user("admin")
        assert cu.has_all_permissions(["device:read", "alert:read", "vpn:read"])

    def test_has_all_permissions_false(self) -> None:
        cu = _make_current_user("viewer")
        # viewer has device:read but NOT device:delete
        assert not cu.has_all_permissions(["device:read", "device:delete"])


# ===================================================================
# Test 12: has_min_role
# ===================================================================

@pytest.mark.parametrize("user_role,min_role,expected", [
    ("super_admin", "admin", True),
    ("admin", "admin", True),
    ("admin", "super_admin", False),
    ("org_admin", "site_admin", True),
    ("site_admin", "org_admin", False),
    ("operator", "viewer", True),
    ("viewer", "operator", False),
    ("guest", "guest", True),
    ("guest", "viewer", False),
])
def test_has_min_role(user_role: str, min_role: str, expected: bool) -> None:
    cu = _make_current_user(user_role)
    assert cu.has_min_role(min_role) is expected


# ===================================================================
# Test 13: is_superuser / is_org_admin properties
# ===================================================================

class TestRoleProperties:
    def test_super_admin_is_superuser(self) -> None:
        cu = _make_current_user("super_admin")
        assert cu.is_superuser is True
        assert cu.is_org_admin is True

    def test_admin_is_org_admin(self) -> None:
        cu = _make_current_user("admin")
        assert cu.is_superuser is False
        assert cu.is_org_admin is True

    def test_org_admin_is_org_admin(self) -> None:
        cu = _make_current_user("org_admin")
        assert cu.is_superuser is False
        assert cu.is_org_admin is True

    def test_site_admin_is_not_org_admin(self) -> None:
        cu = _make_current_user("site_admin")
        assert cu.is_superuser is False
        assert cu.is_org_admin is False

    def test_viewer_is_neither(self) -> None:
        cu = _make_current_user("viewer")
        assert cu.is_superuser is False
        assert cu.is_org_admin is False

    def test_guest_is_neither(self) -> None:
        cu = _make_current_user("guest")
        assert cu.is_superuser is False
        assert cu.is_org_admin is False


# ===================================================================
# Test 14: DEFAULT_ROLE_PERMISSIONS and ROLE_HIERARCHY cover same roles
# ===================================================================

def test_permission_and_hierarchy_keys_match() -> None:
    perm_roles = set(DEFAULT_ROLE_PERMISSIONS.keys())
    hier_roles = set(ROLE_HIERARCHY.keys())
    assert perm_roles == hier_roles, (
        f"Mismatch: permissions has {perm_roles - hier_roles}, "
        f"hierarchy has {hier_roles - perm_roles}"
    )


# ===================================================================
# Test 15: role escalation prevention via validate_role_assignment
# ===================================================================

class TestRoleEscalationPrevention:
    """Verify the role hierarchy is enforced on user creation/update.

    These tests lock down a caller must never be able to create
    or modify a user whose role is equal to or higher than the caller's own
    level. Without this, an ``org_admin`` could mint an ``admin`` (which
    holds ``organization:*`` cross-org permissions) and break tenant isolation.
    """

    def test_org_admin_cannot_create_admin(self) -> None:
        """org_admin must not be able to create admin users."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("org_admin", "admin")
        assert exc_info.value.status_code == 403

    def test_org_admin_cannot_create_super_admin(self) -> None:
        """org_admin must not be able to create super_admin users."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("org_admin", "super_admin")
        assert exc_info.value.status_code == 403

    def test_org_admin_cannot_create_org_admin(self) -> None:
        """Equal-privilege assignment is blocked (strict hierarchy)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("org_admin", "org_admin")
        assert exc_info.value.status_code == 403

    def test_org_admin_can_create_site_admin(self) -> None:
        """org_admin CAN create site_admin (lower tier)."""
        # Should not raise
        validate_role_assignment("org_admin", "site_admin")

    def test_org_admin_can_create_operator(self) -> None:
        """org_admin CAN create operator."""
        validate_role_assignment("org_admin", "operator")

    def test_admin_cannot_create_admin(self) -> None:
        """admin must not be able to create another admin."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("admin", "admin")
        assert exc_info.value.status_code == 403

    def test_admin_cannot_create_super_admin(self) -> None:
        """admin must not be able to create super_admin."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("admin", "super_admin")
        assert exc_info.value.status_code == 403

    def test_admin_can_create_org_admin(self) -> None:
        """admin CAN create org_admin (lower tier)."""
        validate_role_assignment("admin", "org_admin")

    def test_super_admin_cannot_create_super_admin(self) -> None:
        """super_admin cannot create another super_admin (equal priv block)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("super_admin", "super_admin")
        assert exc_info.value.status_code == 403

    def test_super_admin_can_create_admin(self) -> None:
        """super_admin CAN create admin."""
        validate_role_assignment("super_admin", "admin")

    def test_super_admin_can_create_org_admin(self) -> None:
        """super_admin CAN create org_admin."""
        validate_role_assignment("super_admin", "org_admin")

    def test_site_admin_cannot_create_org_admin(self) -> None:
        """site_admin cannot escalate."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("site_admin", "org_admin")
        assert exc_info.value.status_code == 403

    def test_site_admin_can_create_operator(self) -> None:
        """site_admin CAN create operator (lower tier)."""
        validate_role_assignment("site_admin", "operator")

    def test_viewer_cannot_create_anyone(self) -> None:
        """viewer has no privileges to create users (level 10, guest is 0)."""
        # viewer (10) trying to make a guest (0) → 10 > 0 so the *hierarchy*
        # technically allows it, but the policy (require_admin dependency)
        # blocks viewer from even reaching create_user. We still assert that
        # viewer cannot cross upward.
        with pytest.raises(HTTPException):
            validate_role_assignment("viewer", "operator")

    def test_guest_cannot_create_anyone(self) -> None:
        """guest (level 0) is denied outright."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("guest", "viewer")
        assert exc_info.value.status_code == 403

    def test_unknown_target_role_rejected(self) -> None:
        """Unknown role names are rejected as 400."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("admin", "god_mode")
        assert exc_info.value.status_code == 400

    def test_unknown_caller_role_rejected(self) -> None:
        """Unknown caller roles default to deny (403)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("random_string", "viewer")
        assert exc_info.value.status_code == 403

    def test_empty_caller_role_rejected(self) -> None:
        """Empty-string caller role is denied (level 0)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_role_assignment("", "viewer")
        assert exc_info.value.status_code == 403
