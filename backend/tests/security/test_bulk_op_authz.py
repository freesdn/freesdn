# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for bulk-operation permission model.

Validates that:
  - Each bulk-op type has its own permission scope
  - Firmware upgrade is restricted to admin-level roles
  - Operators can reboot (triage) but not push config or upgrade firmware
  - Viewers/guests have no bulk-op write permissions
"""

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS


def _role_has_permission(role: str, permission: str) -> bool:
    """Return True if *role*'s default perms grant *permission*.

    Handles the same wildcard rules as CurrentUser.has_permission():
      • literal match
      • "*" wildcard
      • "resource:*" (colon) matches "resource:action"
      • "module.*"  (dot)   matches "module.action"
    """
    perms = DEFAULT_ROLE_PERMISSIONS.get(role, [])
    if "*" in perms or permission in perms:
        return True
    if ":" in permission:
        resource = permission.split(":", 1)[0]
        if f"{resource}:*" in perms:
            return True
    if "." in permission:
        module = permission.split(".", 1)[0]
        if f"{module}.*" in perms:
            return True
    return False


# ---------------------------------------------------------------------------
# firmware:upgrade — admin only (super_admin + admin)
# ---------------------------------------------------------------------------

def test_admin_has_firmware_upgrade() -> None:
    assert _role_has_permission("admin", "firmware:upgrade")


def test_super_admin_has_firmware_upgrade() -> None:
    assert _role_has_permission("super_admin", "firmware:upgrade")


def test_org_admin_cannot_firmware_upgrade() -> None:
    """org_admin is too risky to hold firmware:upgrade (can brick fleet)."""
    assert not _role_has_permission("org_admin", "firmware:upgrade")


def test_site_admin_cannot_firmware_upgrade() -> None:
    assert not _role_has_permission("site_admin", "firmware:upgrade")


def test_operator_cannot_firmware_upgrade() -> None:
    assert not _role_has_permission("operator", "firmware:upgrade")


def test_viewer_cannot_firmware_upgrade() -> None:
    assert not _role_has_permission("viewer", "firmware:upgrade")


def test_guest_cannot_firmware_upgrade() -> None:
    assert not _role_has_permission("guest", "firmware:upgrade")


# ---------------------------------------------------------------------------
# device:reboot — operator+ (for triage)
# ---------------------------------------------------------------------------

def test_operator_can_reboot_devices() -> None:
    """Operators need device:reboot for triage work."""
    assert _role_has_permission("operator", "device:reboot")


def test_site_admin_can_reboot() -> None:
    assert _role_has_permission("site_admin", "device:reboot")


def test_org_admin_can_reboot() -> None:
    assert _role_has_permission("org_admin", "device:reboot")


def test_admin_can_reboot() -> None:
    assert _role_has_permission("admin", "device:reboot")


def test_viewer_cannot_reboot() -> None:
    assert not _role_has_permission("viewer", "device:reboot")


def test_guest_cannot_reboot() -> None:
    assert not _role_has_permission("guest", "device:reboot")


# ---------------------------------------------------------------------------
# config:push — site_admin+ (not operator)
# ---------------------------------------------------------------------------

def test_site_admin_can_push_config() -> None:
    assert _role_has_permission("site_admin", "config:push")


def test_org_admin_can_push_config() -> None:
    assert _role_has_permission("org_admin", "config:push")


def test_admin_can_push_config() -> None:
    assert _role_has_permission("admin", "config:push")


def test_operator_cannot_push_config() -> None:
    """Operators are triage-only — no config push."""
    assert not _role_has_permission("operator", "config:push")


def test_viewer_cannot_push_config() -> None:
    assert not _role_has_permission("viewer", "config:push")


# ---------------------------------------------------------------------------
# Viewers have no bulk-op write permissions
# ---------------------------------------------------------------------------

def test_viewer_has_no_write_permissions() -> None:
    """Viewers must not be able to reboot / push / upgrade."""
    assert not _role_has_permission("viewer", "device:reboot")
    assert not _role_has_permission("viewer", "config:push")
    assert not _role_has_permission("viewer", "firmware:upgrade")


def test_guest_has_no_write_permissions() -> None:
    assert not _role_has_permission("guest", "device:reboot")
    assert not _role_has_permission("guest", "config:push")
    assert not _role_has_permission("guest", "firmware:upgrade")


# ---------------------------------------------------------------------------
# Cross-role sanity: mapping lines up with BULK_OPERATION_PERMISSIONS
# ---------------------------------------------------------------------------

def test_bulk_operation_permission_mapping_is_complete() -> None:
    """Every BulkOperationCreate operation enum value has a perm mapping."""
    try:
        from app.api.v1.endpoints.enterprise import BULK_OPERATION_PERMISSIONS
    except ModuleNotFoundError as e:  # pragma: no cover - optional dep
        # Celery is not installed in every test environment — skip rather
        # than fail. The mapping itself is trivially verifiable and the
        # permission rules above cover the actual security contract.
        import pytest
        pytest.skip(f"optional dep not installed: {e.name}")
    assert BULK_OPERATION_PERMISSIONS["reboot"] == "device:reboot"
    assert BULK_OPERATION_PERMISSIONS["push_config"] == "config:push"
    assert BULK_OPERATION_PERMISSIONS["firmware_update"] == "firmware:upgrade"
