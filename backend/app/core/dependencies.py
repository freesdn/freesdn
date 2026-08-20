# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Authentication & Authorization Dependencies
=========================================================

Provides reusable FastAPI dependencies for:
- Getting current authenticated user
- Permission checking (RBAC)
- API key authentication
- Organization/site access control
"""

import logging
import uuid
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import verify_token
from app.db import get_session
from app.models import User

logger = logging.getLogger(__name__)

# ===========================================
# Security Schemes
# ===========================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/token",
    auto_error=False,
)

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


# ===========================================
# Custom Exceptions
# ===========================================


class AuthenticationError(HTTPException):
    """Authentication failed."""

    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class PermissionDeniedError(HTTPException):
    """User does not have required permission."""

    def __init__(self, permission: str | None = None):
        detail = "Permission denied"
        if permission:
            detail = f"Permission denied: requires '{permission}'"
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


# ===========================================
# Role Hierarchy & Permissions
# ===========================================

# Role hierarchy - higher levels include all lower level permissions
ROLE_HIERARCHY = {
    "super_admin": 100,
    "admin": 80,
    "org_admin": 60,
    "site_admin": 40,
    "operator": 20,
    "viewer": 10,
    "guest": 0,
}


def validate_role_assignment(caller_role: str, target_role: str) -> None:
    """Enforce: callers can only assign roles strictly lower than their own.

    Prevents privilege escalation via user creation/modification. A caller
    cannot create or modify a user whose role is equal to or higher than the
    caller's own role level. This is the P0 tenant-isolation guarantee:
    without it, an ``org_admin`` could mint an ``admin`` user (which holds
    ``organization:*`` cross-org permissions) and escape their own org.

    Rules:
      - super_admin  → may assign admin or lower (NOT another super_admin)
      - admin        → may assign org_admin or lower (NOT admin, NOT super_admin)
      - org_admin    → may assign site_admin or lower
      - site_admin   → may assign operator or lower
      - operator / viewer / guest → level 0-20, cannot assign anyone at guest (0) level,
        and callers with level 0 (guest / unknown) are denied outright.

    Raises:
        HTTPException(403): if the target role is unknown-to-caller level or
            would violate the strict-lower-than hierarchy rule.
        HTTPException(400): if the target role is not a recognised role name.
    """
    caller_level = ROLE_HIERARCHY.get(caller_role, 0)
    target_level = ROLE_HIERARCHY.get(target_role)

    if caller_level == 0:
        # Caller role not in hierarchy, or caller is a guest-level principal.
        # Neither is allowed to assign any role.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unknown or insufficient role for caller",
        )

    if target_level is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown role: {target_role}",
        )

    if target_level >= caller_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Cannot assign role '{target_role}' — your role "
                f"'{caller_role}' can only assign strictly lower-privilege roles"
            ),
        )


def is_platform_super_admin(user: Any) -> bool:
    """Scope-aware platform-super-admin check for platform-GLOBAL (no-tenant-key)
    security surfaces (FailedLoginRecord / IPBlockRecord counts, platform IP
    activity, the enterprise/health platform posture, tenant-root org list/create).

    the R13/R14 gates used ``user.role == SUPER_ADMIN`` directly, which
    IGNORES the API-key scope ceiling. A super_admin who minted a deliberately
    narrowed key (e.g. scopes=['network:read']) still passed and read cross-tenant
    platform data. An UNSCOPED principal (full session, or unscoped / '*' key)
    keeps full access exactly as before; a SCOPED principal must explicitly carry
    'audit:read' (an existing catalog permission for super_admin/admin/org_admin/
    site_admin) — its '*' no longer implicitly bypasses, because has_permission
    only honors exact / resource:* / module.* matches once _scoped is set.
    """
    # ``is_superuser`` is a CurrentUser property; fall back to the raw role for a
    # bare User (or any principal) that lacks it, so the check is robust to both.
    is_super = getattr(user, "is_superuser", None)
    if is_super is None:
        is_super = getattr(user, "role", None) == "super_admin"
    if not is_super:
        return False
    if not getattr(user, "_scoped", False):
        return True
    return bool(getattr(user, "has_permission", None)) and user.has_permission("audit:read")


def is_unscoped_superuser(user: Any) -> bool:
    """True only for a super_admin whose credential is NOT scope-limited.

    the bare ``is_superuser`` role check is used pervasively to *bypass
    org scoping* (``if not is_superuser: where(org_id == ...)``). A deliberately
    narrowed (scoped) super_admin API key must NOT inherit that cross-tenant
    bypass — only an unscoped principal (full session or unscoped/'*' key) may.
    Use ``is_unscoped_superuser(user)`` in place of ``user.is_superuser`` wherever
    the check decides whether to DROP the organization filter. Behaviour is
    identical to ``is_superuser`` for every non-scoped principal (normal sessions
    unaffected; only scoped keys are newly org-confined). getattr-based so it is
    robust to bare User / stub principals (mirrors ``is_platform_super_admin``).
    """
    # ``is_superuser`` is a CurrentUser property; fall back to the raw role for a
    # bare User, and then to ``.user.role`` for a CurrentUser-shaped stub, so the
    # check is robust to every principal shape (mirrors is_platform_super_admin).
    is_super = getattr(user, "is_superuser", None)
    if is_super is None:
        role = getattr(user, "role", None) or getattr(getattr(user, "user", None), "role", None)
        is_super = role == "super_admin"
    return bool(is_super) and not bool(getattr(user, "_scoped", False))


def is_unscoped_org_admin(user: Any) -> bool:
    """True only for an org_admin / admin / super_admin whose credential is NOT
    scope-limited.

    some module gates allow access when ``has_permission(perm)`` OR
    the caller holds an org-admin *role* (``user.is_org_admin``). The raw role
    arm ignores the API-key scope ceiling, so a scoped key deliberately narrowed
    away from that permission still passed via its role. Write such a gate as
    ``has_permission(perm) or is_unscoped_org_admin(user)``: an UNSCOPED org-admin
    keeps role-based access (no regression — ``org_admin`` need not carry the
    fine-grained permission in the catalog), while a SCOPED key must hold the
    permission explicitly. getattr-based so it is robust to bare User / stub
    principals (mirrors ``is_unscoped_superuser``).
    """
    is_admin = getattr(user, "is_org_admin", None)
    if is_admin is None:
        role = getattr(user, "role", None) or getattr(getattr(user, "user", None), "role", None)
        is_admin = role in ("org_admin", "admin", "super_admin")
    return bool(is_admin) and not bool(getattr(user, "_scoped", False))


def org_scope_or_platform(user: Any) -> uuid.UUID | None:
    """Resolve the org filter for an org-keyed audit/log read.

    returning ``None`` means "platform-wide, all tenants" and is allowed
    ONLY for an UNSCOPED super_admin. A scoped key or an org user is confined to
    its own ``organization_id``. A non-unscoped caller with NO org (e.g. a scoped
    super_admin API key, since super_admin users often have ``organization_id is
    None``) must FAIL CLOSED rather than fall through to an unfiltered query that
    the service would treat as platform-wide.
    """
    if is_unscoped_superuser(user):
        return None
    org = getattr(user, "organization_id", None)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization context required",
        )
    return org


# Default permissions by role
DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "super_admin": ["*"],
    "admin": [
        # Core resources
        "organization:*",
        "site:*",
        "controller:*",
        "network:*",  # network module: switches/APs/VLANs/WiFi/PoE/clients + vendor passthrough
        "firewall:*",  # firewall dashboard/orchestration (colon-style route guards)
        "hypervisor:*",  # compute/hypervisor module
        "firmware:read",  # firmware lifecycle read (firmware:upgrade stays admin-only)
        "device:*",
        "device:reboot",  # explicit for bulk ops
        "user:*",
        "role:*",
        "audit:read",
        "settings:*",
        # explicit bulk-op permissions (firmware is destructive,
        # deserves its own scope even though admin holds everything anyway)
        "config:push",
        "firmware:upgrade",
        # Agents & discovery
        "agent:*",
        "discovery:run",
        "discovery:write",
        # Alerts & events
        "alert:*",
        "event:*",
        "events:replay",
        "events:subscribe",
        # Analytics & config
        "analytics:*",
        "config:*",
        # VPN & tasks
        "vpn:*",
        "tasks:view",
        "tasks:manage",
        # Module permissions
        "cameras.*",
        "firewall.*",
        "gateway.*",
        "voip.*",
        "access.*",
        # Collector / Observability
        "collector.config",
        "collector.flows.read",
        "collector.logs.read",
        # Fabric Operation permissions. These are declared by
        # app/modules/*/module.py as Operation(permission=...) and were
        # never wired into this map, so the whole Fabric surface for five
        # modules answered "permission denied" to every role except
        # super_admin. Same defect the network HTTP surface had; the guard
        # that was added for it (tests/security/test_rbac_permission_parity)
        # only scanned require_permissions() call sites, not Operation
        # declarations, so this half went unnoticed. It now scans both.
        "hypervisor.*",
        "network.*",
        "storage.*",
        "backup.*",
        "ai.*",
        "automation.*",
        # NOTE: three-part codes must be listed explicitly -- the dot
        # wildcard above only expands two-part codes (see has_permission,
        # `if len(dot_parts) == 2`), which is why collector.*.read has
        # always been spelled out in full rather than as "collector.*".
        "network.vlan.manage",
        "network.wifi.manage",
        "automation.rules.read",
    ],
    "org_admin": [
        # Core resources
        "site:*",
        "controller:*",
        "network:*",  # network module: switches/APs/VLANs/WiFi/PoE/clients + vendor passthrough
        "firewall:*",  # firewall dashboard/orchestration (colon-style route guards)
        "hypervisor:*",  # compute/hypervisor module
        "firmware:read",  # firmware lifecycle read (firmware:upgrade stays admin-only)
        "device:*",
        "device:reboot",
        "config:push",
        # Note: no firmware:upgrade — too risky for org_admin (can brick fleet)
        "user:read",
        "user:create",
        "user:update",
        "role:read",
        "audit:read",
        "settings:read",
        # Agents & discovery
        "agent:*",
        "discovery:run",
        "discovery:write",
        # Alerts & events
        "alert:*",
        "event:read",
        "event:write",
        "events:replay",
        "events:subscribe",
        # Analytics & config
        "analytics:read",
        "analytics:write",
        "config:read",
        "config:write",
        # VPN & tasks
        "vpn:read",
        "vpn:write",
        "tasks:view",
        "tasks:manage",
        # Module permissions
        "cameras.*",
        "firewall.*",
        "gateway.*",
        "voip.*",
        "access.*",
        # Collector / Observability
        "collector.config",
        "collector.flows.read",
        "collector.logs.read",
        # Fabric Operation permissions. These are declared by
        # app/modules/*/module.py as Operation(permission=...) and were
        # never wired into this map, so the whole Fabric surface for five
        # modules answered "permission denied" to every role except
        # super_admin. Same defect the network HTTP surface had; the guard
        # that was added for it (tests/security/test_rbac_permission_parity)
        # only scanned require_permissions() call sites, not Operation
        # declarations, so this half went unnoticed. It now scans both.
        "hypervisor.*",
        "network.*",
        "storage.*",
        "backup.*",
        "ai.*",
        "automation.*",
        # NOTE: three-part codes must be listed explicitly -- the dot
        # wildcard above only expands two-part codes (see has_permission,
        # `if len(dot_parts) == 2`), which is why collector.*.read has
        # always been spelled out in full rather than as "collector.*".
        "network.vlan.manage",
        "network.wifi.manage",
        "automation.rules.read",
    ],
    "site_admin": [
        # Core resources
        "site:read",
        "controller:*",
        "network:*",  # network module: switches/APs/VLANs/WiFi/PoE/clients + vendor passthrough
        "firewall:*",  # firewall dashboard/orchestration (colon-style route guards)
        "hypervisor:*",  # compute/hypervisor module
        "firmware:read",  # firmware lifecycle read (firmware:upgrade stays admin-only)
        "device:*",
        "device:reboot",
        "config:push",
        # Note: no firmware:upgrade — too risky for site_admin
        "user:read",
        "audit:read",
        "settings:read",
        # Agents & discovery
        "agent:read",
        "agent:create",
        "agent:write",
        "discovery:run",
        # Alerts & events
        "alert:read",
        "alert:create",
        "alert:update",
        "event:read",
        "events:subscribe",
        # Analytics & config
        "analytics:read",
        "config:read",
        "config:write",
        # VPN & tasks
        "vpn:read",
        "vpn:write",
        "tasks:view",
        # Module permissions
        "cameras.*",
        "firewall.view",
        "firewall.view_logs",
        "firewall.manage_rules",
        "firewall.manage_nat",
        "firewall.manage_ids",
        "firewall.manage_vpn",
        "gateway.view",
        "gateway.manage_vlans",
        "gateway.manage_dhcp",
        "gateway.manage_dns",
        "gateway.manage_topology",
        "gateway.diagnostics",
        "gateway.drift",
        "voip.view",
        "voip.view_calls",
        "voip.manage_phones",
        "access.*",
        # Collector / Observability (read-only)
        "collector.flows.read",
        "collector.logs.read",
        # Fabric Operation permissions. These are declared by
        # app/modules/*/module.py as Operation(permission=...) and were
        # never wired into this map, so the whole Fabric surface for five
        # modules answered "permission denied" to every role except
        # super_admin. Same defect the network HTTP surface had; the guard
        # that was added for it (tests/security/test_rbac_permission_parity)
        # only scanned require_permissions() call sites, not Operation
        # declarations, so this half went unnoticed. It now scans both.
        "hypervisor.*",
        "network.*",
        "storage.view",
        "storage.write",
        "backup.view",
        "ai.chat",
        # Three-part codes: the dot wildcard only expands two-part
        # codes (has_permission, `if len(dot_parts) == 2`).
        "network.vlan.manage",
        "network.wifi.manage",
        "automation.rules.read",
    ],
    "operator": [
        # Core resources
        "site:read",
        "controller:read",
        "network:read",  # view switches/APs/VLANs/WiFi/PoE (no write — see admin tiers)
        "firewall:read",
        "hypervisor:read",
        "firmware:read",
        "device:read",
        "device:update",
        "device:reboot",
        "audit:read",
        # Agents & discovery
        "agent:read",
        "discovery:run",
        # Alerts & events
        "alert:read",
        "event:read",
        "events:subscribe",
        # Analytics & config
        "analytics:read",
        "config:read",
        # VPN & tasks
        "vpn:read",
        "tasks:view",
        # Module permissions
        "cameras.view",
        "cameras.playback",
        "cameras.ptz",
        "cameras.access",
        "firewall.view",
        "firewall.view_logs",
        "gateway.view",
        "gateway.diagnostics",
        "gateway.drift",
        "voip.view",
        "voip.view_calls",
        "access.view",
        "access.view_events",
        "access.door_control",
        # Collector / Observability (read-only)
        "collector.flows.read",
        "collector.logs.read",
        # Fabric Operation permissions. These are declared by
        # app/modules/*/module.py as Operation(permission=...) and were
        # never wired into this map, so the whole Fabric surface for five
        # modules answered "permission denied" to every role except
        # super_admin. Same defect the network HTTP surface had; the guard
        # that was added for it (tests/security/test_rbac_permission_parity)
        # only scanned require_permissions() call sites, not Operation
        # declarations, so this half went unnoticed. It now scans both.
        "hypervisor.view",
        "network.view",
        "storage.view",
        "backup.view",
        "ai.chat",
        "automation.rules.read",
    ],
    "viewer": [
        # Core resources
        "site:read",
        "controller:read",
        "network:read",  # view switches/APs/VLANs/WiFi/PoE (no write — see admin tiers)
        "firewall:read",
        "hypervisor:read",
        "firmware:read",
        "device:read",
        "audit:read",
        # Alerts & events
        "alert:read",
        "event:read",
        "events:subscribe",
        # Analytics & config
        "analytics:read",
        "config:read",
        # VPN & tasks
        "vpn:read",
        "tasks:view",
        # Module permissions (read-only)
        "cameras.view",
        "cameras.playback",
        "firewall.view",
        "firewall.view_logs",
        "gateway.view",
        "voip.view",
        "voip.view_calls",
        "access.view",
        "access.view_events",
        # Fabric Operation permissions. These are declared by
        # app/modules/*/module.py as Operation(permission=...) and were
        # never wired into this map, so the whole Fabric surface for five
        # modules answered "permission denied" to every role except
        # super_admin. Same defect the network HTTP surface had; the guard
        # that was added for it (tests/security/test_rbac_permission_parity)
        # only scanned require_permissions() call sites, not Operation
        # declarations, so this half went unnoticed. It now scans both.
        "hypervisor.view",
        "network.view",
        "storage.view",
        "backup.view",
    ],
    "guest": [
        "site:read",
        "device:read",
        "event:read",
        "cameras.view",
    ],
}


# ===========================================
# Current User Context
# ===========================================


class CurrentUser:
    """
    Container for current authenticated user context.

    Provides methods for permission and access checking.
    """

    # Make CurrentUser a valid Pydantic type so FastAPI ≥0.130 accepts it
    # as a dependency parameter annotation (Annotated[CurrentUser, Depends(...)]).
    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: Any,
    ) -> Any:
        from pydantic_core import core_schema as cs

        return cs.is_instance_schema(cls)

    def __init__(
        self,
        user: User,
        permissions: list[str],
        token_claims: dict[str, Any] | None = None,
        accessible_site_ids: set[uuid.UUID] | None = None,
        site_access_levels: dict[uuid.UUID, str | None] | None = None,
        scoped: bool = False,
    ):
        self.user = user
        self.permissions = permissions
        self.token_claims = token_claims or {}
        # Pre-loaded from user_site_access junction table
        self._accessible_site_ids: set[uuid.UUID] = accessible_site_ids or set()
        # Per-site access level: site_id → "admin"|"write"|"read"|None
        self._site_access_levels: dict[uuid.UUID, str | None] = site_access_levels or {}
        # True when ``permissions`` is an EXPLICIT scope ceiling (e.g. an API key
        # issued with a restricted scope list) rather than the user's full role
        # permissions. When scoped, has_permission evaluates ONLY against the
        # scope list — the super_admin / "*" implicit grants must NOT bypass a
        # deliberately-narrowed credential.
        self._scoped = scoped

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def organization_id(self) -> uuid.UUID | None:
        return self.user.organization_id

    @property
    def role(self) -> str:
        return self.user.role

    @property
    def is_superuser(self) -> bool:
        # Check if user has super_admin role
        return self.role == "super_admin"

    @property
    def is_org_admin(self) -> bool:
        return self.role in ("org_admin", "admin", "super_admin") or self.is_superuser

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        # When this principal carries an EXPLICIT scope ceiling (e.g. a scoped
        # API key), evaluate ONLY against the scope list — the super_admin / "*"
        # implicit grants must not bypass a deliberately-narrowed credential
        # . A read-only key minted by a super_admin must stay read-only.
        if not self._scoped:
            if self.is_superuser:
                return True
            if "*" in self.permissions:
                return True

        # Check exact match
        if permission in self.permissions:
            return True

        # Check wildcard patterns for colon-separated permissions
        # e.g., "device:*" matches "device:read"
        permission_parts = permission.split(":")
        if len(permission_parts) == 2:
            resource, _ = permission_parts
            if f"{resource}:*" in self.permissions:
                return True

        # Check wildcard patterns for dot-separated permissions
        # e.g., "cameras.*" matches "cameras.view"
        dot_parts = permission.split(".")
        if len(dot_parts) == 2:
            module, _ = dot_parts
            if f"{module}.*" in self.permissions:
                return True

        return False

    def has_any_permission(self, permissions: list[str]) -> bool:
        """Check if user has any of the specified permissions."""
        return any(self.has_permission(p) for p in permissions)

    @property
    def is_scoped(self) -> bool:
        """True when this principal carries an EXPLICIT scope ceiling (e.g. a
        scoped API key). Exposed so platform-security gates can refuse to let a
        deliberately-narrowed credential exceed its scope."""
        return bool(getattr(self, "_scoped", False))

    def has_all_permissions(self, permissions: list[str]) -> bool:
        """Check if user has all specified permissions."""
        return all(self.has_permission(p) for p in permissions)

    def has_role(self, role: str) -> bool:
        """Check if user has exactly the specified role.

        A SCOPED API key NEVER satisfies a role check via its owner's role —
        role authority can't be expressed in a scope list, so scoped keys are
        confined to permission (``has_permission``) gates. This completes the
        role-gate scope ceiling: the require_* dependency factories already
        refuse scoped keys, and now INLINE ``has_role()`` / ``has_min_role()``
        checks scattered across the API enforce the same ceiling.
        """
        if self.is_scoped:
            return False
        return self.role == role

    def has_min_role(self, min_role: str) -> bool:
        """Check if user's role level is at least the specified role.

        Returns False for a scoped API key (see :meth:`has_role`) so the many
        inline ``has_min_role(...)`` authorization gates (firewall config
        download, camera export/evidence, mikrotik/omada catastrophic-feature
        gates, staging guards, …) enforce the scope ceiling too — a
        deliberately-narrowed key can't borrow its owner's role to clear them.
        """
        if self.is_scoped:
            return False
        user_level = ROLE_HIERARCHY.get(self.role, 0)
        required_level = ROLE_HIERARCHY.get(min_role, 100)
        return user_level >= required_level

    def can_access_organization(self, org_id: uuid.UUID) -> bool:
        """Check if user can access a specific organization."""
        if self.is_superuser:
            return True
        return self.organization_id == org_id

    @property
    def accessible_site_ids(self) -> set[uuid.UUID]:
        """Set of site UUIDs this user is explicitly granted access to."""
        return self._accessible_site_ids

    @property
    def is_site_limited(self) -> bool:
        """True when this user is constrained to a subset of org sites.

        HYBRID model: a user becomes site-limited the
        moment they're given ANY ``UserSiteAccess`` grant. A user with
        zero grants is NOT limited — they keep full role-based access to
        every site in their org (backwards-compatible; nobody is locked
        out by the introduction of the model). super_admin / org_admin
        are never site-limited.
        """
        if self.is_superuser or self.is_org_admin:
            return False
        return bool(self._accessible_site_ids)

    def can_access_site(self, site_id: uuid.UUID) -> bool:
        """Check if user can access a specific site (hybrid model).

        - super_admin / org_admin → all sites in scope
        - site-limited user (has ≥1 grant) → only granted sites
        - user with no grants → unrestricted (role-based, org-scoped
          elsewhere) for backwards compatibility
        """
        if self.is_superuser or self.is_org_admin:
            return True
        if self.is_site_limited:
            return site_id in self._accessible_site_ids
        return True  # no grants configured → not site-limited

    def get_site_access_level(self, site_id: uuid.UUID) -> str | None:
        """Return the access_level for a site, or None if not explicitly set."""
        return self._site_access_levels.get(site_id)

    def has_site_permission(self, permission: str, site_id: uuid.UUID | None) -> bool:
        """Check if user has a permission, optionally constrained by site access level.

        When *site_id* is provided and the user has a ``UserSiteAccess`` record
        for that site with a non-null ``access_level``, the permission is
        filtered according to:

          • ``"read"``  → only read-like permissions pass
          • ``"write"`` → read + write-like permissions pass (not delete/admin)
          • ``"admin"`` / ``"full"`` → all permissions pass

        If the user has no explicit site access record, or the record has
        ``access_level=None``, the check falls through to the normal
        role-based ``has_permission()`` (backward compatible).
        """
        # First, the user must have the base permission via role
        if not self.has_permission(permission):
            return False

        # No site context → no additional restriction
        if site_id is None:
            return True

        # Super-admins and org-admins bypass site-level restrictions
        if self.is_superuser or self.is_org_admin:
            return True

        # Hybrid model: a site-limited user (has ≥1 grant) is denied
        # outright on any site they weren't granted — even for a
        # permission their role would otherwise allow.
        if self.is_site_limited and site_id not in self._accessible_site_ids:
            return False

        # Look up per-site access level
        access_level = self._site_access_levels.get(site_id)

        # No explicit record or NULL access_level → inherit role permissions.
        # (For a site-limited user this only reaches here when site_id IS
        # in their grants but the row's access_level is NULL → full.)
        if access_level is None:
            return True

        access_level = access_level.lower()

        if access_level in ("admin", "full"):
            return True

        if access_level == "write":
            # Block delete and admin actions
            return not _is_admin_or_delete_permission(permission)

        if access_level == "read":
            return _is_read_permission(permission)

        # Unknown access level → deny (fail-secure)
        return False


def _is_read_permission(permission: str) -> bool:
    """Return True if the permission represents a read-only action."""
    # Colon-separated: "device:read", "alert:read"
    if ":" in permission:
        action = permission.rsplit(":", 1)[1]
        return action in ("read", "list", "view", "*")

    # Dot-separated: "cameras.view", "firewall.view_logs"
    if "." in permission:
        action = permission.rsplit(".", 1)[1]
        return action in (
            "view",
            "view_logs",
            "view_calls",
            "view_events",
            "playback",
            "list",
            "read",
            "*",
        )

    return False


def _is_admin_or_delete_permission(permission: str) -> bool:
    """Return True if the permission represents a delete or admin action."""
    # Colon-separated: "device:delete", "device:admin"
    if ":" in permission:
        action = permission.rsplit(":", 1)[1]
        return action in ("delete", "admin")

    # Dot-separated: "cameras.delete", "plugins.admin"
    if "." in permission:
        action = permission.rsplit(".", 1)[1]
        return action in ("delete", "admin", "remove")

    return False


# ===========================================
# User Loading Helpers
# ===========================================


def _permission_granted_by(permission: str, granted: list[str]) -> bool:
    """Does ``granted`` cover ``permission``? Same rules as ``has_permission``.

    Role permissions are written with wildcards -- ``network:*``,
    ``organization:*``, and ``*`` for super_admin -- so a plain set
    intersection would drop an API-key scope of ``network:read`` from an admin
    whose role list holds ``network:*`` but not that literal string. That would
    break working keys, which is a worse outcome than the bug being fixed.

    Kept as a module function rather than reusing CurrentUser.has_permission
    because the intersection happens while BUILDING the principal, before one
    exists.
    """
    if "*" in granted or permission in granted:
        return True
    colon = permission.split(":")
    if len(colon) == 2 and f"{colon[0]}:*" in granted:
        return True
    dot = permission.split(".")
    if len(dot) == 2 and f"{dot[0]}.*" in granted:
        return True
    return False


async def _load_user_permissions(user: User) -> list[str]:
    """
    Load permissions for a user based on their role.

    In a full implementation, this would load from:
    - User's assigned roles
    - Role permissions
    - User-specific permission overrides
    """
    role = user.role or "viewer"
    return DEFAULT_ROLE_PERMISSIONS.get(role, DEFAULT_ROLE_PERMISSIONS["viewer"])


async def _get_user_by_id(
    session: AsyncSession,
    user_id: str,
) -> User | None:
    """Load user by ID from database."""
    try:
        user_uuid = uuid.UUID(user_id)
    except (ValueError, TypeError):
        return None

    result = await session.execute(
        select(User)
        .options(
            selectinload(User.organization),
            selectinload(User.site_access),
        )
        .where(User.id == user_uuid, User.deleted_at.is_(None))
    )
    return result.scalar_one_or_none()


# ===========================================
# Authentication Dependencies
# ===========================================


async def get_current_user_optional(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    api_key: str | None = Depends(api_key_header),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser | None:
    """
    Get current user if authenticated, None otherwise.

    Supports JWT tokens (Bearer header or httpOnly cookie) and API keys.
    """
    # Try JWT token: Bearer header first, then httpOnly cookie fallback
    if not token:
        from app.core.cookies import ACCESS_COOKIE

        token = request.cookies.get(ACCESS_COOKIE)

    if token:
        payload = await verify_token(token, token_type="access")
        if payload:
            user_id = payload.get("sub")
            if user_id:
                user = await _get_user_by_id(session, user_id)
                if user and user.is_active:
                    # SECURITY: reject tokens minted before a session revocation
                    current_tv = getattr(user, "token_version", 0) or 0
                    if payload.get("tv", 0) != current_tv:
                        return None  # stale session — force re-login
                    # SECURITY (AUTH-001): a TARGETED single-device
                    # revocation (DELETE /auth/sessions/{id}) flips the
                    # UserSession row WITHOUT bumping token_version or
                    # blacklisting the JTI, so the tv check above does not catch
                    # it. Enforce the per-device access-jti revocation here on the
                    # shared REST path (the auth router already enforced it for
                    # its own routes). Missing rows = legacy tokens = allowed.
                    from app.core.session_revocation import (
                        is_session_revoked_for_access_jti,
                    )

                    access_jti = payload.get("jti")
                    if access_jti and await is_session_revoked_for_access_jti(
                        session, str(access_jti)
                    ):
                        return None  # session revoked — force re-login
                    permissions = await _load_user_permissions(user)
                    site_accesses = (
                        user.site_access
                        if hasattr(user, "site_access") and user.site_access
                        else []
                    )
                    site_ids = {sa.site_id for sa in site_accesses}
                    site_levels = {sa.site_id: sa.access_level for sa in site_accesses}
                    return CurrentUser(
                        user=user,
                        permissions=permissions,
                        token_claims=payload,
                        accessible_site_ids=site_ids,
                        site_access_levels=site_levels,
                    )

    # Try API key authentication
    if api_key:
        try:
            from sqlalchemy import select as _select

            from app.models.api_keys import APIKey, extract_prefix, verify_api_key

            prefix = extract_prefix(api_key)
            if prefix:
                result = await session.execute(
                    _select(APIKey).where(
                        APIKey.key_prefix == prefix,
                        APIKey.is_active == True,  # noqa: E712
                    )
                )
                db_key = result.scalar_one_or_none()
                if db_key and verify_api_key(api_key, db_key.key_hash):
                    # Check expiration
                    if db_key.expires_at and db_key.expires_at < datetime.now(UTC):
                        return None
                    # Record last usage (best-effort, don't fail auth if this errors)
                    try:
                        db_key.last_used = datetime.now(UTC)
                        await session.commit()
                    except SQLAlchemyError:
                        await session.rollback()
                    # Load the key owner
                    user = await _get_user_by_id(session, str(db_key.user_id))
                    # SECURITY: apply the same gates as JWT auth.
                    # _get_user_by_id already filters deleted_at IS NULL, but
                    # we re-check defensively in case that helper changes.
                    if user is None:
                        return None
                    if getattr(user, "deleted_at", None) is not None:
                        return None
                    if user and user.is_active:
                        # Use key scopes if set; otherwise inherit from user's role.
                        # A non-empty scope list is an explicit CEILING — mark the
                        # principal scoped so has_permission enforces it even for a
                        # super_admin owner.
                        is_scoped = bool(db_key.scopes)
                        # A key's scopes are a ceiling, NOT a grant.
                        #
                        # ``list(db_key.scopes)`` was used verbatim, so a key
                        # minted while its owner was an org_admin kept those
                        # permissions after the owner was demoted to viewer.
                        # Demoting bumps ``token_version``, which kills the
                        # user's JWTs -- and does nothing to their API keys. So
                        # the documented way to strip someone's access left
                        # their long-lived credential holding the old role's
                        # powers indefinitely.
                        #
                        # The ceiling is now the INTERSECTION with whatever the
                        # owner can do today. Self-healing: it applies to keys
                        # already in the database, with no migration and no
                        # revocation sweep.
                        #
                        # Deliberately not auto-revoking on demote instead:
                        # deleting somebody's credential as a side effect of a
                        # role edit is a surprise, and a key that quietly stops
                        # authorising what its owner can no longer do is both
                        # safer and easier to reason about. The permission load
                        # is a dict lookup, so this costs nothing per request.
                        user_permissions = await _load_user_permissions(user)
                        if db_key.scopes:
                            permissions = [
                                s
                                for s in db_key.scopes
                                if _permission_granted_by(s, user_permissions)
                            ]
                        else:
                            permissions = user_permissions
                        site_accesses = (
                            user.site_access
                            if hasattr(user, "site_access") and user.site_access
                            else []
                        )
                        site_ids = {sa.site_id for sa in site_accesses}
                        site_levels = {sa.site_id: sa.access_level for sa in site_accesses}
                        return CurrentUser(
                            user=user,
                            permissions=permissions,
                            token_claims={
                                "auth_method": "api_key",
                                "key_id": str(db_key.id),
                            },
                            accessible_site_ids=site_ids,
                            site_access_levels=site_levels,
                            scoped=is_scoped,
                        )
        except Exception:
            logger.warning("API key authentication failed", exc_info=True)

    return None


async def get_current_user(
    current_user: CurrentUser | None = Depends(get_current_user_optional),
) -> CurrentUser:
    """
    Get current authenticated user. Raises 401 if not authenticated.
    """
    if not current_user:
        raise AuthenticationError()
    # Publish the resolved user into the request-scoped contextvar at the
    # EARLIEST authenticated chokepoint — every authed path funnels through
    # get_current_user (directly or via get_current_active_user/
    # require_permissions), so deep resolvers (_resolve_site_context,
    # _resolve_controller_or_gateway) can enforce the per-user site grant
    # regardless of which auth dependency the endpoint declares. Request-local.
    from app.core.site_access import current_user_var

    current_user_var.set(current_user)
    return current_user


async def get_current_active_user(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Get current active user. Raises 403 if user is inactive.
    """
    if not current_user.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    # (current_user_var is published in get_current_user, the base auth
    # chokepoint that this dependency funnels through.)
    return current_user


async def get_current_superuser(
    current_user: CurrentUser = Depends(get_current_active_user),
) -> CurrentUser:
    """
    Get current superuser. Raises 403 if not superuser.
    """
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise PermissionDeniedError("Superuser access required")
    return current_user


async def get_current_org_admin(
    current_user: CurrentUser = Depends(get_current_active_user),
) -> CurrentUser:
    """
    Get current organization admin. Raises 403 if not org admin or superuser.

    R17: scope-aware (mirrors is_unscoped_superuser / is_unscoped_org_admin). A
    scoped API key narrowed below admin must not pass via its raw role. Currently
    unused, hardened so it can never become a permission-ceiling footgun.
    """
    if not is_unscoped_superuser(current_user) and not is_unscoped_org_admin(current_user):
        raise PermissionDeniedError("Organization admin access required")
    return current_user


# ===========================================
# Permission Dependencies (Factories)
# ===========================================


def require_permissions(*permissions: str) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring specific permissions.

    Usage:
        @router.get("/devices")
        async def list_devices(
            user: CurrentUser = Depends(require_permissions("device:read"))
        ):
            ...
    """

    async def check_permissions(
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        logger.debug(
            f"Permission check: user={current_user.user.email}, "
            f"required={permissions}, role={current_user.role}"
        )

        if not current_user.has_all_permissions(list(permissions)):
            missing = [p for p in permissions if not current_user.has_permission(p)]
            logger.warning(f"Permission denied for {current_user.user.email}: missing {missing}")
            raise PermissionDeniedError(f"Missing permissions: {', '.join(missing)}")

        return current_user

    return check_permissions


def require_any_permission(*permissions: str) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring any of the specified permissions.

    Usage:
        @router.get("/devices")
        async def list_devices(
            user: CurrentUser = Depends(require_any_permission("device:read", "device:admin"))
        ):
            ...
    """

    async def check_permissions(
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        if not current_user.has_any_permission(list(permissions)):
            raise PermissionDeniedError(f"Requires one of: {', '.join(permissions)}")
        return current_user

    return check_permissions


def require_site_permissions(
    *permissions: str,
    site_id_param: str = "site_id",
) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring permissions with site-level access enforcement.

    Extracts ``site_id`` from path or query parameters and checks the user's
    ``UserSiteAccess.access_level`` for that site.  If the access level is too
    restrictive for the requested permission, a 403 is raised.

    Usage::

        @router.post("/sites/{site_id}/devices")
        async def create_device(
            site_id: UUID,
            user: CurrentUser = Depends(
                require_site_permissions("device:write", site_id_param="site_id")
            ),
        ):
            ...
    """

    async def check_permissions(
        request: Request,
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        # Resolve site_id from path params first, then query params
        raw_site_id = request.path_params.get(site_id_param) or request.query_params.get(
            site_id_param
        )
        site_id: uuid.UUID | None = None
        if raw_site_id:
            try:
                site_id = uuid.UUID(str(raw_site_id))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid site_id",
                )

        # Check each permission against site access level
        for perm in permissions:
            if not current_user.has_site_permission(perm, site_id):
                logger.warning(
                    "Site permission denied for %s: %s (site=%s, access_level=%s)",
                    current_user.user.email,
                    perm,
                    site_id,
                    current_user.get_site_access_level(site_id) if site_id else None,
                )
                raise PermissionDeniedError(
                    f"Insufficient site access level for permission: {perm}"
                )

        return current_user

    return check_permissions


def require_role(role: str) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring a specific role.

    Usage:
        @router.delete("/users/{user_id}")
        async def delete_user(
            user: CurrentUser = Depends(require_role("admin"))
        ):
            ...
    """

    async def check_role(
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        # Scope ceiling: a scoped API key must not pass a role-only gate on its
        # owner's raw role (see require_min_role). No-op for unscoped principals.
        if current_user.is_scoped:
            raise PermissionDeniedError(
                f"Requires role {role}; scoped API keys cannot satisfy role-based gates"
            )
        if not current_user.has_role(role) and not current_user.is_superuser:
            raise PermissionDeniedError(f"Requires role: {role}")
        return current_user

    return check_role


def require_min_role(min_role: str) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring a minimum role level.

    Usage:
        @router.post("/controllers")
        async def create_controller(
            user: CurrentUser = Depends(require_min_role("operator"))
        ):
            ...
    """

    async def check_min_role(
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        # Scope ceiling: a SCOPED API key must not
        # satisfy a role-based gate via its OWNER's raw role — has_min_role reads
        # user.role and ignores the deliberately-narrowed scopes. Role gates grant
        # authority a scope list can't express, so a scoped key is refused here and
        # must use a permission-scoped endpoint (require_permissions honors scopes).
        # No-op for normal users and unscoped keys (_scoped=False).
        if current_user.is_scoped:
            raise PermissionDeniedError(
                f"Requires minimum role {min_role}; scoped API keys cannot satisfy "
                "role-based gates — use a permission-scoped key"
            )
        if not current_user.has_min_role(min_role):
            raise PermissionDeniedError(f"Requires minimum role: {min_role}")
        return current_user

    return check_min_role


# ===========================================
# Organization Access Dependencies
# ===========================================


def require_organization_access(
    org_id_param: str = "organization_id",
) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    """
    Dependency factory for requiring access to a specific organization.

    Extracts organization ID from path parameters and validates access.
    """

    async def check_org_access(
        request: Request,
        current_user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        org_id = request.path_params.get(org_id_param)
        if org_id:
            try:
                org_uuid = uuid.UUID(org_id)
                if not current_user.can_access_organization(org_uuid):
                    raise PermissionDeniedError("Organization access denied")
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid organization ID",
                )
        return current_user

    return check_org_access
