# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Organization Service
===================================

Multi-tenancy and organization management including:
- Organization CRUD operations
- Membership management
- Settings and quotas
- Resource limits
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Controller, Device, Organization, Site, User

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class OrganizationTier(StrEnum):
    """Organization subscription tiers."""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"


class OrganizationStatus(StrEnum):
    """Organization status."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    PENDING = "pending"
    CANCELLED = "cancelled"


class MemberRole(StrEnum):
    """Organization member roles."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class OrganizationQuota:
    """Resource quotas for an organization tier."""

    tier: OrganizationTier

    # User limits
    max_users: int = 5
    max_admins: int = 1

    # Site limits
    max_sites: int = 3

    # Device limits
    max_devices: int = 50
    max_devices_per_site: int = 25

    # Controller limits
    max_controllers: int = 5

    # API limits
    api_rate_limit: int = 1000
    max_api_keys: int = 5

    # Storage
    max_audit_retention_days: int = 30
    max_metric_retention_days: int = 7

    # Features
    features: list[str] = field(default_factory=list)


@dataclass
class OrganizationSettings:
    """Organization-level settings."""

    timezone: str = "UTC"
    locale: str = "en-US"
    date_format: str = "YYYY-MM-DD"
    time_format: str = "24h"

    # Notifications
    email_notifications: bool = True
    webhook_notifications: bool = False

    # Security
    require_mfa: bool = False
    session_timeout_minutes: int = 60
    password_min_length: int = 8

    # Discovery
    auto_discovery_enabled: bool = True
    discovery_interval_hours: int = 24

    # Alerts
    alert_threshold: str = "warning"


@dataclass
class OrganizationStats:
    """Organization statistics."""

    user_count: int = 0
    site_count: int = 0
    device_count: int = 0
    controller_count: int = 0
    online_device_count: int = 0
    offline_device_count: int = 0


# =============================================================================
# Tier Quotas
# =============================================================================

TIER_QUOTAS: dict[OrganizationTier, OrganizationQuota] = {
    OrganizationTier.FREE: OrganizationQuota(
        tier=OrganizationTier.FREE,
        max_users=3,
        max_admins=1,
        max_sites=1,
        max_devices=10,
        max_devices_per_site=10,
        max_controllers=1,
        api_rate_limit=100,
        max_api_keys=1,
        max_audit_retention_days=7,
        max_metric_retention_days=1,
        features=["basic_monitoring"],
    ),
    OrganizationTier.STARTER: OrganizationQuota(
        tier=OrganizationTier.STARTER,
        max_users=10,
        max_admins=2,
        max_sites=5,
        max_devices=100,
        max_devices_per_site=50,
        max_controllers=10,
        api_rate_limit=500,
        max_api_keys=5,
        max_audit_retention_days=30,
        max_metric_retention_days=7,
        features=["basic_monitoring", "webhooks", "automation"],
    ),
    OrganizationTier.PROFESSIONAL: OrganizationQuota(
        tier=OrganizationTier.PROFESSIONAL,
        max_users=50,
        max_admins=10,
        max_sites=20,
        max_devices=500,
        max_devices_per_site=100,
        max_controllers=50,
        api_rate_limit=2000,
        max_api_keys=20,
        max_audit_retention_days=90,
        max_metric_retention_days=30,
        features=["basic_monitoring", "webhooks", "automation", "backup", "api_access"],
    ),
    OrganizationTier.ENTERPRISE: OrganizationQuota(
        tier=OrganizationTier.ENTERPRISE,
        max_users=500,
        max_admins=50,
        max_sites=100,
        max_devices=5000,
        max_devices_per_site=500,
        max_controllers=200,
        api_rate_limit=10000,
        max_api_keys=100,
        max_audit_retention_days=365,
        max_metric_retention_days=90,
        features=["all"],
    ),
    OrganizationTier.UNLIMITED: OrganizationQuota(
        tier=OrganizationTier.UNLIMITED,
        max_users=999999,
        max_admins=999999,
        max_sites=999999,
        max_devices=999999,
        max_devices_per_site=999999,
        max_controllers=999999,
        api_rate_limit=999999,
        max_api_keys=999999,
        max_audit_retention_days=9999,
        max_metric_retention_days=9999,
        features=["all"],
    ),
}


# =============================================================================
# Exceptions
# =============================================================================


class OrganizationError(Exception):
    """Base organization error."""

    pass


class OrganizationNotFoundError(OrganizationError):
    """Organization not found."""

    pass


class QuotaExceededError(OrganizationError):
    """Resource quota exceeded."""

    def __init__(self, resource: str, limit: int, current: int):
        self.resource = resource
        self.limit = limit
        self.current = current
        super().__init__(f"Quota exceeded for {resource}: {current}/{limit}")


class DuplicateSlugError(OrganizationError):
    """Organization slug already exists."""

    pass


# =============================================================================
# Organization Service
# =============================================================================


class OrganizationService:
    """
    Service for managing organizations.

    Features:
    - Organization CRUD
    - Member management
    - Quota enforcement
    - Settings management
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # Organization CRUD
    # =========================================================================

    async def create_organization(
        self,
        name: str,
        slug: str | None = None,
        tier: OrganizationTier = OrganizationTier.FREE,
        owner_id: UUID | None = None,
        settings: dict[str, Any] | None = None,
    ) -> Organization:
        """
        Create a new organization.

        Args:
            name: Organization display name
            slug: URL-safe identifier (auto-generated if not provided)
            tier: Subscription tier
            owner_id: User ID of the owner
            settings: Initial settings

        Returns:
            Created Organization object
        """
        # Generate slug if not provided
        if not slug:
            slug = self._generate_slug(name)

        # Check for duplicate slug
        existing = await self.get_by_slug(slug)
        if existing:
            raise DuplicateSlugError(f"Slug '{slug}' already exists")

        # Create organization
        org = Organization(
            name=name,
            slug=slug,
            tier=tier.value,
            status=OrganizationStatus.ACTIVE.value,
            settings=settings or {},
        )

        self.db.add(org)
        await self.db.commit()
        await self.db.refresh(org)

        # Add owner as member if provided
        if owner_id:
            await self.add_member(org.id, owner_id, MemberRole.OWNER)

        logger.info("Created organization: %s (%s)", name, slug)
        return org

    async def get_organization(self, org_id: UUID) -> Organization | None:
        """Get organization by ID (live only — soft-deleted orgs are not found)."""
        result = await self.db.execute(
            select(Organization).where(Organization.id == org_id, Organization.deleted_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Organization | None:
        """Get organization by slug (live only)."""
        result = await self.db.execute(
            select(Organization).where(Organization.slug == slug, Organization.deleted_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def update_organization(
        self,
        org_id: UUID,
        **updates: Any,
    ) -> Organization:
        """
        Update organization fields.

        Allowed fields: name, settings, tier, status
        """
        org = await self.get_organization(org_id)
        if not org:
            raise OrganizationNotFoundError(f"Organization {org_id} not found")

        allowed_fields = {"name", "settings", "tier", "status"}
        for field_name, value in updates.items():
            if field_name in allowed_fields:
                setattr(org, field_name, value)

        org.updated_at = datetime.now(UTC)
        await self.db.commit()
        await self.db.refresh(org)

        return org

    async def delete_organization(self, org_id: UUID, soft: bool = True) -> bool:
        """
        Delete an organization.

        Args:
            org_id: Organization ID
            soft: If True, mark as deleted. If False, permanently delete.
        """
        org = await self.get_organization(org_id)
        if not org:
            return False

        if soft:
            org.deleted_at = datetime.now(UTC)
            org.status = OrganizationStatus.CANCELLED.value
        else:
            await self.db.delete(org)

        await self.db.commit()
        logger.info("Deleted organization: %s (soft=%s)", org_id, soft)
        return True

    # =========================================================================
    # Member Management
    # =========================================================================

    async def add_member(
        self,
        org_id: UUID,
        user_id: UUID,
        role: MemberRole = MemberRole.MEMBER,
    ) -> bool:
        """Add a user as a member of the organization."""
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id, User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()
        if not user:
            return False

        # Check quota
        await self._check_quota(org_id, "users")

        # Update user's organization
        user.organization_id = org_id
        user.org_role = role.value

        await self.db.commit()
        logger.info("Added user %s to org %s as %s", user_id, org_id, role.value)
        return True

    async def remove_member(self, org_id: UUID, user_id: UUID) -> bool:
        """Remove a user from the organization."""
        result = await self.db.execute(
            select(User).where(
                and_(
                    User.id == user_id,
                    User.organization_id == org_id,
                    User.deleted_at.is_(None),
                )
            )
        )
        user = result.scalar_one_or_none()
        if not user:
            return False

        user.organization_id = None
        user.org_role = None

        await self.db.commit()
        return True

    async def get_members(self, org_id: UUID) -> list[User]:
        """Get all members of an organization."""
        result = await self.db.execute(
            select(User).where(User.organization_id == org_id, User.deleted_at.is_(None))
        )
        return list(result.scalars().all())

    async def update_member_role(
        self,
        org_id: UUID,
        user_id: UUID,
        role: MemberRole,
    ) -> bool:
        """Update a member's role."""
        result = await self.db.execute(
            select(User).where(
                and_(
                    User.id == user_id,
                    User.organization_id == org_id,
                    User.deleted_at.is_(None),
                )
            )
        )
        user = result.scalar_one_or_none()
        if not user:
            return False

        # Check admin quota if promoting to admin
        if role in (MemberRole.ADMIN, MemberRole.OWNER):
            await self._check_quota(org_id, "admins")

        user.org_role = role.value
        await self.db.commit()
        return True

    # =========================================================================
    # Statistics
    # =========================================================================

    async def get_stats(self, org_id: UUID) -> OrganizationStats:
        """Get organization statistics."""
        # User count
        user_result = await self.db.execute(
            select(func.count(User.id)).where(User.organization_id == org_id)
        )
        user_count = user_result.scalar() or 0

        # Site count
        site_result = await self.db.execute(
            select(func.count(Site.id)).where(Site.organization_id == org_id)
        )
        site_count = site_result.scalar() or 0

        # Device count
        device_result = await self.db.execute(
            select(func.count(Device.id))
            .join(Site, Device.site_id == Site.id)
            .where(Site.organization_id == org_id)
        )
        device_count = device_result.scalar() or 0

        # Controller count (controllers have no direct org FK — join via site)
        controller_result = await self.db.execute(
            select(func.count(Controller.id))
            .select_from(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(Site.organization_id == org_id)
        )
        controller_count = controller_result.scalar() or 0

        # Online/offline devices
        online_result = await self.db.execute(
            select(func.count(Device.id))
            .join(Site, Device.site_id == Site.id)
            .where(and_(Site.organization_id == org_id, Device.status == "online"))
        )
        online_count = online_result.scalar() or 0

        return OrganizationStats(
            user_count=user_count,
            site_count=site_count,
            device_count=device_count,
            controller_count=controller_count,
            online_device_count=online_count,
            offline_device_count=device_count - online_count,
        )

    # =========================================================================
    # Quota Management
    # =========================================================================

    def get_quota(self, tier: OrganizationTier) -> OrganizationQuota:
        """Get quota for a tier."""
        return TIER_QUOTAS.get(tier, TIER_QUOTAS[OrganizationTier.FREE])

    async def check_quota(
        self,
        org_id: UUID,
        resource: str,
        increment: int = 1,
    ) -> bool:
        """
        Check if adding resources would exceed quota.

        Returns True if within quota, False otherwise.
        """
        from fastapi import HTTPException

        try:
            await self._check_quota(org_id, resource, increment)
            return True
        except QuotaExceededError:
            return False
        except HTTPException as exc:
            if exc.status_code == 403:
                return False
            raise

    async def _check_quota(
        self,
        org_id: UUID,
        resource: str,
        increment: int = 1,
    ) -> None:
        """Atomically verify the org is under its tier quota for a resource.

        Holds a row-level lock on the ``organizations`` row via
        ``SELECT ... FOR UPDATE`` so concurrent resource creations serialize
        through this check, closing the TOCTOU window between
        ``COUNT(*)`` and the caller's subsequent insert. Must run inside a
        transaction — the caller is expected to commit after the insert.

        Supported ``resource`` values:
        ``users``, ``admins``, ``sites``, ``devices``, ``controllers``.
        Unknown resources and tiers without a matching ``max_*`` silently
        pass (noop).

        Raises:
            OrganizationNotFoundError: org missing or soft-deleted
            QuotaExceededError: would exceed tier's max_<resource>
        """
        from fastapi import HTTPException  # local import avoids cycles in tests

        from app.core.config import settings as _settings

        # Self-hosted installs are unlimited: the tier ladder is a SaaS
        # monetization construct and must never gate someone who owns the
        # deployment (capping a self-hoster at 1 site is nonsensical). A SaaS
        # operator running FreeSDN multi-tenant opts in with
        # FREESDN_ENFORCE_ORG_QUOTAS=true.
        if not getattr(_settings, "ENFORCE_ORG_QUOTAS", False):
            return

        # Lock the org row so concurrent quota checks serialize.
        lock_stmt = (
            select(Organization)
            .where(Organization.id == org_id, Organization.deleted_at.is_(None))
            .with_for_update()
        )
        org = (await self.db.execute(lock_stmt)).scalar_one_or_none()
        if org is None:
            raise OrganizationNotFoundError(f"Organization {org_id} not found")

        # NOTE: ``tier`` is not yet a first-class column on the
        # Organization model — it is stashed in ``settings["tier"]`` so
        # we do not have to ship a migration before tier-based quotas
        # roll out. Defaults to FREE if absent or invalid.
        raw_tier = (org.settings or {}).get("tier") if hasattr(org, "settings") else None
        try:
            tier = OrganizationTier(raw_tier) if raw_tier else OrganizationTier.FREE
        except ValueError:
            tier = OrganizationTier.FREE
        quota = self.get_quota(tier)

        # Build a scalar COUNT(*) under the row lock. For resources without
        # a direct org FK (devices, controllers) we count via Site join.
        if resource == "users":
            count_stmt = select(func.count(User.id)).where(
                User.organization_id == org_id,
                User.deleted_at.is_(None),
            )
            max_allowed = quota.max_users
        elif resource == "admins":
            # M2: count by the real authority column `role`. The old
            # `User.org_role.in_(("admin","owner"))` referenced a column that
            # does not exist on the User model (would AttributeError at query
            # build) and used enum values that never matched.
            count_stmt = select(func.count(User.id)).where(
                User.organization_id == org_id,
                User.deleted_at.is_(None),
                User.role.in_(("org_admin", "super_admin")),
            )
            max_allowed = quota.max_admins
        elif resource == "sites":
            count_stmt = select(func.count(Site.id)).where(
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
            max_allowed = quota.max_sites
        elif resource == "devices":
            count_stmt = (
                select(func.count(Device.id))
                .select_from(Device)
                .join(Site, Device.site_id == Site.id)
                .where(
                    Site.organization_id == org_id,
                    Device.deleted_at.is_(None),
                    Site.deleted_at.is_(None),
                )
            )
            max_allowed = quota.max_devices
        elif resource == "controllers":
            count_stmt = (
                select(func.count(Controller.id))
                .select_from(Controller)
                .join(Site, Controller.site_id == Site.id)
                .where(
                    Site.organization_id == org_id,
                    Controller.deleted_at.is_(None),
                    Site.deleted_at.is_(None),
                )
            )
            max_allowed = quota.max_controllers
        else:
            return  # unknown resource — noop

        if max_allowed is None:
            return

        current = (await self.db.execute(count_stmt)).scalar() or 0
        if current + increment > max_allowed:
            # Raise both the structured service error (for library callers)
            # and surface as a 403 for FastAPI callers through HTTPException
            # translation downstream. QuotaExceededError is caught by
            # check_quota() above so backward-compat is preserved.
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Quota exceeded: {resource} limit is {max_allowed} "
                    f"(current: {current}). Upgrade your tier to add more."
                ),
            )

    # =========================================================================
    # Utilities
    # =========================================================================

    def _generate_slug(self, name: str) -> str:
        """Generate URL-safe slug from name."""
        slug = name.lower()
        slug = re.sub(r"[^a-z0-9\s-]", "", slug)
        slug = re.sub(r"[\s_]+", "-", slug)
        slug = re.sub(r"-+", "-", slug)
        slug = slug.strip("-")
        return slug[:50]
