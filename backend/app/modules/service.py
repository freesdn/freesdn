# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Service
============================

Business logic for module management.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.base import ModuleNotEnabledError
from app.modules.models import ModuleEvent, ModuleFeatureFlag, OrganizationModule
from app.modules.registry import ModuleRegistry, module_registry

logger = logging.getLogger(__name__)


class ModuleService:
    """
    Service for managing module state and settings.

    Provides methods for:
    - Enabling/disabling modules for organizations
    - Managing module settings
    - Logging module events
    - Managing feature flags
    """

    def __init__(
        self,
        db: AsyncSession,
        registry: ModuleRegistry | None = None,
    ):
        """
        Initialize the service.

        Args:
            db: Database session
            registry: Module registry (default: global registry)
        """
        self.db = db
        self.registry = registry or module_registry

    # ==========================================
    # Module Enablement
    # ==========================================

    async def get_org_modules(
        self,
        organization_id: UUID,
        include_disabled: bool = False,
    ) -> list[OrganizationModule]:
        """
        Get all module records for an organization.

        Args:
            organization_id: Organization ID
            include_disabled: Include disabled modules

        Returns:
            List of OrganizationModule records
        """
        query = select(OrganizationModule).where(
            OrganizationModule.organization_id == organization_id
        )

        if not include_disabled:
            query = query.where(OrganizationModule.is_enabled)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_org_module(
        self,
        organization_id: UUID,
        module_id: str,
    ) -> OrganizationModule | None:
        """
        Get a specific module record for an organization.

        Args:
            organization_id: Organization ID
            module_id: Module ID

        Returns:
            OrganizationModule or None
        """
        result = await self.db.execute(
            select(OrganizationModule).where(
                and_(
                    OrganizationModule.organization_id == organization_id,
                    OrganizationModule.module_id == module_id,
                )
            )
        )
        return result.scalar_one_or_none()

    async def is_module_enabled(
        self,
        organization_id: UUID,
        module_id: str,
    ) -> bool:
        """
        Check if a module is enabled for an organization.

        Args:
            organization_id: Organization ID
            module_id: Module ID

        Returns:
            True if enabled
        """
        # Check if module exists
        module = self.registry.get_module_or_none(module_id)
        if not module:
            return False

        # Core modules are always enabled
        if module.manifest.is_core:
            return True

        # Check database
        org_module = await self.get_org_module(organization_id, module_id)
        return org_module is not None and org_module.is_enabled

    async def enable_module(
        self,
        organization_id: UUID,
        module_id: str,
        settings: dict[str, Any] | None = None,
        user_id: UUID | None = None,
    ) -> OrganizationModule:
        """
        Enable a module for an organization.

        Args:
            organization_id: Organization ID
            module_id: Module ID
            settings: Initial settings
            user_id: User enabling the module

        Returns:
            OrganizationModule record

        Raises:
            ModuleNotFoundError: If module doesn't exist
        """
        # Validate module exists
        module = self.registry.get_module(module_id)

        # Preview modules are not ready for production use and cannot be
        # enabled. The admin UI presents them as non-enableable; this guard
        # rejects any direct API attempt as well.
        if getattr(module.manifest, "coming_soon", False):
            raise ValueError(f"Module '{module_id}' is a preview and cannot be enabled yet")

        # Check if already enabled
        org_module = await self.get_org_module(organization_id, module_id)

        if org_module:
            if org_module.is_enabled:
                return org_module  # Already enabled

            # Re-enable
            org_module.is_enabled = True
            org_module.enabled_at = datetime.now(UTC)
            org_module.disabled_at = None
            if settings:
                org_module.settings = settings
        else:
            # Create new record
            org_module = OrganizationModule(
                organization_id=organization_id,
                module_id=module_id,
                is_enabled=True,
                enabled_at=datetime.now(UTC),
                settings=settings or module.get_default_settings(),
            )
            self.db.add(org_module)

        # Start module for org
        await self.registry.start_module_for_org(module_id, organization_id, self.db)

        # Log event
        await self._log_event(
            organization_id=organization_id,
            module_id=module_id,
            event_type="enabled",
            user_id=user_id,
            details={"settings": settings},
        )

        await self.db.commit()
        await self.db.refresh(org_module)

        logger.info("Enabled module %s for org %s", module_id, organization_id)
        return org_module

    async def disable_module(
        self,
        organization_id: UUID,
        module_id: str,
        user_id: UUID | None = None,
    ) -> OrganizationModule | None:
        """
        Disable a module for an organization.

        Args:
            organization_id: Organization ID
            module_id: Module ID
            user_id: User disabling the module

        Returns:
            OrganizationModule record or None if not found

        Raises:
            ValueError: If trying to disable a core module
        """
        # Check if core module
        module = self.registry.get_module_or_none(module_id)
        if module and module.manifest.is_core:
            raise ValueError(f"Cannot disable core module: {module_id}")

        # Get record
        org_module = await self.get_org_module(organization_id, module_id)
        if not org_module:
            return None

        if not org_module.is_enabled:
            return org_module  # Already disabled

        # Disable
        org_module.is_enabled = False
        org_module.disabled_at = datetime.now(UTC)

        # Stop module for org
        await self.registry.stop_module_for_org(module_id, organization_id, self.db)

        # Log event
        await self._log_event(
            organization_id=organization_id,
            module_id=module_id,
            event_type="disabled",
            user_id=user_id,
        )

        await self.db.commit()
        await self.db.refresh(org_module)

        logger.info("Disabled module %s for org %s", module_id, organization_id)
        return org_module

    async def update_module_settings(
        self,
        organization_id: UUID,
        module_id: str,
        settings: dict[str, Any],
        user_id: UUID | None = None,
    ) -> OrganizationModule:
        """
        Update settings for a module.

        Args:
            organization_id: Organization ID
            module_id: Module ID
            settings: New settings (merged with existing)
            user_id: User updating settings

        Returns:
            Updated OrganizationModule

        Raises:
            ModuleNotEnabledError: If module is not enabled
        """
        org_module = await self.get_org_module(organization_id, module_id)
        if not org_module or not org_module.is_enabled:
            raise ModuleNotEnabledError(module_id, organization_id)

        # Validate settings
        module = self.registry.get_module(module_id)
        is_valid, errors = await module.validate_settings(settings, organization_id)
        if not is_valid:
            raise ValueError(f"Invalid settings: {errors}")

        # Merge settings
        old_settings = org_module.settings.copy()
        org_module.settings = {**org_module.settings, **settings}

        # Log event
        await self._log_event(
            organization_id=organization_id,
            module_id=module_id,
            event_type="settings_changed",
            user_id=user_id,
            details={
                "old_settings": old_settings,
                "new_settings": org_module.settings,
            },
        )

        await self.db.commit()
        await self.db.refresh(org_module)

        return org_module

    # ==========================================
    # Module Events
    # ==========================================

    async def _log_event(
        self,
        module_id: str,
        event_type: str,
        organization_id: UUID | None = None,
        user_id: UUID | None = None,
        details: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> ModuleEvent:
        """Log a module event."""
        event = ModuleEvent(
            organization_id=organization_id,
            module_id=module_id,
            event_type=event_type,
            timestamp=datetime.now(UTC),
            user_id=user_id,
            details=details or {},
            error_message=error_message,
        )
        self.db.add(event)
        return event

    async def get_module_events(
        self,
        organization_id: UUID | None = None,
        module_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ModuleEvent]:
        """
        Get module events.

        Args:
            organization_id: Filter by organization
            module_id: Filter by module
            limit: Max results
            offset: Results offset

        Returns:
            List of ModuleEvent records
        """
        query = select(ModuleEvent).order_by(ModuleEvent.timestamp.desc())

        if organization_id:
            query = query.where(ModuleEvent.organization_id == organization_id)
        if module_id:
            query = query.where(ModuleEvent.module_id == module_id)

        query = query.limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # ==========================================
    # Feature Flags
    # ==========================================

    async def get_feature_flags(
        self,
        organization_id: UUID,
        module_id: str,
    ) -> list[ModuleFeatureFlag]:
        """Get all feature flags for a module."""
        result = await self.db.execute(
            select(ModuleFeatureFlag).where(
                and_(
                    ModuleFeatureFlag.organization_id == organization_id,
                    ModuleFeatureFlag.module_id == module_id,
                )
            )
        )
        return list(result.scalars().all())

    async def get_feature_flag(
        self,
        organization_id: UUID,
        module_id: str,
        feature_key: str,
    ) -> ModuleFeatureFlag | None:
        """Get a specific feature flag."""
        result = await self.db.execute(
            select(ModuleFeatureFlag).where(
                and_(
                    ModuleFeatureFlag.organization_id == organization_id,
                    ModuleFeatureFlag.module_id == module_id,
                    ModuleFeatureFlag.feature_key == feature_key,
                )
            )
        )
        return result.scalar_one_or_none()

    async def set_feature_flag(
        self,
        organization_id: UUID,
        module_id: str,
        feature_key: str,
        is_enabled: bool,
        value: dict[str, Any] | None = None,
    ) -> ModuleFeatureFlag:
        """Set a feature flag value."""
        flag = await self.get_feature_flag(organization_id, module_id, feature_key)

        if flag:
            flag.is_enabled = is_enabled
            flag.value = value
        else:
            flag = ModuleFeatureFlag(
                organization_id=organization_id,
                module_id=module_id,
                feature_key=feature_key,
                is_enabled=is_enabled,
                value=value,
            )
            self.db.add(flag)

        await self.db.commit()
        await self.db.refresh(flag)

        return flag

    async def is_feature_enabled(
        self,
        organization_id: UUID,
        module_id: str,
        feature_key: str,
        default: bool = True,
    ) -> bool:
        """Check if a feature flag is enabled."""
        flag = await self.get_feature_flag(organization_id, module_id, feature_key)
        if flag:
            return flag.is_enabled
        return default

    # ==========================================
    # Cache Management
    # ==========================================

    async def load_enabled_modules_to_cache(
        self,
        organization_id: UUID,
    ) -> set[str]:
        """
        Load enabled modules from database into registry cache.

        Call this when an organization is loaded/accessed.

        Args:
            organization_id: Organization ID

        Returns:
            Set of enabled module IDs
        """
        org_modules = await self.get_org_modules(organization_id, include_disabled=False)
        enabled_ids = {om.module_id for om in org_modules}

        self.registry.set_enabled_modules(organization_id, enabled_ids)

        return enabled_ids
