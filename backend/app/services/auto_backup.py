# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Auto-Backup Service
==================================

Automatic backup before config changes (config push, firmware update,
adoption). Enforces per-organization retention policies.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enterprise import AutoBackupPolicy, ConfigVersion

if TYPE_CHECKING:
    from app.models.devices import Device

logger = logging.getLogger(__name__)


class AutoBackupService:
    """
    Service that creates automatic config snapshots before
    destructive operations, governed by per-org AutoBackupPolicy.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def backup_before_change(self, device: Device, trigger: str) -> ConfigVersion | None:
        """
        Create an automatic backup of the device config before a change.

        Steps:
            1. Check if an AutoBackupPolicy exists and is enabled for this trigger.
            2. Snapshot the device's current running config into a ConfigVersion.
            3. Enforce retention_count by deleting the oldest auto-backup versions.

        Args:
            device: The Device ORM instance (must have .id, .organization_id
                    and related config_state with running_config).
            trigger: One of "config_push", "firmware_update", "adoption".

        Returns:
            The newly created ConfigVersion, or None if policy is disabled
            or does not exist.
        """
        org_id = getattr(device, "organization_id", None)
        if not org_id:
            # Try to derive from site
            from app.models.core import Site

            site_q = select(Site.organization_id).where(Site.id == device.site_id)
            result = await self.db.execute(site_q)
            org_id = result.scalar_one_or_none()
            if not org_id:
                logger.warning("Cannot determine org for device %s", device.id)
                return None

        # 1. Check policy
        policy = await self._get_policy(org_id)
        if not policy or not policy.enabled:
            return None

        # Check trigger flags
        trigger_map = {
            "config_push": policy.trigger_on_config_push,
            "firmware_update": policy.trigger_on_firmware_update,
            "adoption": policy.trigger_on_adoption,
        }
        if not trigger_map.get(trigger, False):
            logger.debug(
                "Auto-backup skipped: trigger '%s' disabled for org %s",
                trigger,
                org_id,
            )
            return None

        # 2. Snapshot the running config
        running_config: dict[str, Any] = {}
        config_state = getattr(device, "config_state", None)
        if config_state and isinstance(config_state, list) and config_state:
            running_config = config_state[0].running_config or {}
        elif config_state and not isinstance(config_state, list):
            running_config = config_state.running_config or {}

        # Delegate version creation to ConfigVersionService
        from app.services.config_versions import ConfigVersionService

        cv_svc = ConfigVersionService(self.db)
        version = await cv_svc.record_version(
            device_id=device.id,
            config=running_config,
            source=f"auto_backup_{trigger}",
            organization_id=org_id,
        )

        logger.info(
            "Auto-backup created: device=%s version=%d trigger=%s",
            device.id,
            version.version_number,
            trigger,
        )

        # 3. Enforce retention count
        await self._enforce_retention(device.id, policy.retention_count)

        return version

    async def get_or_create_policy(self, org_id: UUID) -> AutoBackupPolicy:
        """
        Get the existing auto-backup policy for an organization,
        or create one with default settings.

        Args:
            org_id: Organization UUID.

        Returns:
            AutoBackupPolicy instance.
        """
        policy = await self._get_policy(org_id)
        if policy:
            return policy

        policy = AutoBackupPolicy(
            organization_id=org_id,
            enabled=True,
            trigger_on_config_push=True,
            trigger_on_firmware_update=True,
            trigger_on_adoption=False,
            retention_count=5,
        )
        self.db.add(policy)
        await self.db.flush()
        logger.info("Created default auto-backup policy for org %s", org_id)
        return policy

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_policy(self, org_id: UUID) -> AutoBackupPolicy | None:
        """Fetch AutoBackupPolicy for the given organization."""
        q = select(AutoBackupPolicy).where(
            AutoBackupPolicy.organization_id == org_id,
        )
        result = await self.db.execute(q)
        return result.scalar_one_or_none()

    async def _enforce_retention(self, device_id: UUID, retention_count: int) -> int:
        """
        Delete the oldest auto-backup ConfigVersions if the total exceeds
        the retention_count.

        Returns the number of versions deleted.
        """
        # Count total auto-backup versions for this device
        count_q = select(func.count(ConfigVersion.id)).where(
            ConfigVersion.device_id == device_id,
            ConfigVersion.source.like("auto_backup_%"),
        )
        result = await self.db.execute(count_q)
        total = result.scalar() or 0

        if total <= retention_count:
            return 0

        excess = total - retention_count

        # Find the oldest excess version IDs
        oldest_q = (
            select(ConfigVersion.id)
            .where(
                ConfigVersion.device_id == device_id,
                ConfigVersion.source.like("auto_backup_%"),
            )
            .order_by(ConfigVersion.version_number.asc())
            .limit(excess)
        )
        result = await self.db.execute(oldest_q)
        old_ids = result.scalars().all()

        if old_ids:
            del_q = delete(ConfigVersion).where(ConfigVersion.id.in_(old_ids))
            await self.db.execute(del_q)
            logger.info(
                "Retention enforced: deleted %d old auto-backup versions for device %s",
                len(old_ids),
                device_id,
            )

        return len(old_ids)
