# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Config Version Service
=====================================

Immutable config snapshots with version tracking, diff, and rollback.
Each config change (push, manual save, rollback, adoption) produces
a new ConfigVersion row for full audit trail.
"""

from __future__ import annotations

import difflib
import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enterprise import ConfigVersion

logger = logging.getLogger(__name__)


class ConfigVersionService:
    """
    Service for managing immutable config version snapshots.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_version(
        self,
        device_id: UUID,
        config: dict[str, Any],
        source: str,
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
    ) -> ConfigVersion:
        """
        Create a new config version for a device.

        Automatically increments version_number and generates a
        change_summary by diffing against the previous version.

        Args:
            device_id: The device UUID.
            config: The full config snapshot (JSONB).
            source: Origin of the change — "config_push", "manual_save",
                    "rollback", "adoption".
            user_id: Optional user who triggered the change.
            organization_id: Organization UUID. If not provided, it will
                             be looked up from the previous version or device.

        Returns:
            The newly created ConfigVersion.
        """
        # Auto-increment version number
        max_ver_q = (
            select(func.coalesce(func.max(ConfigVersion.version_number), 0))
            .where(ConfigVersion.device_id == device_id)
            .with_for_update()
        )
        result = await self.db.execute(max_ver_q)
        next_version = (result.scalar() or 0) + 1

        # Resolve organization_id if not provided
        if not organization_id:
            prev_q = (
                select(ConfigVersion.organization_id)
                .where(ConfigVersion.device_id == device_id)
                .order_by(ConfigVersion.version_number.desc())
                .limit(1)
            )
            result = await self.db.execute(prev_q)
            organization_id = result.scalar_one_or_none()  # type: ignore[assignment]

        if not organization_id:
            # Fall back to device's organization
            from app.models.core import Site
            from app.models.devices import Device

            dev_q = select(Device.site_id).where(Device.id == device_id)
            result = await self.db.execute(dev_q)
            site_id = result.scalar_one_or_none()
            if site_id:
                site_q = select(Site.organization_id).where(Site.id == site_id)
                result = await self.db.execute(site_q)
                organization_id = result.scalar_one_or_none()  # type: ignore[assignment]

        # Generate change summary by diffing with previous version
        change_summary = await self._generate_change_summary(device_id, config)

        # Retry loop to handle race conditions on concurrent version inserts.
        # The unique constraint uq_config_versions_device_version will reject
        # duplicate (device_id, version_number) pairs; on IntegrityError we
        # increment and retry.
        #
        # Each attempt is wrapped in a SAVEPOINT (begin_nested) so that an
        # IntegrityError only rolls back the failed INSERT — not the entire
        # session transaction. Calling db.rollback() here would silently
        # discard any other pending writes the caller made in the same
        # request (e.g. the rollback() flow's device-state bookkeeping).
        max_retries = 3
        version: ConfigVersion | None = None
        for attempt in range(max_retries):
            version = ConfigVersion(
                device_id=device_id,
                organization_id=organization_id,
                version_number=next_version,
                config_snapshot=config,
                change_summary=change_summary,
                source=source,
                created_by=user_id,
            )
            try:
                async with self.db.begin_nested():
                    self.db.add(version)
                    await self.db.flush()
                break
            except IntegrityError:
                # The savepoint has already been rolled back by the context
                # manager, so the outer transaction's other writes survive.
                if attempt == max_retries - 1:
                    raise
                next_version += 1
                logger.warning(
                    "Version number conflict for device %s, retrying with version %d (attempt %d/%d)",
                    device_id,
                    next_version,
                    attempt + 2,
                    max_retries,
                )

        logger.info(
            "Config version %d recorded for device %s (source=%s)",
            next_version,
            device_id,
            source,
        )
        return version

    async def list_versions(
        self,
        device_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ConfigVersion]:
        """
        List config versions for a device, newest first.

        Args:
            device_id: Device UUID.
            limit: Maximum number of versions to return.
            offset: Number of versions to skip (for pagination).

        Returns:
            List of ConfigVersion instances ordered by version_number DESC.
        """
        q = (
            select(ConfigVersion)
            .where(ConfigVersion.device_id == device_id)
            .order_by(ConfigVersion.version_number.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.db.execute(q)
        return list(result.scalars().all())

    async def get_version(self, version_id: UUID) -> ConfigVersion | None:
        """
        Get a single config version by ID.

        Args:
            version_id: ConfigVersion UUID.

        Returns:
            ConfigVersion or None.
        """
        q = select(ConfigVersion).where(ConfigVersion.id == version_id)
        result = await self.db.execute(q)
        return result.scalar_one_or_none()

    async def rollback(
        self,
        device_id: UUID,
        version_id: UUID,
        adapter: Any,
        session: AsyncSession | None = None,
        user_id: UUID | None = None,
    ) -> ConfigVersion:
        """
        Rollback a device to a previous config version.

        Steps:
            1. Load the target config version.
            2. Push the config to the device via the adapter.
            3. Record a new "rollback" version with the restored config.

        Args:
            device_id: Device UUID.
            version_id: The ConfigVersion UUID to roll back to.
            adapter: Network adapter instance for pushing config.
            session: Optional alternative DB session.
            user_id: Optional user who triggered the rollback.

        Returns:
            The new ConfigVersion created for the rollback.

        Raises:
            ValueError: If version not found or device mismatch.
            RuntimeError: If adapter push fails.
        """

        # Load the target version
        target = await self.get_version(version_id)
        if not target:
            raise ValueError(f"Config version {version_id} not found")
        if target.device_id != device_id:
            raise ValueError(f"Version {version_id} does not belong to device {device_id}")

        # Reserve the rollback version row in the DB BEFORE mutating the
        # device. record_version() only flushes (does not commit), so if the
        # subsequent device push fails we raise RuntimeError and the request
        # transaction is rolled back by the session dependency — leaving no
        # orphan ConfigVersion for a push that never happened. Conversely, the
        # row is never committed without the device write also being in flight,
        # which closes the prior device-mutated-but-no-DB-record divergence.
        rollback_version = await self.record_version(
            device_id=device_id,
            config=target.config_snapshot,
            source="rollback",
            user_id=user_id,
            organization_id=target.organization_id,
        )

        # Push to device via adapter
        try:
            async with adapter:
                await adapter.push_config(target.config_snapshot)
        except Exception as e:
            logger.error("Rollback push failed for device %s: %s", device_id, e, exc_info=True)
            raise RuntimeError(
                f"Failed to push rollback configuration to device {device_id}: {e}"
            ) from e

        logger.info(
            "Rollback complete: device=%s from_version=%d new_version=%d",
            device_id,
            target.version_number,
            rollback_version.version_number,
        )
        return rollback_version

    async def diff_versions(
        self,
        version_a_id: UUID,
        version_b_id: UUID,
    ) -> dict[str, Any]:
        """
        Compare two config versions and return a structured diff.

        Args:
            version_a_id: First ConfigVersion UUID (typically older).
            version_b_id: Second ConfigVersion UUID (typically newer).

        Returns:
            Dict with "added", "removed", "changed" keys summarizing
            the differences, plus a "unified_diff" text representation.

        Raises:
            ValueError: If either version is not found.
        """
        version_a = await self.get_version(version_a_id)
        version_b = await self.get_version(version_b_id)

        if not version_a:
            raise ValueError(f"Config version {version_a_id} not found")
        if not version_b:
            raise ValueError(f"Config version {version_b_id} not found")

        # redact secret-bearing values BEFORE diffing so neither the
        # structural diff nor the unified_diff text leaks RADIUS secrets / WiFi
        # PSKs / SNMP communities / tokens to a config:read caller. (Secrets mask
        # to a constant, so a rotated secret reads as "unchanged" — acceptable:
        # a read-tier diff must not surface secret values.)
        from app.core.redaction import redact_secrets

        config_a = redact_secrets(version_a.config_snapshot or {})
        config_b = redact_secrets(version_b.config_snapshot or {})

        # Compute structural diff
        added = {}
        removed = {}
        changed = {}

        all_keys = set(config_a.keys()) | set(config_b.keys())
        for key in all_keys:
            if key not in config_a:
                added[key] = config_b[key]
            elif key not in config_b:
                removed[key] = config_a[key]
            elif config_a[key] != config_b[key]:
                changed[key] = {
                    "old": config_a[key],
                    "new": config_b[key],
                }

        # Generate unified diff of JSON representations
        text_a = json.dumps(config_a, indent=2, sort_keys=True, default=str).splitlines(
            keepends=True
        )
        text_b = json.dumps(config_b, indent=2, sort_keys=True, default=str).splitlines(
            keepends=True
        )
        unified = list(
            difflib.unified_diff(
                text_a,
                text_b,
                fromfile=f"v{version_a.version_number}",
                tofile=f"v{version_b.version_number}",
            )
        )

        return {
            "version_a": {
                "id": str(version_a.id),
                "version_number": version_a.version_number,
                "source": version_a.source,
                "created_at": version_a.created_at.isoformat() if version_a.created_at else None,
            },
            "version_b": {
                "id": str(version_b.id),
                "version_number": version_b.version_number,
                "source": version_b.source,
                "created_at": version_b.created_at.isoformat() if version_b.created_at else None,
            },
            "added": added,
            "removed": removed,
            "changed": changed,
            "has_changes": bool(added or removed or changed),
            "unified_diff": "".join(unified),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _generate_change_summary(
        self, device_id: UUID, new_config: dict[str, Any]
    ) -> str | None:
        """
        Generate a human-readable summary of changes by comparing
        the new config against the most recent version.
        """
        prev_q = (
            select(ConfigVersion)
            .where(ConfigVersion.device_id == device_id)
            .order_by(ConfigVersion.version_number.desc())
            .limit(1)
        )
        result = await self.db.execute(prev_q)
        previous = result.scalar_one_or_none()

        if not previous:
            return "Initial config version"

        old_config = previous.config_snapshot or {}
        if old_config == new_config:
            return "No changes detected"

        changes: list[str] = []
        all_keys = set(old_config.keys()) | set(new_config.keys())

        added_keys = [k for k in all_keys if k not in old_config]
        removed_keys = [k for k in all_keys if k not in new_config]
        changed_keys = [
            k
            for k in all_keys
            if k in old_config and k in new_config and old_config[k] != new_config[k]
        ]

        if added_keys:
            changes.append(f"Added: {', '.join(sorted(added_keys)[:5])}")
        if removed_keys:
            changes.append(f"Removed: {', '.join(sorted(removed_keys)[:5])}")
        if changed_keys:
            changes.append(f"Changed: {', '.join(sorted(changed_keys)[:5])}")

        total = len(added_keys) + len(removed_keys) + len(changed_keys)
        if total > 15:
            changes.append(f"({total} total changes)")

        return "; ".join(changes) if changes else "Minor changes"
