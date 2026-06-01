# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Backup Module - Main Module Class
=========================================

The Backup module provides comprehensive backup and restore functionality
for device configurations and system state.
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
    ModuleWidget,
)

logger = logging.getLogger(__name__)


class BackupModule(BaseModule):
    """
    Configuration Backup module for FreeSDN.

    SCOPE (readiness): this module exports a PORTABLE
    CONFIGURATION SNAPSHOT — sites, controllers, devices, users,
    automation rules — to a self-contained ``.fsdn`` archive that can be
    replayed on any FreeSDN instance. It is intentionally NOT a
    full-system disaster-recovery backup:

      Out of scope for this module (use ``pg_dump`` / ``pg-backup``
      container for these):
        - audit log + audit hash chain (instance-tied integrity)
        - encrypted credential ciphertexts (tied to SECRET_KEY)
        - agent registry + heartbeats
        - plugin install state + on-disk plugin code
        - VoIP / cameras / firewall / access-control / hypervisor
          per-module operational state
        - sessions, rate-limit state, queued tasks (Redis)

    Use cases this module IS designed for:
      - Migrate config from a dev/staging instance to production
      - Spin up a new tenant with a curated template
      - Customer offboarding bundle ("here is your settings export")
      - Periodic config-only snapshots independent of the DB dump

    The frontend page at ``/backup`` displays a banner reminding operators
    that this is config-only, not a full-system DR backup.
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="backup",
            name="Configuration Backup",
            version="1.1.0",
            description=(
                "Portable configuration snapshot (sites / controllers / devices / "
                "users / automation). Not a full-system DR backup — see "
                "docs.freesdn.org and the pg-backup container for DR."
            ),
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SYSTEM,
            icon="archive",
            color="#8B5CF6",  # Purple
            # Dependencies
            dependencies=[],
            # Capabilities this module provides
            capabilities=[
                ModuleCapability.BACKUP_CREATE,
                ModuleCapability.BACKUP_RESTORE,
                ModuleCapability.BACKUP_SCHEDULE,
                ModuleCapability.BACKUP_CLOUD,
            ],
            # Required capabilities from other modules
            required_capabilities=[],
            # Device types - backup applies to all
            device_types=[],
            # Permissions
            permissions=[
                ModulePermission(
                    code="backup.view",
                    name="View Backups",
                    description="View backup history and status",
                    resource="backup",
                    action="read",
                ),
                ModulePermission(
                    code="backup.create",
                    name="Create Backups",
                    description="Create new backups",
                    resource="backup",
                    action="create",
                ),
                ModulePermission(
                    code="backup.restore",
                    name="Restore Backups",
                    description="Restore from backups",
                    resource="backup",
                    action="execute",
                ),
                ModulePermission(
                    code="backup.delete",
                    name="Delete Backups",
                    description="Delete backup files",
                    resource="backup",
                    action="delete",
                ),
                ModulePermission(
                    code="backup.schedule",
                    name="Manage Schedules",
                    description="Create and manage backup schedules",
                    resource="backup_schedule",
                    action="update",
                ),
                ModulePermission(
                    code="backup.settings",
                    name="Backup Settings",
                    description="Configure backup storage and encryption settings",
                    resource="backup_settings",
                    action="update",
                ),
            ],
            # Navigation items. URLs stay at /backup* so existing bookmarks
            # and OpenAPI clients keep working; only the user-visible labels
            # change to reflect the renamed module.
            nav_items=[
                ModuleNavItem(
                    path="/backup",
                    label="Config Backup",
                    icon="archive",
                    order=80,
                    permission="backup.view",
                ),
                ModuleNavItem(
                    path="/backup/history",
                    label="Snapshot History",
                    icon="history",
                    order=1,
                    parent="/backup",
                    permission="backup.view",
                ),
                ModuleNavItem(
                    path="/backup/schedules",
                    label="Schedules",
                    icon="calendar",
                    order=2,
                    parent="/backup",
                    permission="backup.schedule",
                ),
                ModuleNavItem(
                    path="/backup/settings",
                    label="Storage Settings",
                    icon="settings",
                    order=3,
                    parent="/backup",
                    permission="backup.settings",
                ),
            ],
            # Dashboard widgets
            widgets=[
                ModuleWidget(
                    id="backup_status",
                    name="Backup Status",
                    description="Shows last backup status and next scheduled backup",
                    component="BackupStatusWidget",
                    default_size="small",
                    refresh_interval=300,
                    permission="backup.view",
                ),
                ModuleWidget(
                    id="backup_history",
                    name="Recent Backups",
                    description="List of recent backups with size and status",
                    component="BackupHistoryWidget",
                    default_size="medium",
                    refresh_interval=60,
                    permission="backup.view",
                ),
            ],
            # Settings schema
            settings_schema={
                "type": "object",
                "properties": {
                    "storage_type": {
                        "type": "string",
                        "enum": ["local", "s3", "sftp"],
                        "default": "local",
                        "description": "Storage backend type",
                    },
                    "retention_days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "default": 30,
                        "description": "Days to retain backups",
                    },
                    "encryption_enabled": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enable backup encryption (recommended)",
                    },
                    "compression_level": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 9,
                        "default": 6,
                        "description": "Gzip compression level",
                    },
                    "s3_bucket": {
                        "type": "string",
                        "description": "S3 bucket name (if using S3)",
                    },
                    "s3_region": {
                        "type": "string",
                        "default": "us-east-1",
                        "description": "S3 region",
                    },
                },
            },
            # Default settings
            # NOTE H1: encryption_enabled defaults to True. Backups contain
            # cross-org configuration data (users, devices, automation rules)
            # and should be encrypted at rest by default.
            default_settings={
                "storage_type": "local",
                "retention_days": 30,
                "encryption_enabled": True,
                "compression_level": 6,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Backup routes are registered via app.api.v1.endpoints.backups."""
        return APIRouter()

    def get_models(self) -> list[type]:
        """Return SQLAlchemy models for this module."""
        from app.modules.backup.models import (
            Backup,
            BackupSchedule,
            RestoreJob,
            StorageLocation,
        )

        return [Backup, BackupSchedule, StorageLocation, RestoreJob]

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """Backup tasks are registered via app.tasks.backup."""
        return {}

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event source: a scheduled backup-restore validation failed
        (tasks/backup.py) — a genuine ops-alerting trigger (→ fabric.notify)."""
        from app.core.fabric.operations import EventSpec, OperationTier

        return [
            EventSpec(
                event_type="backup.validation.failed",
                title="Backup validation failed",
                description="A monthly backup-restore validation run failed.",
                payload_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "backup_id": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="backup",
            ),
        ]

    async def on_load(self) -> None:
        """Called when module is loaded."""
        await super().on_load()
        logger.info("Backup module loaded")

    async def on_unload(self) -> None:
        """Called when module is unloaded."""
        await super().on_unload()
        logger.info("Backup module unloaded")
