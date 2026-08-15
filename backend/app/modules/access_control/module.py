# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Access Control Module - Main Module Class
=================================================

The Access Control module provides physical access control functionality
including door management, credential management, and access event tracking.

NOTE (#11): This module ships disabled by default. Until at least one
real door-controller adapter is implemented and the PIN/card encryption
migration (013) has been applied in production, ``lock_door`` /
``unlock_door`` will refuse with HTTP 501. Operators can opt in
explicitly via the Modules settings page.

NOTE (H5): The previous manifest advertised "anti-passback enforcement"
in the settings schema but no code path implemented it. It has been
removed from the public surface. To add it later: track a
``last_access_zone`` per credential, check it on grant, and reject
within ``anti_passback_timeout`` minutes.
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

# NOTE (#11): Manifest fields don't include a ``is_enabled_by_default``
# attribute today. Module registration treats non-core modules as
# off-by-default unless an OrgModule row enables them, so the existing
# loader already gives us the "off" behavior we want. The constant
# below documents intent and is exposed via the module instance so the
# admin UI can render an explanatory note.
ACCESS_CONTROL_ENABLED_BY_DEFAULT = False


class AccessControlModule(BaseModule):
    """
    Access Control Module for FreeSDN.

    Provides physical access control capabilities including:
    - Door and reader management (CRUD)
    - Card/credential management
    - Access schedules and time zones
    - Access event logging

    Physical door CONTROL (lock/unlock) refuses with HTTP 501 until a real
    door-controller adapter is registered (see NOTE #11). Anti-passback was
    removed from the public surface (NOTE H5) and is intentionally NOT listed
    here — no code path implements it.
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="access_control",
            name="Access Control",
            version="1.0.0",
            description="Physical access control, door management, and credential management",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SECURITY,
            icon="door-open",
            color="#F59E0B",  # Amber
            # Dependencies
            dependencies=[],
            # Capabilities this module provides
            capabilities=[
                ModuleCapability.DOOR_MANAGEMENT,
                ModuleCapability.CARD_MANAGEMENT,
                ModuleCapability.ACCESS_SCHEDULES,
                ModuleCapability.ACCESS_EVENTS,
            ],
            # Required capabilities from other modules
            required_capabilities=[],
            # Device types this module supports
            device_types=[
                "access_controller",
                "door",
                "reader",
                "io_module",
            ],
            # Permissions
            permissions=[
                ModulePermission(
                    code="access.view",
                    name="View Access Control",
                    description="View doors, readers, and access events",
                    resource="access",
                    action="read",
                ),
                ModulePermission(
                    code="access.manage_doors",
                    name="Manage Doors",
                    description="Add, edit, and configure doors and readers",
                    resource="door",
                    action="update",
                ),
                ModulePermission(
                    code="access.manage_credentials",
                    name="Manage Credentials",
                    description="Issue and revoke access cards/credentials",
                    resource="credential",
                    action="update",
                ),
                ModulePermission(
                    code="access.manage_schedules",
                    name="Manage Schedules",
                    description="Configure access schedules and time zones",
                    resource="schedule",
                    action="update",
                ),
                ModulePermission(
                    code="access.door_control",
                    name="Door Control",
                    description="Lock, unlock, and control doors remotely",
                    resource="door",
                    action="execute",
                ),
                ModulePermission(
                    code="access.view_events",
                    name="View Events",
                    description="View access event history",
                    resource="event",
                    action="read",
                ),
            ],
            # Navigation items
            nav_items=[
                ModuleNavItem(
                    path="/access",
                    label="Access Control",
                    icon="door-open",
                    order=30,
                    permission="access.view",
                ),
                ModuleNavItem(
                    path="/access/doors",
                    label="Doors",
                    icon="door-closed",
                    order=1,
                    parent="/access",
                    permission="access.view",
                ),
                ModuleNavItem(
                    path="/access/credentials",
                    label="Credentials",
                    icon="credit-card",
                    order=2,
                    parent="/access",
                    permission="access.view",
                ),
                ModuleNavItem(
                    path="/access/cardholders",
                    label="Cardholders",
                    icon="users",
                    order=3,
                    parent="/access",
                    permission="access.view",
                ),
                ModuleNavItem(
                    path="/access/schedules",
                    label="Schedules",
                    icon="clock",
                    order=4,
                    parent="/access",
                    permission="access.manage_schedules",
                ),
                ModuleNavItem(
                    path="/access/events",
                    label="Events",
                    icon="list",
                    order=5,
                    parent="/access",
                    permission="access.view_events",
                ),
                ModuleNavItem(
                    path="/access/controllers",
                    label="Controllers",
                    icon="cpu",
                    order=6,
                    parent="/access",
                    permission="access.manage_doors",
                ),
            ],
            # Dashboard widgets
            widgets=[
                ModuleWidget(
                    id="door_status",
                    name="Door Status",
                    description="Real-time door status overview",
                    component="DoorStatusWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="access.view",
                ),
                ModuleWidget(
                    id="recent_access",
                    name="Recent Access Events",
                    description="Latest access events",
                    component="RecentAccessWidget",
                    default_size="medium",
                    refresh_interval=15,
                    permission="access.view_events",
                ),
                ModuleWidget(
                    id="access_denied",
                    name="Access Denied",
                    description="Recent access denied events",
                    component="AccessDeniedWidget",
                    default_size="small",
                    refresh_interval=30,
                    permission="access.view_events",
                ),
            ],
            # Settings schema
            #
            # NOTE (H5): anti_passback_enabled / anti_passback_timeout
            # were advertised in the previous version of this schema
            # despite no implementation existing. Removed until a real
            # implementation lands. TODO: track last-access-zone per
            # credential, reject within timeout window.
            settings_schema={
                "type": "object",
                "properties": {
                    "default_door_unlock_time": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 60,
                        "default": 5,
                        "description": "Default door unlock time in seconds",
                    },
                    "event_retention_days": {
                        "type": "integer",
                        "minimum": 30,
                        "maximum": 365,
                        "default": 90,
                        "description": "Access event retention period",
                    },
                },
            },
            # Default settings
            default_settings={
                "default_door_unlock_time": 5,
                "event_retention_days": 90,
            },
            # This module is a preview: the data model and CRUD surface exist,
            # but physical door control has no shipping hardware adapter yet
            # (lock/unlock refuse with HTTP 501). It is surfaced in the admin
            # UI as a non-enableable "Coming soon" entry, and the enablement
            # service refuses to turn it on for an organization until a real
            # door-controller adapter lands. Kept off the auto-enabled list
            # because it is not ``is_core``. See ACCESS_CONTROL_ENABLED_BY_DEFAULT.
            is_beta=True,
            coming_soon=True,
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Return the FastAPI router for access control endpoints."""
        from app.modules.access_control.api import router

        return router

    def get_models(self) -> list[type]:
        """Return SQLAlchemy models for this module."""
        from app.modules.access_control.models import (
            AccessController,
            AccessCredential,
            AccessEvent,
            AccessSchedule,
            Cardholder,
            Door,
            Reader,
        )

        return [
            AccessController,
            Door,
            Reader,
            AccessCredential,
            Cardholder,
            AccessSchedule,
            AccessEvent,
        ]

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """Return Celery tasks for this module.

        NOTE (H4): ``relock_door_after`` is scheduled by
        ``AccessControlService.unlock_door`` so the DB row matches the
        hardware once the unlock window elapses.
        """
        from app.modules.access_control.service import relock_door_after

        return {
            "access_control.relock_door_after": relock_door_after,
        }

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources: door/access events (published from
        AccessControlService._store_event). These make the marquee security
        vertical wireable — e.g. ``access.door.forced → cameras.snapshot →
        storage.store_blob``.
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        _payload = {
            "type": "object",
            "properties": {
                "door_id": {"type": "string"},
                "credential_id": {"type": "string"},
                "cardholder_id": {"type": "string"},
                "event_type": {"type": "string"},
                "card_number": {"type": "string"},
                "description": {"type": "string"},
            },
        }

        def _ev(et, title, desc):
            return EventSpec(
                event_type=et,
                title=title,
                description=desc,
                payload_schema=_payload,
                tier=OperationTier.NATIVE,
                provider_id="access_control",
            )

        return [
            _ev("access.door.granted", "Access granted", "A credential was granted at a door."),
            _ev("access.door.denied", "Access denied", "A credential was denied at a door."),
            _ev("access.door.forced", "Door forced", "A door was forced open (no valid access)."),
            _ev(
                "access.door.held_open", "Door held open", "A door was held open beyond its window."
            ),
            _ev("access.door.unlocked", "Door unlocked", "A door was unlocked."),
            _ev("access.door.locked", "Door locked", "A door was locked."),
            _ev("access.door.alarm", "Access alarm", "An access-control alarm was raised."),
        ]

    async def on_load(self) -> None:
        """Called when module is loaded."""
        await super().on_load()
        logger.info("Access Control module loaded")

    async def on_unload(self) -> None:
        """Called when module is unloaded."""
        await super().on_unload()
        logger.info("Access Control module unloaded")
