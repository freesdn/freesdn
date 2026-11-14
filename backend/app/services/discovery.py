# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Discovery Service
================================

Runs controller discovery for the ``/discovery/controllers/{id}``,
``/discovery/sites/{id}`` and ``/discovery/all`` endpoints (the Discovery page's
"Discover" and "Discover all" buttons).

There is ONE controller-discovery implementation:
``app.tasks.discovery._discover_devices_for_controller``. The Celery task, the
controller page's "Sync Now" and this service all run it, so every path builds
its adapter through ``build_adapter_for_controller``, upserts devices the same
way and holds the same per-controller solo lock.

This class used to carry a private copy of that pipeline, and the copy could not
work: it built ``Device(vendor=, serial=, mac=, ip=, hostname=, vendor_data=,
discovered_at=)`` -- none of them fields of ``Device``, so every new device raised
``TypeError`` (logged and swallowed per device); it updated existing devices
through ``getattr(device, "ip")``, which raises ``AttributeError``; it built
adapters from its own kwargs (no TrueNAS API key, no UniFi, TrueNAS, FreePBX,
Grandstream, OpenWrt or ONVIF at all); it wrote ``controller.status = "online"``,
which is not a ``ControllerStatus``; and it selected controllers by
``status != "disabled"``, a status nothing writes, so soft-deleted and disabled
controllers were discovered too. The buttons reported "running" and no device
ever appeared.
"""

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Controller

logger = logging.getLogger(__name__)


class DiscoveryError(Exception):
    """Error during discovery process."""

    pass


class DiscoveryService:
    """Discovery entry points for the /discovery endpoints."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def discover_controller(self, controller_id: UUID) -> dict[str, Any]:
        """Discover all devices from one controller; returns discovery statistics.

        The canonical implementation opens its own session, so this works the
        same from a request (``sync=true``) and from a background task.
        """
        from app.tasks.discovery import _discover_devices_for_controller

        result = await _discover_devices_for_controller(str(controller_id))
        if not result.get("success"):
            raise DiscoveryError(str(result.get("error") or "Discovery failed"))
        discovered = int(result.get("devices_discovered") or 0)
        created = int(result.get("devices_created") or 0)
        updated = int(result.get("devices_updated") or 0)
        return {
            "total": discovered,
            "new": created,
            "updated": updated,
            "unchanged": max(discovered - created - updated, 0),
            "skipped": bool(result.get("skipped")),
            "errors": [],
        }

    async def discover_all(
        self,
        site_id: UUID | None = None,
        *,
        organization_id: UUID | None = None,
        site_ids: list[UUID] | set[UUID] | None = None,
    ) -> dict[str, Any]:
        """
        Discover devices from all enabled controllers (optionally filtered by site).

        SECURITY: ``organization_id`` and ``site_ids`` scope the
        controller set so a user-triggered "discover all" never opens adapters
        against another tenant's controllers (org scope) or against sibling
        sites a site-limited caller was not granted (per-user site grant).
        ``organization_id=None`` is the unscoped system/maintenance path; the
        endpoint always passes the caller's org + accessible-site set so the
        public surface is fail-closed.
        """
        from app.db.models import Site

        # The same selection as the scheduled discover_all_devices task: enabled,
        # not deleted. (The canonical implementation refuses anything else anyway.)
        query = select(Controller).where(
            Controller.is_active.is_(True),
            Controller.deleted_at.is_(None),
        )
        if organization_id is not None:
            # Scope to the caller's org via the controller's Site, so a
            # non-superuser run can never reach another tenant's controllers.
            query = query.join(Site, Controller.site_id == Site.id).where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
            )
        if site_ids is not None:
            # Per-user site grant: a site-limited caller only discovers the
            # controllers in their granted sites. An empty set fails closed.
            query = query.where(Controller.site_id.in_(list(site_ids)))
        if site_id:
            query = query.where(Controller.site_id == site_id)

        result = await self.db.execute(query)
        controllers = result.scalars().all()

        total_stats: dict[str, Any] = {
            "controllers": len(controllers),
            "total_devices": 0,
            "new_devices": 0,
            "updated_devices": 0,
            "failed_controllers": 0,
            "errors": [],
        }

        for controller in controllers:
            try:
                stats = await self.discover_controller(controller.id)
                total_stats["total_devices"] += stats["total"]
                total_stats["new_devices"] += stats["new"]
                total_stats["updated_devices"] += stats["updated"]
            except Exception as e:
                logger.error("Discovery failed for controller %s: %s", controller.name, e)
                total_stats["failed_controllers"] += 1
                total_stats["errors"].append({"controller": controller.name, "error": str(e)})

        return total_stats
