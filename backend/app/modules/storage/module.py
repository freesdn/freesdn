# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Storage Module — Fabric storage participant (TrueNAS).

Declares the storage Operations the Fabric negotiator can wire:

  * ``storage.health``     — read: roll up ZFS pool/alert health across the org's
                             TrueNAS appliances (executable now).
  * ``storage.store_blob`` — write: stage a blob (e.g. a camera snapshot) for
                             upload into a TrueNAS dataset. STAGE-only: invoking
                             it stages a pending change; an operator applies it
                             through the dual-gate (the upload runs only on
                             sign-off). The bytes ride ``ctx.input_artifact`` and
                             are persisted to the durable store by the executor.

No DB tables and no HTTP routes (live reads already live under
``/controllers/{id}/storage``); the module exists to own the storage Fabric
surface, discovered by the FabricRegistry like any other module.
"""

import contextlib
import logging
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModulePermission,
)

logger = logging.getLogger(__name__)


def _worse(a: str, b: str) -> str:
    order = {"ok": 0, "warning": 1, "error": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


async def _fabric_storage_health_handler(ctx: Any) -> Any:
    """Fabric handler for ``storage.health``.

    Rolls up ZFS pool status + active alerts across the org's TrueNAS
    appliances (optionally one, via ``controller_id``). Read-only, org-scoped,
    fail-closed: a controller from another org is never queried. Never raises;
    returns a normalized ``OperationResult``.
    """
    from uuid import UUID

    from sqlalchemy import select

    from app.core.fabric.execution import OperationResult
    from app.models.core import Controller, Site
    from app.modules.storage.health import summarize_health
    from app.services.adapter_truenas_storage import build_truenas_adapter

    if ctx.db is None:
        return OperationResult.fail("storage.health requires a DB session", "NO_DB")

    q = (
        select(Controller)
        .join(Site, Controller.site_id == Site.id)
        .where(
            Controller.controller_type == "truenas",
            Controller.deleted_at.is_(None),
            Site.organization_id == ctx.organization_id,
        )
    )
    cid_raw = ctx.params.get("controller_id")
    if cid_raw:
        try:
            q = q.where(Controller.id == UUID(str(cid_raw)))
        except (ValueError, TypeError):
            return OperationResult.fail("invalid controller_id", "BAD_TARGET")

    controllers = list((await ctx.db.execute(q)).scalars().all())
    appliances: list[dict[str, Any]] = []
    worst = "ok"

    for ctrl in controllers:
        entry: dict[str, Any] = {"controller_id": str(ctrl.id), "name": ctrl.name}
        try:
            adapter = await build_truenas_adapter(ctrl)
        except Exception as exc:  # noqa: BLE001 — surface per-appliance, keep going
            entry.update({"status": "unreachable", "error": str(exc)[:200]})
            appliances.append(entry)
            worst = _worse(worst, "error")
            continue
        try:
            pools = await adapter.get_pools()
            alerts = await adapter.get_alerts()
            temps = await adapter.get_disk_temperatures()
        except Exception as exc:  # noqa: BLE001
            entry.update({"status": "unreachable", "error": str(exc)[:200]})
            worst = _worse(worst, "error")
            appliances.append(entry)
            continue
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

        # Shared rollup — the same summary the storage.poll_health monitor uses
        # to decide transitions, so the catalog read and the events agree.
        summ = summarize_health(pools, alerts, temps)
        entry.update(
            {
                "status": summ["status"],
                "pools": len(pools),
                "degraded_pools": summ["degraded_pools"],
                "over_capacity_pools": summ["over_capacity_pools"],
                "alerts": len(alerts),
                "critical_alerts": summ["critical_alerts"],
                "max_temp_c": summ["max_temp_c"],
            }
        )
        appliances.append(entry)
        worst = _worse(worst, summ["status"])

    return OperationResult.ok(
        output={"status": worst, "appliances": appliances, "count": len(appliances)}
    )


class StorageModule(BaseModule):
    """Storage module — declares the TrueNAS Fabric participant surface."""

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        return ModuleManifest(
            id="storage",
            name="Storage",
            version="1.0.0",
            description="Storage appliance (TrueNAS) Fabric participant: health reads + staged blob writes",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SYSTEM,
            icon="hard-drive",
            color="#0EA5E9",
            permissions=[
                ModulePermission(
                    code="storage.view",
                    name="View Storage",
                    description="View storage appliance health, pools, and datasets",
                    resource="storage",
                    action="read",
                ),
                ModulePermission(
                    code="storage.write",
                    name="Write to Storage",
                    description="Stage blob writes to a storage appliance dataset (apply requires sign-off)",
                    resource="storage",
                    action="update",
                ),
            ],
            nav_items=[],
            widgets=[],
        )

    @property
    def manifest(self) -> ModuleManifest:
        return self.get_manifest()

    _router: APIRouter | None = None

    def get_router(self) -> APIRouter:
        # No HTTP routes — live storage reads already live under
        # /controllers/{id}/storage. An empty router keeps the module loader happy.
        if StorageModule._router is None:
            StorageModule._router = APIRouter()
        return StorageModule._router

    def get_models(self) -> list[type]:
        return []

    def get_operations(self):  # type: ignore[no-untyped-def]
        from app.core.fabric.operations import MEDIA_BLOB, Operation, OperationTier

        return [
            Operation(
                id="storage.health",
                title="Storage health rollup",
                description="Aggregate ZFS pool + alert health across the org's TrueNAS appliances.",
                input_schema={
                    "type": "object",
                    "properties": {"controller_id": {"type": "string", "format": "uuid"}},
                    "required": [],
                },
                produces=("application/json",),
                permission="storage.view",
                write=False,
                handler=_fabric_storage_health_handler,
                tier=OperationTier.NATIVE,
                provider_id="storage",
            ),
            Operation(
                id="storage.store_blob",
                title="Store blob to a TrueNAS dataset",
                description=(
                    "Stage an upload of a blob (e.g. a camera snapshot) into a TrueNAS "
                    "dataset. STAGE-only: an operator applies the staged change through "
                    "the dual-gate; the upload runs only on sign-off."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "controller_id": {"type": "string", "format": "uuid"},
                        "site_id": {"type": "string", "format": "uuid"},
                        "dataset_path": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 512,
                            "description": "Destination dir under /mnt, e.g. /mnt/s4_hdd/freesdn",
                        },
                        "filename": {"type": "string", "minLength": 1, "maxLength": 255},
                    },
                    "required": ["controller_id", "dataset_path", "filename"],
                },
                accepts=("image/jpeg", MEDIA_BLOB),
                permission="storage.write",
                write=True,
                feature="storage.store_blob",
                handler=None,  # staged by the executor; never run inline
                tier=OperationTier.NATIVE,
                provider_id="storage",
            ),
        ]

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources emitted by the storage.poll_health monitor on
        TrueNAS state transitions — this is what makes "something happens ON
        TrueNAS → trigger X" wireable (e.g. storage.pool.degraded → notify,
        storage.capacity.warning → fabric.notify)."""
        from app.core.fabric.operations import EventSpec, OperationTier

        _p = {
            "type": "object",
            "properties": {
                "controller_id": {"type": "string"},
                "controller_name": {"type": "string"},
                "pool": {"type": "string"},
                "capacity_pct": {"type": "number"},
                "critical_alerts": {"type": "integer"},
            },
        }

        def _ev(et, title, desc):
            return EventSpec(
                event_type=et,
                title=title,
                description=desc,
                payload_schema=_p,
                tier=OperationTier.NATIVE,
                provider_id="storage",
            )

        return [
            _ev(
                "storage.pool.degraded",
                "Pool degraded",
                "A ZFS pool entered a degraded/faulted state.",
            ),
            _ev(
                "storage.pool.healthy",
                "Pool recovered",
                "A previously-degraded ZFS pool returned to healthy.",
            ),
            _ev(
                "storage.capacity.warning",
                "Pool capacity warning",
                "A pool crossed its capacity warn threshold.",
            ),
            _ev(
                "storage.alert.critical",
                "Storage critical alert",
                "A new critical/error alert was raised on the appliance.",
            ),
            _ev(
                "storage.appliance.unreachable",
                "Appliance unreachable",
                "The TrueNAS appliance stopped responding.",
            ),
            _ev(
                "storage.appliance.online",
                "Appliance online",
                "The TrueNAS appliance became reachable again.",
            ),
        ]

    async def on_load(self) -> None:
        await super().on_load()
        logger.info("Storage module loaded")

    async def on_unload(self) -> None:
        await super().on_unload()
        logger.info("Storage module unloaded")
