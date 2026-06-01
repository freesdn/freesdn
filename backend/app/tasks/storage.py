# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — TrueNAS storage health monitor (Celery).

Polls every active TrueNAS appliance on a schedule, rolls up its pool / alert /
temperature health, and emits ``storage.*`` Fabric events ONLY on state
transitions (degraded↔healthy, capacity crossing the warn threshold, a new
critical alert, appliance unreachable↔online). This is what makes "something
happens *on* TrueNAS → trigger something elsewhere" real — e.g.
``storage.pool.degraded → fabric.notify`` or ``→ hypervisor.vm.snapshot``.

Enterprise-grade properties:
  * **Transition-only emission** — last state is persisted per controller (in
    ``Controller.config['_fabric_storage_health']``, no migration), so a steady
    degraded pool does not spam an event every 2 minutes; only the edge fires.
  * **Per-appliance fault isolation** — one unreachable NAS never aborts the
    poll of the others; an unreachable transition is itself an event.
  * **Solo-locked** — overlapping beat runs (a slow/partitioned fleet) don't
    double-poll across workers.
  * **Org-scoped fail-closed** — every event carries the appliance's
    organization_id (resolved via its site); a controller with no resolvable
    org is skipped, never emitted cross-tenant.
  * **Best-effort publish** — a bus failure never fails the poll or the
    last-state persistence.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from app.core.celery_app import acquire_solo_lock, celery_app, release_solo_lock
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Site
from app.modules.storage.health import summarize_health

logger = logging.getLogger(__name__)

_SNAP_KEY = "_fabric_storage_health"
_DEFAULT_CAPACITY_WARN_PCT = 85.0


def _mk_event(event_type: str, priority: Any, payload: dict[str, Any], org_id: UUID) -> Any:
    from app.core.events import Event, EventCategory

    return Event(
        event_type=event_type,
        category=EventCategory.DEVICE,
        priority=priority,
        payload=payload,
        organization_id=str(org_id),
        source="storage",
    )


def _transitions(
    prev: dict[str, Any],
    summary: dict[str, Any] | None,
    reachable: bool,
    ctrl: Controller,
    org_id: UUID,
) -> list[Any]:
    """Diff the previous snapshot against the current reading → bus events."""
    from app.core.events import EventPriority

    base = {"controller_id": str(ctrl.id), "controller_name": ctrl.name}
    events: list[Any] = []
    prev_reachable = bool(prev.get("reachable", True))

    if not reachable:
        if prev_reachable:
            events.append(
                _mk_event(
                    "storage.appliance.unreachable",
                    EventPriority.HIGH,
                    {**base, "detail": "TrueNAS appliance is unreachable"},
                    org_id,
                )
            )
        return events

    if not prev_reachable:
        events.append(
            _mk_event("storage.appliance.online", EventPriority.NORMAL, dict(base), org_id)
        )

    summary = summary or {}
    prev_degraded = set(prev.get("degraded_pools") or [])
    now_degraded = set(summary.get("degraded_pools") or [])
    for pool in sorted(now_degraded - prev_degraded):
        events.append(
            _mk_event("storage.pool.degraded", EventPriority.HIGH, {**base, "pool": pool}, org_id)
        )
    for pool in sorted(prev_degraded - now_degraded):
        events.append(
            _mk_event("storage.pool.healthy", EventPriority.NORMAL, {**base, "pool": pool}, org_id)
        )

    prev_overcap = set(prev.get("over_capacity_pools") or [])
    now_overcap = set(summary.get("over_capacity_pools") or [])
    cap_by_pool = {p.get("name"): p.get("capacity_pct") for p in summary.get("pools") or []}
    for pool in sorted(now_overcap - prev_overcap):
        events.append(
            _mk_event(
                "storage.capacity.warning",
                EventPriority.HIGH,
                {**base, "pool": pool, "capacity_pct": cap_by_pool.get(pool)},
                org_id,
            )
        )

    prev_crit = int(prev.get("critical_alerts") or 0)
    now_crit = int(summary.get("critical_alerts") or 0)
    if now_crit > prev_crit:
        events.append(
            _mk_event(
                "storage.alert.critical",
                EventPriority.HIGH,
                {**base, "critical_alerts": now_crit, "new_alerts": now_crit - prev_crit},
                org_id,
            )
        )
    return events


def _snapshot(reachable: bool, summary: dict[str, Any] | None) -> dict[str, Any]:
    snap: dict[str, Any] = {"reachable": reachable}
    if reachable and summary:
        snap.update(
            {
                "status": summary.get("status"),
                "degraded_pools": summary.get("degraded_pools") or [],
                "over_capacity_pools": summary.get("over_capacity_pools") or [],
                "critical_alerts": int(summary.get("critical_alerts") or 0),
            }
        )
    return snap


async def _org_for_controller(session: Any, ctrl: Controller) -> UUID | None:
    if ctrl.site_id is None:
        return None
    return (
        await session.execute(select(Site.organization_id).where(Site.id == ctrl.site_id))
    ).scalar_one_or_none()


async def _poll_storage_health() -> dict[str, Any]:
    from app.services.adapter_truenas_storage import build_truenas_adapter

    polled = 0
    emitted = 0
    pending_events: list[Any] = []

    async with CelerySessionLocal() as session:
        controllers = list(
            (
                await session.execute(
                    select(Controller).where(
                        Controller.controller_type == "truenas",
                        Controller.deleted_at.is_(None),
                        Controller.is_active.is_(True),
                        Controller.sync_enabled.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )

        for ctrl in controllers:
            polled += 1
            org_id = await _org_for_controller(session, ctrl)
            if org_id is None:
                # No resolvable org → cannot org-scope the event. Skip (fail-closed).
                continue

            cfg = ctrl.config or {}
            prev = cfg.get(_SNAP_KEY) or {}
            warn_pct = float(
                cfg.get("_fabric_storage_capacity_warn_pct", _DEFAULT_CAPACITY_WARN_PCT)
            )

            reachable = True
            summary: dict[str, Any] | None = None
            adapter = None
            try:
                adapter = await build_truenas_adapter(ctrl)
                pools = await adapter.get_pools()
                alerts = await adapter.get_alerts()
                temps = await adapter.get_disk_temperatures()
                summary = summarize_health(pools, alerts, temps, capacity_warn_pct=warn_pct)
            except Exception as exc:  # noqa: BLE001 — one bad NAS must not abort the rest
                reachable = False
                logger.warning(
                    "Storage poll: %s (%s) unhealthy/unreachable: %s", ctrl.name, ctrl.host, exc
                )
            finally:
                if adapter is not None:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

            # Collect transition events (published after commit so a steady
            # state never re-fires, and a publish failure can't roll back).
            pending_events.extend(_transitions(prev, summary, reachable, ctrl, org_id))

            ctrl.config = {**cfg, _SNAP_KEY: _snapshot(reachable, summary)}
            flag_modified(ctrl, "config")

        await session.commit()

    # Publish AFTER the snapshot is durably committed.
    for ev in pending_events:
        try:
            from app.core.events import get_event_bus

            await get_event_bus().publish(ev)
            emitted += 1
        except Exception:
            logger.debug("storage event publish skipped", exc_info=True)

    return {"success": True, "polled": polled, "events_emitted": emitted}


@celery_app.task(bind=True, name="storage.poll_health", soft_time_limit=240, time_limit=300)
def poll_health(self) -> dict[str, Any]:
    """Periodic TrueNAS health poll → storage.* transition events."""
    if not acquire_solo_lock("storage.poll_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_storage_health())
    finally:
        release_solo_lock("storage.poll_health")
