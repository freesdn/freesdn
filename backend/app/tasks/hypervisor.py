# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Proxmox hypervisor health monitor (Celery).

Polls every active Proxmox controller on a schedule, rolls up cluster quorum +
per-node online/offline, and emits ``hypervisor.*`` Fabric events ONLY on state
transitions (node offline↔online, cluster inquorate↔quorate, controller
unreachable↔online). This is what makes "something happens *on* the cluster →
trigger something elsewhere" real — e.g. ``hypervisor.node.offline →
fabric.notify`` or ``→ hypervisor.vm.snapshot``.

Before this, the hypervisor module declared ZERO Fabric events and had no
publisher, so no cross-system vertical could be triggered BY cluster state.
Mirrors ``tasks/storage.py`` exactly:
  * **Transition-only emission** — last state persisted per controller in
    ``Controller.config['_fabric_hypervisor_health']`` (no migration); a steady
    state never re-fires, only the edge.
  * **Per-controller fault isolation** — one unreachable cluster never aborts the
    others; an unreachable transition is itself an event.
  * **Solo-locked** — overlapping beat runs don't double-poll across workers.
  * **Org-scoped fail-closed** — every event carries the controller's org
    (resolved via its site); a controller with no resolvable org is skipped.
  * **Best-effort publish** — a bus failure never fails the poll or the snapshot.
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

logger = logging.getLogger(__name__)

_SNAP_KEY = "_fabric_hypervisor_health"


def _mk_event(event_type: str, priority: Any, payload: dict[str, Any], org_id: UUID) -> Any:
    from app.core.events import Event, EventCategory

    return Event(
        event_type=event_type,
        category=EventCategory.DEVICE,
        priority=priority,
        payload=payload,
        organization_id=str(org_id),
        source="hypervisor",
    )


def _transitions(
    prev: dict[str, Any],
    status: dict[str, Any] | None,
    reachable: bool,
    ctrl: Controller,
    org_id: UUID,
) -> list[Any]:
    """Diff the previous snapshot against the current cluster reading → events."""
    from app.core.events import EventPriority

    base = {"controller_id": str(ctrl.id), "controller_name": ctrl.name}
    events: list[Any] = []
    prev_reachable = bool(prev.get("reachable", True))

    if not reachable:
        if prev_reachable:
            events.append(
                _mk_event(
                    "hypervisor.controller.unreachable",
                    EventPriority.HIGH,
                    {**base, "detail": "Proxmox cluster is unreachable"},
                    org_id,
                )
            )
        return events

    if not prev_reachable:
        events.append(
            _mk_event("hypervisor.controller.online", EventPriority.NORMAL, dict(base), org_id)
        )

    status = status or {}

    # Cluster quorum: inquorate fires on transition (and first-seen-inquorate);
    # quorate fires only on recovery (mirrors storage degraded/healthy).
    # When quorum is UNKNOWN (per-node fallback read), skip quorum diffing
    # entirely — emitting a quorate/inquorate edge off a guessed value would be
    # a false transition.
    prev_q = bool(prev.get("quorate", True))
    now_q = bool(status.get("quorate", True))
    if status.get("quorum_unknown"):
        now_q = prev_q  # carry forward → no spurious quorum edge
    if not now_q and prev_q:
        events.append(
            _mk_event(
                "hypervisor.cluster.inquorate",
                EventPriority.HIGH,
                {**base, "node_count": status.get("node_count")},
                org_id,
            )
        )
    elif now_q and not prev_q:
        events.append(
            _mk_event("hypervisor.cluster.quorate", EventPriority.NORMAL, dict(base), org_id)
        )

    # Per-node up/down: offline fires on transition (and first-seen-offline);
    # online fires only on recovery.
    prev_nodes = prev.get("nodes") or {}
    now_nodes = status.get("nodes") or {}
    for name in sorted(now_nodes):
        st = now_nodes[name]
        was = prev_nodes.get(name)
        if st == "offline" and was != "offline":
            events.append(
                _mk_event(
                    "hypervisor.node.offline", EventPriority.HIGH, {**base, "node": name}, org_id
                )
            )
        elif st == "online" and was == "offline":
            events.append(
                _mk_event(
                    "hypervisor.node.online", EventPriority.NORMAL, {**base, "node": name}, org_id
                )
            )
    return events


def _snapshot(
    reachable: bool, status: dict[str, Any] | None, prev: dict[str, Any] | None = None
) -> dict[str, Any]:
    snap: dict[str, Any] = {"reachable": reachable}
    if reachable and status:
        # When quorum is unknown (per-node fallback), persist the PRIOR quorate
        # so a later real reading diffs against a true baseline, not a guess.
        if status.get("quorum_unknown"):
            quorate = bool((prev or {}).get("quorate", True))
        else:
            quorate = bool(status.get("quorate", True))
        snap.update({"quorate": quorate, "nodes": status.get("nodes") or {}})
    return snap


async def _org_for_controller(session: Any, ctrl: Controller) -> UUID | None:
    if ctrl.site_id is None:
        return None
    return (
        await session.execute(select(Site.organization_id).where(Site.id == ctrl.site_id))
    ).scalar_one_or_none()


async def _read_cluster_status(adapter: Any) -> dict[str, Any] | None:
    """Roll the adapter's cluster status into the snapshot/diff shape, or None.

    Falls back to a per-node read (``get_nodes`` hits ``/nodes`` and does NOT
    need cluster ``Sys.Audit``) when cluster status is unavailable — a token
    lacking ``Sys.Audit`` or a standalone (non-cluster) node is still REACHABLE,
    so we must not false-emit ``controller.unreachable``. In the fallback we
    can't observe quorum, so we mark ``quorum_unknown`` (the diff skips quorum
    events and the snapshot carries the prior quorate forward) — node up/down
    transitions still fire normally.
    """
    with contextlib.suppress(Exception):
        res = await adapter.get_cluster_status()
        if getattr(res, "success", False) and res.data is not None:
            cs = res.data
            return {
                "quorate": bool(getattr(cs, "quorate", True)),
                "node_count": getattr(cs, "node_count", None),
                "nodes": {n.node: n.status for n in getattr(cs, "nodes", []) or []},
            }

    # Cluster status unavailable (perms / standalone) — fall back to /nodes.
    res = await adapter.get_nodes()
    if getattr(res, "success", False) and res.data is not None:
        nodes = {n.node: n.status for n in (res.data or [])}
        if nodes:
            return {"node_count": len(nodes), "nodes": nodes, "quorum_unknown": True}
    return None


async def _poll_hypervisor_health() -> dict[str, Any]:
    from app.services.adapter_proxmox_vm import build_proxmox_adapter

    polled = 0
    emitted = 0
    pending_events: list[Any] = []

    async with CelerySessionLocal() as session:
        controllers = list(
            (
                await session.execute(
                    select(Controller).where(
                        Controller.controller_type == "proxmox",
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

            reachable = True
            status: dict[str, Any] | None = None
            adapter = None
            try:
                adapter = await build_proxmox_adapter(ctrl)
                status = await _read_cluster_status(adapter)
                if status is None:
                    reachable = False
            except Exception as exc:  # noqa: BLE001 — one bad cluster must not abort the rest
                reachable = False
                logger.warning(
                    "Hypervisor poll: %s (%s) unreachable: %s", ctrl.name, ctrl.host, exc
                )
            finally:
                if adapter is not None:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

            pending_events.extend(_transitions(prev, status, reachable, ctrl, org_id))

            ctrl.config = {**cfg, _SNAP_KEY: _snapshot(reachable, status, prev)}
            flag_modified(ctrl, "config")

        await session.commit()

    # Publish AFTER the snapshot is durably committed (steady state never re-fires).
    for ev in pending_events:
        try:
            from app.core.events import get_event_bus

            await get_event_bus().publish(ev)
            emitted += 1
        except Exception:
            logger.debug("hypervisor event publish skipped", exc_info=True)

    return {"success": True, "polled": polled, "events_emitted": emitted}


@celery_app.task(bind=True, name="hypervisor.poll_health", soft_time_limit=240, time_limit=300)
def poll_health(self) -> dict[str, Any]:
    """Periodic Proxmox health poll → hypervisor.* transition events."""
    if not acquire_solo_lock("hypervisor.poll_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_hypervisor_health())
    finally:
        release_solo_lock("hypervisor.poll_health")
