# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — firewall/gateway health monitor (Celery).

Polls every active gateway (OPNsense/pfSense/…) and emits ``firewall.event.*``
Fabric events ONLY on state transitions — a critical IDS signature firing for
the first time, a WAN/gateway going down or recovering, the appliance becoming
unreachable or coming back. This makes "something happens ON the firewall →
trigger X" real (e.g. ``firewall.event.ids_critical → fabric.notify`` or
``firewall.event.wan_down → hypervisor.vm.snapshot``).

Mirrors the TrueNAS monitor (app/tasks/storage.py): transition-only emission
(last state persisted in ``GatewayConnection.fabric_health``), per-gateway fault
isolation, solo-locked, org-scoped fail-closed (``GatewayConnection.org_id`` is a
direct FK), best-effort publish. Reads are guarded per-vendor — a gateway whose
adapter lacks ``get_ids_alerts`` / ``get_gateway_status`` simply skips that
signal (reachability still applies to all).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from app.core.celery_app import acquire_solo_lock, celery_app, release_solo_lock
from app.db.session import CelerySessionLocal
from app.modules.firewall.models import GatewayConnection

logger = logging.getLogger(__name__)

_DOWN_STATES = {"down", "unreachable"}

# Per-read timeout inside a poll cycle. A gateway that accepts the TCP
# connection but then stalls (half-open link, overloaded box) would otherwise
# hang each read for the adapter's full request timeout (~60s) and starve the
# rest of the gateways in this run. Bound each read; a timeout is caught by the
# surrounding ``suppress`` and that signal is simply skipped (reachability still
# applies). Kept well under the task soft-time-limit.
_READ_TIMEOUT = 15.0


def _fw_event(
    event_type: str, priority: Any, payload: dict[str, Any], gw: GatewayConnection
) -> Any:
    from app.core.events import Event, EventCategory

    category = EventCategory.SECURITY if ".ids_" in event_type else EventCategory.DEVICE
    return Event(
        event_type=event_type,
        category=category,
        priority=priority,
        payload=payload,
        organization_id=str(gw.org_id),
        source="firewall",
    )


def _fw_transitions(
    prev: dict[str, Any], cur: dict[str, Any] | None, reachable: bool, gw: GatewayConnection
) -> list[Any]:
    from app.core.events import EventPriority

    prev = prev or {}
    base = {
        "gateway_id": str(gw.id),
        "gateway_name": gw.name,
        "vendor": gw.vendor,
        "host": gw.host,
    }
    events: list[Any] = []
    prev_reachable = bool(prev.get("reachable", True))

    if not reachable:
        if prev_reachable:
            events.append(
                _fw_event(
                    "firewall.event.gateway_unreachable",
                    EventPriority.HIGH,
                    {**base, "detail": "gateway unreachable"},
                    gw,
                )
            )
        return events

    if not prev_reachable:
        events.append(
            _fw_event("firewall.event.gateway_online", EventPriority.NORMAL, dict(base), gw)
        )

    cur = cur or {}
    prev_gw = prev.get("gateways") or {}
    cur_gw = cur.get("gateways") or {}
    for name, status in cur_gw.items():
        was = str(prev_gw.get(name, "")).lower()
        now = str(status).lower()
        if now in _DOWN_STATES and was not in _DOWN_STATES:
            events.append(
                _fw_event(
                    "firewall.event.wan_down",
                    EventPriority.HIGH,
                    {**base, "gateway": name, "status": now},
                    gw,
                )
            )
        elif was in _DOWN_STATES and now == "up":
            events.append(
                _fw_event(
                    "firewall.event.wan_up", EventPriority.NORMAL, {**base, "gateway": name}, gw
                )
            )

    # IDS: diff by the SET of critical signature ids (not count) so a re-trigger
    # of an existing SID doesn't re-alert, but a genuinely-new signature does.
    prev_sids = set(prev.get("critical_sids") or [])
    cur_sids = set(cur.get("critical_sids") or [])
    new_sids = sorted(cur_sids - prev_sids)
    if new_sids:
        # Attacker source IPs from the current critical alerts — so a Connection
        # can auto-respond (firewall.event.ids_critical → firewall.block_ip).
        # ``source_ip`` is a convenience single value for simple {{trigger.*}} wires.
        src_ips = sorted(set(cur.get("critical_src_ips") or []))
        payload = {**base, "new_signatures": new_sids[:50], "count": len(new_sids)}
        if src_ips:
            payload["source_ips"] = src_ips[:50]
            payload["source_ip"] = src_ips[0]
        events.append(_fw_event("firewall.event.ids_critical", EventPriority.HIGH, payload, gw))
    return events


def _fw_snapshot(reachable: bool, cur: dict[str, Any] | None) -> dict[str, Any]:
    snap: dict[str, Any] = {"reachable": reachable}
    if reachable and cur:
        snap["gateways"] = cur.get("gateways") or {}
        snap["critical_sids"] = cur.get("critical_sids") or []
    return snap


async def _read_current(adapter: Any) -> dict[str, Any]:
    """Guarded reads — a vendor lacking a method just contributes nothing."""
    cur: dict[str, Any] = {"gateways": {}, "critical_sids": []}

    if hasattr(adapter, "get_gateway_status"):
        with contextlib.suppress(Exception):
            res = await asyncio.wait_for(adapter.get_gateway_status(), timeout=_READ_TIMEOUT)
            if getattr(res, "success", False):
                gateways = (getattr(res, "data", {}) or {}).get("gateways") or []
                cur["gateways"] = {
                    g["name"]: g.get("status")
                    for g in gateways
                    if isinstance(g, dict) and g.get("name")
                }

    if hasattr(adapter, "get_ids_alerts"):
        with contextlib.suppress(Exception):
            res = await asyncio.wait_for(adapter.get_ids_alerts(), timeout=_READ_TIMEOUT)
            if getattr(res, "success", False):
                alerts = (getattr(res, "data", {}) or {}).get("alerts") or []
                crit = [
                    a
                    for a in alerts
                    if isinstance(a, dict) and str(a.get("severity", "")).lower() == "critical"
                ]
                cur["critical_sids"] = sorted(
                    {str(a["alert_sid"]) for a in crit if a.get("alert_sid")}
                )
                # Carry the attacker source IPs so an automation can act on them
                # (e.g. firewall.event.ids_critical → firewall.block_ip). Both a
                # list and a convenience single value for simple {{trigger.*}} wires.
                cur["critical_src_ips"] = sorted(
                    {str(a["source_ip"]) for a in crit if a.get("source_ip")}
                )
    return cur


async def _poll_firewall_health() -> dict[str, Any]:
    from app.modules.firewall.gateway_service import GatewayService

    polled = 0
    pending_events: list[Any] = []

    async with CelerySessionLocal() as session:
        svc = GatewayService(session)
        gateways = list(
            (
                await session.execute(
                    select(GatewayConnection).where(
                        GatewayConnection.deleted_at.is_(None),
                        GatewayConnection.sync_enabled.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )

        for gw in gateways:
            polled += 1
            prev = gw.fabric_health or {}
            reachable = True
            cur: dict[str, Any] | None = None
            adapter = None
            try:
                adapter = svc._build_adapter(gw)
                await adapter.connect()
                cur = await _read_current(adapter)
            except Exception as exc:  # noqa: BLE001 — one bad gateway must not abort the rest
                reachable = False
                logger.warning("Firewall poll: %s (%s) unreachable: %s", gw.name, gw.host, exc)
            finally:
                if adapter is not None:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

            pending_events.extend(_fw_transitions(prev, cur, reachable, gw))
            gw.fabric_health = _fw_snapshot(reachable, cur)
            flag_modified(gw, "fabric_health")

        await session.commit()

    emitted = 0
    for ev in pending_events:
        try:
            from app.core.events import get_event_bus

            await get_event_bus().publish(ev)
            emitted += 1
        except Exception:
            logger.debug("firewall event publish skipped", exc_info=True)

    return {"success": True, "polled": polled, "events_emitted": emitted}


@celery_app.task(bind=True, name="firewall.poll_health", soft_time_limit=240, time_limit=300)
def poll_health(self) -> dict[str, Any]:
    """Periodic firewall/gateway health poll → firewall.event.* transitions."""
    if not acquire_solo_lock("firewall.poll_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_firewall_health())
    finally:
        release_solo_lock("firewall.poll_health")
