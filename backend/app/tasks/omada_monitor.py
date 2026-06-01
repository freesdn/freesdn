# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Omada controller health/alert monitor (Celery).

Polls every active Omada controller and emits ``omada.event.*`` Fabric events
ONLY on transitions — a NEW controller alert (normalized to a canonical class:
device offline, rogue AP, PoE overload, firmware available, …), or the controller
becoming unreachable / coming back. This makes Omada a Fabric *source*: "something
happens on the Omada network → trigger X" (e.g. ``omada.event.device_offline →
fabric.notify`` or ``omada.event.rogue_ap → firewall.block_ip``).

Mirrors the firewall monitor (app/tasks/firewall_monitor.py): transition-only
emission, per-controller fault isolation, solo-locked, org-scoped fail-closed,
best-effort publish. The one difference: the ``Controller`` model has no
``fabric_health`` column (unlike ``GatewayConnection``), so the last-seen state is
persisted in **Redis** (per-controller key), avoiding a migration on the shared
prod table. A Redis miss degrades to "first poll" (re-surface current alerts
once), never a crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.adapters.omada.event_types import (
    ROGUE_AP,
    event_type_for,
    normalize_alert,
    priority_for_level,
)
from app.core.celery_app import acquire_solo_lock, celery_app, release_solo_lock
from app.db.session import CelerySessionLocal
from app.models.core import Controller

logger = logging.getLogger(__name__)

_READ_TIMEOUT = 15.0
#: Cap NEW alerts emitted per controller per cycle so a controller that suddenly
#: has hundreds of active alerts (or a first-ever poll) can't flood the bus.
_MAX_NEW_ALERTS = 25
_STATE_KEY = "omada:fabric_health:{cid}"
#: Transition state is transient; expire it after a week of no polls so a removed
#: controller's key doesn't linger. A miss just re-seeds (= first-poll behavior).
_STATE_TTL = 7 * 24 * 3600


def _decrypt(value: str | None) -> str:
    from app.core.crypto import decrypt_credential, is_encrypted

    if not value:
        return ""
    return decrypt_credential(value) if is_encrypted(value) else value


def _state_get(cid: str) -> dict[str, Any]:
    """Last-seen snapshot from Redis; {} on miss/error (→ first-poll behavior)."""
    try:
        from app.core.celery_app import _get_solo_redis

        raw = _get_solo_redis().get(_STATE_KEY.format(cid=cid))
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001 — a state-store miss must never break the poll
        return {}


def _state_set(cid: str, snapshot: dict[str, Any]) -> None:
    with contextlib.suppress(Exception):
        from app.core.celery_app import _get_solo_redis

        _get_solo_redis().set(_STATE_KEY.format(cid=cid), json.dumps(snapshot), ex=_STATE_TTL)


def _omada_event(event_type: str, priority_value: str, payload: dict[str, Any], org_id: str) -> Any:
    from app.core.events import Event, EventCategory, EventPriority

    priority = EventPriority.HIGH if priority_value == "high" else EventPriority.NORMAL
    if event_type == event_type_for(ROGUE_AP):
        category = EventCategory.SECURITY
    elif event_type.endswith((".device_offline", ".device_online")):
        category = EventCategory.DEVICE
    else:
        category = EventCategory.NETWORK
    return Event(
        event_type=event_type,
        category=category,
        priority=priority,
        payload=payload,
        organization_id=org_id,
        source="omada",
    )


def _omada_transitions(
    prev: dict[str, Any], cur: dict[str, Any] | None, reachable: bool, ctrl: Any, org_id: str
) -> list[Any]:
    prev = prev or {}
    base = {
        "controller_id": str(ctrl.id),
        "controller_name": ctrl.name,
        "vendor": "omada",
        "host": ctrl.host,
    }
    events: list[Any] = []
    prev_reachable = bool(prev.get("reachable", True))

    if not reachable:
        if prev_reachable:
            events.append(
                _omada_event(
                    "omada.event.controller_unreachable",
                    "high",
                    {**base, "detail": "controller unreachable"},
                    org_id,
                )
            )
        return events

    if not prev_reachable:
        events.append(_omada_event("omada.event.controller_online", "normal", dict(base), org_id))

    cur = cur or {}
    prev_ids = set(prev.get("alert_ids") or [])
    new_alerts = [
        a
        for a in (cur.get("alerts") or [])
        if a.get("id") is not None and str(a.get("id")) not in prev_ids
    ]
    for alert in new_alerts[:_MAX_NEW_ALERTS]:
        canonical = normalize_alert(alert.get("category"), alert.get("message"))
        events.append(
            _omada_event(
                event_type_for(canonical),
                priority_for_level(alert.get("level")),
                {
                    **base,
                    "alert_id": str(alert.get("id")),
                    "category": canonical,
                    "raw_category": alert.get("category"),
                    "message": alert.get("message"),
                    "level": alert.get("level"),
                    "device_mac": alert.get("device_mac"),
                    "device_name": alert.get("device_name"),
                    "client_mac": alert.get("client_mac"),
                },
                org_id,
            )
        )
    return events


def _omada_snapshot(reachable: bool, cur: dict[str, Any] | None) -> dict[str, Any]:
    snap: dict[str, Any] = {"reachable": reachable}
    if reachable and cur:
        snap["alert_ids"] = sorted(
            {str(a["id"]) for a in (cur.get("alerts") or []) if a.get("id") is not None}
        )
    return snap


async def _read_current(adapter: Any) -> dict[str, Any]:
    """Guarded read — the controller's active alert log."""
    cur: dict[str, Any] = {"alerts": []}
    if hasattr(adapter, "get_alerts"):
        with contextlib.suppress(Exception):
            rows = await asyncio.wait_for(adapter.get_alerts(limit=100), timeout=_READ_TIMEOUT)
            cur["alerts"] = [r for r in (rows or []) if isinstance(r, dict)]
    return cur


def _build_omada_adapter(controller: Any) -> Any:
    from app.services.adapter_factory import get_adapter

    kwargs: dict[str, Any] = {
        "port": controller.port,
        "use_ssl": controller.use_ssl,
        "verify_ssl": controller.verify_ssl,
        "mode": controller.connection_mode,
    }
    if controller.connection_mode == "cloud":
        kwargs["client_id"] = controller.client_id or ""
        kwargs["client_secret"] = _decrypt(controller.client_secret)
        kwargs["omada_id"] = controller.omada_id or ""
        kwargs["cloud_region"] = controller.cloud_region or ""
    return get_adapter(
        controller.type,
        host=controller.host,
        username=controller.username or "",
        password=_decrypt(controller.password),
        **kwargs,
    )


async def _poll_omada_health() -> dict[str, Any]:
    polled = 0
    pending: list[tuple[str, dict[str, Any], list[Any]]] = []

    async with CelerySessionLocal() as session:
        controllers = list(
            (
                await session.execute(
                    select(Controller)
                    .options(selectinload(Controller.site))
                    .where(
                        Controller.controller_type == "omada",
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
            # Org-scoped fail-closed: no site → no org → can't route an event.
            if ctrl.site is None:
                continue
            org_id = str(ctrl.site.organization_id)
            polled += 1
            prev = _state_get(str(ctrl.id))
            reachable = True
            cur: dict[str, Any] | None = None
            adapter = None
            try:
                adapter = _build_omada_adapter(ctrl)
                await adapter.connect()
                cur = await _read_current(adapter)
            except Exception as exc:  # noqa: BLE001 — one bad controller must not abort the rest
                reachable = False
                logger.warning("Omada poll: %s (%s) unreachable: %s", ctrl.name, ctrl.host, exc)
            finally:
                if adapter is not None:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

            events = _omada_transitions(prev, cur, reachable, ctrl, org_id)
            pending.append((str(ctrl.id), _omada_snapshot(reachable, cur), events))

    emitted = 0
    for cid, snapshot, events in pending:
        for ev in events:
            try:
                from app.core.events import get_event_bus

                await get_event_bus().publish(ev)
                emitted += 1
            except Exception:
                logger.debug("omada event publish skipped", exc_info=True)
        # Persist AFTER attempting publish so a publish failure re-surfaces next
        # cycle rather than being silently swallowed by an advanced snapshot.
        _state_set(cid, snapshot)

    return {"success": True, "polled": polled, "events_emitted": emitted}


@celery_app.task(bind=True, name="omada.poll_health", soft_time_limit=240, time_limit=300)
def poll_health(self) -> dict[str, Any]:
    """Periodic Omada controller poll → omada.event.* transitions."""
    if not acquire_solo_lock("omada.poll_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_omada_health())
    finally:
        release_solo_lock("omada.poll_health")
