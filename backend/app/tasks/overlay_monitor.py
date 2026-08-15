# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Overlay-mesh peer health monitor (Celery).

Polls the connected overlay (Tailscale / NetBird) and emits ``overlay.*`` Fabric
events ONLY on state transitions — a peer coming online/offline, its metadata
changing, or the overlay enumeration itself becoming unreachable / recovering.
This makes the overlay a Fabric *source*: "a peer on the mesh went offline →
notify the operator", "a remote site rejoined → re-sync".

Mirrors ``app/tasks/omada_monitor.py``: transition-only emission, solo-locked,
org-scoped fail-closed, best-effort publish. Like Omada there is no DB column to
hang the last-seen snapshot on (the overlay is appliance-level, not a Controller
row), so the snapshot lives in Redis under one per-org key. A state miss degrades
to "first poll" (re-surface current offline peers once), never a crash.

Read-only by construction: this task only READS the overlay and EMITS events. It
stages nothing and runs no ``tailscale up/down`` — the staging chokepoint and
operator sign-off belong to the VPN *write* ops, not here.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from sqlalchemy import func, select

from app.core.celery_app import acquire_solo_lock, celery_app, release_solo_lock
from app.db.session import CelerySessionLocal
from app.models.core import Organization

logger = logging.getLogger(__name__)

_STATE_KEY = "overlay:fabric_health:{org_id}"
#: Transition state is transient; expire it after a week of no polls so a removed
#: appliance's key doesn't linger. A miss just re-seeds (= first-poll behavior).
_STATE_TTL = 7 * 24 * 3600


def _state_get(org_id: str) -> dict[str, Any]:
    """Last-seen snapshot from Redis; ``{}`` on miss/error (→ first-poll behavior)."""
    try:
        from app.core.celery_app import _get_solo_redis

        raw = _get_solo_redis().get(_STATE_KEY.format(org_id=org_id))
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001 — a state-store miss must never break the poll
        return {}


def _state_set(org_id: str, snapshot: dict[str, Any]) -> None:
    with contextlib.suppress(Exception):
        from app.core.celery_app import _get_solo_redis

        _get_solo_redis().set(_STATE_KEY.format(org_id=org_id), json.dumps(snapshot), ex=_STATE_TTL)


def _mk_event(event_type: str, priority: Any, payload: dict[str, Any], org_id: str) -> Any:
    from app.core.events import Event, EventCategory

    return Event(
        event_type=event_type,
        category=EventCategory.NETWORK,
        priority=priority,
        payload={**payload, "organization_id": org_id},
        organization_id=org_id,
        source="overlay",
    )


def _peer_key(p: dict[str, Any]) -> str:
    # Identity across cycles: the same key the discovery dedupe uses (source|address).
    return f"{p.get('source')}|{p.get('address')}"


def _metadata_changed(was: dict[str, Any], now: dict[str, Any]) -> bool:
    return (
        was.get("hostname") != now.get("hostname")
        or was.get("os") != now.get("os")
        or was.get("suggested_type") != now.get("suggested_type")
        or set(was.get("tags") or []) != set(now.get("tags") or [])
    )


def _transitions(
    prev: dict[str, Any],
    peers: list[dict[str, Any]] | None,
    reachable: bool,
    org_id: str,
) -> list[Any]:
    """Diff the previous snapshot against the current overlay reading → events.

    Mirrors ``hypervisor._transitions``: offline fires on transition AND
    first-seen-offline; online fires only on recovery; steady state is silent.
    """
    from app.core.events import EventPriority

    events: list[Any] = []
    prev_reachable = bool(prev.get("reachable", True))

    if not reachable:
        if prev_reachable:  # reachable → unreachable (overlay enumeration went down)
            events.append(
                _mk_event(
                    "overlay.status.unreachable",
                    EventPriority.HIGH,
                    {"detail": "overlay enumeration unavailable"},
                    org_id,
                )
            )
        return events

    if not prev_reachable:  # unreachable → reachable
        events.append(_mk_event("overlay.status.online", EventPriority.NORMAL, {}, org_id))

    peers = peers or []
    prev_peers = {p["key"]: p for p in (prev.get("peers") or [])}
    now_peers = {_peer_key(p): p for p in peers}

    for key in sorted(now_peers):
        now_p = now_peers[key]
        was_p = prev_peers.get(key)
        now_online = bool(now_p.get("online"))
        if was_p is None:
            # First sighting: offline-now fires offline (matches the hypervisor
            # first-seen-offline rule); online-now is NOT an edge (online is
            # recovery-only) — a brand-new online peer is discovery's job.
            if not now_online:
                events.append(_mk_event("overlay.peer.offline", EventPriority.HIGH, now_p, org_id))
            continue
        was_online = bool(was_p.get("online"))
        if was_online and not now_online:
            events.append(_mk_event("overlay.peer.offline", EventPriority.HIGH, now_p, org_id))
        elif not was_online and now_online:
            events.append(_mk_event("overlay.peer.online", EventPriority.NORMAL, now_p, org_id))
        elif _metadata_changed(was_p, now_p):
            events.append(
                _mk_event(
                    "overlay.connection.changed",
                    EventPriority.NORMAL,
                    {"prev": was_p, "now": now_p},
                    org_id,
                )
            )

    # A peer that vanished while previously online → offline (no longer reachable).
    for key in sorted(prev_peers):
        if key not in now_peers and bool(prev_peers[key].get("online")):
            events.append(
                _mk_event("overlay.peer.offline", EventPriority.HIGH, prev_peers[key], org_id)
            )
    return events


def _snapshot(reachable: bool, peers: list[dict[str, Any]] | None) -> dict[str, Any]:
    snap: dict[str, Any] = {"reachable": reachable}
    if reachable:
        snap["peers"] = [
            {
                "key": _peer_key(p),
                "source": p.get("source"),
                "address": p.get("address"),
                "hostname": p.get("hostname"),
                "online": bool(p.get("online")),
                "os": p.get("os"),
                "tags": p.get("tags"),
                "suggested_type": p.get("suggested_type"),
            }
            for p in (peers or [])
        ]
    return snap


async def _appliance_org_id(session: Any) -> str | None:
    """Single-tenant appliance: resolve THE organization (fail-closed).

    Beat tasks have no user context (unlike ``/vpn/discovery`` which reads
    ``user.organization_id``), so we resolve the one non-deleted org directly. The
    single-tenant threat model guarantees exactly one; if that invariant is
    violated (0 or >1 orgs), we refuse to emit rather than guess a tenant or fan
    one node-local daemon's peers across every org.
    """
    try:
        count = (
            await session.execute(
                select(func.count())
                .select_from(Organization)
                .where(Organization.deleted_at.is_(None))
            )
        ).scalar() or 0
        if count != 1:
            logger.warning("Overlay poll: expected 1 organization, found %d — skipping", count)
            return None
        org = (
            await session.execute(
                select(Organization).where(Organization.deleted_at.is_(None)).limit(1)
            )
        ).scalar_one_or_none()
        return str(org.id) if org else None
    except Exception:
        logger.exception("Overlay poll: failed to resolve appliance organization")
        return None


async def _poll_overlay_health() -> dict[str, Any]:
    from app.core.config import settings

    # VPN off (the default, Omada/UniFi parity) → no overlay exists; emit nothing
    # and never touch Redis. discover_overlay_devices() also short-circuits to [],
    # but the explicit check avoids a spurious overlay.status.unreachable in off
    # mode and skips the org query entirely.
    if settings.resolved_vpn_mode == "off":
        return {"success": True, "skipped": True, "reason": "vpn_off"}

    from app.services.overlay_discovery import (
        discover_overlay_devices,
        emit_overlay_discovery,
    )

    emitted = 0
    pending_events: list[Any] = []
    reachable = True
    peers: list[dict[str, Any]] | None = None

    async with CelerySessionLocal() as session:
        org_id = await _appliance_org_id(session)
        if org_id is None:
            return {"success": False, "reason": "no_organization"}

        try:
            peers = await discover_overlay_devices()  # reuses the shipped read-op
        except Exception as exc:  # noqa: BLE001 — a bad daemon read must not crash the beat
            reachable = False
            logger.warning("Overlay poll unreachable: %s", exc)

        prev = _state_get(org_id)
        pending_events = _transitions(prev, peers, reachable, org_id)
        _state_set(org_id, _snapshot(reachable, peers))

    # Publish AFTER the snapshot is durably stored (steady state never re-fires).
    for ev in pending_events:
        try:
            from app.core.events import get_event_bus

            await get_event_bus().publish(ev)
            emitted += 1
        except Exception:  # noqa: BLE001 — one bad publish must not drop the rest
            logger.debug("overlay event publish skipped", exc_info=True)

    # Reuse the shared discovery emitter so first-sighting overlay.peer.discovered
    # fires from the periodic loop too (deduped per (org, source, address)).
    discovered = 0
    if reachable and peers:
        with contextlib.suppress(Exception):
            discovered = await emit_overlay_discovery(peers, organization_id=org_id)

    return {
        "success": True,
        "polled": len(peers or []),
        "events_emitted": emitted,
        "discovered": discovered,
    }


@celery_app.task(bind=True, name="overlay.poll_health", soft_time_limit=120, time_limit=180)
def poll_health(self) -> dict[str, Any]:
    """Periodic overlay-mesh peer health poll → ``overlay.*`` transition events."""
    if not acquire_solo_lock("overlay.poll_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_overlay_health())
    finally:
        release_solo_lock("overlay.poll_health")
