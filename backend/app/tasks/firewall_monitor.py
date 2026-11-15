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

#: The reachability probe (the adapter's connect; for OPNsense one status GET).
#: Short on purpose: a box that cannot answer its status page in 20 s is in
#: trouble, and waiting longer only holds one more of its workers.
_PROBE_TIMEOUT = 20.0


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


def _note_failure(failures: list[str] | None, what: str, res: Any = None, exc: Any = None) -> None:
    """Remember a read that failed because the DEVICE did not answer."""
    if failures is None:
        return
    from app.adapters import io_policy

    if exc is not None:
        if io_policy.is_device_failure(exc):
            failures.append(f"{what}: {type(exc).__name__}")
    elif res is not None and not getattr(res, "success", False):
        error = str(getattr(res, "error", "") or "")
        if io_policy.is_device_failure_text(error):
            failures.append(f"{what}: {error[:100]}")


async def _guarded(call: Any, what: str, failures: list[str] | None) -> Any:
    try:
        res = await asyncio.wait_for(call(), timeout=_READ_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - a missing signal must not fail the poll
        _note_failure(failures, what, exc=exc)
        return None
    _note_failure(failures, what, res=res)
    return res


async def _read_current(adapter: Any, failures: list[str] | None = None) -> dict[str, Any]:
    """Guarded reads — a vendor lacking a method just contributes nothing.

    ``failures`` (optional) collects the reads that failed because the device
    did not answer (timeout, dropped connection), as opposed to a refused or
    unsupported read. The poll counts those against the device's breaker, and
    once one has failed the remaining reads are not sent.
    """
    cur: dict[str, Any] = {"gateways": {}, "critical_sids": []}

    if hasattr(adapter, "get_gateway_status"):
        res = await _guarded(adapter.get_gateway_status, "gateway_status", failures)
        with contextlib.suppress(Exception):
            if getattr(res, "success", False):
                gateways = (getattr(res, "data", {}) or {}).get("gateways") or []
                cur["gateways"] = {
                    g["name"]: g.get("status")
                    for g in gateways
                    if isinstance(g, dict) and g.get("name")
                }

    if hasattr(adapter, "get_ids_alerts") and not failures:
        res = await _guarded(adapter.get_ids_alerts, "ids_alerts", failures)
        with contextlib.suppress(Exception):
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
    """Poll every sync-enabled gateway; emit transitions.

    Gentle by construction (2026-11 soak: this poll and the full sync kept
    hitting an OPNsense whose PHP/configd backend had wedged):

    * a gateway whose shared breaker is OPEN is not contacted at all until its
      cooldown ends; then ONE poll probes it;
    * the probe is the adapter's connect (OPNsense: one status GET), bounded by
      ``_PROBE_TIMEOUT``; only if it answers do the gateway-status and IDS
      reads follow, and a read the device did not answer stops the rest;
    * no database transaction is open while any device is contacted: the
      gateways are loaded and that session closed first, and the snapshots are
      written afterwards in one short transaction.
    """
    from types import SimpleNamespace

    from app.core.device_breaker import gateway_breaker, gateway_key
    from app.core.device_slot import device_slots, gateway_slot_key
    from app.modules.firewall.gateway_service import GatewayService
    from app.modules.poll_gate import module_not_disabled

    # 1. load, then close the session before any device I/O
    targets: list[tuple[Any, Any, dict[str, Any]]] = []
    async with CelerySessionLocal() as session:
        svc = GatewayService(session)
        gateways = list(
            (
                await session.execute(
                    select(GatewayConnection).where(
                        GatewayConnection.deleted_at.is_(None),
                        GatewayConnection.sync_enabled.is_(True),
                        # Disabling the Firewall module stops its polling.
                        module_not_disabled(GatewayConnection.org_id, "firewall"),
                    )
                )
            )
            .scalars()
            .all()
        )
        for gw in gateways:
            ident = SimpleNamespace(
                id=gw.id, name=gw.name, vendor=gw.vendor, host=gw.host, org_id=gw.org_id
            )
            try:
                adapter = svc._build_adapter(gw)
            except Exception as exc:  # noqa: BLE001 - one bad row must not abort the rest
                logger.warning("Firewall poll: cannot build adapter for %s: %s", gw.name, exc)
                continue
            targets.append((ident, adapter, dict(gw.fabric_health or {})))

    # 2. talk to the devices, with no transaction open
    polled = skipped = busy = 0
    pending_events: list[Any] = []
    snapshots: dict[Any, dict[str, Any]] = {}
    for ident, adapter, prev in targets:
        key = gateway_key(ident.id)
        gate = gateway_breaker.check(key)
        if not gate.allowed:
            skipped += 1
            logger.info("Firewall poll: %s skipped: %s", ident.name, gate.skip_message())
            continue
        # One request group per device: while the full sync, a drift check, a
        # config backup or a UI read is talking to this box, skip this cycle.
        slot_key = gateway_slot_key(ident)
        lease = await device_slots.acquire(slot_key, "firewall health poll")
        if lease is None:
            busy += 1
            if gate.probe:
                gateway_breaker.release_probe(key)
            logger.info(
                "Firewall poll: %s skipped: %s",
                ident.name,
                await device_slots.abusy_reason(slot_key),
            )
            continue
        polled += 1
        reachable = True
        cur: dict[str, Any] | None = None
        failures: list[str] = []
        try:
            await asyncio.wait_for(adapter.connect(), timeout=_PROBE_TIMEOUT)
            cur = await _read_current(adapter, failures)
        except Exception as exc:  # noqa: BLE001 — one bad gateway must not abort the rest
            reachable = False
            failures.append(f"connect: {type(exc).__name__}")
            logger.warning("Firewall poll: %s (%s) unreachable: %s", ident.name, ident.host, exc)
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()
            await device_slots.arelease(lease)

        if failures:
            gateway_breaker.record_failure(key, failures[0])
        else:
            gateway_breaker.record_success(key)
        pending_events.extend(_fw_transitions(prev, cur, reachable, ident))
        snapshots[ident.id] = _fw_snapshot(reachable, cur)

    # 3. write the snapshots in one short transaction
    if snapshots:
        async with CelerySessionLocal() as session:
            rows = (
                (
                    await session.execute(
                        select(GatewayConnection).where(GatewayConnection.id.in_(list(snapshots)))
                    )
                )
                .scalars()
                .all()
            )
            for gw in rows:
                gw.fabric_health = snapshots[gw.id]
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

    return {
        "success": True,
        "polled": polled,
        "skipped": skipped,
        "busy": busy,
        "events_emitted": emitted,
    }


@celery_app.task(bind=True, name="firewall.poll_health", soft_time_limit=240, time_limit=300)
def poll_health(self) -> dict[str, Any]:
    """Periodic firewall/gateway health poll → firewall.event.* transitions."""
    lock_token = acquire_solo_lock("firewall.poll_health", ttl_seconds=300)
    if not lock_token:
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_poll_firewall_health())
    finally:
        release_solo_lock("firewall.poll_health", lock_token)
