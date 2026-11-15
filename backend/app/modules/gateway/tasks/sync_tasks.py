# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Sync Tasks
====================================

Periodic Celery tasks that refresh the imported-cache tables from gateway
devices: brain gateways, and every sync-enabled gateway on its own interval.
"""

import asyncio
import hashlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal

logger = logging.getLogger(__name__)


# ── Async helpers ────────────────────────────────────────────────────────


async def _sync_gateway(gateway_id: str) -> dict[str, Any]:
    """Sync a single gateway device."""
    from app.modules.gateway.services.sync_service import SyncService

    async with AsyncSessionLocal() as session:
        svc = SyncService(session)
        result = await svc.sync_gateway(UUID(gateway_id))
        await session.commit()
        return result


#: Hard floor under any configuration: a full gateway sync is a dozen API calls.
_HARD_FLOOR_SECONDS = 300


def _effective_interval(interval_seconds: int | None) -> int:
    """The gateway's own interval, never below the platform floor.

    The floor (GATEWAY_SYNC_MIN_INTERVAL_SECONDS, 30 min by default) is what
    makes the default gentle: every gateway created so far carries the old
    implicit 300 s, and the 2026-11 soak showed a 5-minute full sync is too
    much for a struggling OPNsense.
    """
    from app.core.config import settings

    floor = max(_HARD_FLOOR_SECONDS, int(settings.GATEWAY_SYNC_MIN_INTERVAL_SECONDS))
    return max(int(interval_seconds or floor), floor)


def _jitter_seconds(gateway_id: Any, interval: int) -> int:
    """A stable per-gateway offset (0-10 % of the interval).

    Gateways created together were all due on the same beat forever after; the
    offset spreads them out, and it is deterministic so a gateway does not
    wander.
    """
    if gateway_id is None:
        return 0
    digest = hashlib.sha256(str(gateway_id).encode()).digest()
    return int(interval * 0.10 * (digest[0] / 255))


def _due(
    last_sync_at: datetime | None,
    interval_seconds: int | None,
    now: datetime,
    gateway_id: Any = None,
) -> bool:
    """Is a gateway's own sync interval up? 30 s of slack absorbs beat jitter."""
    if last_sync_at is None:
        return True
    interval = _effective_interval(interval_seconds)
    interval += _jitter_seconds(gateway_id, interval)
    return now - last_sync_at >= timedelta(seconds=interval - 30)


async def _sync_all_brain_gateways() -> dict[str, Any]:
    """Sync every sync-enabled gateway that is due on its own interval, brains
    included.

    This used to select only gateways assigned the BRAIN role in a site role map.
    A gateway added from the Gateways page without a role was synced once, when it
    was created, and never again, although it carried ``sync_enabled=true`` and a
    300 s interval, so its rules, NAT, tunnels, interfaces and DHCP leases froze.
    Found on the 2026-11 soak VM with the office OPNsense. Sync is read-only
    (``SyncService.sync_gateway`` makes only ``get_*`` adapter calls and upserts
    locally), so honouring the gateway's own switch and interval is safe.

    Brains used to be synced on EVERY 5-minute beat regardless of interval. A
    brain is the site's production firewall, the box that most needs a gentle
    neighbour, so it now follows the same interval and floor as any gateway.
    """
    from app.modules.firewall.models import GatewayConnection
    from app.modules.gateway.services.sync_service import SyncService
    from app.modules.poll_gate import module_not_disabled

    async with AsyncSessionLocal() as session:
        now = datetime.now(UTC)
        enabled = await session.execute(
            select(
                GatewayConnection.id,
                GatewayConnection.last_sync_at,
                GatewayConnection.sync_interval_seconds,
            ).where(
                GatewayConnection.sync_enabled.is_(True),
                GatewayConnection.deleted_at.is_(None),
                # Disabling the Firewall module stops its polling.
                module_not_disabled(GatewayConnection.org_id, "firewall"),
            )
        )
        due_ids = {gid for gid, last, interval in enabled.all() if _due(last, interval, now, gid)}

        gateway_ids = sorted(due_ids, key=str)
        if not gateway_ids:
            return {
                "success": True,
                "message": "No gateway is due for sync",
                "synced": 0,
            }

        svc = SyncService(session)
        results = []
        for gw_id in gateway_ids:
            gate, probes = _breaker_gate(gw_id)
            if gate is not None:
                results.append({"gateway_id": str(gw_id), "status": "skipped", "reason": gate})
                await _record_skip(session, gw_id, gate)
                continue
            try:
                r = await svc.sync_gateway(gw_id)
                results.append({"gateway_id": str(gw_id), **r})
                if r.get("status") == "skipped":
                    # Another poller held the device (its slot): nothing was
                    # sent, so nothing is learned about it. Give back any
                    # half-open probe lease so the next cycle can probe.
                    for release in probes:
                        release()
                    await _record_skip(session, gw_id, str(r.get("reason") or "skipped"))
                else:
                    _breaker_record(gw_id, r)
            except Exception:
                logger.exception("Sync failed for gateway %s", gw_id)
                results.append({"gateway_id": str(gw_id), "status": "failed", "error": "exception"})
                # Leave the session usable for the next gateway.
                await session.rollback()

        await session.commit()

        ok = [r for r in results if r.get("status") == "success"]
        failed = [r for r in results if r.get("status") == "failed"]
        skipped = [r for r in results if r.get("status") == "skipped"]

        return {
            "success": True,
            "total": len(gateway_ids),
            "synced": len(ok),
            "failed": len(failed),
            "skipped": len(skipped),
            "details": results,
        }


def _breaker_gate(gw_id: Any) -> tuple[str | None, list[Any]]:
    """Why this gateway must not be synced now (None to go ahead), and how to
    give back the half-open probe leases this check took.

    The per-device breakers are shared by every worker (Redis), so a firewall
    that stopped answering one cycle is not handed the next one regardless of
    which process runs it. The sync breaker is checked first so a denial costs
    no reachability probe lease.
    """
    from app.core.device_breaker import (
        gateway_breaker,
        gateway_key,
        gateway_sync_breaker,
        gateway_sync_key,
    )

    probes: list[Any] = []
    sync_gate = gateway_sync_breaker.check(gateway_sync_key(gw_id))
    if not sync_gate.allowed:
        return "Full sync backed off: " + sync_gate.skip_message(), probes
    if sync_gate.probe:
        probes.append(lambda: gateway_sync_breaker.release_probe(gateway_sync_key(gw_id)))
    reach = gateway_breaker.check(gateway_key(gw_id))
    if not reach.allowed:
        for release in probes:
            release()
        return reach.skip_message(), []
    if reach.probe:
        probes.append(lambda: gateway_breaker.release_probe(gateway_key(gw_id)))
    return None, probes


def _breaker_record(gw_id: Any, result: dict[str, Any]) -> None:
    from app.core.device_breaker import (
        gateway_breaker,
        gateway_key,
        gateway_sync_breaker,
        gateway_sync_key,
    )

    status = result.get("status")
    if status == "success":
        gateway_sync_breaker.record_success(gateway_sync_key(gw_id))
        gateway_breaker.record_success(gateway_key(gw_id))
    elif result.get("device_failure"):
        error = str(result.get("error") or "")
        gateway_sync_breaker.record_failure(gateway_sync_key(gw_id), error)
        if error.startswith("connect:"):
            gateway_breaker.record_failure(gateway_key(gw_id), error)
        else:
            # It answered the connect probe, so it is reachable.
            gateway_breaker.record_success(gateway_key(gw_id))


async def _record_skip(session: Any, gw_id: Any, reason: str) -> None:
    """Show WHY the gateway was not synced, in one short transaction."""
    from sqlalchemy import update

    from app.modules.firewall.models import GatewayConnection

    try:
        await session.execute(
            update(GatewayConnection)
            .where(GatewayConnection.id == gw_id, GatewayConnection.deleted_at.is_(None))
            .values(last_sync_error=reason[:500])
        )
        await session.commit()
    except Exception:
        logger.debug("could not record the breaker skip for %s", gw_id, exc_info=True)
        await session.rollback()


# ── Celery tasks ─────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=2,
    name="gateway.sync_gateway",
    soft_time_limit=300,
    time_limit=360,
)
def sync_gateway(self, gateway_id: str) -> dict[str, Any]:
    """Sync imported data from a single gateway device."""
    try:
        return asyncio.run(_sync_gateway(gateway_id))
    except Exception as exc:
        logger.exception("sync_gateway failed for %s", gateway_id)
        self.retry(exc=exc, countdown=30)


@celery_app.task(
    name="gateway.sync_all_gateways",
    soft_time_limit=600,
    time_limit=660,
)
def sync_all_gateways() -> dict[str, Any]:
    """Periodic: sync every due gateway (brains, and sync-enabled gateways).

    Uses a solo-lock so a slow run (each gateway is synced serially
    and the task may run up to its 11-minute hard limit on a 5-minute beat)
    cannot overlap a fresh run across workers — overlap would otherwise
    double the device load and re-run the delete-then-insert replace on
    the imported cache tables.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    lock_token = acquire_solo_lock("gateway.sync_all_gateways", ttl_seconds=660)
    if not lock_token:
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_sync_all_brain_gateways())
    except Exception:
        logger.exception("sync_all_gateways failed")
        return {"success": False, "error": "see logs"}
    finally:
        release_solo_lock("gateway.sync_all_gateways", lock_token)
