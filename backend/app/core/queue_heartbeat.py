# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - one heartbeat per Celery queue
========================================

There was one worker heartbeat (``worker.heartbeat``, routed to ``default``)
for two worker tiers. In pro and max the I/O worker owns ``discovery``,
``sync`` and ``metrics``: every device poller. It had no heartbeat, so a
wedged or stopped I/O worker stopped all polling while /health stayed green.

Now:

* every worker registers the queues it consumes when it starts
  (``worker_ready``) and refreshes that registration from its event
  heartbeat (``heartbeat_sent``, every 2 s; written at most every 30 s);
* beat runs ``worker.dispatch_queue_heartbeats`` every 30 s, which sends a tiny
  ``worker.queue_heartbeat`` task to each queue some worker on this install
  consumes or consumed within the last 7 days;
* that task records when it RAN on that queue. A queue whose heartbeat is
  older than ``CELERY_QUEUE_STALE_SECONDS`` is stalled: its worker is down,
  wedged, or every slot is stuck on long tasks.

A queue no worker of this install has consumed in 7 days is ``not_consumed``,
not stalled: a tier that does not run a queue is not degraded by it, and no
heartbeat is sent there to pile up unread. Unless tasks are waiting in it:
then nothing will ever run them, and that is reported as stalled.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

HEARTBEAT_PREFIX = "freesdn:celery:queue:heartbeat:"
CONSUMER_PREFIX = "freesdn:celery:consumer:"
#: A registration (and a heartbeat stamp) outlives a dead worker by this long.
REGISTRATION_TTL = 7 * 86400
#: A worker that refreshed its registration within this window is live.
LIVE_CONSUMER_SECONDS = 120
#: How often a worker rewrites its registration.
_REFRESH_SECONDS = 30.0

OK = "ok"
STALLED = "stalled"
STARTING = "starting"
NOT_CONSUMED = "not_consumed"

_worker: dict[str, Any] = {"hostname": None, "queues": [], "since": None, "written": 0.0}


def _redis() -> Any:
    from app.core.celery_app import _get_solo_redis

    return _get_solo_redis()


def _stale_seconds() -> float:
    from app.core.config import settings

    return float(settings.CELERY_QUEUE_STALE_SECONDS)


# ── worker side ─────────────────────────────────────────────────────────


def consumer_queues(consumer: Any) -> list[str]:
    """The queue names a worker's consumer is subscribed to."""
    names: list[str] = []
    task_consumer = getattr(consumer, "task_consumer", None)
    for queue in getattr(task_consumer, "queues", None) or []:
        name = getattr(queue, "name", None)
        if name:
            names.append(str(name))
    if not names:
        app = getattr(consumer, "app", None)
        selected = getattr(
            getattr(getattr(app, "amqp", None), "queues", None), "consume_from", None
        )
        names = [str(n) for n in (selected or {})]
    return sorted(set(names))


def register_consumer(hostname: str, queues: list[str], *, client: Any = None) -> None:
    """Record that ``hostname`` consumes ``queues`` (refreshes the TTL)."""
    now = time.time()
    if _worker["hostname"] != hostname:
        _worker.update(hostname=hostname, since=now)
    _worker["queues"] = list(queues)
    record = {"hostname": hostname, "queues": list(queues), "since": _worker["since"], "seen": now}
    (client or _redis()).set(CONSUMER_PREFIX + hostname, json.dumps(record), ex=REGISTRATION_TTL)
    _worker["written"] = now


def refresh_registration() -> None:
    """From the worker's event heartbeat; writes at most every 30 s."""
    if not _worker["hostname"] or time.time() - _worker["written"] < _REFRESH_SECONDS:
        return
    try:
        register_consumer(_worker["hostname"], _worker["queues"])
    except Exception:  # noqa: BLE001 - the heartbeat must never stop the worker
        _worker["written"] = time.time()
        logger.debug("queue consumer registration refresh failed", exc_info=True)


def unregister_consumer(hostname: str | None) -> None:
    if not hostname:
        return
    try:
        _redis().delete(CONSUMER_PREFIX + hostname)
    except Exception:  # noqa: BLE001
        logger.debug("queue consumer unregistration failed", exc_info=True)


def record_heartbeat(queue: str, *, client: Any = None) -> None:
    """The heartbeat task ran on ``queue`` just now."""
    (client or _redis()).set(HEARTBEAT_PREFIX + queue, repr(time.time()), ex=REGISTRATION_TTL)


# ── reader side (/health/detail, /metrics, the dispatcher) ──────────────


def _registrations(client: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in client.scan_iter(match=CONSUMER_PREFIX + "*", count=100):
        raw = client.get(key)
        try:
            record = json.loads(raw) if raw else None
        except (TypeError, ValueError):
            record = None
        if isinstance(record, dict) and isinstance(record.get("queues"), list):
            out.append(record)
    return out


def consumed_queues(*, client: Any = None) -> set[str]:
    """Queues some worker of this install consumes or consumed in the last 7 days."""
    client = client or _redis()
    return {str(q) for record in _registrations(client) for q in record["queues"]}


def queue_status(
    *, client: Any = None, depths: dict[str, int] | None = None, now: float | None = None
) -> dict[str, dict[str, Any]]:
    """Per declared queue: state, heartbeat age, live consumers, depth."""
    from app.core.celery_app import task_queues

    client = client or _redis()
    now = time.time() if now is None else now
    stale = _stale_seconds()
    if depths is None:
        try:
            from app.core.metrics import celery_queue_lengths

            depths = celery_queue_lengths()
        except Exception:  # noqa: BLE001 - depth is informative, the heartbeat decides
            depths = {}
    regs = _registrations(client)
    out: dict[str, dict[str, Any]] = {}
    for queue in (q.name for q in task_queues):
        known = [r for r in regs if queue in r["queues"]]
        live = [r for r in known if now - float(r.get("seen") or 0) <= LIVE_CONSUMER_SECONDS]
        raw = client.get(HEARTBEAT_PREFIX + queue)
        try:
            last = float(raw) if raw else None
        except (TypeError, ValueError):
            last = None
        age = None if last is None else max(0.0, now - last)
        depth = int(depths.get(queue, 0) or 0)
        if age is not None and age <= stale:
            state = OK
        elif not known and depth == 0:
            state = NOT_CONSUMED
        elif (
            live
            and (last is None or age is None or age > stale)
            and min(now - float(r.get("since") or now) for r in live) <= stale
        ):
            state = STARTING  # a worker came up moments ago; give it one interval
        else:
            state = STALLED
        out[queue] = {
            "state": state,
            "last_heartbeat_age_seconds": None if age is None else round(age, 1),
            "consumers": len(live),
            "depth": depth,
        }
    return out
