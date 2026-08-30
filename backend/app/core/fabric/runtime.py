# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — live-runtime wiring (boot composition).

Connects the (decoupled) Negotiator to the running platform: the RBAC
permission-checker, a DB session factory, the ConnectionRun audit recorder, the
persisted Connection store, and the event bus. Kept out of the engine modules so
the engine stays unit-testable, and out of ``main.py`` so the composition is
itself testable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

# ── transient-artifact sweep ───────────────────────────────────────────────
# The transient ArtifactBroker holds cross-step handoff blobs under a short TTL.
# Expired blobs are dropped lazily on get(), but a chain that fails before its
# consuming step leaves orphans behind, so without a sweep the broker dir grows
# unbounded. This periodic task reclaims them. It runs IN THE API PROCESS (where
# the negotiator + broker live and write their files) — a Celery worker is a
# separate container with its own filesystem and could not see them, which is why
# this is an asyncio task here rather than a Celery beat job.
_ARTIFACT_SWEEP_INTERVAL_SECONDS = 900  # 15 minutes
_sweep_task: asyncio.Task[None] | None = None


async def _artifact_sweep_loop() -> None:
    """Sweep expired transient artifacts on a fixed interval until cancelled.

    Multi-worker note: each gunicorn worker process runs its own loop over the
    shared artifact dir. That is safe — ``cleanup_expired`` only unlinks already
    -expired files with ``missing_ok=True`` and swallows per-file errors, so two
    workers racing on the same expired file is benign (idempotent). The only cost
    is a little duplicated globbing every 15 min, which is negligible.
    """
    from app.core.fabric.artifact_broker import artifact_broker

    while True:
        try:
            await asyncio.sleep(_ARTIFACT_SWEEP_INTERVAL_SECONDS)
            removed = await artifact_broker.cleanup_expired()
            if removed:
                logger.info("Fabric: swept %d expired transient artifact(s)", removed)
            # Belt-and-suspenders for Connection CRUD propagation: real-time sync
            # rides the fabric.connection.changed bus event, but a missed control
            # event (a worker briefly down, a Redis blip) would leave this worker's
            # negotiator stale. A periodic re-prime from the DB self-heals it.
            try:
                await prime_negotiator()
            except Exception:
                logger.exception("Fabric: periodic negotiator re-prime failed (will retry)")
        except asyncio.CancelledError:
            raise
        except Exception:
            # A sweep failure must never kill the loop — log and retry next tick.
            logger.exception("Fabric: transient artifact sweep failed (will retry)")


def _start_artifact_sweep() -> None:
    """Start the periodic sweep (idempotent — a no-op if already running)."""
    global _sweep_task
    if _sweep_task is None or _sweep_task.done():
        _sweep_task = asyncio.create_task(_artifact_sweep_loop(), name="fabric-artifact-sweep")


async def stop_fabric_runtime() -> None:
    """Cancel background Fabric tasks (artifact sweep + chain workers) at shutdown."""
    global _sweep_task, _chain_queue, _chain_loop
    task = _sweep_task
    _sweep_task = None
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    # Tear down the Connection-chain worker pool and drop its backlog.
    for worker in list(_chain_workers):
        with contextlib.suppress(Exception):
            worker.cancel()
    for worker in list(_chain_workers):
        # A worker from an already-closed loop cannot be awaited: suppress and move on.
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await worker
    _chain_workers.clear()
    _chain_queue = None
    _chain_loop = None


async def fabric_permission_checker(actor_id: UUID | None, permission: str, org_id: UUID) -> bool:
    """Re-resolve a Connection author's current permissions and check ``permission``.

    Fail-closed: a missing/inactive author, a cross-org author, or any error
    denies. Reuses the platform's role→permission resolver so the Fabric gate
    matches the rest of the RBAC system exactly.
    """
    if actor_id is None:
        return False
    try:
        from sqlalchemy import select

        from app.core.dependencies import CurrentUser, _load_user_permissions
        from app.db.session import async_session_factory
        from app.models.core import User

        async with async_session_factory() as db:
            user = (await db.execute(select(User).where(User.id == actor_id))).scalar_one_or_none()
            if user is None or not getattr(user, "is_active", False):
                return False
            # The author must still belong to the Connection's org.
            if user.organization_id != org_id:
                return False
            perms = await _load_user_permissions(user)
            return CurrentUser(user, perms).has_permission(permission)
    except Exception:
        logger.exception("Fabric: permission check failed for %r; denying", permission)
        return False


async def fabric_run_recorder(
    conn: Any, run: dict[str, Any], event_type: str, payload: dict[str, Any]
) -> None:
    """Persist a ConnectionRun audit row (best-effort; own session/transaction)."""
    from app.db.session import async_session_factory
    from app.services.fabric_connections import FabricConnectionService

    async with async_session_factory() as db:
        svc = FabricConnectionService(db)
        await svc.record_run(
            organization_id=conn.organization_id,
            connection_id=UUID(str(conn.id)),
            source_event_type=event_type,
            trigger_payload=payload or {},
            run=run,
            duration_ms=int(run.get("duration_ms", 0)),
        )
        await db.commit()


async def prime_negotiator() -> int:
    """Load all enabled Connections from the DB into the live negotiator."""
    from app.core.fabric.negotiator import negotiator
    from app.db.session import async_session_factory
    from app.services.fabric_connections import FabricConnectionService

    async with async_session_factory() as db:
        svc = FabricConnectionService(db)
        conns = await svc.load_all_enabled()
        negotiator.reload_connections(
            [FabricConnectionService.to_engine_connection(c) for c in conns]
        )
    return len(negotiator.list_connections())


# ── Connection-chain dispatch: a bounded worker pool ──────────────────────
# The bus subscriber must not run a chain INLINE (the bus wraps each subscriber
# in a 10s wait_for, which would cancel a multi-step chain mid-run), so the work
# is handed off. It used to be handed off as ``asyncio.create_task`` PER EVENT,
# with a semaphore the task acquired only AFTER it existed. That capped
# concurrent EXECUTION at 16 but placed no bound on ADMISSION: a Connection
# subscribed to a high-rate event (or to the '*' firehose) retained one live
# task, coroutine frame and event object per event. Measured on the real
# dispatcher with a blocked handler: 1000 events in -> 1000 tasks retained, 16
# actually running. The old comment called the parked tasks "cheap"; at 1000:16
# they are not.
#
# So: a FIXED pool of long-lived workers draining a BOUNDED queue. Steady-state
# task count is constant (_MAX_CONCURRENT_CHAINS) no matter the event rate, and
# the backlog is capped at _CHAIN_QUEUE_MAXSIZE plain event references — no
# task, no coroutine frame, no DB session per queued event.
#
# OVERLOAD POLICY: DROP-NEWEST, COUNTED, LOGGED.
# When the backlog is full the incoming event is refused and counted rather than
# queued. Blocking the producer is not an option — back-pressure would land in
# the bus's 10s subscriber budget and stall publishing for every other
# subscriber — and growing without bound is the bug being fixed. Coalescing was
# considered and rejected: the dispatcher only knows "some Connection matches",
# not which one, so it has no key to coalesce on. A drop is therefore VISIBLE,
# never silent: it increments ``_chain_stats["dropped"]``, which
# ``dispatch_stats()`` exposes and a rate-limited WARNING reports with the
# running total.
_MAX_CONCURRENT_CHAINS = 16
# The backlog bound is set by STALENESS, not by memory: a queued entry is one
# reference to an event the bus already holds, so 512 of them cost nothing,
# but at the pessimistic drain rate of this pool a chain admitted at the tail
# of a full queue starts roughly a minute after its trigger and would act on
# stale device state. Shedding beats acting late.
_CHAIN_QUEUE_MAXSIZE = 512

_chain_queue: asyncio.Queue[Any] | None = None
_chain_workers: set[asyncio.Task[None]] = set()
# The loop the pool is bound to. asyncio primitives are not portable across
# loops, so if we ever wake up on a different one (tests, a re-entered lifespan)
# the pool is rebuilt rather than silently parking on a dead queue.
_chain_loop: asyncio.AbstractEventLoop | None = None

# admitted: accepted onto the backlog. dropped: refused, backlog full.
# handled: a worker ran the chain to completion (success OR error).
# admitted + dropped == every event that passed would_handle; once drained,
# handled == admitted. No event leaves the dispatcher uncounted.
_chain_stats: dict[str, int] = {"admitted": 0, "dropped": 0, "handled": 0}

_DROP_LOG_INTERVAL_SECONDS = 60.0
_last_drop_log = 0.0


def dispatch_stats() -> dict[str, int]:
    """Snapshot of chain-dispatch accounting (admitted / dropped / handled).

    ``dropped`` > 0 means Fabric shed load: events a Connection was wired to
    never ran a chain. That is the deliberate overload policy, and this counter
    (plus the WARNING in ``_note_chain_drop``) is how an operator sees it.
    """
    return {
        **_chain_stats,
        "queued": _chain_queue.qsize() if _chain_queue is not None else 0,
        "workers": len(_chain_workers),
        "capacity": _CHAIN_QUEUE_MAXSIZE,
    }


def _note_chain_drop(event: Any) -> None:
    """Count a shed event and report it (rate-limited, with the running total)."""
    global _last_drop_log
    _chain_stats["dropped"] += 1
    now = time.monotonic()
    if now - _last_drop_log < _DROP_LOG_INTERVAL_SECONDS:
        return
    _last_drop_log = now
    logger.warning(
        "Fabric: connection-chain backlog full (%d queued / %d workers) — DROPPING "
        "event %s; %d event(s) dropped in total. Chains are running slower than "
        "events arrive: narrow the Connection's source_event, or raise "
        "_MAX_CONCURRENT_CHAINS if the DB pool can take it.",
        _chain_queue.qsize() if _chain_queue is not None else 0,
        len(_chain_workers),
        getattr(event, "event_type", "?"),
        _chain_stats["dropped"],
    )


async def _chain_worker(queue: asyncio.Queue[Any]) -> None:
    """Long-lived drainer: run one Connection chain at a time, forever.

    Never exits on a chain failure. A worker that died on an exception would
    permanently shrink the pool, so 16 bad events would leave Fabric inert.
    """
    from app.core.fabric.negotiator import negotiator

    while True:
        event = await queue.get()
        try:
            await negotiator.handle_event(event)
            _chain_stats["handled"] += 1
        except asyncio.CancelledError:
            queue.task_done()
            raise
        except Exception:
            _chain_stats["handled"] += 1
            logger.error("Fabric: connection-chain crashed", exc_info=True)
        queue.task_done()


def _ensure_chain_workers() -> asyncio.Queue[Any]:
    """Create (or repair) the bounded queue + fixed worker pool for this loop."""
    global _chain_queue, _chain_loop
    loop = asyncio.get_running_loop()
    if _chain_queue is None or _chain_loop is not loop:
        for stale in list(_chain_workers):
            with contextlib.suppress(Exception):
                stale.cancel()
        _chain_workers.clear()
        _chain_queue = asyncio.Queue(maxsize=_CHAIN_QUEUE_MAXSIZE)
        _chain_loop = loop
    queue = _chain_queue
    for dead in [w for w in _chain_workers if w.done()]:
        _chain_workers.discard(dead)
    while len(_chain_workers) < _MAX_CONCURRENT_CHAINS:
        _chain_workers.add(asyncio.create_task(_chain_worker(queue), name="fabric-chain-worker"))
    return queue


async def _dispatch_connections(event: Any) -> None:
    """Bus subscriber that hands matching Connections to the bounded chain pool.

    Returns immediately: a chain can far exceed the bus's 10s subscriber budget,
    and being cancelled mid-chain leaves partial side-effects and no run record.

    Three guards keep a high-volume bus ('*' fan-out) from exhausting memory or
    the DB pool: a cheap ``would_handle`` pre-filter skips events no Connection
    is wired to (the common case — nothing queued, no session), the fixed pool
    caps concurrent chain EXECUTION, and the bounded queue caps ADMISSION. See
    the module comment above for the drop-newest overload policy.
    """
    from app.core.fabric.negotiator import negotiator

    if not negotiator.would_handle(event):
        return

    queue = _ensure_chain_workers()
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        _note_chain_drop(event)
        return
    _chain_stats["admitted"] += 1


async def handle_connection_changed(event: Any) -> None:
    """Re-sync ONE Connection into this worker's negotiator on a CRUD control event.

    Connection CRUD only mutates the serving worker's in-process negotiator. Under
    multiple workers + the Redis event-bus fan-out, the other workers would keep a
    stale view (a disabled/deleted wire would keep firing on them; a new wire would
    never fire). The CRUD endpoints publish ``fabric.connection.changed``; this
    handler — subscribed on every worker — reloads that single connection from the
    DB (re-checking org scope) so all workers converge within bus latency.
    """
    from uuid import UUID

    from app.core.fabric.negotiator import negotiator
    from app.db.session import async_session_factory
    from app.services.fabric_connections import FabricConnectionService

    payload = getattr(event, "payload", {}) or {}
    conn_id = payload.get("connection_id")
    org_raw = getattr(event, "organization_id", None) or payload.get("organization_id")
    if not conn_id or not org_raw:
        return
    try:
        async with async_session_factory() as db:
            svc = FabricConnectionService(db)
            conn = await svc.get(UUID(str(conn_id)), UUID(str(org_raw)))
        if conn is not None and conn.enabled:
            negotiator.add_connection(FabricConnectionService.to_engine_connection(conn))
        else:
            # Deleted, disabled, or not-in-this-org → ensure it is not live here.
            negotiator.remove_connection(str(conn_id))
    except Exception:
        logger.exception("Fabric: failed to re-sync connection %s from control event", conn_id)


async def wire_and_start() -> int:
    """Configure the negotiator's runtime collaborators, prime it from the DB,
    and subscribe it to the event bus. Returns the number of primed Connections."""
    from app.core.events import get_event_bus
    from app.core.fabric.negotiator import negotiator
    from app.db.session import async_session_factory

    negotiator.configure_runtime(
        permission_checker=fabric_permission_checker,
        session_factory=async_session_factory,
        run_recorder=fabric_run_recorder,
    )
    count = await prime_negotiator()
    bus = get_event_bus()
    # Subscribe the DETACHED dispatcher (not handle_event directly): the bus wraps
    # each subscriber in a 10s wait_for, which would cancel a long multi-step
    # Connection chain mid-run (partial side-effects, no run record). _dispatch_
    # connections returns immediately and runs the chain in its own task.
    bus.subscribe("*", _dispatch_connections)
    # Cluster-wide CRUD propagation: every worker reloads a connection when any
    # worker creates/updates/deletes it (see handle_connection_changed).
    bus.subscribe("fabric.connection.changed", handle_connection_changed)
    logger.info("Fabric negotiator subscribed to event bus (%d connection(s) primed)", count)

    # Start the periodic transient-artifact sweep + negotiator re-prime (in-process).
    _start_artifact_sweep()
    # Bring the bounded chain-worker pool up now, so its size and the backlog
    # bound are properties of boot rather than of whichever event arrives first.
    _ensure_chain_workers()

    # P3 convergence: expose every native Fabric Operation as an AI-assistant
    # tool. Runs here (boot wiring, after ALL modules have loaded) rather than in
    # AIModule.on_load, because modules load alphabetically and the op-providing
    # modules load after `ai`. Additive + idempotent + non-fatal.
    try:
        from app.core.fabric.ai_bridge import register_fabric_ops_as_ai_tools

        register_fabric_ops_as_ai_tools()
    except Exception:
        logger.exception("Fabric: AI-tool bridge registration failed (non-fatal)")

    return count
