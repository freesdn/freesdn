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
    """Cancel background Fabric tasks (artifact sweep + in-flight chains) at shutdown."""
    global _sweep_task
    task = _sweep_task
    _sweep_task = None
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    # Cancel any detached Connection-chain tasks still running.
    for chain in list(_chain_tasks):
        chain.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await chain
    _chain_tasks.clear()


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


# In-flight Connection-chain tasks, kept referenced so the event loop can't GC a
# detached task mid-run (asyncio holds only a weak reference to bare tasks).
_chain_tasks: set[asyncio.Task[Any]] = set()
# Bound concurrent chain EXECUTION (each chain opens a DB session) so an event
# burst can't saturate the connection pool. Tasks beyond the limit park on the
# semaphore before opening any session — cheap.
_MAX_CONCURRENT_CHAINS = 16
_chain_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CHAINS)


def _on_chain_done(task: asyncio.Task[Any]) -> None:
    _chain_tasks.discard(task)
    if not task.cancelled():
        exc = task.exception()
        if exc is not None:
            logger.error("Fabric: connection-chain task crashed", exc_info=exc)


async def _dispatch_connections(event: Any) -> None:
    """Bus subscriber that runs matching Connections in a DETACHED, bounded task.

    The bus wraps every subscriber in a 10s ``wait_for``; a multi-step Connection
    chain (slow ops, staged writes) can exceed that and be cancelled mid-chain —
    leaving partial side-effects and no run record. Detaching the work lets this
    subscriber return immediately while the chain runs to completion under the
    negotiator's own per-step fault isolation + run recorder.

    Two guards keep a high-volume bus ('*' fan-out) from exhausting the DB pool:
    a cheap ``would_handle`` pre-filter skips events no Connection is wired to
    (the common case — no task, no session), and ``_chain_semaphore`` caps
    concurrent chain execution.
    """
    from app.core.fabric.negotiator import negotiator

    if not negotiator.would_handle(event):
        return

    async def _run() -> None:
        async with _chain_semaphore:
            await negotiator.handle_event(event)

    task = asyncio.create_task(_run())
    _chain_tasks.add(task)
    task.add_done_callback(_on_chain_done)


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
