# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — the Negotiator (Connection runtime).

The Negotiator is the bridge: it watches the event bus and, when a source event
matches an operator-authored **Connection**, runs that Connection's step chain —
flowing the trigger payload and prior-step outputs/artifacts into each step via
safe templating, and invoking each step's Operation through the tier-aware
:class:`OperationExecutor`.

Enterprise-grade safety, enforced here + in the executor:
  * **Fail-closed org-scoping** — a Connection only fires on events of its own
    organization.
  * **Authoring authority** — a Connection executes with its *author's*
    permissions; before each step the author must hold the step Operation's
    ``permission`` (a plugin can never borrow native authority, because a plugin
    cannot author a Connection — only operators do, through the API).
  * **Cross-tier matrix** — native writes are STAGED (executor), plugin
    operations run sandboxed/bounded (executor), plugin writes are refused.
  * **Untrusted plugin input** — a plugin-sourced event is just data; it is
    matched/conditioned/templated like any event and only ever feeds an
    operation the operator-author is permitted to invoke.

This phase uses an in-memory Connection store + direct ``handle_event`` so the
engine + the camera→storage-style verticals can be proven end-to-end; DB-backed
persistence, the CRUD API, and live bus subscription land in the next increment.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.core.fabric.execution import OperationContext
from app.core.fabric.operations import OperationTier
from app.core.fabric.templating import resolve_template

if TYPE_CHECKING:
    from app.core.fabric.executor import OperationExecutor
    from app.core.fabric.registry import FabricRegistry

logger = logging.getLogger(__name__)

# Sentinel for "Redis not yet probed" (distinct from None = "probed, unavailable").
_REDIS_UNSET: Any = object()

#: ``(actor_id, permission, organization_id) -> bool`` — does the Connection
#: author hold this permission? Injected so the engine stays decoupled from RBAC.
PermissionChecker = Callable[["UUID | None", "str | None", UUID], Awaitable[bool]]


@dataclass
class ConnectionStep:
    """One step in a Connection: invoke an Operation with (templated) params."""

    operation_id: str
    params: dict[str, Any] = field(default_factory=dict)
    continue_on_error: bool = True


@dataclass
class Connection:
    """An operator-authored wire: source event → conditions → step chain."""

    id: str
    organization_id: UUID
    name: str
    source_event: str  # event pattern: exact, ``a.b.*`` (one segment), ``a.b.#`` (any), or ``*``
    steps: list[ConnectionStep]
    enabled: bool = True
    conditions: dict[str, Any] | None = None  # ConditionGroup.from_dict shape
    actor_id: UUID | None = None  # authoring operator (permission + staging identity)
    cooldown_seconds: int = 0  # min seconds between fires (loop/flood guard; 0 = none)


def _event_matches(event_type: str, pattern: str) -> bool:
    """Match an event type against a Connection source pattern (bus semantics)."""
    if pattern in ("*", event_type):
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        if event_type.startswith(prefix + "."):
            return "." not in event_type[len(prefix) + 1 :]
        return False
    if pattern.endswith(".#"):
        prefix = pattern[:-2]
        return event_type == prefix or event_type.startswith(prefix + ".")
    return False


class Negotiator:
    """Matches events to Connections and runs their step chains."""

    def __init__(
        self,
        registry: FabricRegistry | None = None,
        executor: OperationExecutor | None = None,
        *,
        permission_checker: PermissionChecker | None = None,
        session_factory: Callable[[], Any] | None = None,
        run_recorder: Callable[..., Any] | None = None,
    ) -> None:
        if registry is None:
            from app.core.fabric.registry import fabric_registry

            registry = fabric_registry
        if executor is None:
            from app.core.fabric.executor import operation_executor

            executor = operation_executor
        self._registry = registry
        self._executor = executor
        self._permission_checker = permission_checker
        self._session_factory = session_factory
        # ``async (conn, run, event_type, payload) -> None`` — persists a
        # ConnectionRun audit row. Best-effort: a recorder failure never affects
        # the run outcome.
        self._run_recorder = run_recorder
        self._connections: dict[str, Connection] = {}
        # connection_id -> last-fire monotonic timestamp. IN-PROCESS FALLBACK only,
        # used when Redis is unavailable (unit tests / single-instance). Under
        # multiple workers the cooldown + at-most-once guards are Redis-backed so
        # they hold cluster-wide — see _claim_event / _cooldown_ok.
        self._last_fire: dict[str, float] = {}
        # Lazily-created shared Redis client (None once we've determined Redis is
        # unavailable; the sentinel means "not yet attempted").
        self._redis: Any = _REDIS_UNSET

    # ── connection store ─────────────────────────────────────────────────

    def add_connection(self, connection: Connection) -> None:
        self._connections[connection.id] = connection

    def remove_connection(self, connection_id: str) -> None:
        self._connections.pop(connection_id, None)
        self._last_fire.pop(connection_id, None)  # bound in-process fallback growth

    def list_connections(self) -> list[Connection]:
        return list(self._connections.values())

    def would_handle(self, event: Any) -> bool:
        """Cheap, synchronous pre-check: could ANY enabled connection fire on
        ``event``? Lets the bus dispatcher skip spawning a task + opening a DB
        session for the common case of an event no Connection is wired to (no
        conditions are evaluated here — just org + source-pattern match)."""
        event_type = getattr(event, "event_type", "")
        event_org = getattr(event, "organization_id", None)
        if event_org is None or event_type == "fabric.connection.changed":
            return False
        org = str(event_org)
        return any(
            c.enabled
            and str(c.organization_id) == org
            and _event_matches(event_type, c.source_event)
            for c in self._connections.values()
        )

    def reload_connections(self, connections: list[Connection]) -> None:
        """Replace the in-memory store (used to prime/refresh from the DB)."""
        self._connections = {c.id: c for c in connections}
        # Drop cooldown timestamps for connections no longer present so the
        # in-process fallback map can't grow unboundedly across reloads.
        live = set(self._connections)
        self._last_fire = {k: v for k, v in self._last_fire.items() if k in live}

    def configure_runtime(
        self,
        *,
        permission_checker: PermissionChecker | None = None,
        session_factory: Callable[[], Any] | None = None,
        run_recorder: Callable[..., Any] | None = None,
    ) -> None:
        """Wire live-runtime collaborators at boot (RBAC, DB session, audit)."""
        if permission_checker is not None:
            self._permission_checker = permission_checker
        if session_factory is not None:
            self._session_factory = session_factory
        if run_recorder is not None:
            self._run_recorder = run_recorder

    # ── permission gate ──────────────────────────────────────────────────

    async def _check_permission(self, op: Any, actor_id: UUID | None, org_id: UUID) -> bool:
        """Does the Connection author hold the authority to invoke ``op``?

        Fail-closed for the untrusted plugin tier and for device writes: a
        ``None`` permission is acceptable ONLY for a native, non-write sink
        (e.g. ``fabric.notify``). Everything else requires a checker that
        affirmatively grants the permission; a missing or raising checker denies.
        """
        if op.permission is None:
            if op.tier is OperationTier.NATIVE and not op.write:
                return True
            logger.warning(
                "Fabric: denying %s operation %s with no declared permission (fail-closed)",
                op.tier,
                op.id,
            )
            return False
        if self._permission_checker is None:
            logger.warning("Fabric: no permission checker configured; denying %r", op.permission)
            return False
        try:
            return bool(await self._permission_checker(actor_id, op.permission, org_id))
        except Exception:
            # A checker error must DENY, never crash the run (fail-closed).
            logger.exception("Fabric: permission checker raised; denying %r", op.permission)
            return False

    # ── cluster-wide guards (Redis) ──────────────────────────────────────

    async def _get_redis(self) -> Any:
        """Lazily return a shared Redis client, or None if unavailable.

        None (after probing) makes the at-most-once + cooldown guards fail-OPEN —
        i.e. fall back to single-instance behavior — so the engine stays usable
        in unit tests / a Redis-less single process.
        """
        if self._redis is _REDIS_UNSET:
            self._redis = None
            try:
                from app.core.config import settings

                if settings.REDIS_URL:
                    from app.core.redis_client import get_async_redis

                    self._redis = get_async_redis(
                        decode_responses=True,
                        # Fail fast instead of hanging the request coroutine on a
                        # black-holed/restarting Redis (matches the event-bus client).
                        socket_connect_timeout=5,
                        socket_timeout=5,
                    )
            except Exception:
                logger.debug("Fabric: Redis unavailable; cluster guards fail-open", exc_info=True)
                self._redis = None
        return self._redis

    async def _claim_event(self, conn: Connection, event: Any) -> bool:
        """At-most-once per (connection, event) across all workers (Redis SET NX).

        Returns True if THIS worker should run the connection for this event.
        Fail-open (True) when there is no event id or Redis is unavailable.
        """
        event_id = getattr(event, "id", None)
        if not event_id:
            return True
        r = await self._get_redis()
        if r is None:
            return True
        try:
            acquired = await r.set(f"fabric:fired:{conn.id}:{event_id}", "1", nx=True, ex=300)
            return bool(acquired)
        except Exception:
            logger.warning("Fabric: idempotency check failed for %s (proceeding)", conn.id)
            return True

    async def _cooldown_ok(self, conn: Connection) -> bool:
        """Cluster-wide cooldown via Redis SET NX EX; in-process fallback otherwise.

        Returns True if the connection may fire now (and starts a new cooldown
        window), False if it is still cooling down.
        """
        r = await self._get_redis()
        if r is not None:
            try:
                acquired = await r.set(
                    f"fabric:cooldown:{conn.id}", "1", nx=True, ex=int(conn.cooldown_seconds)
                )
                return bool(acquired)
            except Exception:
                logger.warning("Fabric: cooldown check failed for %s (in-process)", conn.id)
        last = self._last_fire.get(conn.id)
        now = time.monotonic()
        if last is not None and (now - last) < conn.cooldown_seconds:
            return False
        self._last_fire[conn.id] = now
        return True

    # ── event handling ───────────────────────────────────────────────────

    async def handle_event(self, event: Any) -> list[dict[str, Any]]:
        """Run every enabled Connection whose org + source pattern + conditions
        match ``event``. Returns one run-record per fired Connection."""
        runs: list[dict[str, Any]] = []
        event_type = getattr(event, "event_type", "")
        event_org = getattr(event, "organization_id", None)
        payload = getattr(event, "payload", {}) or {}

        # The internal CRUD-propagation control event is fanned to this "*"
        # subscriber too, but it is NOT a user trigger (runtime.handle_connection_
        # changed handles it). Never let a Connection fire on it — even one an
        # operator wired to "*" / "fabric.#" — to avoid spurious runs.
        if event_type == "fabric.connection.changed":
            return runs

        for conn in self._connections.values():
            if not conn.enabled:
                continue
            # Fail-closed org scoping: never cross tenants.
            if event_org is None or str(event_org) != str(conn.organization_id):
                continue
            if not _event_matches(event_type, conn.source_event):
                continue
            if conn.conditions:
                try:
                    from app.services.automation import ConditionGroup

                    if not ConditionGroup.from_dict(conn.conditions).evaluate(payload):
                        continue
                except Exception:
                    logger.exception("Fabric: bad conditions on connection %s", conn.id)
                    continue
            # At-most-once across workers. Under multiple gunicorn workers the
            # same bus event fans out (Redis pub/sub) to EVERY worker's negotiator;
            # without a cluster-wide guard each worker would independently run the
            # chain — duplicate staged writes / webhooks / notifications. A Redis
            # SET NX per (connection, event) lets exactly ONE worker proceed
            # (mirrors the automation engine). Fail-open if Redis is unavailable.
            if not await self._claim_event(conn, event):
                continue
            # Cooldown guard: bound self-amplifying loops (e.g. a connection wired
            # ingest.external → fabric.webhook whose external target posts back to
            # /fabric/ingest) and flood. Cluster-wide via Redis when available,
            # else in-process.
            if conn.cooldown_seconds and conn.cooldown_seconds > 0:
                if not await self._cooldown_ok(conn):
                    continue
            # Fault isolation: one Connection's failure must never abort the
            # processing of the others matching this event (mirrors the
            # per-module/per-plugin isolation in the registry + the executor's
            # never-raise contract).
            try:
                run = await self._run(conn, payload)
            except Exception:
                logger.exception("Fabric: connection %s run crashed", conn.id)
                runs.append({"connection_id": conn.id, "success": False, "error": "run failed"})
                continue
            runs.append(run)
            # Best-effort audit: persisting a run must never affect the outcome.
            if self._run_recorder is not None:
                try:
                    await self._run_recorder(conn, run, event_type, payload)
                except Exception:
                    logger.exception("Fabric: run_recorder failed for connection %s", conn.id)
        return runs

    async def run_once(self, conn: Connection, trigger_payload: dict[str, Any]) -> dict[str, Any]:
        """Run a single Connection's chain once with an explicit payload.

        Operator-initiated test entry: bypasses event matching/org-routing (the
        caller has already authorized + scoped this Connection) but applies the
        SAME per-step permission + staging gates as a live firing. Never raises.
        """
        try:
            return await self._run(conn, trigger_payload or {})
        except Exception:
            logger.exception("Fabric: test run of connection %s crashed", conn.id)
            return {"connection_id": conn.id, "success": False, "error": "run failed", "steps": []}

    async def _run(self, conn: Connection, trigger_payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a Connection's step chain with data + artifact threading."""
        t0 = time.monotonic()
        context: dict[str, Any] = {"trigger": trigger_payload, "steps": []}
        input_artifact = None
        run: dict[str, Any] = {"connection_id": conn.id, "success": True, "steps": []}

        # A DB session for steps that need one (native writes via staging,
        # fabric.notify). Opened once per run; None if no factory configured.
        factory = self._session_factory
        if factory is None:
            with contextlib.suppress(Exception):
                from app.db.session import async_session_factory as factory  # type: ignore

        session_cm = factory() if factory else None
        db = None
        try:
            if session_cm is not None:
                try:
                    db = await session_cm.__aenter__()
                except Exception:
                    # A DB-acquire failure degrades to db=None (steps then
                    # fail-closed with NO_DB) rather than crashing the run.
                    logger.exception("Fabric: connection %s could not open a DB session", conn.id)
                    db = None
                    session_cm = None
            for step in conn.steps:
                try:
                    step_rec = await self._run_step(conn, step, context, input_artifact, db)
                except Exception:
                    logger.exception(
                        "Fabric: connection %s step %s crashed", conn.id, step.operation_id
                    )
                    step_rec = {
                        "operation_id": step.operation_id,
                        "success": False,
                        "error": "step crashed",
                        "error_code": "STEP_ERROR",
                    }
                run["steps"].append(step_rec)
                # thread a produced artifact into the next step's input
                if step_rec.get("artifact"):
                    from app.core.fabric.execution import ArtifactRef

                    a = step_rec["artifact"]
                    input_artifact = ArtifactRef(
                        handle=a["handle"],
                        media_type=a["media_type"],
                        size=a["size"],
                        sha256=a["sha256"],
                    )
                if not step_rec["success"]:
                    run["success"] = False
                    if not step.continue_on_error:
                        break
            # Commit any rows steps flushed but did not commit themselves — e.g.
            # fabric.notify's NotificationDelivery audit records. The raw
            # sessionmaker session otherwise closes WITHOUT committing in the
            # finally below (implicit rollback). Staged writes already committed
            # their own change rows via AdapterStagingService, so this is additive.
            if db is not None:
                with contextlib.suppress(Exception):
                    await db.commit()
        finally:
            if session_cm is not None:
                with contextlib.suppress(Exception):
                    await session_cm.__aexit__(None, None, None)
        run["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return run

    async def _run_step(
        self,
        conn: Connection,
        step: ConnectionStep,
        context: dict[str, Any],
        input_artifact: Any,
        db: Any,
    ) -> dict[str, Any]:
        op = self._registry.get_operation(step.operation_id)
        if op is None:
            return {
                "operation_id": step.operation_id,
                "success": False,
                "error": "unknown operation",
            }

        allowed = await self._check_permission(op, conn.actor_id, conn.organization_id)
        if not allowed:
            return {
                "operation_id": op.id,
                "success": False,
                "error": f"permission denied: {op.permission}",
                "error_code": "PERMISSION_DENIED",
            }

        resolved = resolve_template(step.params, context)
        ctx = OperationContext(
            organization_id=conn.organization_id,
            params=resolved if isinstance(resolved, dict) else {},
            trigger=context.get("trigger", {}),
            actor_id=conn.actor_id,
            db=db,
            artifacts=self._executor._artifacts,
            input_artifact=input_artifact,
            logger=logger,
        )
        result = await self._executor.execute(op, ctx)
        # Record into the templating context for downstream steps.
        artifact_dict = result.artifact.to_dict() if result.artifact else None
        context["steps"].append(
            {"output": result.output, "artifact": artifact_dict, "success": result.success}
        )
        return {
            "operation_id": op.id,
            "success": result.success,
            "error": result.error,
            "error_code": result.error_code,
            "staged_change_id": result.staged_change_id,
            "artifact": artifact_dict,
        }


# Module-level singleton (DB-backed store + bus subscription wired in the next phase).
negotiator = Negotiator()
