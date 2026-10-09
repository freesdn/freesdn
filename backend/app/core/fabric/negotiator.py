# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — the Negotiator (Connection runtime).

The Negotiator is the bridge: it watches the event bus and, when a source event
matches an operator-authored **Connection**, runs that Connection's step chain —
flowing the trigger payload and prior-step outputs/artifacts into each step via
safe templating, and invoking each step's Operation through the tier-aware
:class:`OperationExecutor`.

Execution safeguards, enforced here and in the executor:
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

The runtime hydrates this worker's in-memory Connection store from the database
and subscribes it to the event bus. Shared event and cooldown claims must be
confirmed before an unattended chain can run. These expiring claims do not
provide durable delivery or exactly-once external effects.
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

# Sentinel for a shared client that has not been constructed yet.
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
        # Cache only a successfully constructed shared client. A construction
        # failure is retried on a later event, never replaced by worker memory.
        self._redis: Any = _REDIS_UNSET

    # ── connection store ─────────────────────────────────────────────────

    def add_connection(self, connection: Connection) -> None:
        self._connections[connection.id] = connection

    def remove_connection(self, connection_id: str) -> None:
        self._connections.pop(connection_id, None)

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
        """Return the shared client; retry construction on a later event if needed."""
        if self._redis is _REDIS_UNSET or self._redis is None:
            try:
                from redis.asyncio.retry import Retry
                from redis.backoff import NoBackoff

                from app.core.redis_client import get_async_redis

                self._redis = get_async_redis(
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry=Retry(NoBackoff(), 0),
                )
            except Exception:
                # Client/connection errors can contain credentials or URLs.
                logger.warning("Fabric: shared coordination client unavailable; refusing event")
                return None
        return self._redis

    async def _claim_event(self, conn: Connection, event: Any) -> bool:
        """Claim a stable event identity with shared SET NX and a 300-second TTL.

        An absent identity, unavailable client or uncertain reply cannot authorize
        unattended effects. Keep the existing key namespace so upgrading workers
        coordinate with older workers. Claims are never released after an error:
        the server may have committed the claim even if its reply was lost.
        """
        event_id = getattr(event, "id", None)
        if not event_id:
            logger.warning("Fabric: event identity unavailable; refusing connection %s", conn.id)
            return False
        try:
            r = await self._get_redis()
            if r is None:
                return False
            acquired = await r.set(f"fabric:fired:{conn.id}:{event_id}", "1", nx=True, ex=300)
            if acquired is True:
                return True
            if acquired is not None and acquired is not False:
                logger.warning(
                    "Fabric: event claim reply uncertain; refusing connection %s", conn.id
                )
        except Exception:
            logger.warning("Fabric: event claim unavailable; refusing connection %s", conn.id)
        return False

    async def _cooldown_ok(self, conn: Connection) -> bool:
        """Require an affirmative shared cooldown claim; never fall back locally."""
        try:
            r = await self._get_redis()
            if r is None:
                return False
            acquired = await r.set(
                f"fabric:cooldown:{conn.id}", "1", nx=True, ex=int(conn.cooldown_seconds)
            )
            if acquired is True:
                return True
            if acquired is not None and acquired is not False:
                logger.warning("Fabric: cooldown reply uncertain; refusing connection %s", conn.id)
        except Exception:
            logger.warning("Fabric: cooldown unavailable; refusing connection %s", conn.id)
        return False

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

        # Iterate a snapshot of the IDs and re-resolve each one, rather than the
        # live ``.values()`` view. Two separate reasons, and the second is why
        # this is an id snapshot and not ``list(self._connections.values())``:
        #
        # 1. CRASH. The body below awaits four times (:_claim_event, _cooldown_ok,
        #    _run, _run_recorder), and _run alone holds the loop for a DB session
        #    plus adapter HTTP. Every mutator -- runtime.handle_connection_changed
        #    and the fabric endpoints' _sync_engine / delete_connection -- runs on
        #    this same event loop with no lock, so a create or delete landing in
        #    one of those windows made the FOR statement itself raise
        #    "RuntimeError: dictionary changed size during iteration". That is
        #    raised by the iterator, not the body, so the per-connection
        #    try/except below could never catch it: the whole fan-out died and
        #    every remaining matching Connection silently lost the event, while
        #    dispatch_stats still reported it handled.
        #
        # 2. DELETE SEMANTICS. A values() snapshot freezes the set when the event
        #    arrives, so a Connection the operator deleted while the chain was
        #    mid-flight would still run -- staged device writes, webhooks and
        #    notifications on behalf of a wire that no longer exists. Worse, it
        #    could not even be audited: delete_connection commits the row
        #    deletion BEFORE calling remove_connection, and ConnectionRun.
        #    connection_id is a NOT NULL FK, so the run record insert fails. A
        #    side effect with no run record is exactly what this module refuses
        #    to do elsewhere. Re-resolving costs one dict lookup and makes both
        #    delete and disable mean "stop firing on this worker, for
        #    Connections this loop has not yet CLAIMED". Narrower than it
        #    first reads, and both counterexamples were reproduced: a
        #    Connection deleted after its own _claim_event runs to
        #    completion, and on a multi-worker cluster this skip leaves the
        #    claim free, so a peer that has not reached it yet still fires
        #    it. Neither is a regression -- this is still strictly better
        #    than both alternatives -- but the guarantee is not "never fires".
        #
        # The skip lands BEFORE _claim_event on purpose: the Redis at-most-once
        # key is never burned, so a peer worker that has not reached this
        # Connection yet can still run it. Do NOT add a post-await liveness
        # re-check -- that burns the claim and then skips, losing the event
        # cluster-wide.
        for _conn_id in list(self._connections):
            conn = self._connections.get(_conn_id)
            if conn is None:
                continue  # deleted or disabled while this event was in flight
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
            # Deduplicate within the shared claim lifetime. Under multiple gunicorn workers the
            # same bus event fans out (Redis pub/sub) to EVERY worker's negotiator;
            # without a cluster-wide guard each worker would independently run the
            # chain — duplicate staged writes / webhooks / notifications. A Redis
            # SET NX per (connection, event) lets exactly ONE worker proceed
            # (mirrors the automation engine). Uncertain coordination refuses.
            if not await self._claim_event(conn, event):
                continue
            # Cooldown guard: bound self-amplifying loops (e.g. a connection wired
            # ingest.external → fabric.webhook whose external target posts back to
            # /fabric/ingest) and flood. A shared cooldown claim is required.
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
                try:
                    await db.commit()
                except Exception:
                    # A lost acknowledgement can follow a successful commit.
                    # Keep each step's outcome: external effects and separately
                    # committed staging rows cannot be undone by this rollback.
                    run["success"] = False
                    run["error_code"] = "COMMIT_FAILED"
                    run["commit_status"] = "unconfirmed"
                    run["error"] = (
                        "Connection persistence could not be confirmed; "
                        "step effects may already have occurred"
                    )
                    logger.warning("Fabric: connection %s commit unconfirmed", conn.id)
                    try:
                        await db.rollback()
                    except Exception:
                        logger.warning("Fabric: connection %s rollback unavailable", conn.id)
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
        # Thread the CONNECTION AUTHOR's
        # per-user site grant. There is no live principal here -- a Connection
        # fires on an event, not a request -- so the grant is resolved from the
        # stored actor_id. Leaving it None (which the field documents as
        # "unrestricted") let a site-limited author's Connection act on any
        # site in the org, while the same operation via POST /fabric/invoke
        # could not.
        from app.core.site_access import resolve_actor_site_grants

        ctx = OperationContext(
            organization_id=conn.organization_id,
            params=resolved if isinstance(resolved, dict) else {},
            trigger=context.get("trigger", {}),
            actor_id=conn.actor_id,
            db=db,
            artifacts=self._executor._artifacts,
            input_artifact=input_artifact,
            logger=logger,
            accessible_site_ids=await resolve_actor_site_grants(db, conn.actor_id),
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


# Module-level singleton; runtime.py wires database hydration and bus subscription.
negotiator = Negotiator()
