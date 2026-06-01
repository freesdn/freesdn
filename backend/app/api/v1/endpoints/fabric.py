# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — catalog + Connection API.

Two surfaces:

* **Catalog** (read-only): the unified, tier-tagged set of Operations
  (callable capabilities) and Events (triggers) declared across native modules
  and external plugins, plus a projection of the AI tool registry. This is the
  discovery surface the Negotiator/builder UI uses to wire any app to any other.
* **Connections** (CRUD): operator-authored wires — ``source event (+conditions)
  → step chain`` — that the live Negotiator fires. Authoring is org-admin-gated
  and every step is permission-checked against the author at create/update time
  (mirroring the engine's runtime gate); mutations keep the in-memory engine in
  sync so a wire goes live the moment it is saved.

Multi-tenancy is fail-closed: every Connection operation is scoped to the
caller's organization.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_user,
    is_unscoped_org_admin,
    require_permissions,
)
from app.db.session import get_session
from app.services.fabric_connections import (
    ConnectionPermissionError,
    ConnectionValidationError,
    FabricConnectionService,
)

router = APIRouter()


# ── catalog ───────────────────────────────────────────────────────────────


@router.get("/catalog")
async def get_fabric_catalog(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return the full Fabric catalog: operations + events + AI-tool projection.

    Each operation carries its ``tier`` (native vs plugin), required
    ``permission``, and ``write`` flag (write operations route through the
    staged-change pipeline when invoked).
    """
    from app.core.fabric.registry import fabric_registry

    return fabric_registry.catalog()


# ── direct operation invocation ─────────────────────────────────────────────


class InvokeIn(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/operations/{operation_id}/invoke")
async def invoke_operation(
    operation_id: str,
    body: InvokeIn,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Invoke a single catalog Operation once over HTTP.

    The generic counterpart to the AI-tool + automation bridges: any HTTP client
    (n8n/Zapier/a script) can drive a Fabric operation directly, reusing the
    executor — so the SAME safety holds: a device WRITE is STAGED for operator
    sign-off (returns ``staged_change_id``, never auto-applied), org-scoping is
    fail-closed, and the permission gate mirrors the negotiator's:

      * an op with a declared ``permission`` → the caller must hold it (honors
        scoped API keys);
      * a native, permissionless SINK (``fabric.notify``/``log``/``webhook``) →
        org-admin floor (the level that authors Connections);
      * a plugin op with no declared permission → refused.
    """
    from app.core.fabric.execution import OperationContext
    from app.core.fabric.executor import operation_executor
    from app.core.fabric.operations import OperationTier
    from app.core.fabric.registry import fabric_registry

    org = _require_org(current_user)
    op = fabric_registry.get_operation(operation_id)
    if op is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="operation not found")

    # Plugin operations are projected into the catalog with NO executable handler
    # (they run via their own (plugin, org) runtime, not the registry). Refuse
    # them here CLEARLY rather than executing into a NOT_SUPPORTED result.
    if op.tier is not OperationTier.NATIVE:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="only native operations can be invoked here; plugin operations run via their own runtime",
        )

    if op.permission:
        if not current_user.has_permission(op.permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"permission {op.permission!r} required to invoke {operation_id!r}",
            )
    elif not _is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="organization admin required to invoke this operation",
        )

    ctx = OperationContext(
        organization_id=org,
        params=dict(body.params or {}),
        actor_id=current_user.id,
        db=db,
        trigger={},
        logger=logging.getLogger("fabric.invoke"),
        # thread the caller's per-user site grant so site-scoped
        # handlers (e.g. VoIP originate / PBX reads) can't reach a sibling site.
        accessible_site_ids=(
            current_user.accessible_site_ids if current_user.is_site_limited else None
        ),
    )
    result = await operation_executor.execute(op, ctx)
    # Only persist on success — a write op stages an AdapterPendingChange that we
    # want durable, but a FAILED op must not leave a partial/garbage row behind.
    if result.success:
        await db.commit()
    else:
        await db.rollback()
        # A failed op must surface as the right HTTP status, not 200+success:false.
        from app.core.adapter_result import raise_for_adapter_result

        raise_for_adapter_result(result)
    return result.to_dict()


# ── request / response models ───────────────────────────────────────────────


class StepIn(BaseModel):
    operation_id: str = Field(..., max_length=255)
    params: dict[str, Any] = Field(default_factory=dict)
    continue_on_error: bool = True


class ConnectionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    source_event: str = Field(..., min_length=1, max_length=255)
    steps: list[StepIn] = Field(..., min_length=1, max_length=25)
    description: str | None = None
    conditions: dict[str, Any] | None = None
    enabled: bool = True
    cooldown_seconds: int = Field(default=0, ge=0, le=86_400)


class ConnectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    source_event: str | None = Field(default=None, min_length=1, max_length=255)
    steps: list[StepIn] | None = Field(default=None, min_length=1, max_length=25)
    description: str | None = None
    conditions: dict[str, Any] | None = None
    enabled: bool | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86_400)


class TestRun(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)


def _redacted_steps(steps: list[Any]) -> list[Any]:
    """Strip step ``params`` for non-author viewers. Step params are operator
    config that can carry secrets (a fabric.webhook Authorization header, a
    notify Slack/Teams webhook URL), and list/get are readable by ANY org member
    (incl. viewers) — only an author (unscoped org-admin) needs the real values
    to edit. We drop the whole params blob rather than key-name heuristics so a
    secret in an unexpected key can't slip through; operation_id (shown in the
    UI wire) is preserved.
    """
    out: list[Any] = []
    for s in steps or []:
        if isinstance(s, dict):
            redacted = {k: v for k, v in s.items() if k != "params"}
            if s.get("params"):
                redacted["params"] = {"__redacted__": "hidden — author-only"}
            out.append(redacted)
        else:
            out.append(s)
    return out


def _conn_dict(c: Any, *, full_params: bool = True) -> dict[str, Any]:
    steps = c.steps or []
    return {
        "id": str(c.id),
        "organization_id": str(c.organization_id),
        "name": c.name,
        "description": c.description,
        "enabled": c.enabled,
        "source_event": c.source_event,
        "conditions": c.conditions,
        "steps": steps if full_params else _redacted_steps(steps),
        "cooldown_seconds": c.cooldown_seconds,
        "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None,
        "run_count": c.run_count,
        "created_by": str(c.created_by) if c.created_by else None,
        "created_at": c.created_at.isoformat() if getattr(c, "created_at", None) else None,
        "updated_at": c.updated_at.isoformat() if getattr(c, "updated_at", None) else None,
    }


def _run_dict(r: Any, *, full: bool = True) -> dict[str, Any]:
    # CONV2-002: trigger_payload / steps / error can carry event data a low-priv
    # org viewer should not see. Only the connection author or an org admin gets
    # the raw fields (mirrors the connection step-params redaction); other org
    # users get a redacted run summary.
    return {
        "id": str(r.id),
        "connection_id": str(r.connection_id),
        "source_event_type": r.source_event_type,
        "trigger_payload": r.trigger_payload if full else "[redacted]",
        "success": r.success,
        "steps": (r.steps or []) if full else [],
        "error": (r.error if full else None),
        "duration_ms": r.duration_ms,
        "created_at": r.created_at.isoformat() if getattr(r, "created_at", None) else None,
    }


def _require_org(current_user: CurrentUser) -> UUID:
    org = current_user.organization_id
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A Fabric Connection must belong to an organization",
        )
    return org


def _is_unscoped_org_admin(current_user: CurrentUser) -> bool:
    """True only for a full org-admin principal that is NOT operating under a
    reduced scope. ``is_org_admin`` is role-based and scope-BLIND, so a scoped
    API key minted by an admin (e.g. scopes=['event:read']) would otherwise
    inherit full admin authority for the permissionless-sink invoke floor and
    Connection authoring. Mirroring ``has_permission``'s scope ceiling (audit
    #8), a deliberately-narrowed credential is refused here (fail-closed).

    Delegates to the shared ``is_unscoped_org_admin`` helper so the
    scope-aware org-admin rule lives in exactly one place.
    """
    return is_unscoped_org_admin(current_user)


def _require_author(current_user: CurrentUser) -> None:
    # Authoring cross-app automation is an administrative act. The per-step
    # permission gate (in the service) is the finer control; this is the floor.
    if not _is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authoring Fabric Connections requires an organization admin role",
        )


async def _publish_connection_changed(organization_id: Any, connection_id: Any) -> None:
    """Broadcast a Connection CRUD change over the bus so EVERY worker re-syncs it.

    The serving worker updates its own in-process negotiator directly; this event
    (handled by runtime.handle_connection_changed on all workers) propagates the
    change cluster-wide under the Redis fan-out. Best-effort — a publish failure
    must not fail the CRUD; the periodic re-prime is the fallback.
    """
    from app.core.events import Event, EventCategory, get_event_bus

    try:
        await get_event_bus().publish(
            Event(
                event_type="fabric.connection.changed",
                category=EventCategory.SYSTEM,
                payload={
                    "connection_id": str(connection_id),
                    "organization_id": str(organization_id),
                },
                organization_id=str(organization_id),
                source="fabric",
            )
        )
    except Exception:
        logging.getLogger("fabric").exception("Fabric: failed to broadcast connection change")


async def _sync_engine(conn: Any) -> None:
    """Reflect a persisted Connection into THIS worker's negotiator + broadcast a
    control event so every other worker re-syncs too (cluster-consistent CRUD)."""
    from app.core.fabric.negotiator import negotiator

    if conn.enabled:
        negotiator.add_connection(FabricConnectionService.to_engine_connection(conn))
    else:
        negotiator.remove_connection(str(conn.id))
    await _publish_connection_changed(conn.organization_id, conn.id)


# ── connection CRUD ─────────────────────────────────────────────────────────


@router.post("/connections", status_code=status.HTTP_201_CREATED)
async def create_connection(
    body: ConnectionCreate,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = _require_org(current_user)
    _require_author(current_user)
    svc = FabricConnectionService(db)
    try:
        conn = await svc.create(
            organization_id=org,
            current_user=current_user,
            name=body.name,
            source_event=body.source_event,
            steps=[s.model_dump() for s in body.steps],
            conditions=body.conditions,
            description=body.description,
            enabled=body.enabled,
            cooldown_seconds=body.cooldown_seconds,
        )
    except ConnectionPermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except (ConnectionValidationError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await db.commit()
    await _sync_engine(conn)
    return _conn_dict(conn)


@router.get("/connections")
async def list_connections(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
    enabled: bool | None = None,
) -> dict[str, Any]:
    org = _require_org(current_user)
    full = _is_unscoped_org_admin(current_user)  # only authors get raw step params
    svc = FabricConnectionService(db)
    conns = await svc.list(org, enabled=enabled)
    return {"connections": [_conn_dict(c, full_params=full) for c in conns], "total": len(conns)}


@router.get("/connections/suggest")
async def suggest_targets(
    source_event: str,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict[str, Any]:
    """Suggest operations compatible with a source event (builder matchmaking).

    Declared BEFORE ``/connections/{connection_id}`` so the literal ``suggest``
    path isn't parsed as a connection UUID.

    Returns the event spec plus every operation that could serve as a target
    step, each annotated with:

      * ``match`` — ``"artifact"`` (the event produces a media-type the operation
        consumes, so a blob can be handed to it) or ``"data"`` (the operation
        needs no input artifact; it reads the trigger payload via templating);
      * ``allowed`` — whether THIS caller may author a step with the operation
        (mirrors the create/update gate in :class:`FabricConnectionService`): a
        permissionless **native** sink is allowed; a permissionless plugin/write
        operation can never be wired; otherwise the caller must hold the
        operation's permission.

    Read-only. Authoring a Connection from a suggestion is still org-admin-gated
    and per-step permission-checked at create/update time.
    """
    from app.core.fabric.operations import OperationTier, media_compatible
    from app.core.fabric.registry import fabric_registry

    _require_org(current_user)

    def _allowed(op: Any) -> bool:
        if op.permission is None:
            # Mirror _validate_spec: only a native, non-write sink is wirable
            # without a declared permission; a plugin/write op never is.
            return op.tier is OperationTier.NATIVE and not op.write
        return current_user.has_permission(op.permission)

    # Look the event up ONCE and thread it into compatible_targets so the registry
    # doesn't re-discover it (avoids a redundant catalog walk per request).
    ev = fabric_registry.get_event(source_event)
    produced = ev.produces if ev else ()
    targets: list[dict[str, Any]] = []
    for op in fabric_registry.compatible_targets(source_event, event=ev):
        d = op.to_catalog_dict()
        # "artifact" only when the event ACTUALLY produces a media-type this op
        # consumes — a blob-accepting op fired by a pure-data event is "data", not
        # an artifact hand-off (the builder's paperclip hint must not over-promise).
        is_artifact = bool(op.accepts) and bool(produced) and media_compatible(produced, op.accepts)
        d["match"] = "artifact" if is_artifact else "data"
        d["allowed"] = _allowed(op)
        targets.append(d)

    # Most immediately useful first: authorable ops, then artifact-matches, then
    # alphabetical — so the builder's picker leads with what the operator can use.
    targets.sort(key=lambda d: (not d["allowed"], d["match"] != "artifact", d["id"]))
    return {
        "source_event": source_event,
        "event": ev.to_catalog_dict() if ev else None,
        "targets": targets,
        "counts": {
            "total": len(targets),
            "allowed": sum(1 for t in targets if t["allowed"]),
        },
    }


@router.get("/connections/{connection_id}")
async def get_connection(
    connection_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = _require_org(current_user)
    svc = FabricConnectionService(db)
    conn = await svc.get(connection_id, org)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return _conn_dict(conn, full_params=_is_unscoped_org_admin(current_user))


@router.patch("/connections/{connection_id}")
async def update_connection(
    connection_id: UUID,
    body: ConnectionUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = _require_org(current_user)
    _require_author(current_user)
    changes = body.model_dump(exclude_unset=True)
    if "steps" in changes and changes["steps"] is not None:
        changes["steps"] = [s if isinstance(s, dict) else s.model_dump() for s in changes["steps"]]
    svc = FabricConnectionService(db)
    try:
        conn = await svc.update(connection_id, org, current_user, **changes)
    except ConnectionPermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except (ConnectionValidationError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    await db.commit()
    await _sync_engine(conn)
    return _conn_dict(conn)


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(
    connection_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    org = _require_org(current_user)
    _require_author(current_user)
    svc = FabricConnectionService(db)
    ok = await svc.delete(connection_id, org)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    await db.commit()
    from app.core.fabric.negotiator import negotiator

    negotiator.remove_connection(str(connection_id))
    # Broadcast so the other workers drop it too (cluster-consistent delete).
    await _publish_connection_changed(org, connection_id)


@router.get("/connections/{connection_id}/runs")
async def list_connection_runs(
    connection_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
) -> dict[str, Any]:
    org = _require_org(current_user)
    svc = FabricConnectionService(db)
    conn = await svc.get(connection_id, org)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    runs = await svc.list_runs(connection_id, org, limit=limit)
    # CONV2-002: only the connection author or an org admin sees raw run payloads.
    full = _is_unscoped_org_admin(current_user) or str(getattr(conn, "created_by", None)) == str(
        current_user.id
    )
    return {"runs": [_run_dict(r, full=full) for r in runs], "total": len(runs)}


@router.post("/connections/{connection_id}/test")
async def test_connection(
    connection_id: UUID,
    body: TestRun,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Run a Connection once with an explicit payload (operator-initiated).

    Applies the same per-step permission + staging gates as a live firing — a
    write step still STAGES a change rather than applying it. Persists a
    ConnectionRun audit row like any firing.
    """
    org = _require_org(current_user)
    _require_author(current_user)
    svc = FabricConnectionService(db)
    conn = await svc.get(connection_id, org)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    from app.core.fabric.negotiator import negotiator

    engine_conn = FabricConnectionService.to_engine_connection(conn)
    run = await negotiator.run_once(engine_conn, body.payload)
    await svc.record_run(
        organization_id=org,
        connection_id=connection_id,
        source_event_type=conn.source_event,
        trigger_payload=body.payload,
        run=run,
        duration_ms=int(run.get("duration_ms", 0)),
    )
    await db.commit()
    return run


# ── external-orchestration inbound bridge ───────────────────────────────────

_INGEST_NAME_RE = re.compile(r"[^a-z0-9_-]")
_INGEST_MAX_BYTES = 64 * 1024  # bounded body (the global RateLimitMiddleware caps frequency)

# Per-org inbound throttle. Bounds a single org flooding its own event bus /
# the synchronous negotiator via callbacks. CLUSTER-WIDE via Redis (a fixed
# window counter) so the limit holds across all gunicorn workers; falls back to
# an in-process window when Redis is unavailable (tests / single-instance) —
# note the fallback is per-process, so the effective limit is N× under N workers.
_INGEST_RATE_MAX = 120
_INGEST_RATE_WINDOW = 60.0
# Cap the in-process fallback map: once it exceeds this many orgs, each call
# sweeps out entries whose hits have all expired so a long tail of one-off orgs
# (or a churn of spoofed org ids) can't grow the dict without bound.
_INGEST_HITS_MAX_KEYS = 10_000
_ingest_hits: dict[str, deque[float]] = {}
_ingest_redis: Any = None  # lazily created shared client; False once probed-unavailable


async def _get_ingest_redis() -> Any:
    global _ingest_redis
    if _ingest_redis is None:
        _ingest_redis = False  # probed
        try:
            from app.core.config import settings

            if settings.REDIS_URL:
                from app.core.redis_client import get_async_redis

                _ingest_redis = get_async_redis(
                    decode_responses=True,
                    # Fail fast rather than hang the ingest request on a
                    # black-holed Redis (matches the event-bus client).
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
        except Exception:
            _ingest_redis = False
    return _ingest_redis or None


async def _ingest_rate_ok(organization_id: UUID) -> bool:
    """True if this org is under its inbound rate budget for the current window."""
    r = await _get_ingest_redis()
    if r is not None:
        try:
            window = int(time.time()) // int(_INGEST_RATE_WINDOW)
            key = f"fabric:ingest:{organization_id}:{window}"
            n = await r.incr(key)
            if n == 1:
                await r.expire(key, int(_INGEST_RATE_WINDOW))
            return int(n) <= _INGEST_RATE_MAX
        except Exception:
            logging.getLogger("fabric").warning("ingest rate-limit Redis failed; in-process")
    return _ingest_rate_ok_local(organization_id)


def _ingest_rate_ok_local(organization_id: UUID) -> bool:
    now = time.monotonic()
    cutoff = now - _INGEST_RATE_WINDOW
    key = str(organization_id)
    dq = _ingest_hits.setdefault(key, deque())
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= _INGEST_RATE_MAX:
        return False  # over budget — keep the (still-hot) entry
    dq.append(now)
    # Opportunistically evict idle orgs so the in-process fallback map can't grow
    # unbounded across the universe of orgs that have ever ingested (the Redis
    # path self-expires; this per-process fallback must bound itself). Sweep only
    # when the map is non-trivially large to keep the common path O(1).
    if len(_ingest_hits) > _INGEST_HITS_MAX_KEYS:
        for stale in [k for k, d in _ingest_hits.items() if not d or d[-1] < cutoff]:
            if stale != key:  # never drop the entry we just appended to
                del _ingest_hits[stale]
    return True


class IngestIn(BaseModel):
    name: str | None = Field(default="external", max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)


async def _emit_ingest(organization_id: UUID, name: str | None, payload: dict[str, Any]) -> str:
    """Emit the canonical ``ingest.external`` event onto the bus (org-scoped).

    The event type is ALWAYS ``ingest.external`` (never operator-controlled) so
    an external caller can't spoof a native event like ``controller.change.applied``;
    callbacks are differentiated by the sanitized ``name`` in the payload, which a
    Connection routes on via a condition.
    """
    from app.core.events import Event, EventCategory, get_event_bus

    safe = _INGEST_NAME_RE.sub("", (name or "external").lower())[:64] or "external"
    await get_event_bus().publish(
        Event(
            event_type="ingest.external",
            category=EventCategory.SYSTEM,
            payload={"name": safe, "data": payload},
            organization_id=str(organization_id),
            source="ingest",
        )
    )
    return safe


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_external(
    body: IngestIn,
    # Gate on ``event:write`` (NOT mere authentication): emitting an event that
    # fires org-wide Connections is a WRITE capability, so a deliberately
    # read-only / scoped API key (e.g. scopes=['event:read']) must be refused.
    # has_permission honors the scope ceiling, so a low-scope key is blocked
    # while an org-admin session/key passes (review HIGH: key-scope escalation).
    current_user: Annotated[CurrentUser, Depends(require_permissions("event:write"))],
) -> dict[str, Any]:
    """INBOUND half of the external-orchestration bridge.

    An external automation platform (n8n/Zapier/Make/…) authenticates with an
    org API key (scoped to ``event:write``) and POSTs here; we emit an
    ``ingest.external`` event that any Connection wired to it fires on — e.g.
    ``ingest.external (name=n8n_done) → storage.store_blob``. Async + decoupled:
    this never blocks on the external system, and the inbound event continues
    the flow.
    """
    org = _require_org(current_user)
    if len(json.dumps(body.payload, default=str)) > _INGEST_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"payload too large (max {_INGEST_MAX_BYTES} bytes)",
        )
    # Per-org throttle (belt-and-suspenders with the global RateLimitMiddleware +
    # the negotiator cooldown): a single org can't flood its own bus / the
    # synchronous negotiator with inbound callbacks.
    if not await _ingest_rate_ok(org):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="ingest rate limit exceeded for this organization",
        )
    name = await _emit_ingest(org, body.name, body.payload)
    return {"accepted": True, "event_type": "ingest.external", "name": name}
