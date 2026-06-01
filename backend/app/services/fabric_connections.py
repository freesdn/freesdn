# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — Connection persistence + lifecycle service.

CRUD for ``fabric.connections`` plus the helpers the Negotiator needs to go
live: load enabled wires into the engine, map DB rows to the engine's
``Connection`` dataclass, and record per-firing ``ConnectionRun`` audit rows.

Security: every mutation is org-scoped (fail-closed multi-tenancy), and a
Connection is validated at CREATE/UPDATE time — the authoring operator MUST hold
the RBAC permission each step Operation declares (mirroring the engine's runtime
gate so a wire can never be authored that the author couldn't run). Plugin /
write operations that declare no permission are refused at authoring time (they
would always be denied at runtime).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import func, select, update

from app.models.fabric import Connection, ConnectionRun

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.dependencies import CurrentUser
    from app.core.fabric.negotiator import Connection as EngineConnection

logger = logging.getLogger(__name__)

# Bounds (DoS hygiene on operator-authored specs).
_MAX_STEPS = 25
_MAX_NAME = 255


class ConnectionValidationError(ValueError):
    """Malformed Connection spec (bad steps/conditions/source)."""


class ConnectionPermissionError(PermissionError):
    """Author lacks a permission a step Operation requires."""


class FabricConnectionService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── validation ────────────────────────────────────────────────────────

    def _validate_spec(
        self,
        *,
        source_event: str,
        steps: list[dict[str, Any]],
        conditions: dict[str, Any] | None,
        current_user: CurrentUser,
    ) -> None:
        from app.core.fabric.operations import OperationTier
        from app.core.fabric.registry import fabric_registry

        if not source_event or not isinstance(source_event, str):
            raise ConnectionValidationError("source_event is required")
        if not steps or not isinstance(steps, list):
            raise ConnectionValidationError("at least one step is required")
        if len(steps) > _MAX_STEPS:
            raise ConnectionValidationError(f"too many steps (max {_MAX_STEPS})")

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ConnectionValidationError(f"step {i} must be an object")
            op_id = step.get("operation_id")
            if not op_id or not isinstance(op_id, str):
                raise ConnectionValidationError(f"step {i} missing operation_id")
            if not isinstance(step.get("params", {}), dict):
                raise ConnectionValidationError(f"step {i} params must be an object")
            op = fabric_registry.get_operation(op_id)
            if op is None:
                raise ConnectionValidationError(f"step {i}: unknown operation {op_id!r}")
            # Mirror the runtime permission gate at authoring time.
            if op.permission is None:
                if op.tier is not OperationTier.NATIVE or op.write:
                    raise ConnectionPermissionError(
                        f"step {i}: operation {op_id!r} cannot be wired "
                        "(no declared permission for a plugin/write operation)"
                    )
            elif not current_user.has_permission(op.permission):
                raise ConnectionPermissionError(
                    f"step {i}: you lack permission {op.permission!r} required by {op_id!r}"
                )

        if conditions:
            # Parse to validate shape + nesting depth (raises on malformed).
            from app.services.automation import ConditionGroup

            ConditionGroup.from_dict(conditions)

    # ── CRUD (org-scoped) ─────────────────────────────────────────────────

    async def create(
        self,
        *,
        organization_id: UUID,
        current_user: CurrentUser,
        name: str,
        source_event: str,
        steps: list[dict[str, Any]],
        conditions: dict[str, Any] | None = None,
        description: str | None = None,
        enabled: bool = True,
        cooldown_seconds: int = 0,
    ) -> Connection:
        if not name or len(name) > _MAX_NAME:
            raise ConnectionValidationError("name is required (≤255 chars)")
        self._validate_spec(
            source_event=source_event, steps=steps, conditions=conditions, current_user=current_user
        )
        conn = Connection(
            organization_id=organization_id,
            name=name,
            description=description,
            enabled=enabled,
            source_event=source_event,
            conditions=conditions,
            steps=steps,
            cooldown_seconds=max(0, int(cooldown_seconds)),
            created_by=current_user.id,
        )
        self.db.add(conn)
        await self.db.flush()
        await self.db.refresh(conn)
        return conn

    async def list(self, organization_id: UUID, *, enabled: bool | None = None) -> list[Connection]:
        q = select(Connection).where(Connection.organization_id == organization_id)
        if enabled is not None:
            q = q.where(Connection.enabled == enabled)
        q = q.order_by(Connection.created_at.desc())
        return list((await self.db.execute(q)).scalars().all())

    async def get(self, connection_id: UUID, organization_id: UUID) -> Connection | None:
        return (
            await self.db.execute(
                select(Connection).where(
                    Connection.id == connection_id,
                    Connection.organization_id == organization_id,
                )
            )
        ).scalar_one_or_none()

    async def update(
        self,
        connection_id: UUID,
        organization_id: UUID,
        current_user: CurrentUser,
        **changes: Any,
    ) -> Connection | None:
        conn = await self.get(connection_id, organization_id)
        if conn is None:
            return None
        # Re-validate when the spec-bearing fields change.
        new_source = changes.get("source_event", conn.source_event)
        new_steps = changes.get("steps", conn.steps)
        new_conditions = changes.get("conditions", conn.conditions)
        if any(k in changes for k in ("source_event", "steps", "conditions")):
            self._validate_spec(
                source_event=new_source,
                steps=new_steps,
                conditions=new_conditions,
                current_user=current_user,
            )
        for field in (
            "name",
            "description",
            "enabled",
            "source_event",
            "conditions",
            "steps",
            "cooldown_seconds",
        ):
            if field in changes:
                setattr(conn, field, changes[field])
        conn.updated_by = current_user.id
        await self.db.flush()
        await self.db.refresh(conn)
        return conn

    async def delete(self, connection_id: UUID, organization_id: UUID) -> bool:
        conn = await self.get(connection_id, organization_id)
        if conn is None:
            return False
        await self.db.delete(conn)
        await self.db.flush()
        return True

    # ── engine integration ───────────────────────────────────────────────

    async def load_all_enabled(self) -> list[Connection]:
        """All enabled connections across orgs (used to prime the engine at boot)."""
        return list(
            (await self.db.execute(select(Connection).where(Connection.enabled.is_(True))))
            .scalars()
            .all()
        )

    @staticmethod
    def to_engine_connection(c: Connection) -> EngineConnection:
        from app.core.fabric.negotiator import Connection as EngineConnection
        from app.core.fabric.negotiator import ConnectionStep

        steps = [
            ConnectionStep(
                operation_id=str(s.get("operation_id")),
                params=dict(s.get("params") or {}),
                continue_on_error=bool(s.get("continue_on_error", True)),
            )
            for s in (c.steps or [])
            if isinstance(s, dict) and s.get("operation_id")
        ]
        return EngineConnection(
            id=str(c.id),
            organization_id=c.organization_id,
            name=c.name,
            source_event=c.source_event,
            steps=steps,
            enabled=c.enabled,
            conditions=c.conditions,
            actor_id=c.created_by,
            cooldown_seconds=int(c.cooldown_seconds or 0),
        )

    # ── run audit ─────────────────────────────────────────────────────────

    async def record_run(
        self,
        *,
        organization_id: UUID,
        connection_id: UUID,
        source_event_type: str,
        trigger_payload: dict[str, Any],
        run: dict[str, Any],
        duration_ms: int = 0,
    ) -> None:
        """Persist a ConnectionRun and bump the parent's lightweight stats."""
        rec = ConnectionRun(
            connection_id=connection_id,
            organization_id=organization_id,
            source_event_type=source_event_type,
            trigger_payload=trigger_payload or {},
            success=bool(run.get("success")),
            steps=run.get("steps") or [],
            error=run.get("error"),
            duration_ms=max(0, int(duration_ms)),
        )
        self.db.add(rec)
        # Atomic increment at the DB level — a Python read-modify-write
        # (run_count = run_count + 1) loses increments when the same Connection
        # fires concurrently (multi-worker fan-out, or Redis-fail-open at-most-once
        # not deduping), drifting run_count below the true ConnectionRun count.
        await self.db.execute(
            update(Connection)
            .where(
                Connection.id == connection_id,
                Connection.organization_id == organization_id,
            )
            .values(
                run_count=func.coalesce(Connection.run_count, 0) + 1,
                last_run_at=datetime.now(UTC),
            )
        )
        await self.db.flush()

    async def list_runs(
        self, connection_id: UUID, organization_id: UUID, *, limit: int = 50
    ) -> list[ConnectionRun]:
        q = (
            select(ConnectionRun)
            .where(
                ConnectionRun.connection_id == connection_id,
                ConnectionRun.organization_id == organization_id,
            )
            .order_by(ConnectionRun.created_at.desc())
            .limit(max(1, min(limit, 200)))
        )
        return list((await self.db.execute(q)).scalars().all())
