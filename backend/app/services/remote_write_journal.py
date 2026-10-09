# SPDX-License-Identifier: AGPL-3.0-only
"""Independent retained history used by remote backup coordination.

No network operation, caller-session commit, authentication, automatic retry or
catalogue promotion lives here. A dispatched row means the outcome may be
unknown; even an acknowledged row is not a verified backup. A caller must NOT
dispatch after any exception (including an ambiguous commit) or reuse a prior
row as dispatch permission. Inspection grants no mutation authority.

Table/schema migration, startup validation, current-authority integration and
operator recovery remain separate qualification requirements.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import anyio
from sqlalchemy import (
    func,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.owned_async import complete_before_cancellation
from app.core.remote_write_intent import RemoteWriteIntent
from app.models.remote_write_operations import operations


class RemoteIntentConflict(RuntimeError):
    """Already reserved/changed history: inspect; never automatically replay."""


@dataclass(frozen=True)
class RemoteWriteHistory:
    operation_id: UUID
    intent_sha256: str
    intent_bytes: bytes
    phase: str
    sequence: int

    @property
    def outcome_unknown(self) -> bool:
        return self.phase == "dispatched"


class RemoteWriteJournal:
    def __init__(self, engine: AsyncEngine):
        if not isinstance(engine, AsyncEngine) or engine.dialect.name != "postgresql":
            raise TypeError("Independent PostgreSQL engine is required")
        self.engine = engine

    @complete_before_cancellation
    async def reserve(self, intent: RemoteWriteIntent) -> None:
        raw = intent.encoded()
        # A new transaction/physical connection; never use the caller's Session.
        with anyio.fail_after(6):
            async with self.engine.begin() as connection:
                await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
                row = (
                    await connection.execute(
                        insert(operations)
                        .values(
                            operation_id=intent.operation_id,
                            backup_id=intent.backup_id,
                            organization_id=intent.organization_id,
                            intent_bytes=raw,
                            intent_sha256=intent.digest(),
                            payload_size=intent.payload_size,
                            phase="reserved",
                            sequence=0,
                        )
                        .on_conflict_do_nothing()
                        .returning(operations.c.operation_id)
                    )
                ).scalar_one_or_none()
                if row is None:
                    raise RemoteIntentConflict(
                        "Remote operation already reserved; inspect its history"
                    )

    @complete_before_cancellation
    async def advance(self, intent: RemoteWriteIntent, action: str) -> None:
        # SQL CAS allows one winner, including contenders blocked on row locks.
        transitions = {
            "dispatch": ("reserved", 0, "dispatched", 1),
            "acknowledge": ("dispatched", 1, "acknowledged", 2),
            "cancel_before_dispatch": ("reserved", 0, "cancelled", 1),
        }
        if action not in transitions:
            raise RemoteIntentConflict("Invalid remote operation transition")
        before, sequence, after, next_sequence = transitions[action]
        digest = intent.digest()
        with anyio.fail_after(6):
            async with self.engine.begin() as connection:
                await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
                row = (
                    await connection.execute(
                        update(operations)
                        .where(
                            operations.c.operation_id == intent.operation_id,
                            operations.c.organization_id == intent.organization_id,
                            operations.c.intent_sha256 == digest,
                            operations.c.intent_bytes == intent.encoded(),
                            operations.c.phase == before,
                            operations.c.sequence == sequence,
                        )
                        .values(
                            phase=after, sequence=next_sequence, updated_at=func.clock_timestamp()
                        )
                        .returning(operations.c.operation_id)
                    )
                ).scalar_one_or_none()
                if row is None:
                    raise RemoteIntentConflict("Remote operation changed; inspect its history")

    @complete_before_cancellation
    async def inspect(self, organization_id: UUID, operation_id: UUID) -> RemoteWriteHistory | None:
        # Tenant scope is necessary, not sufficient: the API must authenticate
        # current authority before and after any wait. This is internal storage.
        with anyio.fail_after(6):
            async with self.engine.begin() as connection:
                await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
                row = (
                    (
                        await connection.execute(
                            select(operations).where(
                                operations.c.operation_id == operation_id,
                                operations.c.organization_id == organization_id,
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        if row is None:
            return None
        return RemoteWriteHistory(
            row.operation_id, row.intent_sha256, row.intent_bytes, row.phase, row.sequence
        )
