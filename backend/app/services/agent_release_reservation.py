# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned reservation/cancellation phases for the unfinished release coordinator.

No artifact is created, prepared, published or removed here. In particular, the
returned acknowledged journal state is not a storage capability. The complete
coordinator must retain this ownership AND drained filesystem ownership across
its work; session locks alone cannot protect a worker after connection loss.
No existing endpoint calls this module. Incompatible writers must be drained.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import exists, func, insert, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.core import Organization
from app.services.agent_release_artifact_store import ArtifactUnavailable
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_capacity import charged_owned_publications
from app.services.agent_release_cleanup import ReleaseOperationRecord, _record
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_operation_status import _check_authority
from app.services.agent_release_promotion import lock_release_bucket
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget

_OPERATIONS = threading.BoundedSemaphore(8)


def _lease_keys(operation_id: UUID, release_id: UUID) -> tuple[int, ...]:
    keys = [
        int.from_bytes(hashlib.sha256(domain + identity.bytes).digest()[:8], "big", signed=True)
        for domain, identity in (
            (b"FreeSDN/release-operation/v1\0", operation_id),
            (b"FreeSDN/release-object/v1\0", release_id),
        )
    ]
    # A hash collision reduces concurrency; it must not acquire/release the
    # same reentrant session lock twice or invent a different ownership domain.
    return tuple(sorted(set(keys)))


@dataclass(frozen=True)
class ReleaseReservationResult:
    operation_id: UUID
    release_id: UUID
    phase: str
    decision: str | None
    created: bool
    requested_by: UUID
    last_transition_by: UUID


async def _commit_phase(db: AsyncSession) -> None:
    # A driver exception after this commit is an unknown acknowledgment, not
    # proof that the transaction rolled back. Never automatically replay it.
    await db.commit()


class _OperationOwner[Q: ReleasePublicationRequest | ReleaseDeletionRequest]:
    def __init__(
        self,
        connection: AsyncConnection,
        db: AsyncSession,
        authority: ReleaseMutationAuthority,
        request: Q,
        keys: tuple[int, ...],
        pid: object,
    ) -> None:
        self.connection, self.db = connection, db
        self.authority, self.request = authority, request
        self.keys, self.pid = keys, pid
        self.deadline = anyio.current_time() + 120
        self.active, self.poisoned, self.busy = True, False, False

    async def _assert_owner(self) -> None:
        if (
            not self.active
            or self.poisoned
            or anyio.current_time() >= self.deadline
            or self.connection.closed
            or self.connection.invalidated
        ):
            raise HTTPException(503, "Release operation ownership ended; inspect retained state")
        if await self.db.scalar(text("SELECT pg_backend_pid()")) != self.pid:
            raise HTTPException(503, "Release operation connection changed; inspect retained state")
        for key in self.keys:
            unsigned = key & ((1 << 64) - 1)
            present = await self.db.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                    "AND pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) "
                    "AND classid::bigint=:high AND objid::bigint=:low AND objsubid=1 "
                    "AND mode='ExclusiveLock' AND granted)"
                ),
                {"high": unsigned >> 32, "low": unsigned & 0xFFFFFFFF},
            )
            if not present:
                raise HTTPException(503, "Release operation lease was lost; inspect retained state")

    async def phase[R](
        self, function: Callable[[AsyncSession], Awaitable[R]], *, release_write: bool = False
    ) -> R:
        if type(release_write) is not bool:
            raise HTTPException(422, "Invalid internal release phase mode")
        if (
            self.busy
            or self.poisoned
            or not self.active
            or self.db.in_transaction()
            or self.connection.closed
            or self.connection.invalidated
            or anyio.current_time() >= self.deadline
        ):
            raise HTTPException(503, "Release phase cannot be reused; inspect retained state")
        self.busy = True
        try:
            with anyio.fail_after(5):
                await self.db.begin()
                await self.db.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                await self.db.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                await self.db.execute(text("SET LOCAL lock_timeout = '500ms'"))
                await self._assert_owner()
                metadata = self.request.metadata()
                await lock_release_bucket(
                    self.db,
                    self.request.organization_id,
                    metadata["platform"],
                    metadata["agent_type"],
                )
                # Short exclusion also protects absence/count decisions from
                # INSERT/DELETE writers that do not take our advisory locks.
                # No network, file I/O or caller callback runs under these locks.
                await self.db.execute(
                    text(
                        "LOCK TABLE agents.agent_release_operations IN SHARE ROW EXCLUSIVE MODE NOWAIT"
                    )
                )
                # Mutation phases take their stronger table lock up front, not
                # as a waiting lock upgrade after account/identity row locks.
                await self.db.execute(
                    text(
                        "LOCK TABLE agents.agent_releases IN SHARE ROW EXCLUSIVE MODE NOWAIT"
                        if release_write
                        else "LOCK TABLE agents.agent_releases IN SHARE MODE NOWAIT"
                    )
                )
                fence = await self.authority.lock(self.db)
                self.authority.require_scope(self.request.organization_id)
                result = await function(self.db)
                await self._assert_owner()
                await fence.recheck()
                await _commit_phase(self.db)
            await _check_authority(self.authority)
            if anyio.current_time() >= self.deadline:
                raise HTTPException(503, "Release operation deadline ended; inspect retained state")
            return result
        except BaseException:
            self.poisoned = True
            raise
        finally:
            self.busy = False

    async def _load(
        self: _OperationOwner[ReleasePublicationRequest], db: AsyncSession
    ) -> ReleaseOperationRecord | None:
        value = (
            (
                await db.execute(
                    select(AgentReleaseOperation.__table__).where(
                        AgentReleaseOperation.operation_id == self.request.operation_id
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if value is None:
            return None
        self.authority.require_scope(value["organization_id"])
        row = _record(value)
        metadata = self.request.metadata()
        expected = {
            "kind": "publish",
            "release_id": self.request.release_id,
            "organization_id": self.request.organization_id,
            "storage_kind": self.request.storage_kind,
            "artifact_id": self.request.operation_id
            if self.request.storage_kind == "owned"
            else None,
            "request_bytes": self.request.request_bytes(),
            "request_sha256": self.request.request_sha256(),
            "expected_sha256": metadata["checksum_sha256"],
            "expected_size": metadata["file_size"],
        }
        if any(cast(Mapping[str, object], row)[name] != expected[name] for name in expected):
            raise HTTPException(409, "Operation identity is already bound to another request")
        return row

    async def reserve(
        self: _OperationOwner[ReleasePublicationRequest], budget: ReleaseReservationBudget
    ) -> tuple[ReleaseOperationRecord, bool]:
        if type(self.request) is not ReleasePublicationRequest:
            raise HTTPException(422, "Publication reservation requires its exact request type")

        async def action(db: AsyncSession) -> tuple[ReleaseOperationRecord, bool]:
            existing = await self._load(db)
            if existing is not None:
                return existing, False
            if self.request.organization_id is not None:
                destination = (
                    await db.execute(
                        select(Organization.id)
                        .where(
                            Organization.id == self.request.organization_id,
                            Organization.deleted_at.is_(None),
                            Organization.is_active.is_(True),
                        )
                        .with_for_update(read=True, nowait=True)
                    )
                ).one_or_none()
                if destination is None:
                    raise HTTPException(404, "Live destination organization not found")
            if await db.scalar(
                select(exists().where(AgentRelease.id == self.request.release_id))
            ) or await db.scalar(
                select(exists().where(AgentReleaseOperation.release_id == self.request.release_id))
            ):
                raise HTTPException(409, "Release identity already has retained history")
            c = AgentReleaseOperation.__table__.c
            scope = c.organization_id.is_not_distinct_from(self.request.organization_id)
            # These aggregate SELECTs always produce one non-null count row.
            history = cast(
                int, await db.scalar(select(func.count()).select_from(AgentReleaseOperation))
            )
            organization_history = cast(
                int,
                await db.scalar(
                    select(func.count()).select_from(AgentReleaseOperation).where(scope)
                ),
            )
            if (
                history >= budget.global_history
                or organization_history >= budget.organization_history
            ):
                raise HTTPException(
                    409, "Retained release history capacity requires operator resolution"
                )
            metadata = self.request.metadata()
            if self.request.storage_kind == "owned":
                charged = charged_owned_publications()
                total = cast(
                    int,
                    await db.scalar(
                        select(func.coalesce(func.sum(c.expected_size), 0)).where(charged)
                    ),
                )
                scoped = cast(
                    int,
                    await db.scalar(
                        select(func.coalesce(func.sum(c.expected_size), 0)).where(charged, scope)
                    ),
                )
                if (
                    total + metadata["file_size"] > budget.global_owned_bytes
                    or scoped + metadata["file_size"] > budget.organization_owned_bytes
                ):
                    raise HTTPException(
                        409, "Declared release storage capacity requires operator resolution"
                    )
            now = await db.scalar(select(func.clock_timestamp()))
            row = {
                "operation_id": self.request.operation_id,
                "format_version": 1,
                "kind": "publish",
                "release_id": self.request.release_id,
                "organization_id": self.request.organization_id,
                "requested_by": self.authority.actor_id,
                "storage_kind": self.request.storage_kind,
                "artifact_id": self.request.operation_id
                if self.request.storage_kind == "owned"
                else None,
                "request_bytes": self.request.request_bytes(),
                "request_sha256": self.request.request_sha256(),
                "expected_sha256": metadata["checksum_sha256"],
                "expected_size": metadata["file_size"],
                "phase": "reserved",
                "decision": None,
                "transition_sequence": 0,
                "created_at": now,
                "prepared_at": None,
                "decided_at": None,
                "cleaned_at": None,
                "last_transition_by": self.authority.actor_id,
            }
            _record(row)
            await db.execute(insert(AgentReleaseOperation).values(**row))
            # _record above checked the complete row before the original insert.
            return cast(ReleaseOperationRecord, row), True

        return await self.phase(action)

    async def cancel(
        self: _OperationOwner[ReleasePublicationRequest],
    ) -> tuple[ReleaseOperationRecord, bool]:
        if type(self.request) is not ReleasePublicationRequest:
            raise HTTPException(422, "Publication cancellation requires its exact request type")

        async def action(db: AsyncSession) -> tuple[ReleaseOperationRecord, bool]:
            row = await self._load(db)
            if row is None:
                raise HTTPException(
                    404, "Release operation not found; cancellation cannot create an operation"
                )
            if row["decision"] == "cancelled":
                return row, False
            if row["phase"] not in ("reserved", "prepared"):
                raise HTTPException(
                    409, "A confirmed publication cannot be cancelled; use a separate deletion"
                )
            if await db.scalar(select(exists().where(AgentRelease.id == row["release_id"]))):
                raise HTTPException(
                    409, "Pending publication conflicts with a live release; inspect recovery state"
                )
            change = {
                "phase": "decided",
                "decision": "cancelled",
                "transition_sequence": row["transition_sequence"] + 1,
                "decided_at": await db.scalar(select(func.clock_timestamp())),
                "last_transition_by": self.authority.actor_id,
            }
            await db.execute(
                update(AgentReleaseOperation)
                .where(AgentReleaseOperation.operation_id == row["operation_id"])
                .values(**change)
            )
            return _record({**row, **change}), False

        return await self.phase(action)


@complete_before_cancellation
async def _execute_owned[Q: ReleasePublicationRequest | ReleaseDeletionRequest, R](
    *,
    authority: ReleaseMutationAuthority,
    request: Q,
    function: Callable[[_OperationOwner[Q]], Awaitable[R]],
) -> R:
    """Internal operation owner; only trusted coordinators provide the function.

    A caller's body source is never invoked under a phase's database locks. The
    callback must drain all filesystem work before returning or raising here.
    """
    if type(authority) is not ReleaseMutationAuthority or type(request) not in (
        ReleasePublicationRequest,
        ReleaseDeletionRequest,
    ):
        raise HTTPException(422, "Invalid release operation command")
    authority.require_scope(request.organization_id)
    if not _OPERATIONS.acquire(blocking=False):
        raise HTTPException(503, "Release operation capacity is busy")
    try:
        await _check_authority(authority)
        keys = _lease_keys(request.operation_id, request.release_id)
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                connection = await cleanup.enter_async_context(sessions.security_engine.connect())
                db = await cleanup.enter_async_context(
                    AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
                )
            acquired = []
            owner = None
            acquisition_confirmed = False
            try:
                with anyio.fail_after(5):
                    pid = await db.scalar(text("SELECT pg_backend_pid()"))
                    for key in keys:
                        locked = await db.scalar(
                            text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"), {"key": key}
                        )
                        if locked is not True:
                            raise HTTPException(
                                409, "Another operation owns this release; retry inspection"
                            )
                        acquired.append(key)
                    await db.commit()
                    acquisition_confirmed = True
                owner = _OperationOwner(connection, db, authority, request, keys, pid)
                result = await function(owner)
            finally:
                if owner is not None:
                    owner.active = False
                try:
                    with anyio.fail_after(5):
                        if not acquisition_confirmed:
                            # A granted lock whose acknowledgment was lost may
                            # not be in acquired. Never return that session to
                            # the pool; invalidate its physical connection.
                            await connection.invalidate()
                        else:
                            if db.in_transaction():
                                await db.rollback()
                            if connection.closed or connection.invalidated:
                                raise RuntimeError(
                                    "Release connection was lost before ownership cleanup"
                                )
                            for key in reversed(acquired):
                                if (
                                    await db.scalar(
                                        text("SELECT pg_advisory_unlock(CAST(:key AS bigint))"),
                                        {"key": key},
                                    )
                                    is not True
                                ):
                                    raise RuntimeError(
                                        "Release lease ownership could not be confirmed at cleanup"
                                    )
                            await db.commit()
                except BaseException:
                    await connection.invalidate()
                    raise
        await _check_authority(authority)
        return result
    except ArtifactUnavailable:
        await _check_authority(authority)
        raise HTTPException(409, "Retained release records require coordinated recovery") from None
    except HTTPException:
        await _check_authority(authority)
        raise
    except (SQLAlchemyError, TimeoutError, ConnectionError, RuntimeError):
        await _check_authority(authority)
        raise HTTPException(
            503,
            "Release outcome could not be confirmed; inspect the same operation before retrying",
        ) from None
    finally:
        _OPERATIONS.release()


async def execute_release_reservation(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleasePublicationRequest,
    budget: ReleaseReservationBudget,
    action: str,
) -> ReleaseReservationResult:
    """Reserve/replay or cancel exact intent; never return a storage grant.

    The budget is server policy, not a client override. Ownership and all error
    handling are shared with the private preparation coordinator. No existing
    public endpoint is converted by this internal extraction.
    """
    if (
        type(request) is not ReleasePublicationRequest
        or type(budget) is not ReleaseReservationBudget
        or action not in ("reserve", "cancel")
    ):
        raise HTTPException(422, "Invalid release reservation command")

    async def execute(
        owner: _OperationOwner[ReleasePublicationRequest],
    ) -> ReleaseReservationResult:
        row, created = await (owner.reserve(budget) if action == "reserve" else owner.cancel())
        return ReleaseReservationResult(
            row["operation_id"],
            row["release_id"],
            row["phase"],
            row["decision"],
            created,
            row["requested_by"],
            row["last_transition_by"],
        )

    return await _execute_owned(authority=authority, request=request, function=execute)
