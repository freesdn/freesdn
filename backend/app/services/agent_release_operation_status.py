# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Authenticated journal inspection, without filesystem or mutation authority.

One owned transaction briefly excludes journal/release writers, including SQL
writers that do not use advisory locks. It never waits for those table locks.
The observation is historical when returned. In particular, an absent release
row is NOT absence of every artifact reference, cancellation, safe cleanup or
permission to retry a lost write. The mutation coordinator must retain its own
operation and artifact ownership through each transition and filesystem action.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.services.agent_release_artifact_store import ArtifactUnavailable
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import (
    ReleaseOperationInput,
    ReleaseOperationRecord,
    _record,
)

_READERS = threading.BoundedSemaphore(8)
_PUBLIC_FIELDS = (
    "operation_id",
    "release_id",
    "organization_id",
    "requested_by",
    "kind",
    "storage_kind",
    "phase",
    "decision",
    "transition_sequence",
    "created_at",
    "prepared_at",
    "decided_at",
    "cleaned_at",
    "last_transition_by",
)


@dataclass(frozen=True)
class ReleaseOperationSnapshot:
    # Only the allowlisted public projection survives the transaction. Raw
    # request bytes, artifact identifiers and planner decisions never escape.
    operation: tuple[tuple[str, object], ...]
    release_row_present: bool
    observed_at: datetime

    def public(self) -> dict[str, object]:
        row = dict(self.operation)
        return {
            "operation": row,
            "release_row_present": self.release_row_present,
            "observed_at": self.observed_at,
            "storage_checked": False,
            "all_artifact_references_checked": False,
            "authorization_granted": False,
            "absence_authorizes_retry_or_cleanup": False,
        }


async def _check_authority(authority: ReleaseMutationAuthority) -> None:
    authority.validate(await authority._read())
    # validate() reads the clock after I/O; it does not authenticate an API key
    # or commit its last_used while a caller holds database locks.


def _check_predecessor(row: ReleaseOperationRecord, original: ReleaseOperationInput | None) -> None:
    if row["kind"] != "delete" or row["storage_kind"] != "owned":
        return
    if original is None:
        raise ArtifactUnavailable("Owned deletion has no publication history")
    prior = _record(original)
    if (
        prior["kind"] != "publish"
        or prior["storage_kind"] != "owned"
        or prior["phase"] != "decided"
        or prior["decision"] != "published"
        or prior["operation_id"] == row["operation_id"]
        or any(
            cast(Mapping[str, object], prior)[name] != cast(Mapping[str, object], row)[name]
            for name in (
                "release_id",
                "organization_id",
                "artifact_id",
                "expected_sha256",
                "expected_size",
            )
        )
    ):
        raise ArtifactUnavailable("Owned deletion conflicts with publication history")


async def _read_snapshot(
    authority: ReleaseMutationAuthority, operation_id: UUID
) -> ReleaseOperationSnapshot:
    deadline = anyio.current_time() + 5
    async with AsyncExitStack() as cleanup:
        with anyio.fail_after(5):
            connection = await cleanup.enter_async_context(sessions.security_engine.connect())
            db = await cleanup.enter_async_context(
                AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
            )
            async with db.begin():
                # No caller session or transaction is accepted. READ COMMITTED
                # takes a fresh snapshot after the table locks are granted.
                await db.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                await db.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                await db.execute(text("SET LOCAL lock_timeout = '500ms'"))
                await db.execute(
                    text(
                        "LOCK TABLE agents.agent_release_operations, agents.agent_releases "
                        "IN SHARE MODE NOWAIT"
                    )
                )
                fence = await authority.lock(db)
                value = (
                    (
                        await db.execute(
                            select(AgentReleaseOperation.__table__).where(
                                AgentReleaseOperation.operation_id == operation_id
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if value is None:
                    # A 404 conveys no recovery grant, even with table exclusion.
                    raise HTTPException(404, "Release operation not found")
                authority.require_scope(value["organization_id"])
                row = _record(value)
                original = None
                if row["kind"] == "delete" and row["storage_kind"] == "owned":
                    original = (
                        (
                            await db.execute(
                                select(AgentReleaseOperation.__table__).where(
                                    AgentReleaseOperation.kind == "publish",
                                    AgentReleaseOperation.release_id == row["release_id"],
                                )
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                _check_predecessor(row, original)
                release = (
                    await db.execute(
                        select(AgentRelease.organization_id).where(
                            AgentRelease.id == row["release_id"]
                        )
                    )
                ).one_or_none()
                if release is not None and release.organization_id != row["organization_id"]:
                    raise ArtifactUnavailable("Release scope conflicts with retained history")
                # The scalar PostgreSQL clock expression always yields one datetime.
                observed_at = cast(datetime, await db.scalar(select(func.clock_timestamp())))
                await fence.recheck()
                result = ReleaseOperationSnapshot(
                    tuple((name, cast(Mapping[str, object], row)[name]) for name in _PUBLIC_FIELDS),
                    release is not None,
                    observed_at,
                )
    # Cleanup is owned and drained, not abandoned when a timed block expires.
    if anyio.current_time() >= deadline:
        raise TimeoutError("Release inspection exceeded its deadline")
    return result


@complete_before_cancellation
async def inspect_release_operation(
    authority: ReleaseMutationAuthority,
    *,
    operation_id: UUID,
) -> ReleaseOperationSnapshot:
    """Report a scoped retained decision; never issue a reusable cleanup grant.

    A fresh authorized credential may inspect another requester's operation within
    its current scope. Both the original and latest transition actor are retained.
    This function changes no journal/release rows and touches no artifact/key files.
    """
    if type(authority) is not ReleaseMutationAuthority:
        raise HTTPException(403, "Current release authority is required")
    if type(operation_id) is not UUID or operation_id.int == 0:
        raise HTTPException(422, "Invalid release operation identity")
    await _check_authority(authority)
    if not _READERS.acquire(blocking=False):
        raise HTTPException(503, "Release inspection capacity is busy")
    try:
        try:
            snapshot = await _read_snapshot(authority, operation_id)
        except DBAPIError as error:
            await _check_authority(authority)
            state = getattr(error.orig, "sqlstate", None) or getattr(error.orig, "pgcode", None)
            if state == "55P03":
                raise HTTPException(409, "Release state is busy; retry inspection") from None
            raise HTTPException(
                503, "Release state unavailable; no recovery decision can be inferred"
            ) from None
        except TimeoutError:
            await _check_authority(authority)
            raise HTTPException(
                503, "Release state unavailable; no recovery decision can be inferred"
            ) from None
        except ArtifactUnavailable:
            await _check_authority(authority)
            raise HTTPException(
                409, "Retained release records require coordinated recovery"
            ) from None
        except HTTPException:
            await _check_authority(authority)
            raise
        # Recheck after transaction/connection cleanup before disclosing even a
        # conflict. A captured user object cannot authorize a late response.
        await _check_authority(authority)
        return snapshot
    finally:
        _READERS.release()
