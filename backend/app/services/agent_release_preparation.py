# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private owned upload/prepared-state coordination; no public route enables it.

The operation's physical database connection and exclusive filesystem lifetime
remain owned across every worker call and the final prepared-state commit. No
SQL transaction or account/table lock spans stream or filesystem work. Existing
upload/delete writers must be drained before this protocol can be enabled.

Preparation is not publication, a signature, delivery authority or safe cleanup.
Failure preserves bytes/history. An explicit resume verifies retained prepared
bytes; it never restarts a partial upload or infers rollback from a driver error.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import partial
from typing import Literal, cast, overload
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import exists, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.core import Organization
from app.services.agent_release_artifact_store import (
    ArtifactIntent,
    ArtifactLease,
    PreparedArtifact,
)
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import ReleaseOperationRecord, _record
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from app.services.agent_release_reservation import _execute_owned, _OperationOwner


@dataclass(frozen=True)
class ReleasePreparationResult:
    operation_id: UUID
    release_id: UUID
    phase: str
    requested_by: UUID
    last_transition_by: UUID
    # Always false: the filesystem lease has closed before this leaves the call.
    publication_or_storage_authorized: bool = False


def _intent(request: ReleasePublicationRequest) -> ArtifactIntent:
    metadata = request.metadata()
    return ArtifactIntent(
        request.operation_id,
        request.operation_id,
        request.release_id,
        request.request_sha256(),
        metadata["checksum_sha256"],
        metadata["file_size"],
    )


async def _pending(
    owner: _OperationOwner[ReleasePublicationRequest], db: AsyncSession
) -> ReleaseOperationRecord:
    row = await owner._load(db)
    if row is None:
        raise HTTPException(404, "Acknowledged release reservation not found")
    if row["phase"] not in ("reserved", "prepared") or row["decision"] is not None:
        raise HTTPException(409, "Release operation is already decided; inspect retained state")
    if row["storage_kind"] != "owned":
        raise HTTPException(409, "This preparation requires an owned artifact")
    if row["organization_id"] is not None:
        destination = (
            await db.execute(
                select(Organization.id)
                .where(
                    Organization.id == row["organization_id"],
                    Organization.deleted_at.is_(None),
                    Organization.is_active.is_(True),
                )
                .with_for_update(read=True, nowait=True)
            )
        ).one_or_none()
        if destination is None:
            raise HTTPException(404, "Live destination organization not found")
    if await db.scalar(select(exists().where(AgentRelease.id == row["release_id"]))):
        raise HTTPException(
            409, "Pending artifact conflicts with a live release; inspect recovery state"
        )
    return row


async def _preparation_state(
    owner: _OperationOwner[ReleasePublicationRequest],
) -> ReleaseOperationRecord:
    async def inspect(db: AsyncSession) -> ReleaseOperationRecord:
        return await _pending(owner, db)

    return await owner.phase(inspect)


async def _record_prepared(
    owner: _OperationOwner[ReleasePublicationRequest], receipt: PreparedArtifact
) -> ReleaseOperationRecord:
    # This internal receipt must come from the retained lease's actual readback.
    # It is never accepted as request JSON or as a detached authorization proof.
    if type(receipt) is not PreparedArtifact or receipt.intent != _intent(owner.request):
        raise HTTPException(409, "Prepared artifact differs from this reservation")

    async def transition(db: AsyncSession) -> ReleaseOperationRecord:
        row = await _pending(owner, db)
        if row["phase"] == "prepared":
            return row
        change = {
            "phase": "prepared",
            "transition_sequence": 1,
            "prepared_at": await db.scalar(select(func.clock_timestamp())),
            "last_transition_by": owner.authority.actor_id,
        }
        await db.execute(
            update(AgentReleaseOperation)
            .where(AgentReleaseOperation.operation_id == row["operation_id"])
            .values(**change)
        )
        return _record({**row, **change})

    return await owner.phase(transition)


class _PreparationStorage:
    """Retain the acquired lease inside its worker, including lost await results.

    Calls are sequential within the separately owned operation. Non-abandoned
    workers finish before closure and database-lease cleanup. This cannot promise
    to interrupt a stuck kernel syscall; the synchronous store's limits still
    apply, and shutdown/power loss requires separate recovery qualification.
    """

    def __init__(self) -> None:
        self.lease: ArtifactLease | None = None

    def _acquire(self, root: str, intent: ArtifactIntent, create: bool) -> None:
        self.lease = ArtifactLease.acquire(root, intent, mode="exclusive", create=create)

    async def acquire(self, root: str, intent: ArtifactIntent, *, create: bool) -> None:
        await anyio.to_thread.run_sync(
            partial(self._acquire, root, intent, create), abandon_on_cancel=False
        )

    @overload
    async def run(self, method: Literal["begin"]) -> None: ...

    @overload
    async def run(self, method: Literal["append"], chunk: bytes, /) -> None: ...

    @overload
    async def run(self, method: Literal["finish", "verify_prepared"]) -> PreparedArtifact: ...

    async def run(self, method: str, *args: object) -> PreparedArtifact | None:
        if self.lease is None or method not in ("begin", "append", "finish", "verify_prepared"):
            raise HTTPException(503, "Artifact preparation ownership is unavailable")
        # The whitelist above dispatches only these four typed ArtifactLease
        # methods. Workers remain owned until the original completion boundary.
        return cast(
            PreparedArtifact | None,
            await anyio.to_thread.run_sync(
                partial(getattr(self.lease, method), *args), abandon_on_cancel=False
            ),
        )

    async def close(self) -> None:
        if self.lease is not None:
            await anyio.to_thread.run_sync(self.lease.close, abandon_on_cancel=False)


async def _prepare_under_owner(
    owner: _OperationOwner[ReleasePublicationRequest],
    *,
    root: str,
    source: AsyncIterator[bytes] | None,
    mode: str,
) -> ReleasePreparationResult:
    """Leave the SQL owner alive until every artifact worker and closure drains."""
    row = await _preparation_state(owner)
    if mode == "upload" and row["phase"] != "reserved":
        raise HTTPException(409, "Prepared bytes already exist; resume without uploading again")
    storage = _PreparationStorage()
    try:
        # The owned callback is shielded from request cancellation. This timeout
        # bounds cooperative body reads; worker draining may exceed the deadline.
        with anyio.fail_after(max(0, owner.deadline - anyio.current_time())):
            await storage.acquire(root, _intent(owner.request), create=mode == "upload")
            await _preparation_state(owner)
            if mode == "upload":
                await storage.run("begin")
                # The entry point requires an AsyncIterator for upload mode.
                async for chunk in cast(AsyncIterator[bytes], source):
                    await anyio.lowlevel.checkpoint()
                    if type(chunk) is not bytes or len(chunk) > 1048576:
                        raise HTTPException(413, "Artifact stream chunk exceeds its bound")
                    if not chunk:
                        continue
                    # Never retain row locks while awaiting a client/worker.
                    # Revalidate after the body wait and before this next write.
                    await _preparation_state(owner)
                    await storage.run("append", chunk)
                await _preparation_state(owner)
                receipt = await storage.run("finish")
            else:
                receipt = await storage.run("verify_prepared")
            # The exclusive filesystem lease still spans this actual SQL commit.
            # An uncertain commit does not unlink or automatically replay either.
            row = await _record_prepared(owner, receipt)
    finally:
        with anyio.CancelScope(shield=True):
            await storage.close()
    return ReleasePreparationResult(
        row["operation_id"],
        row["release_id"],
        row["phase"],
        row["requested_by"],
        row["last_transition_by"],
    )


async def execute_release_preparation(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleasePublicationRequest,
    budget: ReleaseReservationBudget,
    root: str,
    mode: str,
    source: AsyncIterator[bytes] | None = None,
) -> ReleasePreparationResult:
    """Reserve and upload, or explicitly verify/resume the same owned artifact.

    Root/budget are provisioned server policy, never caller-controlled paths or
    JSON overrides. The bounded chunk source is the future route's owned upload;
    ingress/multipart limits and supported retry/UI remain integration work.
    A resume cannot allocate a missing operation or object. No release row is
    published/deleted, no file is removed, and no signing key is opened here.
    """
    if (
        type(request) is not ReleasePublicationRequest
        or request.storage_kind != "owned"
        or type(budget) is not ReleaseReservationBudget
        or type(root) is not str
        or mode not in ("upload", "resume")
        or (mode == "upload" and not isinstance(source, AsyncIterator))
        or (mode == "resume" and source is not None)
    ):
        raise HTTPException(422, "Invalid owned artifact preparation command")

    async def execute(
        owner: _OperationOwner[ReleasePublicationRequest],
    ) -> ReleasePreparationResult:
        if mode == "upload":
            # Only an acknowledged reservation leads to filesystem mutation.
            await owner.reserve(budget)
        try:
            return await _prepare_under_owner(owner, root=root, source=source, mode=mode)
        except OSError:
            raise HTTPException(
                503, "Artifact storage unavailable; preserve bytes and inspect the same operation"
            ) from None

    return await _execute_owned(authority=authority, request=request, function=execute)
