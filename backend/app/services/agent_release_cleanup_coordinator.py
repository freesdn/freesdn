# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private cleanup of exact committed decisions under SQL and file ownership.

Not registered by any public endpoint. Requires the qualified managed-only
reader/writer installation and independent recovery of unknown restore state.
No row/path absence, exception, age or caller boolean authorizes destructive work.
Each I/O stage follows fresh native guards, committed history and authority.
The database connection and exclusive file lifetime outlive all drained workers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Literal, cast, overload
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.services.agent_release_artifact_store import (
    ArtifactCleanupDecision,
    ArtifactIntent,
    ArtifactLease,
    CleanedArtifact,
)
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import (
    ReleaseCleanupPlan,
    ReleaseOperationRecord,
    _record,
    plan_release_cleanup,
)
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_deletion import _load as load_deletion
from app.services.agent_release_reference_validation import validate_release_reference_installation
from app.services.agent_release_request import ReleasePublicationRequest
from app.services.agent_release_reservation import _execute_owned, _OperationOwner

type CleanupOwner = _OperationOwner[ReleasePublicationRequest | ReleaseDeletionRequest]


@dataclass(frozen=True)
class ReleaseCleanupResult:
    operation_id: UUID
    release_id: UUID
    phase: str
    decision: str
    disposition: str
    newly_recorded: bool
    payload_absence_verified_this_call: bool
    complete: bool
    authorization_granted: bool = False


async def _inspect_db(
    owner: CleanupOwner, db: AsyncSession
) -> tuple[ReleaseOperationRecord, ReleaseCleanupPlan]:
    connection = await db.connection()
    await connection.run_sync(validate_release_reference_installation)
    row = await (
        cast(_OperationOwner[ReleasePublicationRequest], owner)._load(db)
        if type(owner.request) is ReleasePublicationRequest
        else load_deletion(cast(_OperationOwner[ReleaseDeletionRequest], owner), db)
    )
    if row is None:
        raise HTTPException(404, "Retained cleanup operation not found")
    if row["phase"] not in ("decided", "cleaned") or row["decision"] not in (
        "cancelled",
        "deleted",
    ):
        raise HTTPException(409, "Operation has no confirmed cleanup decision")
    # This native function checks the current retained association/row, not just
    # the revision label or an application-side expectation about installation.
    await db.execute(text("SELECT agents.assert_release_reference(:id)"), {"id": row["release_id"]})
    original: RowMapping | ReleaseOperationRecord | None = None
    c = AgentReleaseOperation.__table__.c
    if row["kind"] == "delete" and row["storage_kind"] == "owned":
        original = (
            (
                await db.execute(
                    select(AgentReleaseOperation.__table__).where(
                        c.release_id == row["release_id"], c.kind == "publish"
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        original = _record(original) if original is not None else None
    if row["storage_kind"] == "owned":
        # Native unique birth identity plus immutable associations define the
        # managed physical-reference graph. Scan all matching history in SQL;
        # return booleans, never an unbounded list of unrelated tenant records.
        wrong = await db.scalar(
            select(
                exists().where(
                    c.artifact_id == row["artifact_id"],
                    (c.release_id != row["release_id"])
                    | c.organization_id.is_distinct_from(row["organization_id"])
                    | (c.expected_sha256 != row["expected_sha256"])
                    | (c.expected_size != row["expected_size"]),
                )
            )
        )
        other_pending = await db.scalar(
            select(
                exists().where(
                    c.artifact_id == row["artifact_id"],
                    c.operation_id != row["operation_id"],
                    c.phase.in_(("reserved", "prepared")),
                )
            )
        )
        if wrong or other_pending:
            raise HTTPException(409, "Artifact has conflicting or unresolved retained ownership")
    # SELECT EXISTS yields one non-null boolean, including when no release exists.
    live = cast(bool, await db.scalar(select(exists().where(AgentRelease.id == row["release_id"]))))
    plan = plan_release_cleanup(operation=row, publication=original, live_reference_present=live)
    return row, plan


async def _state(owner: CleanupOwner) -> tuple[ReleaseOperationRecord, ReleaseCleanupPlan]:
    async def inspect(db: AsyncSession) -> tuple[ReleaseOperationRecord, ReleaseCleanupPlan]:
        return await _inspect_db(owner, db)

    return await owner.phase(inspect)


def _same_plan(expected: ReleaseCleanupPlan, actual: ReleaseCleanupPlan) -> None:
    if expected != actual:
        raise HTTPException(409, "Retained cleanup decision changed; inspect recovery state")


def _result(
    row: ReleaseOperationRecord,
    plan: ReleaseCleanupPlan,
    *,
    newly_recorded: bool = False,
    verified: bool = False,
) -> ReleaseCleanupResult:
    return ReleaseCleanupResult(
        row["operation_id"],
        row["release_id"],
        row["phase"],
        # _inspect_db accepts only confirmed cancelled/deleted cleanup decisions.
        cast(str, row["decision"]),
        plan.outcome,
        newly_recorded,
        verified,
        row["phase"] == "cleaned" and plan.outcome != "retain-unverified",
    )


async def _record_cleaned(
    owner: CleanupOwner,
    expected: ReleaseCleanupPlan,
    *,
    receipt: CleanedArtifact | None = None,
    retirement: str | None = None,
) -> ReleaseCleanupResult:
    async def transition(db: AsyncSession) -> ReleaseCleanupResult:
        row, plan = await _inspect_db(owner, db)
        _same_plan(expected, plan)
        if plan.outcome == "retire-owned":
            # Only the still-owned worker supplies this internal receipt. It is
            # never accepted from a request, status response or stale journal.
            if (
                type(receipt) is not CleanedArtifact
                or plan.decision is None
                or receipt.artifact_id != plan.decision.intent.artifact_id
                or receipt.operation_id != row["operation_id"]
                or receipt.retirement_sha256 != retirement
            ):
                raise HTTPException(409, "Verified cleanup differs from the retained decision")
        elif (
            plan.outcome not in ("preserve-live", "no-owned-file")
            or receipt is not None
            or retirement is not None
        ):
            raise HTTPException(409, "Unverified residuals cannot be marked cleaned")
        if row["phase"] == "cleaned":
            return _result(row, plan, verified=receipt is not None)
        change = {
            "phase": "cleaned",
            "transition_sequence": row["transition_sequence"] + 1,
            "cleaned_at": await db.scalar(select(func.clock_timestamp())),
            "last_transition_by": owner.authority.actor_id,
        }
        await db.execute(
            update(AgentReleaseOperation)
            .where(AgentReleaseOperation.operation_id == row["operation_id"])
            .values(**change)
        )
        return _result(
            _record({**row, **change}), plan, newly_recorded=True, verified=receipt is not None
        )

    return await owner.phase(transition)


class _CleanupStorage:
    """Non-abandoned exclusive workers; closure drains before SQL ownership ends."""

    def __init__(self) -> None:
        self.lease: ArtifactLease | None = None

    def _acquire(self, root: str, intent: ArtifactIntent) -> None:
        # Missing objects remain unavailable evidence, including cancelled
        # reservations. Never fabricate an empty artifact or cleanup tombstone.
        self.lease = ArtifactLease.acquire(root, intent, mode="exclusive", create=False)

    async def acquire(self, root: str, intent: ArtifactIntent) -> None:
        await anyio.to_thread.run_sync(
            partial(self._acquire, root, intent), abandon_on_cancel=False
        )

    @overload
    async def run(self, method: Literal["retire"], decision: ArtifactCleanupDecision) -> str: ...

    @overload
    async def run(
        self, method: Literal["cleanup_retired"], decision: ArtifactCleanupDecision
    ) -> CleanedArtifact: ...

    async def run(self, method: str, decision: ArtifactCleanupDecision) -> str | CleanedArtifact:
        if self.lease is None or method not in ("retire", "cleanup_retired"):
            raise HTTPException(503, "Cleanup file ownership is unavailable")
        return await anyio.to_thread.run_sync(
            # The existing guard permits only the two annotated native methods.
            partial(
                cast(
                    Callable[[ArtifactCleanupDecision], str | CleanedArtifact],
                    getattr(self.lease, method),
                ),
                decision,
            ),
            abandon_on_cancel=False,
        )

    async def close(self) -> None:
        if self.lease is not None:
            await anyio.to_thread.run_sync(self.lease.close, abandon_on_cancel=False)


async def _cleanup_under_owner(owner: CleanupOwner, root: str | None) -> ReleaseCleanupResult:
    row, plan = await _state(owner)
    if plan.outcome != "retire-owned":
        if root is not None:
            raise HTTPException(422, "This cleanup disposition cannot inspect a storage root")
        if plan.outcome == "retain-unverified":
            return _result(row, plan)
        return await _record_cleaned(owner, plan)
    if type(root) is not str or plan.decision is None:
        raise HTTPException(422, "Owned cleanup requires its configured storage root")
    storage = _CleanupStorage()
    try:
        with anyio.fail_after(max(0, owner.deadline - anyio.current_time())):
            await storage.acquire(root, plan.decision.intent)
            _, observed = await _state(owner)
            _same_plan(plan, observed)
            retirement = await storage.run("retire", plan.decision)
            # Retire can verify/hash/fsync substantial storage. Authority and
            # the native/reference state must still hold before destructive work.
            _, observed = await _state(owner)
            _same_plan(plan, observed)
            receipt = await storage.run("cleanup_retired", plan.decision)
            # If this SQL acknowledgment fails, preserve the durable file history
            # and retry the same operation explicitly; never recreate its bytes.
            return await _record_cleaned(owner, plan, receipt=receipt, retirement=retirement)
    except OSError:
        raise HTTPException(
            503, "Artifact cleanup evidence is unavailable; inspect retained state"
        ) from None
    finally:
        with anyio.CancelScope(shield=True):
            await storage.close()


async def execute_release_cleanup(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleasePublicationRequest | ReleaseDeletionRequest,
    root: str | None = None,
) -> ReleaseCleanupResult:
    """Clean only a confirmed exact operation in a qualified managed installation.

    root is trusted server configuration, not request JSON. Missing legacy/owned
    evidence still requires a usable explicit recovery flow before public enablement.
    An in-flight syscall already authorized to start is drained, not retroactively
    cancelled on a later credential change. Final disclosure/bookkeeping rechecks it.
    """
    if type(request) not in (ReleasePublicationRequest, ReleaseDeletionRequest):
        raise HTTPException(422, "Invalid cleanup operation request")

    async def execute(owner: CleanupOwner) -> ReleaseCleanupResult:
        return await _cleanup_under_owner(owner, root)

    return await _execute_owned(authority=authority, request=request, function=execute)


async def execute_managed_release_cleanup(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleasePublicationRequest | ReleaseDeletionRequest,
    root: str,
) -> ReleaseCleanupResult:
    """Select configured storage only from a current, retained server decision.

    The operator API cannot infer ownership from request filenames or URLs.
    Keep the owner across both inspections; the existing cleanup path rechecks
    native references, authority and the disposition before touching storage.
    External, cancelled-delete and legacy decisions never inspect this root.
    """
    if (
        type(request) not in (ReleasePublicationRequest, ReleaseDeletionRequest)
        or type(root) is not str
        or not root.startswith("/")
        or "\x00" in root
    ):
        raise HTTPException(422, "Invalid managed cleanup operation request")

    async def execute(owner: CleanupOwner) -> ReleaseCleanupResult:
        _, plan = await _state(owner)
        selected_root = root if plan.outcome == "retire-owned" else None
        return await _cleanup_under_owner(owner, selected_root)

    return await _execute_owned(authority=authority, request=request, function=execute)
