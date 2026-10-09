# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private atomic unpublication; no filesystem deletion or cleanup grant.

An acknowledged target-bound reservation precedes the transaction which deletes
the release row and records its decision. Retry inspects that decision; it never
deletes a replacement row or interprets missing data as its own successful write.
Owned, external and legacy targets have explicit retained cleanup dispositions.
No old endpoint is converted or enabled by this unregistered internal service.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import ReleaseOperationRecord, _record
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_operation_status import _check_predecessor
from app.services.agent_release_request import ReleaseReservationBudget
from app.services.agent_release_reservation import _execute_owned, _OperationOwner

type DeleteOwner = _OperationOwner[ReleaseDeletionRequest]


@dataclass(frozen=True)
class ReleaseDeletionResult:
    operation_id: UUID
    release_id: UUID
    phase: str
    decision: str | None
    newly_changed: bool
    cleanup_disposition: str
    bytes_removed: bool = False
    cleanup_authorized: bool = False


def _result(row: ReleaseOperationRecord, *, changed: bool) -> ReleaseDeletionResult:
    if row["decision"] == "cancelled":
        disposition = "preserve-live"
    elif row["decision"] == "deleted":
        disposition = {
            "owned": "pending-owned-verification",
            "external": "no-owned-file",
            "legacy": "retain-unverified",
        }[row["storage_kind"]]
    else:
        disposition = "not-authorized"
    return ReleaseDeletionResult(
        row["operation_id"], row["release_id"], row["phase"], row["decision"], changed, disposition
    )


async def _publication(db: AsyncSession, release_id: UUID) -> ReleaseOperationRecord | None:
    value = (
        (
            await db.execute(
                select(AgentReleaseOperation.__table__).where(
                    AgentReleaseOperation.kind == "publish",
                    AgentReleaseOperation.release_id == release_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    return _record(value) if value is not None else None


async def _load(owner: DeleteOwner, db: AsyncSession) -> ReleaseOperationRecord | None:
    value = (
        (
            await db.execute(
                select(AgentReleaseOperation.__table__).where(
                    AgentReleaseOperation.operation_id == owner.request.operation_id
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if value is None:
        return None
    owner.authority.require_scope(value["organization_id"])
    row = _record(value)
    metadata = owner.request.metadata()
    expected = {
        "kind": "delete",
        "release_id": owner.request.release_id,
        "organization_id": owner.request.organization_id,
        "request_bytes": owner.request.request_bytes(),
        "request_sha256": owner.request.request_sha256(),
        "expected_sha256": metadata["checksum_sha256"].lower(),
        "expected_size": metadata["file_size"],
    }
    if any(cast(Mapping[str, object], row)[name] != value for name, value in expected.items()):
        raise HTTPException(409, "Operation identity is already bound to another deletion target")
    if row["storage_kind"] == "owned":
        _check_predecessor(row, await _publication(db, row["release_id"]))
    return row


async def _target(owner: DeleteOwner, db: AsyncSession) -> RowMapping | None:
    release = (
        (
            await db.execute(
                select(AgentRelease.__table__).where(AgentRelease.id == owner.request.release_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if release is None:
        return None
    owner.authority.require_scope(release["organization_id"])
    if not owner.request.matches(release):
        raise HTTPException(
            409, "Release changed since deletion was reviewed; inspect a fresh target"
        )
    return release


def _storage(
    release: RowMapping, prior: ReleaseOperationRecord | None
) -> tuple[Literal["owned", "external", "legacy"], UUID | None]:
    if prior is not None:
        if (
            prior["phase"] != "decided"
            or prior["decision"] != "published"
            or prior["organization_id"] != release["organization_id"]
            or prior["expected_sha256"] != release["checksum_sha256"].lower()
            or prior["expected_size"] != release["file_size"]
        ):
            raise HTTPException(409, "Release conflicts with its publication history")
        if prior["storage_kind"] == "owned":
            if (
                release["download_url"] != f"/api/v1/agents/releases/{release['id']}/binary"
                or release["filename"] is None
            ):
                raise HTTPException(
                    409, "Managed artifact association changed; inspect recovery state"
                )
            return "owned", prior["artifact_id"]
        if release["filename"] is not None:
            raise HTTPException(409, "External publication unexpectedly claims a local filename")
        return "external", None
    # No publication association means no owned artifact identity may be invented.
    # Treat relative/malformed/non-web locations conservatively as legacy.
    # Never turn a caller URL into a local pathname or an owned object reference.
    try:
        location = urlsplit(release["download_url"])
        remote = location.scheme.lower() in ("https", "http") and bool(location.hostname)
    except ValueError:
        remote = False
    if release["filename"] is not None or not remote:
        return "legacy", None
    return "external", None


async def _reserve(
    owner: DeleteOwner, budget: ReleaseReservationBudget
) -> tuple[ReleaseOperationRecord, bool]:
    async def reserve(db: AsyncSession) -> tuple[ReleaseOperationRecord, bool]:
        row = await _load(owner, db)
        if row is not None:
            return row, False
        release = await _target(owner, db)
        if release is None:
            raise HTTPException(404, "Release not found; absence is not a deletion decision")
        c = AgentReleaseOperation.__table__.c
        pending = await db.scalar(
            select(c.operation_id).where(
                c.release_id == release["id"], c.phase.in_(("reserved", "prepared"))
            )
        )
        if pending is not None:
            raise HTTPException(409, "Release has another unresolved operation")
        # COUNT and clock_timestamp each produce one non-null scalar row.
        total = cast(int, await db.scalar(select(func.count()).select_from(AgentReleaseOperation)))
        scoped = cast(
            int,
            await db.scalar(
                select(func.count())
                .select_from(AgentReleaseOperation)
                .where(c.organization_id.is_not_distinct_from(release["organization_id"]))
            ),
        )
        if total >= budget.global_history or scoped >= budget.organization_history:
            raise HTTPException(
                409, "Retained release history capacity requires operator resolution"
            )
        storage, artifact_id = _storage(release, await _publication(db, release["id"]))
        row = {
            "operation_id": owner.request.operation_id,
            "format_version": 1,
            "kind": "delete",
            "release_id": release["id"],
            "organization_id": release["organization_id"],
            "requested_by": owner.authority.actor_id,
            "storage_kind": storage,
            "artifact_id": artifact_id,
            "request_bytes": owner.request.request_bytes(),
            "request_sha256": owner.request.request_sha256(),
            "expected_sha256": release["checksum_sha256"].lower(),
            "expected_size": release["file_size"],
            "phase": "reserved",
            "decision": None,
            "transition_sequence": 0,
            "created_at": cast(datetime, await db.scalar(select(func.clock_timestamp()))),
            "prepared_at": None,
            "decided_at": None,
            "cleaned_at": None,
            "last_transition_by": owner.authority.actor_id,
        }
        _record(row)
        await db.execute(insert(AgentReleaseOperation).values(**row))
        return row, True

    return await owner.phase(reserve)


async def _delete(owner: DeleteOwner) -> ReleaseDeletionResult:
    async def decide(db: AsyncSession) -> ReleaseDeletionResult:
        row = await _load(owner, db)
        if row is None:
            raise HTTPException(404, "Deletion reservation not found")
        if row["decision"] == "deleted":
            # Historical result only; never delete any later replacement row.
            return _result(row, changed=False)
        if row["phase"] not in ("reserved", "prepared") or row["decision"] is not None:
            raise HTTPException(409, "Deletion operation is already decided")
        release = await _target(owner, db)
        if release is None:
            raise HTTPException(
                409, "Target disappeared before this deletion decision; inspect recovery state"
            )
        storage, artifact_id = _storage(release, await _publication(db, release["id"]))
        if (storage, artifact_id) != (row["storage_kind"], row["artifact_id"]):
            raise HTTPException(409, "Release storage association changed")
        if row["phase"] == "reserved":
            # Preparation here means exact SQL target/association validation,
            # not file readback. Cleanup still needs independent file evidence.
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
            row = _record({**row, **change})
        removed = (
            await db.execute(
                delete(AgentRelease)
                .where(AgentRelease.id == row["release_id"])
                .returning(AgentRelease.id)
            )
        ).scalar_one()
        if removed != row["release_id"]:
            raise HTTPException(409, "Deletion target changed")
        change = {
            "phase": "decided",
            "decision": "deleted",
            "transition_sequence": 2,
            "decided_at": await db.scalar(select(func.clock_timestamp())),
            "last_transition_by": owner.authority.actor_id,
        }
        await db.execute(
            update(AgentReleaseOperation)
            .where(AgentReleaseOperation.operation_id == row["operation_id"])
            .values(**change)
        )
        return _result(_record({**row, **change}), changed=True)

    return await owner.phase(decide, release_write=True)


async def _cancel(owner: DeleteOwner) -> ReleaseDeletionResult:
    async def cancel(db: AsyncSession) -> ReleaseDeletionResult:
        row = await _load(owner, db)
        if row is None:
            raise HTTPException(
                404, "Deletion reservation not found; cancellation cannot create one"
            )
        if row["decision"] == "cancelled":
            return _result(row, changed=False)
        if row["phase"] not in ("reserved", "prepared") or row["decision"] is not None:
            raise HTTPException(409, "Confirmed deletion cannot be cancelled")
        change = {
            "phase": "decided",
            "decision": "cancelled",
            "transition_sequence": row["transition_sequence"] + 1,
            "decided_at": await db.scalar(select(func.clock_timestamp())),
            "last_transition_by": owner.authority.actor_id,
        }
        await db.execute(
            update(AgentReleaseOperation)
            .where(AgentReleaseOperation.operation_id == row["operation_id"])
            .values(**change)
        )
        return _result(_record({**row, **change}), changed=True)

    return await owner.phase(cancel)


async def execute_release_deletion(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleaseDeletionRequest,
    budget: ReleaseReservationBudget,
    action: str,
) -> ReleaseDeletionResult:
    """Reserve/delete or cancel exactly reviewed metadata; remove no file bytes."""
    if (
        type(request) is not ReleaseDeletionRequest
        or type(budget) is not ReleaseReservationBudget
        or action not in ("reserve", "delete", "cancel")
    ):
        raise HTTPException(422, "Invalid release deletion command")

    async def execute(owner: DeleteOwner) -> ReleaseDeletionResult:
        if action == "cancel":
            return await _cancel(owner)
        row, created = await _reserve(owner, budget)
        if action == "reserve":
            return _result(row, changed=created)
        return await _delete(owner)

    return await _execute_owned(authority=authority, request=request, function=execute)
