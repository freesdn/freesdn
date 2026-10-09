# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Read-only intent review: exact operator document, never a recovery capability.

No reservation, artifact access or server-side full-intent persistence occurs.
A database commitment cannot recover lost metadata. A current deletion target
can be reviewed for a new operation, but cannot replace an existing operation's
original intent. Mutators independently check every condition on execution.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TypedDict, Unpack, cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import ColumnElement, Select, and_, case, func, or_, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.schemas.agent_release_operations import encode_release_command
from app.services.agent_release_artifact_store import ArtifactUnavailable
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import ReleaseOperationRecord, _record
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_operation_status import _PUBLIC_FIELDS, _check_authority
from app.services.agent_release_request import ReleasePublicationRequest, _uuid

_READERS = threading.BoundedSemaphore(8)
_TEXT_BOUNDS = {
    "version": 50,
    "platform": 50,
    "agent_type": 50,
    "download_url": 500,
    "checksum_sha256": 64,
    "release_notes": 20000,
    "min_backend_version": 50,
    "filename": 128,
    "signature": 4096,
}

type ReviewCommand = ReleasePublicationRequest | ReleaseDeletionRequest


class ReviewArguments(TypedDict, total=False):
    command: ReviewCommand
    release_id: UUID
    operation_id: UUID


@dataclass(frozen=True, repr=False)
class ReleaseIntentReview:
    intent_bytes: bytes
    intent_sha256: str
    operation: tuple[tuple[str, object], ...] | None
    release_row_present: bool
    deletion_target_matches: bool | None
    observed_at: datetime

    def public(self) -> dict[str, object]:
        return {
            "intent": json.loads(self.intent_bytes),
            "intent_sha256": self.intent_sha256,
            "operation": dict(self.operation) if self.operation is not None else None,
            "release_row_present": self.release_row_present,
            "deletion_target_matches": self.deletion_target_matches,
            "observed_at": self.observed_at,
            "historical_observation": True,
            "authorization_granted": False,
            "storage_checked": False,
            "all_artifact_references_checked": False,
            "absence_authorizes_retry_or_cleanup": False,
            "reservation_created": False,
            "server_retains_full_intent": False,
            "save_original_intent_before_mutation": True,
            "retry_requires_identical_intent_and_current_authority": True,
        }


def _target_statement(release_id: UUID | None) -> Select[*tuple[Any, ...]]:
    # Bound text in SQL before transfer, including legacy Text columns. Refuse
    # the complete record if unrepresentable; never truncate reviewed metadata.
    c = AgentRelease.__table__.c
    fields: list[ColumnElement[Any]]
    bounds: list[ColumnElement[bool]]
    fields, bounds = [c.id, c.organization_id], []
    for name, limit in _TEXT_BOUNDS.items():
        column = c[name]
        valid = and_(func.char_length(column) <= limit, func.octet_length(column) <= limit * 4)
        if name in ("filename", "signature"):
            valid = or_(column.is_(None), valid)
        bounds.append(func.coalesce(valid, False))
        fields.append(case((valid, column), else_=None).label(name))
    fields.extend(
        [
            c.file_size,
            c.is_prerelease,
            c.is_latest,
            c.published_at,
            and_(*bounds).label("representable_text"),
        ]
    )
    return select(*fields).where(c.id == release_id)


async def _read_review(
    authority: ReleaseMutationAuthority,
    *,
    command: ReviewCommand | None = None,
    release_id: UUID | None = None,
    operation_id: UUID | None = None,
) -> ReleaseIntentReview:
    deadline = anyio.current_time() + 5
    async with AsyncExitStack() as cleanup:
        with anyio.fail_after(5):
            connection = await cleanup.enter_async_context(sessions.security_engine.connect())
            db = await cleanup.enter_async_context(
                AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
            )
            async with db.begin():
                await db.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                await db.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                await db.execute(text("SET LOCAL lock_timeout = '500ms'"))
                await db.execute(
                    text(
                        "LOCK TABLE agents.agent_release_operations, agents.agent_releases IN SHARE MODE NOWAIT"
                    )
                )
                fence = await authority.lock(db)
                if command is not None:
                    authority.require_scope(command.organization_id)
                    release_id, operation_id = command.release_id, command.operation_id
                release = (await db.execute(_target_statement(release_id))).mappings().one_or_none()
                if release is not None:
                    authority.require_scope(release["organization_id"])
                if command is None:
                    if release is None:
                        raise HTTPException(
                            404,
                            "Release not found; retain the original intent for any existing operation",
                        )
                    if not release["representable_text"]:
                        raise ArtifactUnavailable(
                            "Deletion target requires explicit metadata repair"
                        )
                    command = ReleaseDeletionRequest.capture(
                        # The deletion-review entry point validates both IDs
                        # before this branch; command-review supplies its IDs.
                        operation_id=cast(UUID, operation_id),
                        release=release,
                    )
                elif release is not None and release["organization_id"] != command.organization_id:
                    raise HTTPException(409, "Release scope differs from the supplied intent")
                operation = (
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
                row: ReleaseOperationRecord | None = None
                if operation is not None:
                    authority.require_scope(operation["organization_id"])
                    row = _record(operation)
                    metadata = command.metadata()
                    if (
                        row["request_bytes"] != command.request_bytes()
                        or row["request_sha256"] != command.request_sha256()
                        or row["release_id"] != command.release_id
                        or row["organization_id"] != command.organization_id
                        or row["kind"]
                        != ("delete" if type(command) is ReleaseDeletionRequest else "publish")
                        or row["expected_sha256"] != metadata["checksum_sha256"].lower()
                        or row["expected_size"] != metadata["file_size"]
                        or (
                            type(command) is ReleasePublicationRequest
                            and row["storage_kind"] != command.storage_kind
                        )
                    ):
                        raise HTTPException(
                            409,
                            "Operation identity already binds a different intent; retain its original document",
                        )
                matches: bool | None = None
                if type(command) is ReleaseDeletionRequest:
                    matches = (
                        release is not None
                        and release["representable_text"]
                        and command.matches(release)
                    )
                stamp = cast(datetime, await db.scalar(select(func.clock_timestamp())))
                result = ReleaseIntentReview(
                    encode_release_command(command),
                    command.request_sha256(),
                    tuple((name, cast(Mapping[str, object], row)[name]) for name in _PUBLIC_FIELDS)
                    if row is not None
                    else None,
                    release is not None,
                    matches,
                    stamp,
                )
                await fence.recheck()
    if anyio.current_time() >= deadline:
        raise TimeoutError("Release review exceeded its deadline")
    return result


@complete_before_cancellation
async def _review(
    authority: ReleaseMutationAuthority, **arguments: Unpack[ReviewArguments]
) -> ReleaseIntentReview:
    if type(authority) is not ReleaseMutationAuthority:
        raise HTTPException(403, "Current release authority is required")
    await _check_authority(authority)
    if not _READERS.acquire(blocking=False):
        raise HTTPException(503, "Release review capacity is busy")
    try:
        try:
            result = await _read_review(authority, **arguments)
        except DBAPIError as error:
            await _check_authority(authority)
            state = getattr(error.orig, "sqlstate", None) or getattr(error.orig, "pgcode", None)
            if state == "55P03":
                raise HTTPException(
                    409, "Release state is busy; repeat review explicitly"
                ) from None
            raise HTTPException(
                503, "Release review unavailable; no recovery decision can be inferred"
            ) from None
        except TimeoutError:
            await _check_authority(authority)
            raise HTTPException(
                503, "Release review unavailable; no recovery decision can be inferred"
            ) from None
        except (ArtifactUnavailable, ValueError, TypeError, KeyError, RecursionError):
            await _check_authority(authority)
            raise HTTPException(
                409, "Retained release metadata requires coordinated recovery"
            ) from None
        except HTTPException:
            await _check_authority(authority)
            raise
        await _check_authority(authority)
        return result
    finally:
        _READERS.release()


async def review_release_intent(
    authority: ReleaseMutationAuthority, *, command: ReviewCommand
) -> ReleaseIntentReview:
    if type(command) not in (ReleasePublicationRequest, ReleaseDeletionRequest):
        raise HTTPException(422, "Validated release intent required")
    return await _review(authority, command=command)


async def review_deletion_target(
    authority: ReleaseMutationAuthority, *, release_id: UUID, operation_id: UUID
) -> ReleaseIntentReview:
    try:
        _uuid(release_id)
        _uuid(operation_id)
    except ValueError:
        raise HTTPException(422, "Valid release and operation identities are required") from None
    return await _review(authority, release_id=release_id, operation_id=operation_id)
