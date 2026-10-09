# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private durable local signing lifecycle; not yet routed or rollout-qualified.

One explicitly owned physical connection retains global operation ownership
across short commits and owned filesystem workers. Pending commits precede any
key creation; only the invocation that inserts a new initialization can create.
All retries inspect existing material. Old unanchored writers must be drained
and converted before enabling this coordinator in a deployed application.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from functools import partial
from typing import Any
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import exists, func, insert, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing_binding import SigningCommand
from app.core.owned_async import complete_before_cancellation
from app.core.token_blacklist import claim_token_jti
from app.db import session as sessions
from app.models.agent_signing import AgentSigningIdentity, AgentSigningIntent
from app.models.agents import AgentRelease, RemoteAgent
from app.services import release_signing, release_signing_async
from app.services.agent_signing_authority import FreshSigningFactor
from app.services.agent_signing_commit_fence import lock_current_signing_authority

_OPERATION_LOCK = 0x5349474E4C494645
_OPERATIONS = threading.BoundedSemaphore(1)


@dataclass(frozen=True)
class SigningOperationResult:
    operation_id: UUID
    installation_id: UUID
    identity_epoch: int
    state: str
    public_key_sha256: str | None


def _result(intent: Mapping[str, Any]) -> SigningOperationResult:
    return SigningOperationResult(
        intent["operation_id"],
        intent["installation_id"],
        intent["identity_epoch"],
        intent["state"],
        intent["public_key_sha256"],
    )


def _same_operation(intent: RowMapping | Mapping[str, Any], command: SigningCommand) -> None:
    if (
        intent["operation_id"] != command.operation_id
        or intent["installation_id"] != command.installation_id
        or intent["identity_epoch"] != command.identity_epoch
    ):
        raise HTTPException(409, "Signing operation identity does not match")
    expected = (
        intent["public_key_sha256"]
        if command.action == "recover"
        else intent["expected_public_sha256"]
    )
    if command.expected_public_sha256 != expected:
        raise HTTPException(409, "Signing operation expectation does not match")
    if command.action in ("initialize", "adopt") and command.action != intent["kind"]:
        raise HTTPException(409, "Signing operation kind does not match")


async def _load(
    db: AsyncSession, command: SigningCommand
) -> tuple[RowMapping | None, RowMapping | None]:
    intent = (
        (
            await db.execute(
                select(AgentSigningIntent.__table__)
                .where(AgentSigningIntent.operation_id == command.operation_id)
                .with_for_update(nowait=True)
            )
        )
        .mappings()
        .one_or_none()
    )
    identity = (
        (
            await db.execute(
                select(AgentSigningIdentity.__table__)
                .where(AgentSigningIdentity.singleton_id == 1)
                .with_for_update(read=True, nowait=True)
            )
        )
        .mappings()
        .one_or_none()
    )
    if intent is not None:
        _same_operation(intent, command)
    if identity is not None and (
        identity["operation_id"] != command.operation_id
        or identity["installation_id"] != command.installation_id
        or identity["identity_epoch"] != command.identity_epoch
    ):
        raise HTTPException(409, "Installation already has another active signing identity")
    if identity is not None:
        if (
            intent is None
            or intent["state"] != "activated"
            or identity["format_version"] != 1
            or identity["purpose"] != "agent-release"
            or identity["public_key_pem"] != intent["public_key_pem"]
            or identity["public_key_sha256"] != intent["public_key_sha256"]
            or identity["activated_by"] != intent["closed_by"]
            or identity["activated_at"] != intent["closed_at"]
        ):
            raise HTTPException(
                409, "Active signing record conflicts with retained operation history"
            )
        release_signing.public_key_for_anchor(
            anchor_public_pem=identity["public_key_pem"],
            anchor_sha256=identity["public_key_sha256"],
        )
    return intent, identity


async def _begin(
    db: AsyncSession, factor: FreshSigningFactor, command: SigningCommand
) -> tuple[dict[str, Any], bool]:
    intent, identity = await _load(db, command)
    if intent is not None:
        if intent["state"] == "cancelled":
            raise HTTPException(
                409, "Cancelled signing operation is retained; start a separate reviewed operation"
            )
        if intent["state"] == "activated":
            if identity is None:
                raise HTTPException(
                    409, "Active signing identity is missing; restore the trusted database record"
                )
            if command.action == "cancel":
                raise HTTPException(409, "An active signing identity cannot be cancelled")
            return dict(intent), False
        if identity is not None or command.action == "recover":
            raise HTTPException(409, "Same-identity recovery requires its active trusted record")
        if command.action == "cancel":
            now = await db.scalar(select(func.clock_timestamp()))
            await db.execute(
                update(AgentSigningIntent)
                .where(AgentSigningIntent.operation_id == command.operation_id)
                .values(state="cancelled", closed_at=now, closed_by=factor.authority.actor_id)
            )
            return {
                **intent,
                "state": "cancelled",
                "closed_at": now,
                "closed_by": factor.authority.actor_id,
            }, False
        return dict(intent), False
    if identity is not None or command.action not in ("initialize", "adopt"):
        raise HTTPException(
            409, "Signing operation does not exist; do not infer initialization from absence"
        )
    if command.identity_epoch != 1:
        raise HTTPException(
            409, "A first signing identity must use epoch one; rotation is a separate lifecycle"
        )
    if await db.scalar(
        select(exists().where(AgentSigningIntent.state.in_(["pending", "prepared"])))
    ):
        raise HTTPException(409, "Another signing operation requires resolution")
    history = (
        await db.execute(
            select(AgentSigningIntent.installation_id, AgentSigningIntent.identity_epoch)
            .distinct()
            .limit(2)
        )
    ).all()
    if history and (
        len(history) != 1 or tuple(history[0]) != (command.installation_id, command.identity_epoch)
    ):
        raise HTTPException(
            409, "Retained signing history belongs to another installation identity"
        )
    if command.action == "initialize" and (
        await db.scalar(select(exists().select_from(RemoteAgent)))
        or await db.scalar(select(exists().select_from(AgentRelease)))
    ):
        raise HTTPException(
            409, "Existing agent history requires explicit trusted key adoption or recovery"
        )
    now = await db.scalar(select(func.clock_timestamp()))
    values: dict[str, Any] = {
        "operation_id": command.operation_id,
        "singleton_id": 1,
        "installation_id": command.installation_id,
        "identity_epoch": command.identity_epoch,
        "kind": command.action,
        "expected_public_sha256": command.expected_public_sha256,
        "state": "pending",
        "requested_by": factor.authority.actor_id,
        "created_at": now,
        "public_key_pem": None,
        "public_key_sha256": None,
        "prepared_at": None,
        "closed_at": None,
        "closed_by": None,
    }
    await db.execute(insert(AgentSigningIntent).values(**values))
    return values, True


async def _prepare(db: AsyncSession, command: SigningCommand, public: bytes) -> dict[str, Any]:
    intent, identity = await _load(db, command)
    if intent is None or identity is not None or intent["state"] != "pending":
        raise HTTPException(409, "Signing operation changed before preparation")
    fingerprint = hashlib.sha256(public).hexdigest()
    release_signing.public_key_for_anchor(anchor_public_pem=public, anchor_sha256=fingerprint)
    if intent["kind"] == "adopt" and intent["expected_public_sha256"] != fingerprint:
        raise HTTPException(409, "Stored key differs from the confirmed adoption fingerprint")
    now = await db.scalar(select(func.clock_timestamp()))
    await db.execute(
        update(AgentSigningIntent)
        .where(AgentSigningIntent.operation_id == command.operation_id)
        .values(
            state="prepared", public_key_pem=public, public_key_sha256=fingerprint, prepared_at=now
        )
    )
    return {
        **intent,
        "state": "prepared",
        "public_key_pem": public,
        "public_key_sha256": fingerprint,
        "prepared_at": now,
    }


async def _activate(
    db: AsyncSession,
    factor: FreshSigningFactor,
    command: SigningCommand,
    prepared: Mapping[str, Any],
) -> dict[str, Any]:
    intent, identity = await _load(db, command)
    if intent is None or intent["state"] not in ("prepared", "activated"):
        raise HTTPException(409, "Signing operation changed before activation")
    if (
        intent["public_key_pem"] != prepared["public_key_pem"]
        or intent["public_key_sha256"] != prepared["public_key_sha256"]
    ):
        raise HTTPException(409, "Prepared signing identity changed")
    if intent["state"] == "activated":
        if identity is None:
            raise HTTPException(409, "Trusted active identity requires database recovery")
        return dict(intent)
    if identity is not None:
        raise HTTPException(409, "Unexpected active signing identity")
    now = await db.scalar(select(func.clock_timestamp()))
    await db.execute(
        update(AgentSigningIntent)
        .where(AgentSigningIntent.operation_id == command.operation_id)
        .values(state="activated", closed_at=now, closed_by=factor.authority.actor_id)
    )
    await db.execute(
        insert(AgentSigningIdentity).values(
            singleton_id=1,
            format_version=1,
            purpose="agent-release",
            installation_id=command.installation_id,
            identity_epoch=command.identity_epoch,
            operation_id=command.operation_id,
            public_key_pem=intent["public_key_pem"],
            public_key_sha256=intent["public_key_sha256"],
            activated_by=factor.authority.actor_id,
            activated_at=now,
        )
    )
    return {
        **intent,
        "state": "activated",
        "closed_at": now,
        "closed_by": factor.authority.actor_id,
    }


async def _phase[R](
    db: AsyncSession,
    factor: FreshSigningFactor,
    command: SigningCommand,
    function: Callable[[AsyncSession], Awaitable[R]],
) -> R:
    if db.in_transaction():
        raise RuntimeError("Lifecycle phase requires its own unused transaction")
    with anyio.fail_after(5):
        async with db.begin():
            # The deferred journal trigger checks DB time before completing its
            # validation. This is not the later network/WAL acknowledgement time.
            await db.execute(
                text("SELECT set_config('freesdn.signing_deadline', :deadline, true)"),
                {"deadline": str(factor.expires_at)},
            )
            fence = await lock_current_signing_authority(db, factor=factor, command=command)
            result = await function(db)
            await fence.recheck()
        # A commit timeout is ambiguous: do not repeat this phase automatically.
    await factor.recheck(command)
    return result


async def _storage[R](function: Callable[[], R]) -> R:
    return await release_signing_async._worker(release_signing_async._ADMIN_WORKERS, function)


@complete_before_cancellation
async def execute_signing_lifecycle(
    *, factor: FreshSigningFactor, command: SigningCommand
) -> SigningOperationResult:
    """Consume one server-side fresh factor, preserve each completed phase.

    No caller session is accepted. Missing private material on resume/recovery never
    generates a replacement. An interrupted/ambiguous operation requires inspection
    and a newly confirmed resume/cancel command; it is never automatically replayed.
    """
    if type(factor) is not FreshSigningFactor or type(command) is not SigningCommand:
        raise HTTPException(403, "Fresh signing operation confirmation is required")
    if command.action == "inspect":
        raise HTTPException(403, "Inspection cannot mutate a signing identity")
    if type(factor.confirmation_id) is not UUID:
        raise HTTPException(403, "Signing confirmation identity is invalid")
    await factor.recheck(command)
    if not _OPERATIONS.acquire(blocking=False):
        raise HTTPException(503, "Signing lifecycle is busy; retry fresh confirmation")
    try:
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                connection = await cleanup.enter_async_context(sessions.security_engine.connect())
                db = await cleanup.enter_async_context(
                    AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
                )
                locked = bool(
                    await db.scalar(
                        text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"),
                        {"key": _OPERATION_LOCK},
                    )
                )
                await db.commit()
            if not locked:
                raise HTTPException(
                    409, "Another signing lifecycle operation owns the installation"
                )
            try:
                await factor.recheck(command)
                if not await claim_token_jti(
                    "signing-confirmation:" + str(factor.confirmation_id), factor.expires_at
                ):
                    raise HTTPException(
                        401,
                        "Signing confirmation was consumed, expired or unavailable; confirm again",
                    )
                await factor.recheck(command)
                intent, created = await _phase(
                    db, factor, command, partial(_begin, factor=factor, command=command)
                )
                if intent["state"] == "cancelled":
                    return _result(intent)
                if intent["state"] == "pending":
                    mode = (
                        "adopt"
                        if intent["kind"] == "adopt"
                        else "initialize"
                        if created
                        else "resume"
                    )
                    public = await _storage(
                        partial(
                            release_signing.prepare_signing_identity,
                            mode=mode,
                            expected_sha256=intent["expected_public_sha256"],
                        )
                    )
                    await factor.recheck(command)
                    intent = await _phase(
                        db, factor, command, partial(_prepare, command=command, public=public)
                    )
                await _storage(
                    partial(
                        release_signing.check_signing_anchor,
                        anchor_public_pem=intent["public_key_pem"],
                        anchor_sha256=intent["public_key_sha256"],
                    )
                )
                await factor.recheck(command)
                accepted = await _phase(
                    db,
                    factor,
                    command,
                    partial(
                        _activate,
                        factor=factor,
                        command=command,
                        prepared=intent,
                    ),
                )
                return _result(accepted)
            finally:
                try:
                    with anyio.fail_after(5):
                        if db.in_transaction():
                            await db.rollback()
                        released = await db.scalar(
                            text("SELECT pg_advisory_unlock(CAST(:key AS bigint))"),
                            {"key": _OPERATION_LOCK},
                        )
                        await db.commit()
                        if released is not True:
                            raise RuntimeError(
                                "Signing operation ownership could not be confirmed at cleanup"
                            )
                except BaseException:
                    # This dedicated connection must never be pooled/reused with
                    # uncertain session-level ownership. Its physical close is
                    # retained by the outer owned cleanup/cancellation boundary.
                    await connection.invalidate()
                    raise
    except release_signing.SigningKeyError:
        raise HTTPException(
            409,
            "Signing storage requires explicit same-identity recovery; pending history is retained",
        ) from None
    except (release_signing_async.SigningBusyError, DBAPIError, TimeoutError):
        raise HTTPException(
            503,
            "Signing operation could not be confirmed; inspect retained state before a fresh retry",
        ) from None
    finally:
        _OPERATIONS.release()
