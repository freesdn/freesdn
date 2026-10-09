# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Trusted public identity for ordinary signing and enrollment consumers.

No caller-selected or filesystem-derived identity is accepted. Empty or damaged
database state is unavailable, never permission to initialize a replacement key.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import anyio
from sqlalchemy import Select, exists, func, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_signing import (
    AgentSigningEnrollment,
    AgentSigningIdentity,
    AgentSigningIntent,
)
from app.services.release_signing import SigningKeyError, public_key_for_anchor


@dataclass(frozen=True, repr=False)
class TrustedSigningIdentity:
    operation_id: UUID
    installation_id: UUID
    identity_epoch: int
    public_key_sha256: str
    public_key_pem: bytes


def _identity_statement() -> Select[*tuple[Any, ...]]:
    active, intent = AgentSigningIdentity.__table__, AgentSigningIntent.__table__
    return (
        select(
            *(
                active.c[name]
                for name in (
                    "singleton_id",
                    "format_version",
                    "purpose",
                    "operation_id",
                    "installation_id",
                    "identity_epoch",
                    "public_key_sha256",
                    "public_key_pem",
                    "activated_by",
                    "activated_at",
                )
            ),
            *(
                intent.c[name].label("intent_" + name)
                for name in (
                    "operation_id",
                    "installation_id",
                    "identity_epoch",
                    "state",
                    "public_key_sha256",
                    "public_key_pem",
                    "closed_by",
                    "closed_at",
                )
            ),
            exists()
            .where(AgentSigningIntent.state.in_(["pending", "prepared"]))
            .correlate(None)
            .label("open_operation"),
        )
        .select_from(active.outerjoin(intent, intent.c.operation_id == active.c.operation_id))
        .limit(2)
    )


def _trusted(rows: Sequence[RowMapping | Mapping[str, Any]]) -> TrustedSigningIdentity:
    if len(rows) != 1:
        raise SigningKeyError(
            "Trusted installation signing identity is unavailable; initialize or adopt explicitly"
        )
    row = rows[0]
    if (
        row["singleton_id"] != 1
        or row["format_version"] != 1
        or row["purpose"] != "agent-release"
        or row["intent_state"] != "activated"
        or row["open_operation"]
        or any(
            row[name] != row["intent_" + name]
            for name in (
                "operation_id",
                "installation_id",
                "identity_epoch",
                "public_key_sha256",
                "public_key_pem",
            )
        )
        or row["activated_by"] != row["intent_closed_by"]
        or row["activated_at"] != row["intent_closed_at"]
    ):
        raise SigningKeyError("Trusted signing identity conflicts with operation history")
    public = public_key_for_anchor(
        anchor_public_pem=row["public_key_pem"], anchor_sha256=row["public_key_sha256"]
    )
    return TrustedSigningIdentity(
        row["operation_id"],
        row["installation_id"],
        row["identity_epoch"],
        row["public_key_sha256"],
        public,
    )


@complete_before_cancellation
async def read_trusted_signing_identity() -> TrustedSigningIdentity:
    """One consistent SELECT in an owned bounded session; no key-file access."""
    end = anyio.current_time() + 5
    try:
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                db = await cleanup.enter_async_context(sessions.security_session_factory())
                rows = (await db.execute(_identity_statement())).mappings().all()
        if anyio.current_time() >= end:
            raise TimeoutError("Signing identity read deadline")
        return _trusted(rows)
    except SigningKeyError:
        raise
    except Exception:
        await anyio.lowlevel.checkpoint()
        raise SigningKeyError("Trusted signing identity cannot be confirmed") from None


async def persist_enrollment_pin(
    session: AsyncSession,
    *,
    agent_id: UUID,
    actor_id: UUID,
    identity: TrustedSigningIdentity,
) -> None:
    """Persist with the new agent inside the caller's transaction; never commit.

    The insert trigger compares the active identity and preserves the enrolled pin.
    Failure leaves the caller responsible for rollback, including its new credential.
    This does not reauthenticate the initiating user or establish site authorization.
    """
    if not session.in_transaction() or type(identity) is not TrustedSigningIdentity:
        raise RuntimeError("Enrollment pin requires a caller transaction and trusted identity")
    current = _trusted((await session.execute(_identity_statement())).mappings().all())
    if current != identity:
        raise SigningKeyError("Signing identity changed before agent enrollment")
    session.add(
        AgentSigningEnrollment(
            agent_id=agent_id,
            signing_singleton_id=1,
            installation_id=identity.installation_id,
            identity_epoch=identity.identity_epoch,
            public_key_sha256=identity.public_key_sha256,
            enrolled_at=await session.scalar(select(func.clock_timestamp())),
            enrolled_by=actor_id,
        )
    )
    await session.flush()
