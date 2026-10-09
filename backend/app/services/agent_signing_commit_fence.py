# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hold current signing authority through one caller-owned SQL decision.

Internal prerequisite for the lifecycle coordinator, not an HTTP authorization
grant or a transaction runner. All acquisitions are nonblocking to refuse inverse
lock orders. The caller must roll back on refusal, bound the whole transaction,
and recheck after its writes before commit. Never hold this over filesystem I/O.
An ambiguous/late commit still requires the durable intent recovery protocol.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction

from app.core.agent_signing_binding import SigningCommand
from app.core.token_authority_lock import try_share_token_authority
from app.core.user_lifecycle import try_share_user_lifecycle
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from app.models.sso import SSOProvider
from app.services.agent_signing_authority import FreshSigningFactor


def _expired(factor: FreshSigningFactor, command: SigningCommand) -> None:
    factor.authority.require_command(command)
    if time.time() >= factor.expires_at:
        raise HTTPException(401, "Fresh signing confirmation expired")


@dataclass(frozen=True, repr=False)
class SigningCommitFence:
    session: AsyncSession = field(repr=False)
    transaction: AsyncSessionTransaction = field(repr=False)
    factor: FreshSigningFactor = field(repr=False)
    command: SigningCommand
    session_id: UUID | None = field(default=None, repr=False)

    async def recheck(self) -> None:
        if self.session.get_transaction() is not self.transaction or not self.transaction.is_active:
            raise RuntimeError("Signing authority transaction ended; reacquire authority")
        _expired(self.factor, self.command)
        authority = self.factor.authority
        row = (await self.session.execute(authority._statement())).mappings().one_or_none()
        authority._validate(row)
        if self.session_id is not None:
            # Preserve the actual session identity, not merely a now-absent JTI
            # lookup after a refresh, deletion or caller-side update.
            c = UserSession.__table__.c
            active = (
                (
                    await self.session.execute(
                        select(c.user_id, c.access_jti, c.is_revoked, c.revoked_at).where(
                            c.id == self.session_id
                        )
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                active is None
                or active["user_id"] != authority.actor_id
                or active["access_jti"] != authority.jti
                or active["is_revoked"] is not False
                or active["revoked_at"] is not None
            ):
                raise HTTPException(401, "Current signing session changed")
        _expired(self.factor, self.command)


async def lock_current_signing_authority(
    session: AsyncSession,
    *,
    factor: FreshSigningFactor,
    command: SigningCommand,
) -> SigningCommitFence:
    """Join an existing short SQL transaction; never commit/rollback the caller.

    JWT activation requires exactly one tracked current session. An older token with
    no row must be replaced by a successful current login; do not invent a session
    from token claims. This additional privileged-operation policy must be surfaced
    by the future operator UI and qualified against the actual login flow.
    """
    if type(factor) is not FreshSigningFactor or not session.in_transaction():
        raise RuntimeError("Fresh signing factor and owned transaction are required")
    transaction = session.get_transaction()
    if transaction is None:
        raise RuntimeError("Fresh signing factor and owned transaction are required")
    _expired(factor, command)
    authority = factor.authority
    if not await try_share_user_lifecycle(session):
        raise HTTPException(409, "Account lifecycle changed; retry fresh signing confirmation")
    session_id = None
    try:
        await session.execute(
            select(User.__table__.c.id)
            .where(User.id == authority.actor_id)
            .with_for_update(nowait=True)
        )
        if authority.key_id is not None:
            await session.execute(
                select(APIKey.__table__.c.id)
                .where(APIKey.id == authority.key_id)
                .with_for_update(read=True, nowait=True)
            )
        else:
            if authority.jti is None:
                raise HTTPException(401, "Signing requires a current tracked login; sign in again")
            if not await try_share_token_authority(session, authority.jti):
                raise HTTPException(
                    409, "Credential transition in progress; retry fresh confirmation"
                )
            c = UserSession.__table__.c
            rows = (
                (
                    await session.execute(
                        select(c.id, c.user_id)
                        .where(c.access_jti == authority.jti)
                        .limit(2)
                        .with_for_update(read=True, nowait=True)
                    )
                )
                .mappings()
                .all()
            )
            if len(rows) != 1 or rows[0]["user_id"] != authority.actor_id:
                raise HTTPException(401, "Signing requires a current tracked login; sign in again")
            session_id = rows[0]["id"]
        # The locked user supplies the provider reference. A fresh read follows
        # its nonblocking row lock so stale pre-lock fields cannot authorize SQL.
        row = (await session.execute(authority._statement())).mappings().one_or_none()
        if row is not None and row["a_sso_provider_id"] is not None:
            await session.execute(
                select(SSOProvider.__table__.c.id)
                .where(SSOProvider.id == row["a_sso_provider_id"])
                .with_for_update(read=True, nowait=True)
            )
        fence = SigningCommitFence(session, transaction, factor, command, session_id)
        await fence.recheck()
        return fence
    except DBAPIError as exc:
        code = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
        if code == "55P03":
            raise HTTPException(
                409, "Signing authority is busy; retry fresh confirmation"
            ) from None
        raise
