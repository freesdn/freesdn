# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private current binary-read authority, not publication or cleanup authority.

Operator capture follows actual shared authentication, including its bookkeeping;
no authentication function that commits is called within the reader's SQL phase.
Agent credentials are checked against fresh scalar state. Neither object grants
access to a pathname, and neither may be passed to mutation entry points.
"""

from __future__ import annotations

import hashlib
import hmac
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Self
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from sqlalchemy import RowMapping, Select, select
from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction

from app.core.dependencies import CurrentUser
from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agents import RemoteAgent
from app.services.agent_release_authority import ReleaseMutationAuthority

_FIELDS = (
    "id",
    "organization_id",
    "site_id",
    "agent_key",
    "is_enabled",
    "is_approved",
    "deleted_at",
)


def _ended() -> HTTPException:
    return HTTPException(
        401, "Agent download authorization changed", headers={"WWW-Authenticate": "X-Agent-Key"}
    )


class ReleaseOperatorReadAuthority(ReleaseMutationAuthority):
    """Preserve ordinary operator downloads; respect explicit scoped key ceilings."""

    @staticmethod
    def _permission_allowed(user: CurrentUser) -> bool:
        return (
            not user.is_scoped
            or user.has_permission("agent:read")
            or user.has_permission("agent:admin")
        )

    def require_scope(self, organization_id: UUID | None) -> None:
        if organization_id is None or (self.role == "super_admin" and not self.scoped):
            return
        if self.organization_id is None or self.organization_id != organization_id:
            raise HTTPException(404, "Release not found")


@dataclass(frozen=True, repr=False)
class ReleaseAgentReadAuthority:
    agent_id: UUID
    organization_id: UUID | None
    site_id: UUID | None
    key_hash: str = field(repr=False)

    @classmethod
    async def capture(cls, request: Request) -> Self:
        identity = request.headers.get("X-Agent-ID")
        raw = request.headers.get("X-Agent-Key")
        if not identity or len(identity) > 64 or not raw or len(raw) > 1024:
            raise _ended()
        try:
            agent_id = UUID(identity)
        except ValueError:
            raise _ended() from None
        initial = cls(agent_id, None, None, hashlib.sha256(raw.encode()).hexdigest())
        row = await initial._read()
        if row is None:
            raise _ended()
        result = cls(agent_id, row["organization_id"], row["site_id"], initial.key_hash)
        result.validate(row)
        return result

    def statement(self) -> Select[*tuple[Any, ...]]:
        c = RemoteAgent.__table__.c
        return select(*(c[name] for name in _FIELDS)).where(c.id == self.agent_id)

    def validate(self, row: RowMapping | None) -> None:
        if (
            row is None
            or row["id"] != self.agent_id
            or row["organization_id"] != self.organization_id
            or row["site_id"] != self.site_id
            or row["deleted_at"] is not None
            or row["is_enabled"] is not True
            or row["is_approved"] is not True
            or type(row["agent_key"]) is not str
            or len(row["agent_key"]) != 64
            or not row["agent_key"].isascii()
            or not hmac.compare_digest(row["agent_key"], self.key_hash)
        ):
            raise _ended()

    def require_scope(self, organization_id: UUID | None) -> None:
        if organization_id is not None and organization_id != self.organization_id:
            raise HTTPException(404, "Release not found")

    @complete_before_cancellation
    async def _read(self) -> RowMapping | None:
        deadline = anyio.current_time() + 5
        try:
            async with AsyncExitStack() as cleanup:
                with anyio.fail_after(5):
                    db = await cleanup.enter_async_context(sessions.security_session_factory())
                    row = (await db.execute(self.statement())).mappings().one_or_none()
            if anyio.current_time() >= deadline:
                raise TimeoutError("Agent authority read exceeded its bound")
            return row
        except Exception:
            await anyio.lowlevel.checkpoint()
            raise HTTPException(503, "Current agent authority is unavailable") from None

    async def lock(self, session: AsyncSession) -> ReleaseAgentReadFence:
        if not session.in_transaction():
            raise RuntimeError("Agent read authority needs its owned transaction")
        # Locking the identity alone grants nothing. result.recheck() below
        # validates a fresh scalar snapshot, including RemoteAgent.deleted_at.
        await session.execute(
            select(RemoteAgent.id)
            .where(RemoteAgent.id == self.agent_id)
            .with_for_update(read=True, nowait=True)
        )
        transaction = session.get_transaction()
        if transaction is None:
            raise RuntimeError("Agent read authority needs its owned transaction")
        result = ReleaseAgentReadFence(self, session, transaction)
        await result.recheck()
        return result


@dataclass(frozen=True, repr=False)
class ReleaseAgentReadFence:
    authority: ReleaseAgentReadAuthority
    session: AsyncSession = field(repr=False)
    transaction: AsyncSessionTransaction = field(repr=False)

    async def recheck(self) -> None:
        if self.session.get_transaction() is not self.transaction or not self.transaction.is_active:
            raise RuntimeError("Agent read authority transaction ended")
        self.authority.validate(
            (await self.session.execute(self.authority.statement())).mappings().one_or_none()
        )


async def capture_release_read_authority(
    request: Request, user: CurrentUser | None, *, secret_key: bytes
) -> ReleaseAgentReadAuthority | ReleaseOperatorReadAuthority:
    # Match the established preference: a current operator wins; agent headers
    # are only the fallback when shared authentication returned no operator.
    if user is None:
        return await ReleaseAgentReadAuthority.capture(request)
    return await ReleaseOperatorReadAuthority.capture(request, user, secret_key=secret_key)
