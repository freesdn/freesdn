# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Durable JWT revocations and atomic refresh consumption in PostgreSQL.

Valkey's shared TTL cache can evict keys or lose replicated writes. It cannot
be the authority for token revocation or single-use security decisions.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from app.core.token_authority_lock import lock_token_authority
from app.db.session import security_session_factory
from app.models.core import TokenRevocation

logger = logging.getLogger(__name__)


class TokenRevocationUnavailable(RuntimeError):
    """Revocation was not acknowledged; callers must not report success."""


def _identity(jti: str) -> str:
    if not isinstance(jti, str) or not jti or len(jti) > 1024:
        raise ValueError("Invalid token identifier")
    return hashlib.sha256(jti.encode()).hexdigest()


def _expiry(exp: int | datetime) -> datetime:
    if isinstance(exp, datetime):
        if exp.tzinfo is None:
            raise ValueError("Token expiry must have a timezone")
        return exp.astimezone(UTC)
    return datetime.fromtimestamp(exp, UTC)


async def blacklist_token(jti: str, exp: int | datetime) -> None:
    """Commit revocation before success; storage failure is terminal."""
    try:
        identity, expiry = _identity(jti), _expiry(exp)
        if expiry <= datetime.now(UTC):
            return
        statement = insert(TokenRevocation).values(jti_hash=identity, expires_at=expiry)
        statement = statement.on_conflict_do_update(
            index_elements=[TokenRevocation.jti_hash],
            set_={
                "expires_at": func.greatest(
                    TokenRevocation.expires_at, statement.excluded.expires_at
                )
            },
        )
        async with security_session_factory() as session, session.begin():
            await lock_token_authority(session, jti)
            await session.execute(statement)
    except Exception as exc:
        logger.exception("Durable token revocation failed")
        raise TokenRevocationUnavailable("Token revocation storage unavailable") from exc


async def claim_token_jti(jti: str, exp: int | datetime) -> bool:
    """One committed insert wins; failures and expired claims are refused.

    A lost response after commit requires login, not reuse of the old token.
    """
    try:
        identity, expiry = _identity(jti), _expiry(exp)
        if expiry <= datetime.now(UTC):
            return False
        statement = (
            insert(TokenRevocation)
            .values(jti_hash=identity, expires_at=expiry)
            .on_conflict_do_nothing(index_elements=[TokenRevocation.jti_hash])
            .returning(TokenRevocation.jti_hash)
        )
        async with security_session_factory() as session, session.begin():
            await lock_token_authority(session, jti)
            won = (await session.execute(statement)).scalar_one_or_none() is not None
        # The INSERT or commit may have waited beyond the earlier expiry check.
        # Keep the committed tombstone even when this request is now too late.
        return won and expiry > datetime.now(UTC)
    except Exception:
        logger.exception("Durable token claim failed; refusing token reuse")
        return False


async def is_token_blacklisted(jti: str) -> bool:
    """Database absence is authoritative; storage/validation errors deny."""
    try:
        identity = _identity(jti)
        async with security_session_factory() as session:
            return (
                await session.execute(
                    select(TokenRevocation.jti_hash).where(TokenRevocation.jti_hash == identity)
                )
            ).scalar_one_or_none() is not None
    except Exception:
        logger.exception("Durable token lookup failed; treating token as revoked")
        return True


async def prune_expired_revocations() -> int:
    """Bound each maintenance batch; retain a day beyond expiry for clock skew."""
    cutoff = datetime.now(UTC) - timedelta(days=1)
    async with security_session_factory() as session, session.begin():
        expired = (
            select(TokenRevocation.jti_hash)
            .where(TokenRevocation.expires_at < cutoff)
            .order_by(TokenRevocation.expires_at)
            .limit(1000)
            .with_for_update(skip_locked=True)
        )
        removed = await session.execute(
            delete(TokenRevocation)
            .where(TokenRevocation.jti_hash.in_(expired))
            .returning(TokenRevocation.jti_hash)
        )
        return len(removed.scalars().all())
