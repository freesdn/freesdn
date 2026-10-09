# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Transaction-scoped coordination with durable JWT revocation writers.

The row's absence cannot be row-locked. Cooperating revocation/claim writers take
the exclusive advisory lock before INSERT; final authority readers use a shared
nonblocking lock. A hash collision only serializes unrelated token operations.
This does not replace revocation lookup, expiry checks or account/session locks.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def token_authority_lock_key(jti: str) -> int:
    if type(jti) is not str or not 1 <= len(jti) <= 1024:
        raise ValueError("Invalid token authority identity")
    encoded = jti.encode("utf-8")
    digest = hashlib.sha256(b"FreeSDN/token-authority/v1\x00" + encoded).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def lock_token_authority(session: AsyncSession, jti: str) -> None:
    """Exclusive writer lock; caller owns the transaction, timeout and rollback."""
    if not session.in_transaction():
        raise RuntimeError("Token authority lock requires an owned transaction")
    await session.execute(
        text("SELECT pg_advisory_xact_lock(CAST(:key AS bigint))"),
        {"key": token_authority_lock_key(jti)},
    )


async def try_share_token_authority(session: AsyncSession, jti: str) -> bool:
    """Do not wait while holding account/lifecycle rows in another lock order."""
    if not session.in_transaction():
        raise RuntimeError("Token authority lock requires an owned transaction")
    return bool(
        await session.scalar(
            text("SELECT pg_try_advisory_xact_lock_shared(CAST(:key AS bigint))"),
            {"key": token_authority_lock_key(jti)},
        )
    )
