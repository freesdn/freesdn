# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Token Blacklist (Redis-backed)
=============================================

Provides JWT revocation via Redis SET with automatic TTL expiry.
Tokens are blacklisted by their JTI (JWT ID) claim.
"""

import logging
from datetime import UTC, datetime

import redis.asyncio as aioredis

from app.core.redis_client import get_async_redis

logger = logging.getLogger(__name__)

_BLACKLIST_PREFIX = "token:blacklist:"
_redis_client: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    """Get or create a reusable Redis client instance."""
    global _redis_client
    if _redis_client is None:
        _redis_client = get_async_redis(decode_responses=True)
    return _redis_client


async def blacklist_token(jti: str, exp: int | datetime) -> None:
    """
    Add a token JTI to the blacklist.

    The key automatically expires once the token's own ``exp`` passes,
    so blacklist entries never accumulate beyond the token lifetime.

    Args:
        jti: The JWT ID claim value.
        exp: Token expiration – either a Unix timestamp (int) or a datetime.
    """
    if isinstance(exp, datetime):
        ttl = int((exp - datetime.now(UTC)).total_seconds())
    else:
        ttl = int(exp - datetime.now(UTC).timestamp())

    if ttl <= 0:
        return  # token already expired, nothing to blacklist

    try:
        client = await _get_redis()
        await client.setex(f"{_BLACKLIST_PREFIX}{jti}", ttl, "1")
    except Exception:
        logger.exception("Failed to blacklist token %s", jti)


async def claim_token_jti(jti: str, exp: int | datetime) -> bool:
    """Atomically blacklist a JTI, returning True only if THIS call performed
       the write.

       Implemented with Redis ``SET key 1 NX EX ttl``: exactly one of N concurrent
       callers presenting the same jti wins the claim (returns True); the others
       see the key already set and return False. Used by refresh-token rotation
    to collapse a concurrent same-token refresh to a single
       winner — without it, two requests could both pass the (non-atomic)
       blacklist check, both mint a fresh token pair, and orphan one per-device
       session row (defeating targeted session revocation for that pair).

       Fails OPEN (returns True) when Redis is unavailable, mirroring
       ``blacklist_token``'s best-effort behavior so a Redis outage doesn't block
       all refreshes. Note that ``is_token_blacklisted`` fails CLOSED, so during a
       full outage the refresh is already rejected upstream before reaching here.
    """
    if isinstance(exp, datetime):
        ttl = int((exp - datetime.now(UTC)).total_seconds())
    else:
        ttl = int(exp - datetime.now(UTC).timestamp())

    if ttl <= 0:
        return True  # token already expired; nothing to claim

    try:
        client = await _get_redis()
        was_set = await client.set(f"{_BLACKLIST_PREFIX}{jti}", "1", nx=True, ex=ttl)
        return bool(was_set)
    except Exception:
        logger.exception("Failed to claim token jti %s (failing open)", jti)
        return True  # fail-open: don't break refresh on Redis outage


async def is_token_blacklisted(jti: str) -> bool:
    """
    Check whether a JTI has been revoked.

    Returns ``True`` if blacklisted **or if Redis is unreachable**
    (fail-closed).  This means a brief Redis outage will temporarily
    reject all JWTs rather than silently accepting revoked tokens –
    the safer default for a security-critical check.
    """
    try:
        client = await _get_redis()
        result = await client.exists(f"{_BLACKLIST_PREFIX}{jti}")
        return bool(result)
    except Exception:
        logger.exception(
            "Redis blacklist lookup failed for %s — failing CLOSED "
            "(treating token as revoked for safety)",
            jti,
        )
        return True  # SECURITY: fail-closed — reject token when Redis is down
