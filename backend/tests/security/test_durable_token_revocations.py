# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL arbitration; no evictable-cache authority for token reuse."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, insert, select

from app.core import token_blacklist as tokens
from app.models.core import TokenRevocation


@pytest_asyncio.fixture
async def identities():
    owned = []

    def new():
        jti = uuid4().hex
        owned.append(tokens._identity(jti))
        return jti

    yield new
    async with tokens.security_session_factory() as session, session.begin():
        await session.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(owned)))


async def test_concurrent_refresh_has_one_committed_winner(identities):
    jti = identities()
    expiry = datetime.now(UTC) + timedelta(hours=1)
    claims = await asyncio.gather(*(tokens.claim_token_jti(jti, expiry) for _ in range(16)))
    assert claims.count(True) == 1 and claims.count(False) == 15
    assert await tokens.is_token_blacklisted(jti)
    assert not await tokens.claim_token_jti(jti, expiry)


async def test_revocation_survives_new_connections_and_unavailable_cache(identities, monkeypatch):
    import app.core.redis_client as cache

    def forbidden(*args, **kwargs):
        raise AssertionError("Security decisions must not consult the evictable cache")

    monkeypatch.setattr(cache, "get_async_redis", forbidden)
    jti = identities()
    assert not await tokens.is_token_blacklisted(jti)
    await tokens.blacklist_token(jti, datetime.now(UTC) + timedelta(hours=1))
    # Each helper closes its connection; disposal also models a fresh process pool.
    from app.db.session import security_engine

    await security_engine.dispose()
    assert await tokens.is_token_blacklisted(jti)
    assert not await tokens.claim_token_jti(jti, datetime.now(UTC) + timedelta(hours=1))


async def test_repeated_revocation_cannot_shorten_retention(identities):
    jti = identities()
    late = datetime.now(UTC) + timedelta(days=7)
    await tokens.blacklist_token(jti, late)
    await tokens.blacklist_token(jti, datetime.now(UTC) + timedelta(minutes=1))
    async with tokens.security_session_factory() as session:
        expiry = (
            await session.execute(
                select(TokenRevocation.expires_at).where(
                    TokenRevocation.jti_hash == tokens._identity(jti)
                )
            )
        ).scalar_one()
    assert expiry == late


async def test_storage_failures_deny_claims_reads_and_successful_logout(monkeypatch):
    def broken():
        raise ConnectionError("synthetic unavailable database")

    monkeypatch.setattr(tokens, "security_session_factory", broken)
    assert await tokens.is_token_blacklisted(uuid4().hex)
    assert not await tokens.claim_token_jti(uuid4().hex, datetime.now(UTC) + timedelta(hours=1))
    with pytest.raises(tokens.TokenRevocationUnavailable):
        await tokens.blacklist_token(uuid4().hex, datetime.now(UTC) + timedelta(hours=1))


@pytest.mark.parametrize(
    "expiry", [0, -1, datetime.now(UTC) - timedelta(days=1), datetime(2020, 1, 1)]
)
async def test_expired_or_invalid_claim_cannot_authorize_reuse(expiry):
    assert not await tokens.claim_token_jti(uuid4().hex, expiry)


async def test_pruning_is_bounded_and_retains_recent_and_active_revocations(identities):
    now = datetime.now(UTC)
    expired = [tokens._identity(identities()) for _ in range(1005)]
    recent, active = tokens._identity(identities()), tokens._identity(identities())
    async with tokens.security_session_factory() as session, session.begin():
        await session.execute(
            insert(TokenRevocation),
            [
                *[{"jti_hash": jti, "expires_at": now - timedelta(days=2)} for jti in expired],
                {"jti_hash": recent, "expires_at": now - timedelta(hours=1)},
                {"jti_hash": active, "expires_at": now + timedelta(days=1)},
            ],
        )
    assert await tokens.prune_expired_revocations() == 1000
    assert await tokens.prune_expired_revocations() == 5
    async with tokens.security_session_factory() as session:
        retained = (
            (
                await session.execute(
                    select(TokenRevocation.jti_hash).where(
                        TokenRevocation.jti_hash.in_([recent, active])
                    )
                )
            )
            .scalars()
            .all()
        )
    assert set(retained) == {recent, active}


def test_cleanup_is_registered_on_a_consumed_queue():
    from app.core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    entry = celery_app.conf.beat_schedule["cleanup-token-revocations"]
    assert entry["task"] in celery_app.tasks
    assert entry["options"]["queue"] == "default"


async def test_unconfirmed_revocation_has_a_safe_retryable_http_response():
    import httpx
    from fastapi import FastAPI

    from app.core.middleware import setup_exception_handlers

    app = FastAPI()
    setup_exception_handlers(app)

    @app.post("/logout")
    async def logout():
        raise tokens.TokenRevocationUnavailable("synthetic database details must not escape")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/logout")
    assert response.status_code == 503
    assert "not confirmed" in response.text
    assert "database details" not in response.text


@pytest.mark.parametrize("service_path", [False, True])
@pytest.mark.parametrize("failure", ["stale_version", "lost_claim", "missing_jti", "missing_exp"])
async def test_password_reset_rejects_old_cutover_tokens_and_lost_claims(
    monkeypatch, service_path, failure
):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from fastapi import HTTPException

    from app.api.v1.endpoints import auth as endpoints
    from app.services import auth as service

    user = SimpleNamespace(id=uuid4(), token_version=7, hashed_password="unchanged")
    payload = {
        "type": "password_reset",
        "sub": str(user.id),
        "tv": 7,
        "jti": uuid4().hex,
        "exp": int(datetime.now(UTC).timestamp()) + 600,
    }
    if failure == "stale_version":
        payload["tv"] = 6
    elif failure == "missing_jti":
        del payload["jti"]
    elif failure == "missing_exp":
        del payload["exp"]
    claim = AsyncMock(return_value=failure != "lost_claim")
    monkeypatch.setattr(tokens, "claim_token_jti", claim)
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    session = AsyncMock()
    session.execute.return_value = result
    target = service if service_path else endpoints
    monkeypatch.setattr(target, "decode_token", AsyncMock(return_value=payload))
    with pytest.raises(service.TokenInvalidError if service_path else HTTPException):
        if service_path:
            await service.AuthService(session).reset_password(
                "synthetic", "A-strong-new-password-918!"
            )
        else:
            await endpoints.reset_password(
                SimpleNamespace(token="synthetic", new_password="A-strong-new-password-918!"),
                session,
            )
    session.commit.assert_not_awaited()
    assert user.hashed_password == "unchanged"
    if failure in {"missing_jti", "missing_exp"}:
        claim.assert_not_awaited()
    else:
        claim.assert_awaited_once_with(payload["jti"], payload["exp"])
