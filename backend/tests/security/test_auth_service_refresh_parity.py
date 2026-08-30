# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""``AuthService.refresh_tokens`` must not be a weaker /auth/refresh.

``app.services.auth.AuthService`` has no production callers -- every /auth route
is served by ``app/api/v1/endpoints/auth.py`` -- but it is re-exported from
``app.services``, so it reads like the intended entry point, and its own test
file passes with names ("test_refresh_tokens_rejects_stale_token_version") that
look like coverage of the live login path.

Its refresh path omitted three controls the live endpoint enforces:

* the atomic ``claim_token_jti`` rotation claim (a plain blacklist write lets
  two concurrent requests presenting the same token both mint a pair),
* the per-device ``UserSession.revoked_at`` check (the only thing that makes
  ``DELETE /auth/sessions/{id}`` and per-device logout bite), and
* the ``rmb`` remember-me claim across rotation.

Anyone wiring the service up would have regressed all three behind a green
suite. These tests are the ratchet: they fail if any of the three is dropped
again.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import jwt
import pytest

from app.core.config import settings
from app.services.auth import AuthService, TokenInvalidError

_USER_ID = uuid4()


def _user() -> SimpleNamespace:
    return SimpleNamespace(
        id=_USER_ID,
        organization_id=None,
        role="admin",
        token_version=3,
        is_active=True,
        deleted_at=None,
    )


def _payload(**extra: Any) -> dict[str, Any]:
    base = {
        "type": "refresh",
        "sub": str(_USER_ID),
        "tv": 3,
        "jti": "old-refresh-jti",
        "exp": int(datetime.now(UTC).timestamp()) + 3600,
    }
    base.update(extra)
    return base


def _db(session_row: tuple[Any, Any] | None) -> AsyncMock:
    """A db double: first execute() resolves the user, second the session row."""
    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = _user()
    session_result = MagicMock()
    session_result.first.return_value = session_row

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[user_result, session_result])
    return db


def _decode(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        audience="freesdn-api",
        issuer="freesdn",
    )


@pytest.mark.asyncio
async def test_a_revoked_device_cannot_refresh_itself_back() -> None:
    """Mutation caught: deleting the UserSession.revoked_at lookup.

    Without it, revoking one device does nothing -- token_version only covers
    account-wide events, so the revoked device just rotates a fresh pair.
    """
    db = _db(session_row=(datetime.now(UTC), True))
    service = AuthService(db)

    with (
        patch("app.services.auth.decode_token", new=AsyncMock(return_value=_payload())),
        patch("app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=True)),
    ):
        with pytest.raises(TokenInvalidError):
            await service.refresh_tokens("revoked-device-token")


@pytest.mark.asyncio
async def test_an_active_device_still_refreshes() -> None:
    """The control: the revocation check must not reject live sessions."""
    db = _db(session_row=(None, False))
    service = AuthService(db)

    with (
        patch("app.services.auth.decode_token", new=AsyncMock(return_value=_payload())),
        patch("app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=True)),
    ):
        pair = await service.refresh_tokens("live-token")

    assert _decode(pair.refresh_token)["sub"] == str(_USER_ID)


@pytest.mark.asyncio
async def test_a_refresh_token_can_only_be_spent_once() -> None:
    """Mutation caught: swapping claim_token_jti back for blacklist_token.

    The loser of the race must be refused, and refused BEFORE any tokens are
    minted -- so the user lookup must not even run.
    """
    db = _db(session_row=(None, False))
    service = AuthService(db)

    with (
        patch("app.services.auth.decode_token", new=AsyncMock(return_value=_payload())),
        patch("app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=False)),
    ):
        with pytest.raises(TokenInvalidError):
            await service.refresh_tokens("already-used-token")

    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_rotation_preserves_the_remember_me_window() -> None:
    """Mutation caught: dropping the ``rmb`` claim / the long expires_delta.

    A remember-me session would silently shrink to the 14-day default on its
    first refresh and log the user out mid-window.
    """
    db = _db(session_row=(None, False))
    service = AuthService(db)

    with (
        patch(
            "app.services.auth.decode_token",
            new=AsyncMock(return_value=_payload(rmb=True)),
        ),
        patch("app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=True)),
    ):
        pair = await service.refresh_tokens("remember-me-token")

    claims = _decode(pair.refresh_token)
    assert claims.get("rmb") is True, "the rmb claim was not carried across rotation"
    lifetime_days = (claims["exp"] - datetime.now(UTC).timestamp()) / 86400
    assert lifetime_days > settings.REFRESH_TOKEN_EXPIRE_DAYS + 0.5
    assert lifetime_days <= settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS


@pytest.mark.asyncio
async def test_a_normal_session_does_not_get_the_long_window() -> None:
    """The bound has to bound something: no rmb claim, no 30-day token."""
    db = _db(session_row=(None, False))
    service = AuthService(db)

    with (
        patch("app.services.auth.decode_token", new=AsyncMock(return_value=_payload())),
        patch("app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=True)),
    ):
        pair = await service.refresh_tokens("plain-token")

    claims = _decode(pair.refresh_token)
    assert "rmb" not in claims
    lifetime_days = (claims["exp"] - datetime.now(UTC).timestamp()) / 86400
    assert lifetime_days <= settings.REFRESH_TOKEN_EXPIRE_DAYS
