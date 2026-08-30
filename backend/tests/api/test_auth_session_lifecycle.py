# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Session-row bookkeeping and what /auth/logout actually revokes.

Two defects are pinned here.

1. ``_upsert_session`` never wrote ``UserSession.expires_at``. Every row in the
   table carried NULL (135/135 on the dev stack), which made the session
   reaper's ``expires_at < now`` half compare against NULL and match nothing,
   and left ``/auth/logout`` with no way to know when a device's refresh token
   dies.

2. ``/auth/logout`` blacklisted the refresh token only if it found the refresh
   cookie on the request. ``set_auth_cookies`` scopes that cookie to
   ``Path=/api/v1/auth/refresh``; RFC 6265 path-matching means no browser and
   no correct HTTP client ever sends it to ``/api/v1/auth/logout``. The whole
   block was unreachable, so logging out left the refresh token un-blacklisted
   and relied entirely on the ``revoked_at`` flip on one DB row -- a row
   ``_upsert_session`` is explicitly allowed to fail to write.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import Response
from starlette.requests import Request

from app.api.v1.endpoints.auth import _upsert_session, logout
from app.core.config import settings
from app.core.security import verify_token


def _request(cookies: dict[str, str] | None = None) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = [(b"user-agent", b"pytest-agent")]
    if cookies:
        raw_headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    return Request(
        {
            "type": "http",
            "headers": raw_headers,
            "client": ("203.0.113.9", 5555),
        }
    )


def _capture_session() -> tuple[AsyncMock, list[Any]]:
    """An AsyncSession double that records what gets ``add``ed."""
    added: list[Any] = []
    session = AsyncMock()
    session.add = MagicMock(side_effect=added.append)
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result)
    return session, added


# ─── 1. expires_at is written ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_new_session_row_records_when_its_refresh_token_dies() -> None:
    """The row must carry the refresh token's expiry, not NULL.

    Mutation caught: dropping ``expires_at=expires_at`` from the INSERT -- the
    exact shape of the shipped bug.
    """
    session, added = _capture_session()
    before = datetime.now(UTC)

    await _upsert_session(
        session,
        user_id=uuid4(),
        refresh_jti="jti-1",
        access_jti="acc-1",
        request=_request(),
    )

    assert len(added) == 1
    row = added[0]
    assert row.expires_at is not None, "session row still stores no expiry"
    expected = before + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    assert abs((row.expires_at - expected).total_seconds()) < 60


@pytest.mark.asyncio
async def test_remember_me_row_gets_the_long_window() -> None:
    """The row's expiry must track the token that was actually minted.

    Mutation caught: hardcoding the default window, or dropping the
    ``remember_me`` argument at a call site -- which would make the reaper
    delete a remember-me session on day 14 of its 30-day life, un-revoking it
    if it had been revoked.
    """
    session, added = _capture_session()
    before = datetime.now(UTC)

    await _upsert_session(
        session,
        user_id=uuid4(),
        refresh_jti="jti-2",
        access_jti="acc-2",
        request=_request(),
        remember_me=True,
    )

    row = added[0]
    expected = before + timedelta(days=settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS)
    assert abs((row.expires_at - expected).total_seconds()) < 60
    assert settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS != settings.REFRESH_TOKEN_EXPIRE_DAYS, (
        "the two windows are equal, so this test proves nothing"
    )


@pytest.mark.asyncio
async def test_rotation_moves_the_expiry_forward() -> None:
    """A refresh mints a NEW token, so the row's death date has to move with it.

    Mutation caught: updating refresh_jti on rotation but leaving expires_at
    behind, which would strand a live token on a row the reaper deletes.
    """
    stale = datetime.now(UTC) + timedelta(days=1)
    existing = SimpleNamespace(
        refresh_jti="old",
        access_jti="old-acc",
        last_used_at=None,
        expires_at=stale,
        user_agent=None,
        ip_address=None,
    )
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = existing
    session.execute = AsyncMock(return_value=result)

    await _upsert_session(
        session,
        user_id=uuid4(),
        refresh_jti="new",
        access_jti="new-acc",
        request=_request(),
        previous_refresh_jti="old",
    )

    assert existing.refresh_jti == "new"
    assert existing.expires_at > stale


# ─── 2. logout blacklists the refresh token ──────────────────────────────


@pytest.mark.asyncio
async def test_logout_blacklists_the_refresh_jti_without_the_refresh_cookie() -> None:
    """The request carries NO refresh cookie -- exactly what a browser sends.

    Before the fix, ``blacklist_token`` was awaited once (the access token) and
    the refresh token stayed usable for the rest of its window. Mutation
    caught: reverting to reading REFRESH_COOKIE off the request.
    """
    refresh_exp = datetime.now(UTC) + timedelta(days=14)
    row = SimpleNamespace(
        refresh_jti="refresh-jti-1",
        expires_at=refresh_exp,
        revoked_at=None,
        is_revoked=False,
    )
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=result)

    with (
        patch(
            "app.api.v1.endpoints.auth.decode_token",
            new=AsyncMock(return_value={"jti": "access-jti-1", "exp": 9999999999}),
        ),
        patch("app.core.token_blacklist.blacklist_token", new=AsyncMock()) as blacklist,
        patch("app.api.v1.endpoints.auth._audit_auth_event", new=AsyncMock()),
    ):
        await logout(
            request=_request(),  # no refresh cookie: it is Path-scoped away
            response=Response(),
            current_user=SimpleNamespace(id=uuid4(), token_version=1),
            token="access-token",
            session=session,
        )

    blacklisted = {call.args[0] for call in blacklist.await_args_list}
    assert "refresh-jti-1" in blacklisted, (
        "logout did not blacklist the device's refresh token; a stolen refresh "
        "token survives logout for the rest of its window"
    )
    assert "access-jti-1" in blacklisted
    ttl_arg = next(c.args[1] for c in blacklist.await_args_list if c.args[0] == "refresh-jti-1")
    assert ttl_arg == refresh_exp, "blacklist TTL must be the refresh token's own expiry"
    assert row.revoked_at is not None and row.is_revoked is True


@pytest.mark.asyncio
async def test_logout_survives_a_session_row_that_was_never_written() -> None:
    """``_upsert_session`` swallows its own failures, so no-row is a real state.

    Logout must still blacklist the access token and clear cookies rather than
    raise on the missing row.
    """
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result)
    response = Response()

    with (
        patch(
            "app.api.v1.endpoints.auth.decode_token",
            new=AsyncMock(return_value={"jti": "access-jti-2", "exp": 9999999999}),
        ),
        patch("app.core.token_blacklist.blacklist_token", new=AsyncMock()) as blacklist,
        patch("app.api.v1.endpoints.auth._audit_auth_event", new=AsyncMock()),
    ):
        out = await logout(
            request=_request(),
            response=response,
            current_user=SimpleNamespace(id=uuid4(), token_version=1),
            token="access-token",
            session=session,
        )

    assert out == {"message": "Successfully logged out"}
    blacklist.assert_awaited_once_with("access-jti-2", 9999999999)
    assert any(
        "freesdn_refresh=" in h and "Max-Age=0" in h for h in response.headers.getlist("set-cookie")
    )


class _FakeRedis:
    """Enough of the async client for token_blacklist's setex/exists."""

    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.keys.add(key)

    async def exists(self, key: str) -> int:
        return 1 if key in self.keys else 0


@pytest.mark.asyncio
async def test_after_logout_the_refresh_token_no_longer_verifies() -> None:
    """The end of the chain, with a REAL blacklist rather than a mock.

    A blacklist write only matters if ``/auth/refresh`` consults it, so this
    mints a real refresh token, logs out, and then asks ``verify_token`` --
    the first thing /auth/refresh does with the presented token -- whether it
    is still good. Before the fix nothing was written for it and this returns
    a payload; after, it returns None.
    """
    import app.core.token_blacklist as tb
    from app.api.v1.endpoints.auth import _create_refresh_with_jti

    refresh_token, refresh_jti = _create_refresh_with_jti(subject=str(uuid4()), token_version=0)
    assert refresh_jti is not None

    row = SimpleNamespace(
        refresh_jti=refresh_jti,
        expires_at=datetime.now(UTC) + timedelta(days=14),
        revoked_at=None,
        is_revoked=False,
    )
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=result)

    fake = _FakeRedis()
    with (
        patch.object(tb, "_get_redis", new=AsyncMock(return_value=fake)),
        patch("app.api.v1.endpoints.auth._audit_auth_event", new=AsyncMock()),
        patch(
            "app.api.v1.endpoints.auth.decode_token",
            new=AsyncMock(return_value={"jti": "access-jti-3", "exp": 9999999999}),
        ),
    ):
        # Sanity: the token is good before logout, so the assertion after the
        # logout call is about the logout and not about a broken fixture.
        assert await verify_token(refresh_token, token_type="refresh") is not None

        await logout(
            request=_request(),
            response=Response(),
            current_user=SimpleNamespace(id=uuid4(), token_version=1),
            token="access-token",
            session=session,
        )

        assert await verify_token(refresh_token, token_type="refresh") is None, (
            "the refresh token still verifies after logout"
        )
