# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""One mistyped digit must not lock a user out of their own MFA challenge.

``POST /auth/login/mfa`` blacklisted the ``mfa_pending`` token unconditionally,
~50 lines BEFORE it verified the submitted code. So the first wrong code
answered "Invalid MFA code" and every retry -- the login page resubmits the
same ``mfaToken`` -- hit the blacklist check and answered "Invalid or expired
MFA token" no matter how correct the code was. The user reads a fresh, correct
code off their phone and is told it is expired; the only escape is re-entering
the password.

The token is now spent on SUCCESS only, and brute force is bounded by a
per-token attempt budget (``_register_mfa_attempt``) instead. These tests drive
the real endpoint function twice with the same challenge, which is exactly what
the browser does and what nothing previously exercised.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pyotp
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.api.v1.endpoints.auth import login_mfa
from app.core.security import create_access_token
from app.core.security_utils import encrypt_field
from app.schemas.core import MfaLoginRequest


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "headers": [(b"user-agent", b"pytest-agent")],
            "client": ("203.0.113.9", 5555),
            "path": "/api/v1/auth/login/mfa",
            "method": "POST",
            "query_string": b"",
            "scheme": "http",
            "server": ("test", 80),
            "root_path": "",
        }
    )


class _FakeRedis:
    """Just enough of the async client for _register_mfa_attempt."""

    def __init__(self, counters: dict[str, int], broken: bool = False) -> None:
        self._counters = counters
        self._broken = broken

    async def incr(self, key: str) -> int:
        if self._broken:
            raise ConnectionError("redis down")
        self._counters[key] = self._counters.get(key, 0) + 1
        return self._counters[key]

    async def expire(self, key: str, ttl: int) -> None:
        if self._broken:
            raise ConnectionError("redis down")

    async def aclose(self) -> None:
        return None


@contextmanager
def _mfa_env(broken_redis: bool = False) -> Iterator[dict[str, Any]]:
    """Patch out everything around the code check, keeping the ordering real."""
    blacklist: set[str] = set()
    counters: dict[str, int] = {}

    async def _blacklist(jti: str, exp: Any) -> None:
        blacklist.add(jti)

    async def _is_blacklisted(jti: str) -> bool:
        return jti in blacklist

    with (
        patch("app.api.v1.endpoints.auth.check_auth_rate_limit", new=AsyncMock()),
        patch("app.api.v1.endpoints.auth._audit_failed_login", new=AsyncMock()),
        patch("app.api.v1.endpoints.auth._audit_auth_event", new=AsyncMock()),
        patch("app.api.v1.endpoints.auth.reset_auth_user_rate_limit", new=AsyncMock()),
        patch("app.core.token_blacklist.blacklist_token", new=_blacklist),
        patch("app.core.token_blacklist.is_token_blacklisted", new=_is_blacklisted),
        patch(
            "app.core.redis_client.get_async_redis",
            new=MagicMock(return_value=_FakeRedis(counters, broken=broken_redis)),
        ),
    ):
        yield {"blacklist": blacklist, "counters": counters}


def _make_user(secret: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        email="mfa-user@example.com",
        username="mfa-user",
        role="admin",
        organization_id=uuid4(),
        is_active=True,
        deleted_at=None,
        locked_until=None,
        token_version=0,
        mfa_enabled=True,
        mfa_secret=encrypt_field(secret),
        mfa_backup_codes=None,
        mfa_last_totp_step=None,
        last_login=None,
        failed_login_attempts=0,
    )


def _session_for(user: SimpleNamespace) -> AsyncMock:
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    session.execute = AsyncMock(return_value=result)
    return session


def _mfa_token(user: SimpleNamespace) -> str:
    """Exactly what /auth/login mints when MFA is required."""
    return create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=5),
        extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa", "rmb": False},
        token_version=user.token_version,
    )


async def _attempt(user: SimpleNamespace, token: str, code: str) -> Any:
    return await login_mfa(
        request=_request(),
        response=Response(),
        data=MfaLoginRequest(mfa_token=token, code=code),
        session=_session_for(user),
    )


def _wrong_code(valid: str) -> str:
    """A code that is definitely not the live one (fat-fingered last digit)."""
    return valid[:-1] + str((int(valid[-1]) + 5) % 10)


@pytest.mark.asyncio
async def test_a_wrong_code_does_not_burn_the_challenge() -> None:
    """The regression. Fails before the fix with "Invalid or expired MFA token"
    on the SECOND call, even though the code is correct."""
    secret = pyotp.random_base32()
    user = _make_user(secret)
    token = _mfa_token(user)

    with _mfa_env():
        valid = pyotp.TOTP(secret).now()

        with pytest.raises(HTTPException) as first:
            await _attempt(user, token, _wrong_code(valid))
        assert first.value.status_code == 401
        assert first.value.detail == "Invalid MFA code"

        # Same token, correct code -- what the login page actually resubmits.
        result = await _attempt(user, token, valid)

    assert result.expires_in > 0


@pytest.mark.asyncio
async def test_a_completed_challenge_cannot_be_replayed() -> None:
    """The control for the fix above: success must still spend the token.

    Mutation caught: deleting the post-verification blacklist write, which
    would let one mfa_pending token mint sessions until it expired. The
    distinct detail string matters -- without the blacklist the second call
    would fall through to the TOTP replay guard and say "Invalid MFA code".
    """
    secret = pyotp.random_base32()
    user = _make_user(secret)
    token = _mfa_token(user)

    with _mfa_env():
        await _attempt(user, token, pyotp.TOTP(secret).now())

        with pytest.raises(HTTPException) as replay:
            await _attempt(user, token, pyotp.TOTP(secret).now())

    assert replay.value.status_code == 401
    assert replay.value.detail == "Invalid or expired MFA token"


@pytest.mark.asyncio
async def test_guessing_is_bounded_and_then_the_challenge_is_spent() -> None:
    """Retrying must not become unlimited TOTP guessing.

    Mutation caught: removing the _register_mfa_attempt call, or raising the
    budget check above the attempt count.
    """
    secret = pyotp.random_base32()
    user = _make_user(secret)
    token = _mfa_token(user)

    with _mfa_env():
        valid = pyotp.TOTP(secret).now()
        wrong = _wrong_code(valid)

        for _ in range(5):
            with pytest.raises(HTTPException) as exc:
                await _attempt(user, token, wrong)
            assert exc.value.detail == "Invalid MFA code"

        with pytest.raises(HTTPException) as exhausted:
            await _attempt(user, token, wrong)
        assert exhausted.value.status_code == 401
        assert exhausted.value.detail == "Too many incorrect MFA codes. Please log in again."

        # ...and the challenge is now spent, so even the right code is refused.
        with pytest.raises(HTTPException) as after:
            await _attempt(user, token, valid)
        assert after.value.detail == "Invalid or expired MFA token"


@pytest.mark.asyncio
async def test_attempt_accounting_fails_closed_when_redis_is_down() -> None:
    """A Redis DoS must not turn the budget off.

    ``is_token_blacklisted`` upstream is fail-closed for the same reason;
    letting the counter fail open would make Redis the way in.
    """
    secret = pyotp.random_base32()
    user = _make_user(secret)
    token = _mfa_token(user)

    with _mfa_env(broken_redis=True):
        with pytest.raises(HTTPException) as exc:
            await _attempt(user, token, pyotp.TOTP(secret).now())

    assert exc.value.status_code == 503
