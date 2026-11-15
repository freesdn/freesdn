# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Email password reset cannot give an SSO-only account a local password.

A JIT-provisioned SSO account has no local password (``!SSO_MANAGED``), so it
can sign in only through its identity provider. The reset endpoints never
looked at that: requesting a reset minted a link for it, and redeeming the link
set a local password. From then on the account could sign in at /auth/login
around the IdP's MFA and conditional access, and kept doing so after the IdP
disabled the user. Now no link is issued for such an account (same response as
an unknown email), and a link minted earlier is refused.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.core import User

NEW_PASSWORD = "Fresh-Local-Passw0rd!x"


async def _user(db: AsyncSession, *, sso: bool) -> User:
    tag = uuid4().hex[:10]
    user = User(
        id=uuid4(),
        email=f"reset-{tag}@example.com",
        username=f"reset-{tag}",
        full_name="Reset Probe",
        hashed_password="!SSO_MANAGED" if sso else get_password_hash("Old-Local-Passw0rd!"),
        role="viewer",
        is_active=True,
        is_verified=True,
        organization_id=None,
        auth_provider="oidc" if sso else "local",
    )
    db.add(user)
    await db.flush()
    return user


def _reset_token(user: User) -> str:
    """The same token the reset-request endpoint mints."""
    return create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(hours=1),
        token_version=user.token_version or 0,
        extra_claims={"type": "password_reset"},
    )


async def test_a_reset_link_cannot_set_a_password_on_an_sso_account(
    async_client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session, sso=True)

    response = await async_client.post(
        "/api/v1/auth/password/reset",
        json={"token": _reset_token(user), "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 400
    await db_session.refresh(user)
    assert user.hashed_password == "!SSO_MANAGED"


async def test_a_local_account_can_still_reset(
    async_client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session, sso=False)

    response = await async_client.post(
        "/api/v1/auth/password/reset",
        json={"token": _reset_token(user), "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 200, response.text
    await db_session.refresh(user)
    assert verify_password(NEW_PASSWORD, user.hashed_password)


async def test_no_reset_link_is_issued_for_an_sso_account(
    async_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DEBUG with no email provider returns the link in the response, which
    # makes "was a link minted" observable without an outbox.
    monkeypatch.setattr(settings, "DEBUG", True)
    sso = await _user(db_session, sso=True)
    local = await _user(db_session, sso=False)

    sso_resp = await async_client.post(
        "/api/v1/auth/password/reset-request", json={"email": sso.email}
    )
    local_resp = await async_client.post(
        "/api/v1/auth/password/reset-request", json={"email": local.email}
    )

    assert sso_resp.status_code == 200
    assert local_resp.status_code == 200
    assert "reset_url" in local_resp.json(), "control: a local account gets a link"
    assert "reset_url" not in sso_resp.json()
    assert sso_resp.json()["message"] == local_resp.json()["message"]
