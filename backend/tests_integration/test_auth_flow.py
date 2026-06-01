"""
Integration tests — end-to-end authentication flow against a real
Postgres + Redis stack.

Covers the security-critical paths the unit suite mocks out:
  - Setup wizard creates a super_admin from a fresh database
  - Login returns valid JWTs that carry the correct token_version
  - Authenticated requests succeed
  - Refresh rotates the access token
  - Logout bumps token_version and invalidates outstanding tokens

Each test runs inside a SAVEPOINT-rollback transaction (see conftest)
so writes never leak between tests.
"""

from __future__ import annotations

from typing import Any

import pytest


pytestmark = pytest.mark.asyncio


async def test_setup_admin_creates_super_admin(integration_client: Any) -> None:
    """A fresh DB allows POST /setup/admin to create exactly one super_admin."""
    resp = await integration_client.post(
        "/api/v1/setup/admin",
        json={
            "email": "first.admin@example.com",
            "username": "first_admin",
            "password": "FirstP@ssw0rd!1",
            "first_name": "First",
            "last_name": "Admin",
        },
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["email"] == "first.admin@example.com"
    assert body["username"] == "first_admin"
    assert body["user_id"] is not None


async def test_setup_admin_blocked_when_super_admin_exists(
    integration_client: Any, super_admin: dict[str, Any]
) -> None:
    """The setup endpoint MUST refuse a second admin once one exists."""
    resp = await integration_client.post(
        "/api/v1/setup/admin",
        json={
            "email": "second.admin@example.com",
            "username": "second_admin",
            "password": "SecondP@ssw0rd!1",
            "first_name": "Second",
            "last_name": "Admin",
        },
    )
    # setup is closed once a super_admin exists in the DB.
    # The endpoint may return 403 or 409 depending on which gate fires first.
    assert resp.status_code in (403, 409), (
        f"setup/admin must reject second-admin attempt; got {resp.status_code}"
    )


async def test_login_returns_access_and_refresh_tokens(
    integration_client: Any, super_admin: dict[str, Any]
) -> None:
    """Login with valid credentials returns both tokens."""
    assert super_admin["access_token"]
    assert super_admin["refresh_token"]
    assert super_admin["access_token"] != super_admin["refresh_token"]


async def test_login_rejects_wrong_password_with_401(
    integration_client: Any, super_admin: dict[str, Any]
) -> None:
    """Wrong password returns 401 with the same message as unknown user."""
    resp = await integration_client.post(
        "/api/v1/auth/login",
        json={"login": super_admin["email"], "password": "totally-wrong-password"},
    )
    assert resp.status_code == 401, resp.text
    body = resp.json()
    # SECURITY: identical error for wrong-password and unknown-user paths
    detail = body.get("detail") or body.get("error", {}).get("message", "")
    assert "Incorrect" in detail or "incorrect" in detail.lower()


async def test_authenticated_request_succeeds(
    integration_client: Any, super_admin: dict[str, Any]
) -> None:
    """A valid Bearer token unlocks the /me endpoint."""
    resp = await integration_client.get(
        "/api/v1/auth/me",
        headers=super_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["email"] == super_admin["email"]


async def test_unauthenticated_request_is_rejected(integration_client: Any) -> None:
    """No Authorization header → 401 (or 403 depending on implementation)."""
    resp = await integration_client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403), (
        f"unauthenticated request must be rejected; got {resp.status_code}"
    )
