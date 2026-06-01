# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""HTTP-layer security tests for the gateway-* stage endpoints.

These verify the privilege-boundary guards added in the
audit: every stage endpoint must refuse a ``feature`` that doesn't
belong to its own prefix, even when the caller has the documented
permission for that endpoint. Otherwise a low-privilege operator
could smuggle a high-privilege feature through (e.g.
``firmware:upgrade`` user staging ``system.admin/create`` via the
firmware endpoint).

All requests run against the FastAPI app with mocked auth + DB
dependencies. **No live Omada controller is contacted at any point**.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient


def _get_app():
    from app.main import app
    return app


def _fake_user(*, permissions: list[str] | None = None) -> MagicMock:
    user = MagicMock()
    user.id = uuid.uuid4()
    user.organization_id = uuid.uuid4()
    user.is_superuser = False
    user.is_active = True
    user.role = "operator"
    user.permissions = permissions or []
    user.has_permission = lambda p: (
        p in (permissions or []) or "*" in (permissions or [])
    )
    return user


def _override_app(app, fake_user, mock_session) -> None:
    from app.core.dependencies import (
        get_current_active_user,
        get_current_user,
    )
    from app.db import get_session

    async def _override_user() -> MagicMock:
        return fake_user

    async def _override_session():
        yield mock_session

    app.dependency_overrides[get_current_active_user] = _override_user
    app.dependency_overrides[get_current_user] = _override_user
    app.dependency_overrides[get_session] = _override_session


def _clear(app) -> None:
    app.dependency_overrides.clear()


# Cookie-less Bearer header bypasses the CSRF middleware (see
# CSRFMiddleware.dispatch). Auth itself is overridden separately via
# the dependency overrides — the Bearer token here is not validated.
_BEARER_HEADERS = {"Authorization": "Bearer test-bypass-csrf"}


# ── Stage prefix allowlists ──────────────────────────────────────


# (endpoint path, valid feature for this domain, mismatched feature
# from another domain that must be rejected). The path uses
# placeholders for controller_id and (optionally) site_id.
PREFIX_CASES: list[tuple[str, str, str]] = [
    # Each gateway-* stage endpoint locked to its own prefix.
    (
        "/api/v1/gateway-bulk/{ctrl}/sites/{site}/changes/{feature}",
        "bulk.device.adopt",
        "system.admin",
    ),
    (
        "/api/v1/gateway-hotspot/{ctrl}/sites/{site}/changes/{feature}",
        "hotspot.operator",
        "vpn.ipsec.policy",
    ),
    (
        "/api/v1/gateway-routing/{ctrl}/sites/{site}/changes/{feature}",
        "routing.vrrp",
        "system.smtp",
    ),
    (
        "/api/v1/gateway-switch-advanced/{ctrl}/sites/{site}/changes/{feature}",
        "switch.sflow",
        "firewall.dmz",
    ),
    (
        "/api/v1/gateway-wifi/{ctrl}/sites/{site}/changes/{feature}",
        "wifi.wlan_group.advanced",
        "system.admin",
    ),
    (
        "/api/v1/gateway-firewall/{ctrl}/sites/{site}/changes/{feature}",
        "firewall.dmz",
        "system.admin",
    ),
    (
        "/api/v1/gateway-firmware/{ctrl}/sites/{site}/changes/{feature}",
        "firmware.upgrade",
        "system.admin",
    ),
    (
        "/api/v1/gateway-profiles/{ctrl}/sites/{site}/changes/{feature}",
        "profile.dhcp",
        "system.admin",
    ),
    (
        "/api/v1/gateway-vpn/{ctrl}/sites/{site}/changes/{feature}",
        "vpn.ipsec.policy",
        "system.admin",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path_tmpl, valid, mismatched", PREFIX_CASES)
async def test_stage_endpoint_rejects_out_of_prefix_feature(
    path_tmpl: str, valid: str, mismatched: str
) -> None:
    """A low-privilege operator with the endpoint's permission can't
    smuggle a high-privilege ``feature`` through the URL path."""
    app = _get_app()
    user = _fake_user(
        permissions=[
            # Grant every per-endpoint permission so the test isolates
            # the prefix check, not the auth check.
            "controller:read",
            "controller:write",
            "network:read",
            "network:write",
            "vpn:read",
            "vpn:write",
            "firewall:read",
            "firewall:write",
            "firmware:upgrade",
        ]
    )
    mock_session = AsyncMock()
    _override_app(app, user, mock_session)

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            ctrl = str(uuid.uuid4())
            site = str(uuid.uuid4())
            url = path_tmpl.format(ctrl=ctrl, site=site, feature=mismatched)
            resp = await c.post(
                url,
                params={"operation": "create"},
                json={"payload": {}, "target_id": None, "notes": None},
                headers=_BEARER_HEADERS,
            )
            # Either 400 (the prefix-allowlist check fired) or 422
            # (Pydantic refused the body). The keystone is "NOT 201".
            assert resp.status_code in (400, 422), (
                f"out-of-prefix feature was accepted! "
                f"url={url} status={resp.status_code} body={resp.text}"
            )
            if resp.status_code == 400:
                # The allowlist layer produces a specific error
                # message. Backend wraps HTTPException as either
                # ``{"detail": ...}`` (FastAPI default) or
                # ``{"error": {"message": ...}}`` (custom handler).
                body = resp.json()
                detail = (
                    body.get("detail")
                    or body.get("error", {}).get("message", "")
                )
                assert "only accepts" in detail or "feature" in detail.lower()
    finally:
        _clear(app)


# ── Site-scoped vs controller-scoped system endpoint ─────────────


@pytest.mark.asyncio
async def test_system_site_endpoint_refuses_controller_features() -> None:
    """``POST /gateway-system/{c}/sites/{s}/changes/system.admin``
    must be refused because system.* is controller-scoped — even
    though the endpoint requires only network:write."""
    app = _get_app()
    user = _fake_user(
        permissions=["network:read", "network:write", "controller:read"]
    )
    _override_app(app, user, AsyncMock())

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            url = (
                f"/api/v1/gateway-system/{uuid.uuid4()}"
                f"/sites/{uuid.uuid4()}/changes/system.admin"
            )
            resp = await c.post(
                url,
                params={"operation": "create"},
                json={"payload": {}},
                headers=_BEARER_HEADERS,
            )
            assert resp.status_code == 400
            body = resp.json()
            detail = (
                body.get("detail")
                or body.get("error", {}).get("message", "")
            )
            assert "site" in detail.lower()
    finally:
        _clear(app)


@pytest.mark.asyncio
async def test_system_controller_endpoint_refuses_site_features() -> None:
    """And the converse: the controller-scoped endpoint refuses
    site.* features so they go through the site-scoped path."""
    app = _get_app()
    user = _fake_user(
        permissions=["controller:read", "controller:write"]
    )
    _override_app(app, user, AsyncMock())

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            url = (
                f"/api/v1/gateway-system/{uuid.uuid4()}"
                f"/changes/site.led_schedule"
            )
            resp = await c.post(
                url,
                params={"operation": "update"},
                json={"payload": {}},
                headers=_BEARER_HEADERS,
            )
            assert resp.status_code == 400
    finally:
        _clear(app)
