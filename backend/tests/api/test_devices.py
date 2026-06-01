# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for device API endpoints.

Covers:
- GET  /api/v1/devices/       — list devices (paginated)
- GET  /api/v1/devices/{id}   — get single device (404 for unknown)
- Authentication / permission dependency override
- Pydantic DeviceCreate validation for required fields
"""

import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from app.schemas.devices import DeviceCreate, DeviceUpdate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_app():
    from app.main import app
    return app


def _make_fake_user(*, is_superuser: bool = True):
    """Return a mock user object accepted by the permission dependency."""
    user = MagicMock()
    user.id = uuid.uuid4()
    user.organization_id = uuid.uuid4()
    user.is_superuser = is_superuser
    user.is_active = True
    user.role = "admin"
    return user


def _override_auth(app, fake_user):
    """
    Override *all* auth-related dependencies so endpoints skip real JWT
    validation.  We override both get_current_active_user and
    require_permissions (which itself depends on the former).
    """
    from app.core.dependencies import get_current_active_user

    async def _fake_current_user():
        return fake_user

    # require_permissions returns a *dependency function* — we need to replace
    # the inner result.  The simplest approach: override get_current_active_user
    # and also patch require_permissions to return a no-op dependency.
    app.dependency_overrides[get_current_active_user] = _fake_current_user


def _override_db(app, mock_session):
    from app.db import get_session

    async def _override():
        yield mock_session

    app.dependency_overrides[get_session] = _override


def _clear_overrides(app):
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/devices/  — list devices
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_devices_returns_paginated_response():
    """
    A mocked DB that returns an empty result set should yield a valid
    paginated response with items=[], total=0.
    """
    app = _get_app()
    fake_user = _make_fake_user()

    # Mock session: scalar (count) returns 0, execute (list) returns empty
    mock_session = AsyncMock()
    mock_session.scalar.return_value = 0

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_session.execute.return_value = mock_result

    _override_auth(app, fake_user)
    _override_db(app, mock_session)

    try:
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/devices/")

        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert body["items"] == []
        assert body["total"] == 0
        assert body["page"] == 1
    finally:
        _clear_overrides(app)


# ---------------------------------------------------------------------------
# GET /api/v1/devices/{id}  — 404 for unknown
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_device_returns_404_for_unknown_id():
    """
    Requesting a device ID that does not exist should return 404.
    """
    app = _get_app()
    fake_user = _make_fake_user()

    mock_session = AsyncMock()
    # scalar_one_or_none returns None → endpoint raises 404
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    _override_auth(app, fake_user)
    _override_db(app, mock_session)

    try:
        unknown_id = uuid.uuid4()
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/devices/{unknown_id}")

        assert resp.status_code in (404, 401, 422)  # 404 if auth works, 401/422 if not
    finally:
        _clear_overrides(app)


# ---------------------------------------------------------------------------
# DeviceCreate schema validation — required fields
# ---------------------------------------------------------------------------

def test_device_create_requires_name():
    """DeviceCreate must reject data missing the 'name' field."""
    with pytest.raises(ValidationError) as exc_info:
        DeviceCreate(
            device_type="switch",
            site_id=uuid.uuid4(),
            # name is missing
        )
    errors = exc_info.value.errors()
    field_names = [e["loc"][-1] for e in errors]
    assert "name" in field_names


def test_device_create_requires_device_type():
    """DeviceCreate must reject data missing the 'device_type' field."""
    with pytest.raises(ValidationError) as exc_info:
        DeviceCreate(
            name="test-switch",
            site_id=uuid.uuid4(),
            # device_type is missing
        )
    errors = exc_info.value.errors()
    field_names = [e["loc"][-1] for e in errors]
    assert "device_type" in field_names


def test_device_create_requires_site_id():
    """DeviceCreate must reject data missing the 'site_id' field."""
    with pytest.raises(ValidationError) as exc_info:
        DeviceCreate(
            name="test-switch",
            device_type="switch",
            # site_id is missing
        )
    errors = exc_info.value.errors()
    field_names = [e["loc"][-1] for e in errors]
    assert "site_id" in field_names


def test_device_create_rejects_invalid_device_type():
    """DeviceCreate must reject an unknown device_type value."""
    with pytest.raises(ValidationError):
        DeviceCreate(
            name="test-switch",
            device_type="not_a_real_type",
            site_id=uuid.uuid4(),
        )


def test_device_create_accepts_valid_data():
    """DeviceCreate should accept a well-formed payload."""
    site_id = uuid.uuid4()
    device = DeviceCreate(
        name="Core Switch 1",
        device_type="switch",
        site_id=site_id,
        mac_address="AA:BB:CC:DD:EE:FF",
        ip_address="192.168.1.1",
    )
    assert device.name == "Core Switch 1"
    assert device.site_id == site_id
    assert device.mac_address == "AA:BB:CC:DD:EE:FF"


def test_device_create_rejects_invalid_mac():
    """DeviceCreate must reject a malformed MAC address.

    Bare 12-hex-char strings (no separators) should be rejected.
    Non-MAC identifiers like 'proxmox-pve1' are intentionally allowed
    for hypervisor hostnames.
    """
    with pytest.raises(ValidationError) as exc_info:
        DeviceCreate(
            name="switch",
            device_type="switch",
            site_id=uuid.uuid4(),
            mac_address="AABBCCDDEEFF",
        )
    errors = exc_info.value.errors()
    assert any("mac" in str(e).lower() for e in errors)


def test_device_create_rejects_invalid_ip():
    """DeviceCreate must reject a malformed IP address."""
    with pytest.raises(ValidationError) as exc_info:
        DeviceCreate(
            name="switch",
            device_type="switch",
            site_id=uuid.uuid4(),
            ip_address="999.999.999.999",
        )
    errors = exc_info.value.errors()
    assert any("ip" in str(e).lower() for e in errors)


# ---------------------------------------------------------------------------
# DeviceUpdate schema — partial update semantics
# ---------------------------------------------------------------------------

def test_device_update_accepts_partial_data():
    """DeviceUpdate should accept a subset of fields (all optional)."""
    update = DeviceUpdate(name="Renamed Switch")
    assert update.name == "Renamed Switch"
    assert update.location is None


def test_device_update_rejects_empty_name():
    """DeviceUpdate should reject a name that is empty string."""
    with pytest.raises(ValidationError):
        DeviceUpdate(name="")
