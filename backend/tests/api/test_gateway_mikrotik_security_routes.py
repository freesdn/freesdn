# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the MikroTik security routes + user-create
correctness fixes.

Coverage:
* SNMP trap-target + v3-user GET routes exist (surface).
* Stage gate upgraded to controller:write.
* _USER_CREATE_LOCKS is bounded LRU (CORR-CRIT).
* User-create dedup is case-insensitive.
* Apply table covers SNMP trap-target + v3-user operations.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

# ─── Route surface ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path_template",
    [
        "/api/v1/gateway-mikrotik-security/{cid}/snmp/trap-targets",
        "/api/v1/gateway-mikrotik-security/{cid}/snmp/v3-users",
    ],
)
def test_route_exists(path_template: str) -> None:
    from app.main import app

    # OpenAPI is fastapi's canonical full-path route inventory (app.routes no
    # longer flattens included routers as of fastapi 0.137's _IncludedRouter).
    paths = set(app.openapi().get("paths", {}))
    expected = path_template.format(cid="{controller_id}")
    assert expected in paths, (
        f"expected {expected!r} in the route table"
    )


# ─── Stage-gate permission tightening ──────────────────


def test_security_stage_uses_controller_write() -> None:
    """The stage endpoint dependency must require controller:write
    (was network:write)."""
    import inspect

    from app.api.v1.endpoints.adapter_mikrotik_security import (
        stage_mikrotik_security_change,
    )

    src = inspect.getsource(stage_mikrotik_security_change)
    # Look for the permission string in the dependency declaration.
    assert "controller:write" in src, (
        "stage gate must require controller:write"
    )


# ─── _USER_CREATE_LOCKS bounded LRU (CORR-CRIT) ─────────────────────


@pytest.mark.asyncio
async def test_user_create_lock_lru_bound() -> None:
    """Locks dict must stay at or below _USER_CREATE_LOCKS_MAX even
    after seeding past the cap."""
    from app.services import adapter_mikrotik_security as svc

    svc._USER_CREATE_LOCKS.clear()
    cap = svc._USER_CREATE_LOCKS_MAX
    # Seed past the cap.
    for i in range(cap + 50):
        cid = uuid4()
        await svc._get_user_create_lock(cid, f"user{i}")
    assert len(svc._USER_CREATE_LOCKS) <= cap, (
        f"locks dict grew past cap: {len(svc._USER_CREATE_LOCKS)} > {cap}"
    )


@pytest.mark.asyncio
async def test_user_create_lock_case_insensitive_key() -> None:
    """``Admin`` and ``admin`` and ``ADMIN`` must collapse to the same
    lock so RouterOS' case-insensitive duplicate detection cannot be
    raced by two case-variant staged changes."""
    from app.services import adapter_mikrotik_security as svc

    svc._USER_CREATE_LOCKS.clear()
    cid = uuid4()
    a = await svc._get_user_create_lock(cid, "Admin")
    b = await svc._get_user_create_lock(cid, "admin")
    c = await svc._get_user_create_lock(cid, "ADMIN")
    assert a is b is c, (
        "case-variant user names must share the same per-name lock"
    )


# ─── User-create case-variant duplicate detection ─────


@pytest.mark.asyncio
async def test_user_create_rejects_case_variant() -> None:
    """A staged ``add user 'Admin'`` change must 409 when an ``admin``
    row already exists on the router."""
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.services.adapter_mikrotik_security import (
        GatewayMikrotikSecurityService,
    )

    # Build a fake client that reports an existing 'admin' row.
    class _FakeClient:
        async def get_users(self) -> list[dict]:
            return [{"name": "admin", "group": "full"}]

        async def add_user(self, payload: dict, *, force: bool = False) -> dict:
            raise AssertionError(
                "add_user must NOT be reached when a case-variant exists"
            )

    fake_client = _FakeClient()

    # Mock the service's _get_controller + _get_client so we don't
    # need a real DB session.
    svc = GatewayMikrotikSecurityService.__new__(
        GatewayMikrotikSecurityService
    )
    svc.db = None  # type: ignore[assignment]
    svc.staging = None  # type: ignore[assignment]

    async def _get_controller(*args, **kwargs):
        return SimpleNamespace(id=uuid4(), controller_type="mikrotik")

    async def _get_client(*args, **kwargs):
        return fake_client

    svc._get_controller = _get_controller  # type: ignore[assignment]
    # vendor services migrated to the polymorphic
    # ``_resolve_controller_or_gateway`` helper. Stub both names so the
    # test keeps working through the rename.
    svc._resolve_controller_or_gateway = _get_controller  # type: ignore[assignment]
    svc._get_client = _get_client  # type: ignore[assignment]

    change = SimpleNamespace(
        controller_id=uuid4(),
        organization_id=uuid4(),
        feature="mikrotik.security.user",
        operation="create",
        payload={"name": "Admin", "password": "x"},
        target_id=None,
    )
    applier = svc.build_applier(change)
    with pytest.raises(HTTPException) as exc:
        await applier(change)
    assert exc.value.status_code == 409
    assert "already exists" in exc.value.detail


# ─── SNMP applier table coverage ────────────────────────────────────


def test_snmp_apply_table_covers_round3_features() -> None:
    from app.services.adapter_mikrotik_security import _APPLY

    required = [
        ("mikrotik.security.snmp.settings", "update"),
        ("mikrotik.security.snmp.trap_target", "create"),
        ("mikrotik.security.snmp.trap_target", "update"),
        ("mikrotik.security.snmp.trap_target", "delete"),
        ("mikrotik.security.snmp.v3_user", "create"),
        ("mikrotik.security.snmp.v3_user", "update"),
        ("mikrotik.security.snmp.v3_user", "delete"),
    ]
    for key in required:
        assert key in _APPLY, f"applier table missing {key!r}"
