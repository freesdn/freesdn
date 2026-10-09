# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Independent committed site changes must invalidate queued discovery reads."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import delete, update

from app.db.session import CelerySessionLocal
from app.models.core import Organization, Site
from app.modules.network import api
from app.tasks import discovery
from tests.security.test_pentest_network_queued_job_sitegrant import _make_current_user


@pytest_asyncio.fixture
async def committed_sites(monkeypatch):
    org, other, site, sibling, foreign, task_id = [uuid4() for _ in range(6)]
    async with CelerySessionLocal() as db:
        db.add_all(
            [
                Organization(id=identity, name="Owned discovery fixture", slug=identity.hex)
                for identity in [org, other]
            ]
        )
        await db.flush()
        db.add_all(
            [
                Site(id=identity, organization_id=owner, name="Owned site", slug=identity.hex)
                for identity, owner in [(site, org), (sibling, org), (foreign, other)]
            ]
        )
        await db.commit()
    scope = SimpleNamespace(task_id=task_id, organization_id=org, site_id=site)
    status = MagicMock(return_value={"status": "success", "devices_found": 77})
    reserve, publish = AsyncMock(return_value=True), MagicMock()
    monkeypatch.setattr(api, "get_discovery_scope", AsyncMock(return_value=scope))
    monkeypatch.setattr(api, "discovery_status", status)
    monkeypatch.setattr(api, "reserve_discovery_scope", reserve)
    monkeypatch.setattr(discovery.discover_all_devices, "apply_async", publish)
    try:
        yield SimpleNamespace(
            org=org,
            other=other,
            site=site,
            sibling=sibling,
            foreign=foreign,
            task_id=task_id,
            scope=scope,
            status=status,
            reserve=reserve,
            publish=publish,
        )
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(Site).where(Site.id.in_([site, sibling, foreign])))
            await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
            await db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["disabled", "deleted", "moved", "grant-revoked", "removed"])
async def test_committed_current_site_change_refuses_existing_owner_before_backend(
    committed_sites, change
):
    f = committed_sites
    caller = _make_current_user(f.org, role="operator", site_grants=[f.site])
    async with CelerySessionLocal() as db:
        assert (await api.get_discovery_status(db, caller, task_id=str(f.task_id)))[
            "devices_found"
        ] == 77
    f.status.reset_mock()
    if change == "grant-revoked":
        # Explicit grants remain nonempty: zero-grant compatibility is a separate policy.
        caller = _make_current_user(f.org, role="operator", site_grants=[f.sibling])
    else:
        async with CelerySessionLocal() as writer:
            if change == "removed":
                await writer.execute(delete(Site).where(Site.id == f.site))
            else:
                values = {
                    "disabled": {"is_active": False},
                    "deleted": {"deleted_at": datetime.now(UTC)},
                    "moved": {"organization_id": f.other},
                }[change]
                await writer.execute(update(Site).where(Site.id == f.site).values(**values))
            await writer.commit()
    async with CelerySessionLocal() as db:
        with pytest.raises(HTTPException) as error:
            await api.get_discovery_status(db, caller, task_id=str(f.task_id))
    assert error.value.status_code == 404
    f.status.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["org_admin", "super_admin"])
@pytest.mark.parametrize("route", ["start_discovery", "refresh_topology"])
async def test_named_foreign_site_never_reserves_or_publishes_even_for_admin(
    committed_sites, role, route
):
    f = committed_sites
    caller = _make_current_user(f.org, role=role)
    async with CelerySessionLocal() as db:
        with pytest.raises(HTTPException) as error:
            await getattr(api, route)(db, caller, site_id=f.foreign)
    assert error.value.status_code == 404
    f.reserve.assert_not_called()
    f.publish.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["operator", "org_admin", "super_admin"])
async def test_active_same_tenant_site_remains_usable(committed_sites, role):
    f = committed_sites
    caller = _make_current_user(f.org, role=role, site_grants=[f.site])
    async with CelerySessionLocal() as db:
        result = await api.start_discovery(db, caller, site_id=f.site)
    assert result["status"] == "accepted"
    scope = f.reserve.call_args.args[0]
    assert scope.organization_id == f.org and scope.site_id == f.site
    assert str(scope.task_id) == result["task_id"] == f.publish.call_args.kwargs["task_id"]
