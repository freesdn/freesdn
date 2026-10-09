"""Gateway cache authority over real PostgreSQL and HTTP; identity/vendor doubles."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.adapters.base import AdapterResult
from app.adapters.cache import TTLCache
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.middleware import setup_exception_handlers
from app.db import get_session
from app.models.core import Organization, Site, User
from app.modules.firewall import gateway_service
from app.modules.firewall.gateway_api import router
from app.modules.firewall.models import GatewayConnection

ROUTES = ["firmware", "packages", "plugins"]
MARKER = "owned-inventory-private-marker"
DENIALS = [
    "foreign-caller",
    "grant-changed",
    "null-site",
    "soft-deleted",
    "hard-deleted",
    "old-owner-after-transfer",
    "site-reassigned",
]


@pytest_asyncio.fixture
async def cache_gateway(db_session, monkeypatch):
    orgs = [Organization(name="Owned cache", slug=uuid4().hex) for _ in range(2)]
    db_session.add_all(orgs)
    await db_session.flush()
    sites = [
        Site(name="Owned cache site", slug=uuid4().hex, organization_id=orgs[i].id)
        for i in [0, 0, 1]
    ]
    db_session.add_all(sites)
    await db_session.flush()
    gateways = [
        GatewayConnection(
            org_id=orgs[0].id,
            site_id=sites[n % 2].id,
            name="Owned cache gateway",
            vendor="opnsense",
            host="192.168.77.77",
            port=443,
            verify_ssl=True,
            credentials={},
            settings={},
            sync_enabled=False,
        )
        for n in range(8)
    ]
    db_session.add_all(gateways)
    await db_session.flush()
    f = SimpleNamespace(
        db=db_session,
        orgs=orgs,
        sites=sites,
        gateways=gateways,
        gateway=gateways[0],
        site_ids={sites[0].id},
        calls=[],
        marker=MARKER,
        permissions=["firewall.view"],
        anonymous=False,
    )
    f.user = User(
        id=uuid4(),
        organization_id=orgs[0].id,
        email="owned-cache@example.test",
        hashed_password="synthetic",
        role="viewer",
        is_active=True,
    )

    class Adapter:
        async def connect(self):
            f.calls.append("connect")
            return True

        async def disconnect(self):
            f.calls.append("disconnect")

        async def get_firmware_info(self):
            f.calls.append("firmware")
            return AdapterResult.ok({"version": f.marker})

        async def get_installed_packages(self):
            f.calls.append("packages")
            return AdapterResult.ok({"packages": [{"name": f.marker}], "count": 1})

        async def get_installed_plugins(self):
            f.calls.append("plugins")
            return AdapterResult.ok({"plugins": [{"name": f.marker}], "count": 1})

    def create(**kwargs):
        f.calls.append("construct")
        return Adapter()

    monkeypatch.setattr(gateway_service.adapter_registry, "create_adapter", create)
    monkeypatch.setattr(gateway_service, "adapter_cache", TTLCache())
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    setup_exception_handlers(app)
    f.app = app

    def identity():
        if f.anonymous:
            raise HTTPException(401, "Not authenticated")
        return CurrentUser(f.user, f.permissions, accessible_site_ids=f.site_ids)

    async def session():
        yield db_session

    app.dependency_overrides[get_current_active_user] = identity
    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://owned-cache",
    ) as client:
        f.client = client
        try:
            yield f
        finally:
            # Cached dependency closures can retain this fixture after teardown.
            # Break its link to the closed client and its application graph.
            f.client = None
            # Classification caches retain override callables; release
            # their fixture cells after the final request has drained.
            f = None
            db_session = None


async def request(f, route):
    return await f.client.get(f"/firewall/gateways/{f.gateway.id}/{route}")


async def snapshot(f):
    await f.db.flush()
    rows = (
        (
            await f.db.execute(
                select(GatewayConnection.__table__).order_by(GatewayConnection.id)
            )
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


async def deny(f, kind):
    if kind == "foreign-caller":
        f.user.organization_id = f.orgs[1].id
    elif kind == "grant-changed":
        f.site_ids = {f.sites[1].id}
    elif kind == "null-site":
        f.gateway.site_id = None
    elif kind == "soft-deleted":
        f.gateway.deleted_at = datetime.now(UTC)
    elif kind == "hard-deleted":
        await f.db.delete(f.gateway)
    elif kind == "old-owner-after-transfer":
        f.gateway.org_id = f.orgs[1].id
        f.gateway.site_id = f.sites[2].id
    elif kind == "site-reassigned":
        f.gateway.site_id = f.sites[1].id
    else:
        raise AssertionError(kind)
    await f.db.flush()


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("kind", DENIALS)
async def test_warm_cache_cannot_bypass_current_gateway_scope(
    cache_gateway, route, kind
):
    f = cache_gateway
    warm = await request(f, route)
    assert warm.status_code == 200 and MARKER in warm.text
    assert f.calls == ["construct", "connect", route, "disconnect"]
    f.calls.clear()
    await deny(f, kind)
    before = await snapshot(f)
    result = await request(f, route)
    assert result.status_code == 404
    assert MARKER not in result.text and not f.calls
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
async def test_new_owner_does_not_receive_previous_tenant_cache(cache_gateway, route):
    f = cache_gateway
    assert (await request(f, route)).status_code == 200
    f.calls.clear()
    await deny(f, "old-owner-after-transfer")
    f.user.organization_id = f.orgs[1].id
    f.site_ids = {f.sites[2].id}
    f.marker = "owned-new-tenant-current-inventory"
    before = await snapshot(f)
    result = await request(f, route)
    assert (
        result.status_code == 200
        and f.marker in result.text
        and MARKER not in result.text
    )
    assert f.calls == ["construct", "connect", route, "disconnect"]
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
async def test_authorized_inventory_preserves_payload_and_firmware_is_fresh(
    cache_gateway, route
):
    f = cache_gateway
    before = await snapshot(f)
    first = await request(f, route)
    assert first.status_code == 200 and MARKER in first.text
    f.calls.clear()
    second = await request(f, route)
    assert second.status_code == 200 and second.json() == first.json()
    assert f.calls == (["construct", "connect", "firmware", "disconnect"] if route == "firmware" else [])
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
async def test_cold_foreign_tenant_is_still_refused_before_adapter(
    cache_gateway, route
):
    f = cache_gateway
    f.user.organization_id = f.orgs[1].id
    before = await snapshot(f)
    result = await request(f, route)
    assert result.status_code == 404 and MARKER not in result.text
    assert not f.calls and await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("kind,expected", [("permission", 403), ("anonymous", 401)])
async def test_endpoint_authentication_and_permission_still_gate_warm_cache(
    cache_gateway, route, kind, expected
):
    f = cache_gateway
    assert (await request(f, route)).status_code == 200
    f.calls.clear()
    if kind == "permission":
        f.permissions = []
    else:
        f.anonymous = True
    before = await snapshot(f)
    result = await request(f, route)
    assert result.status_code == expected and MARKER not in result.text
    assert not f.calls and await snapshot(f) == before
