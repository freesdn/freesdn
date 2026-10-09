"""Real database/router scope checks; caller identity and vendor responses are synthetic."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.adapters.base import AdapterResult
from app.adapters.cache import TTLCache
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.middleware import setup_exception_handlers
from app.db import get_session
from app.models.core import Organization, Site, User
from app.modules.firewall import gateway_service
from app.modules.firewall.gateway_api import router
from app.modules.firewall.models import GatewayConnection

SURFACES = [
    "detail",
    "list",
    "summary",
    "sync-logs",
    "firmware-cold",
    "firmware-warm",
    "packages-warm",
    "plugins-warm",
]
INVALID_PARENTS = ["org-deleted", "org-disabled", "site-deleted", "site-disabled", "site-foreign"]
MARKER = "owned-parent-private-inventory"


@pytest_asyncio.fixture
async def parent_gateway(db_session, monkeypatch):
    orgs = [Organization(name="Owned parent", slug=uuid4().hex) for _ in range(2)]
    db_session.add_all(orgs)
    await db_session.flush()
    sites = [
        Site(name="Owned parent site", slug=uuid4().hex, organization_id=orgs[n].id)
        for n in (0, 0, 1)
    ]
    db_session.add_all(sites)
    await db_session.flush()
    gateway = GatewayConnection(
        org_id=orgs[0].id,
        site_id=sites[0].id,
        name=MARKER,
        vendor="opnsense",
        host="192.168.77.77",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict({"api_key": "owned-test-key", "api_secret": "owned-test-secret"}),
        settings={},
        sync_enabled=False,
    )
    db_session.add(gateway)
    await db_session.flush()
    f = SimpleNamespace(
        db=db_session, orgs=orgs, sites=sites, gateway=gateway, grants=None, calls=[]
    )

    class Adapter:
        async def connect(self):
            f.calls.append("connect")
            return True

        async def disconnect(self):
            f.calls.append("disconnect")

        async def get_firmware_info(self):
            f.calls.append("firmware")
            return AdapterResult.ok({"version": MARKER})

        async def get_installed_packages(self):
            f.calls.append("packages")
            return AdapterResult.ok({"packages": [{"name": MARKER}], "count": 1})

        async def get_installed_plugins(self):
            f.calls.append("plugins")
            return AdapterResult.ok({"plugins": [{"name": MARKER}], "count": 1})

    def create(**kwargs):
        f.calls.append("construct")
        return Adapter()

    monkeypatch.setattr(gateway_service.adapter_registry, "create_adapter", create)
    monkeypatch.setattr(gateway_service, "adapter_cache", TTLCache())
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    setup_exception_handlers(app)
    user = User(
        id=uuid4(),
        organization_id=orgs[0].id,
        email="owned-parent@example.test",
        hashed_password="synthetic",
        role="viewer",
        is_active=True,
    )
    app.dependency_overrides[get_current_active_user] = lambda: CurrentUser(
        user, ["firewall.view"], accessible_site_ids=f.grants
    )

    async def session():
        yield db_session

    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned-parent"
    ) as client:
        f.client = client
        try:
            yield f
        finally:
            # Cached dependency closures can retain this fixture after teardown.
            # Break its link to the closed client and its application graph.
            f.client = None


async def request(f, surface):
    base = "/firewall/gateways"
    if surface == "list":
        path = base
    elif surface == "summary":
        path = base + "/summary"
    elif surface == "detail":
        path = base + f"/{f.gateway.id}"
    else:
        operation = surface.removesuffix("-cold").removesuffix("-warm")
        path = base + f"/{f.gateway.id}/{operation}"
    return await f.client.get(path)


async def snapshot(f):
    rows = (
        (await f.db.execute(select(GatewayConnection.__table__).order_by(GatewayConnection.id)))
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


def assert_allowed(response, surface):
    assert response.status_code == 200
    if surface == "list":
        assert response.json()["total"] == 1 and len(response.json()["items"]) == 1
    elif surface == "summary":
        assert response.json()["total_gateways"] == 1 and response.json()["by_vendor"] == {
            "opnsense": 1
        }
    elif surface == "sync-logs":
        assert response.json() == []
    else:
        assert MARKER in response.text


def assert_denied(response, surface):
    if surface == "list":
        assert response.status_code == 200 and response.json() == {"items": [], "total": 0}
    elif surface == "summary":
        assert response.status_code == 200
        assert response.json()["total_gateways"] == 0
        assert response.json()["by_vendor"] == {}
        assert all(value == 0 for key, value in response.json().items() if key != "by_vendor")
    else:
        assert response.status_code == 404
    assert MARKER not in response.text


async def invalidate(f, kind):
    if kind == "org-deleted":
        f.orgs[0].deleted_at = datetime.now(UTC)
    elif kind == "org-disabled":
        f.orgs[0].is_active = False
    elif kind == "site-deleted":
        f.sites[0].deleted_at = datetime.now(UTC)
    elif kind == "site-disabled":
        f.sites[0].is_active = False
    elif kind == "site-foreign":
        f.sites[0].organization_id = f.orgs[1].id
    else:
        raise AssertionError(kind)
    await f.db.flush()


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("kind", INVALID_PARENTS)
async def test_gateway_reads_require_current_active_parents(parent_gateway, surface, kind):
    f = parent_gateway
    if surface.endswith("-warm"):
        assert_allowed(await request(f, surface), surface)
    f.calls.clear()
    await invalidate(f, kind)
    before = await snapshot(f)
    response = await request(f, surface)
    assert_denied(response, surface)
    assert not f.calls and await snapshot(f) == before


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize(
    "scope",
    [
        "assigned-unrestricted",
        "assigned-granted",
        "unassigned-unrestricted",
        "unassigned-limited",
        "assigned-empty",
    ],
)
async def test_active_parent_scope_controls(parent_gateway, surface, scope):
    f = parent_gateway
    if scope.startswith("unassigned"):
        f.gateway.site_id = None
    if scope.endswith("granted") or scope.endswith("limited"):
        f.grants = {f.sites[0].id}
    if scope.endswith("empty"):
        f.grants = set()
    await f.db.flush()
    before = await snapshot(f)
    response = await request(f, surface)
    if scope == "unassigned-limited":
        assert_denied(response, surface)
        assert not f.calls
    else:
        assert_allowed(response, surface)
        if surface.endswith("-warm"):
            f.calls.clear()
            assert_allowed(await request(f, surface), surface)
            assert f.calls == (["construct", "connect", "firmware", "disconnect"] if surface == "firmware-warm" else [])
    assert await snapshot(f) == before


@pytest.mark.parametrize("surface", ["firmware-warm", "packages-warm", "plugins-warm"])
async def test_current_database_site_grant_beats_stale_identity_map(parent_gateway, surface):
    f = parent_gateway
    f.grants = {f.sites[0].id}
    assert_allowed(await request(f, surface), surface)
    f.calls.clear()
    old_site = f.gateway.site_id
    await f.db.execute(
        update(GatewayConnection)
        .where(GatewayConnection.id == f.gateway.id)
        .values(site_id=f.sites[1].id)
        .execution_options(synchronize_session=False)
    )
    assert f.gateway.site_id == old_site
    before = await snapshot(f)
    assert_denied(await request(f, surface), surface)
    assert not f.calls and await snapshot(f) == before
