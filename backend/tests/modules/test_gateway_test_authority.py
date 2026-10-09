"""Saved gateway tests cannot return or persist results after resource authority changes.

PostgreSQL transactions and HTTP routes are real. Authenticated identities and
adapter results are synthetic; a second committed session performs each race.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DBAPIError

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.db.session import CelerySessionLocal
from app.models.core import Organization, Site, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import adapter_registry
from app.modules.firewall.models import GatewayConnection

AUTHORITY_CHANGES = [
    "gateway-deleted",
    "gateway-hard-delete",
    "gateway-foreign",
    "gateway-site-moved",
    "gateway-unscoped",
    "site-deleted",
    "site-disabled",
    "site-foreign",
    "org-deleted",
    "org-disabled",
]
CONNECTION_CHANGES = [
    "vendor",
    "host",
    "port",
    "verify",
    "credentials",
    "settings",
    "revision",
    "online",
    "metadata",
    "name",
]
INITIAL_DENIALS = [
    name for name in AUTHORITY_CHANGES if name not in {"gateway-site-moved", "gateway-unscoped"}
]
RESULT_MARKER = "owned-stale-appliance-metadata"


@pytest_asyncio.fixture
async def saved_test(monkeypatch):
    org, other, site, sibling, foreign, gateway = [uuid4() for _ in range(6)]
    f = SimpleNamespace(
        org=org,
        other=other,
        site=site,
        sibling=sibling,
        foreign=foreign,
        gateway=gateway,
        during_io=None,
        before_commit=None,
        outcome=True,
        created=[],
        calls=0,
        disconnected=0,
    )
    async with CelerySessionLocal() as db:
        db.add_all(
            [
                Organization(id=org, name="Owned gateway test", slug=org.hex),
                Organization(id=other, name="Other gateway test", slug=other.hex),
            ]
        )
        await db.flush()
        db.add_all(
            [
                Site(
                    id=identity, organization_id=owner, name="Owned gateway site", slug=identity.hex
                )
                for identity, owner in [(site, org), (sibling, org), (foreign, other)]
            ]
        )
        await db.flush()
        db.add(
            GatewayConnection(
                id=gateway,
                org_id=org,
                site_id=site,
                name="Owned connection",
                vendor="mikrotik",
                host="192.168.77.77",
                port=8443,
                verify_ssl=True,
                credentials=encrypt_dict({"username": "owned-user", "password": "owned-secret"}),
                settings={"use_ssl": True},
                is_online=True,
                sync_enabled=False,
                detected_hostname="original-host",
                detected_version="original-version",
                detected_model="original-model",
                last_seen_at=datetime(2020, 1, 1, tzinfo=UTC),
            )
        )
        await db.commit()

    class Adapter:
        async def test_connection(self):
            f.calls += 1
            if f.during_io:
                await f.during_io()
            return (
                AdapterResult.ok(
                    data={"hostname": RESULT_MARKER, "version": "new-version", "model": "new-model"}
                )
                if f.outcome
                else AdapterResult.fail("owned-failure")
            )

        async def disconnect(self):
            f.disconnected += 1

    def create(**kwargs):
        f.created.append(kwargs)
        return Adapter()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    app = FastAPI()
    app.include_router(router)
    user = User(
        id=uuid4(),
        organization_id=org,
        email="owned-race@example.test",
        hashed_password="synthetic",
        role="org_admin",
        is_active=True,
    )
    current = CurrentUser(user, ["firewall.view", "firewall.manage_rules"])
    app.dependency_overrides[get_current_active_user] = lambda: current

    async def request_session():
        async with CelerySessionLocal() as db:
            yield db
            if f.before_commit:
                await f.before_commit()
            await db.commit()

    app.dependency_overrides[get_session] = request_session
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://owned-fixture",
        ) as client:
            f.client = client
            try:
                yield f
            finally:
                # Cached dependency closures can retain this fixture after teardown.
                # Break its link to the closed client and its application graph.
                f.client = None
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(GatewayConnection).where(GatewayConnection.id == gateway))
            await db.execute(delete(Site).where(Site.id.in_([site, sibling, foreign])))
            await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
            await db.commit()


async def state(f):
    async with CelerySessionLocal() as db:
        gateway = await db.get(GatewayConnection, f.gateway)
        if gateway is None:
            return None
        return {
            name: getattr(gateway, name)
            for name in [
                "org_id",
                "site_id",
                "deleted_at",
                "vendor",
                "host",
                "port",
                "verify_ssl",
                "credentials",
                "settings",
                "name",
                "updated_at",
                "is_online",
                "last_seen_at",
                "detected_hostname",
                "detected_version",
                "detected_model",
            ]
        }


async def change(f, name):
    now = datetime.now(UTC)
    updates = {
        "gateway-deleted": (GatewayConnection, f.gateway, {"deleted_at": now}),
        "gateway-foreign": (
            GatewayConnection,
            f.gateway,
            {"org_id": f.other, "site_id": f.foreign},
        ),
        "gateway-site-moved": (GatewayConnection, f.gateway, {"site_id": f.sibling}),
        "gateway-unscoped": (GatewayConnection, f.gateway, {"site_id": None}),
        "site-deleted": (Site, f.site, {"deleted_at": now}),
        "site-disabled": (Site, f.site, {"is_active": False}),
        "site-foreign": (Site, f.site, {"organization_id": f.other}),
        "org-deleted": (Organization, f.org, {"deleted_at": now}),
        "org-disabled": (Organization, f.org, {"is_active": False}),
        "vendor": (GatewayConnection, f.gateway, {"vendor": "openwrt"}),
        "host": (GatewayConnection, f.gateway, {"host": "192.168.88.88"}),
        "port": (GatewayConnection, f.gateway, {"port": 9443}),
        "verify": (GatewayConnection, f.gateway, {"verify_ssl": False}),
        "credentials": (
            GatewayConnection,
            f.gateway,
            {"credentials": encrypt_dict({"username": "new-user", "password": "new-secret"})},
        ),
        "settings": (GatewayConnection, f.gateway, {"settings": {"use_ssl": True, "timeout": 9}}),
        "revision": (GatewayConnection, f.gateway, {"updated_at": now + timedelta(days=1)}),
        "online": (GatewayConnection, f.gateway, {"is_online": False}),
        "metadata": (GatewayConnection, f.gateway, {"detected_hostname": "newer-independent-test"}),
        "name": (GatewayConnection, f.gateway, {"name": "Renamed during device test"}),
    }
    async with CelerySessionLocal() as writer:
        if name == "gateway-hard-delete":
            await writer.execute(delete(GatewayConnection).where(GatewayConnection.id == f.gateway))
        else:
            model, identity, fields = updates[name]
            await writer.execute(update(model).where(model.id == identity).values(**fields))
        await writer.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("change_name", AUTHORITY_CHANGES + CONNECTION_CHANGES)
@pytest.mark.parametrize("success", [False, True])
async def test_concurrent_change_refuses_stale_result_and_preserves_newer_row(
    saved_test, change_name, success
):
    f = saved_test
    f.outcome = success
    expected = []

    async def during_io():
        await change(f, change_name)
        expected.append(await state(f))

    f.during_io = during_io
    response = await f.client.post(f"/gateways/{f.gateway}/test")
    assert response.status_code == (404 if change_name in AUTHORITY_CHANGES else 409), response.text
    assert RESULT_MARKER not in response.text
    assert response.json()["detail"] == (
        "Gateway not found"
        if change_name in AUTHORITY_CHANGES
        else "Gateway changed during its connection test; retry the test"
    )
    assert f.calls == f.disconnected == 1 and len(f.created) == 1
    assert len(expected) == 1 and await state(f) == expected[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("change_name", INITIAL_DENIALS)
async def test_inactive_or_foreign_resource_scope_is_denied_before_device_contact(
    saved_test, change_name
):
    f = saved_test
    await change(f, change_name)
    expected = await state(f)
    response = await f.client.post(f"/gateways/{f.gateway}/test")
    assert response.status_code == 404, response.text
    assert not f.created and f.calls == f.disconnected == 0
    assert await state(f) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("success", [False, True])
@pytest.mark.parametrize("override", [None, False])
async def test_unchanged_scope_preserves_outcome_metadata_and_trust_override(
    saved_test, scoped, success, override
):
    f = saved_test
    f.outcome = success
    if not scoped:
        await change(f, "gateway-unscoped")
    response = await f.client.post(
        f"/gateways/{f.gateway}/test", json={} if override is None else {"verify_ssl": override}
    )
    assert response.status_code == 200, response.text
    assert response.json()["success"] is success
    assert f.calls == f.disconnected == 1 and len(f.created) == 1
    assert f.created[0]["verify_ssl"] is (override is not False)
    current = await state(f)
    assert current["is_online"] is success and current["verify_ssl"] is True
    assert current["settings"] == {"use_ssl": True}
    assert current["detected_hostname"] == (RESULT_MARKER if success else "original-host")


async def try_lock(f, model_name):
    model = {"gateway": GatewayConnection, "site": Site, "org": Organization}[model_name]
    async with CelerySessionLocal() as writer:
        try:
            await writer.execute(
                select(model).where(model.id == getattr(f, model_name)).with_for_update(nowait=True)
            )
        except DBAPIError as exc:
            return getattr(exc.orig, "sqlstate", None)
        return "unlocked"


@pytest.mark.asyncio
@pytest.mark.parametrize("model_name", ["gateway", "site", "org"])
async def test_current_scope_locked_until_result_transaction_commits(saved_test, model_name):
    f = saved_test
    observed = []

    async def before_commit():
        assert f.disconnected == 1
        observed.append(await try_lock(f, model_name))

    f.before_commit = before_commit
    response = await f.client.post(f"/gateways/{f.gateway}/test")
    assert response.status_code == 200, response.text
    assert observed == ["55P03"]
    assert await try_lock(f, model_name) == "unlocked"


@pytest.mark.asyncio
async def test_resource_locks_do_not_span_device_io(saved_test):
    f = saved_test
    observed = []

    async def during_io():
        for name in ["gateway", "site", "org"]:
            observed.append(await try_lock(f, name))

    f.during_io = during_io
    response = await f.client.post(f"/gateways/{f.gateway}/test")
    assert response.status_code == 200, response.text
    assert observed == ["unlocked"] * 3 and f.disconnected == 1
