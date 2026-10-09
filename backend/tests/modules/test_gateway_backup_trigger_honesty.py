"""Legacy backup admission over PostgreSQL/ASGI; adapter I/O is explicit doubles."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, Site, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import adapter_registry
from app.modules.firewall.models import GatewayConnection

SECRET = "owned-backup-trigger-secret"
XML = "<opnsense><description>owned α</description></opnsense>"
UNAVAILABLE = "Managed gateway configuration backup storage is not implemented; no backup was saved"


@pytest_asyncio.fixture
async def trigger(db_session, monkeypatch):
    org = Organization(name="Owned backup", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    sites = [Site(name=f"Owned {n}", slug=uuid4().hex, organization_id=org.id) for n in range(2)]
    db_session.add_all(sites)
    await db_session.flush()
    gateways = [
        GatewayConnection(
            org_id=org.id,
            site_id=sites[n % 2].id,
            name=f"Owned gateway {n}",
            vendor="opnsense",
            host="192.168.77.77",
            port=443,
            verify_ssl=True,
            credentials=encrypt_dict({"api_key": "owned", "api_secret": SECRET}),
            settings={},
            sync_enabled=False,
        )
        for n in range(8)
    ]
    db_session.add_all(gateways)
    await db_session.flush()
    f = SimpleNamespace(
        db=db_session,
        org=org,
        sites=sites,
        gateways=gateways,
        gateway=gateways[0],
        calls=[],
        result=AdapterResult.ok({"config_xml": XML}),
        failure=None,
        permissions=["firewall.manage_rules", "controller:write"],
        scoped=False,
        site_ids=None,
        anonymous=False,
    )

    class Adapter:
        async def connect(self):
            f.calls.append("connect")
            if f.failure == "connect":
                raise RuntimeError(SECRET)
            return True

        async def disconnect(self):
            f.calls.append("disconnect")

        async def download_config(self):
            f.calls.append("download")
            if isinstance(f.result, BaseException):
                raise f.result
            return f.result

        async def create_backup(self):
            f.calls.append("vendor-create")
            return AdapterResult.ok({"status": "ok"})

    def create(**kwargs):
        f.calls.append("construct")
        if f.failure == "construct":
            raise RuntimeError(SECRET)
        return Adapter()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    f.user = User(
        id=uuid4(),
        organization_id=org.id,
        email="owned-backup@example.test",
        hashed_password="synthetic",
        role="super_admin",
        is_active=True,
    )
    app = FastAPI()
    app.include_router(router, prefix="/firewall")

    def identity():
        if f.anonymous:
            raise HTTPException(401, "Not authenticated")
        return CurrentUser(
            f.user, f.permissions, scoped=f.scoped, accessible_site_ids=f.site_ids
        )

    async def session():
        yield db_session

    app.dependency_overrides[get_current_active_user] = identity
    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://owned",
    ) as client:
        f.client = client
        try:
            yield f
        finally:
            # Cached dependency closures can retain this fixture after teardown.
            # Break its link to the closed client and its application graph.
            f.client = None


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


async def request(f, gateway_id=None):
    return await f.client.post(
        f"/firewall/gateways/{gateway_id or f.gateway.id}/backup/trigger"
    )


@pytest.mark.parametrize("vendor", ["opnsense", "pfsense", "mikrotik", "openwrt"])
@pytest.mark.parametrize("result", ["xml", "empty", "archive", "failure", "exception"])
async def test_no_saved_artifact_must_never_report_backup_success(
    trigger, vendor, result, caplog
):
    f = trigger
    f.gateway.vendor = vendor
    f.result = {
        "xml": AdapterResult.ok({"config_xml": XML}),
        "empty": AdapterResult.ok({}),
        "archive": AdapterResult.ok(
            {"backup_data": b"owned", "format": "tar.gz", "scope": "/etc/config/"}
        ),
        "failure": AdapterResult.fail(SECRET),
        "exception": RuntimeError(SECRET),
    }[result]
    before = await snapshot(f)
    response = await request(f)
    assert response.status_code == 501 and response.json() == {"detail": UNAVAILABLE}
    assert not f.calls
    assert SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before


@pytest.mark.parametrize("failure", ["construct", "connect"])
async def test_unavailable_storage_does_not_attempt_adapter_lifecycle(
    trigger, failure, caplog
):
    f = trigger
    f.failure = failure
    before = await snapshot(f)
    response = await request(f)
    assert response.status_code == 501 and response.json() == {"detail": UNAVAILABLE}
    assert not f.calls and SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before


@pytest.mark.parametrize(
    "denial",
    [
        "missing",
        "organization",
        "deleted",
        "site",
        "null-site",
        "permission",
        "scoped",
        "anonymous",
    ],
)
async def test_existing_admission_and_opaque_not_found_are_preserved(trigger, denial):
    f = trigger
    gateway_id = f.gateway.id
    expected = 404
    if denial == "missing":
        gateway_id = uuid4()
    elif denial == "organization":
        f.user.organization_id = uuid4()
    elif denial == "deleted":
        f.gateway.deleted_at = datetime.now(UTC)
    elif denial in ["site", "null-site"]:
        f.user.role = "viewer"
        f.site_ids = {f.sites[1].id}
        if denial == "null-site":
            f.gateway.site_id = None
    elif denial in ["permission", "scoped"]:
        f.permissions = []
        f.scoped = denial == "scoped"
        if denial == "permission":
            f.user.role = "viewer"
        expected = 403
    else:
        f.anonymous = True
        expected = 401
    before = await snapshot(f)
    response = await request(f, gateway_id)
    assert response.status_code == expected
    assert not f.calls and "not implemented" not in response.text
    assert await snapshot(f) == before


async def test_protected_config_export_remains_available(trigger):
    f = trigger
    before = await snapshot(f)
    response = await f.client.get(f"/firewall/gateways/{f.gateway.id}/config/download")
    assert response.status_code == 200 and response.json()["config"] == {
        "config_xml": XML
    }
    assert f.calls == ["construct", "connect", "download", "disconnect"]
    assert await snapshot(f) == before


async def test_separate_vendor_backup_route_remains_separate(trigger):
    f = trigger
    before = await snapshot(f)
    response = await f.client.post(f"/firewall/gateways/{f.gateway.id}/backups")
    assert response.status_code == 200 and response.json()["success"] is True
    assert f.calls == ["construct", "connect", "vendor-create", "disconnect"]
    assert await snapshot(f) == before
