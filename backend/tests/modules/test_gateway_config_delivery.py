"""Configuration delivery over PostgreSQL and HTTP, with synthetic adapters/auth."""

import asyncio
import base64
import logging
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import GatewayService, adapter_registry
from app.modules.firewall.models import GatewayConnection

SECRET = "owned-private-export-diagnostic"
XML = '<?xml version="1.0"?>\n<opnsense><name>owned α</name></opnsense>\n'
LIMIT = 16 * 1024 * 1024


@pytest_asyncio.fixture
async def delivery(db_session, monkeypatch):
    org = Organization(name="Owned delivery", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    gateway = GatewayConnection(
        org_id=org.id,
        name="Owned delivery",
        vendor="opnsense",
        host="192.168.77.77",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict({"api_key": "owned", "api_secret": "owned"}),
        settings={},
        sync_enabled=False,
    )
    db_session.add(gateway)
    await db_session.flush()
    f = SimpleNamespace(
        db=db_session,
        org=org,
        gateway=gateway,
        created=0,
        closed=0,
        calls=[],
        result=AdapterResult.ok({"config_xml": XML}),
        failure=None,
        permissions=["controller:write"],
        scoped=False,
    )

    class Adapter:
        async def connect(self):
            f.calls.append("connect")
            if f.failure == "connect":
                raise RuntimeError(SECRET)
            return True

        async def disconnect(self):
            f.closed += 1

        async def download_config(self):
            f.calls.append("download")
            if isinstance(f.result, BaseException):
                raise f.result
            if callable(f.result):
                return await f.result()
            return f.result

    def create(**kwargs):
        f.calls.append("construct")
        if f.failure == "construct":
            raise RuntimeError(SECRET)
        f.created += 1
        return Adapter()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    f.user = User(
        id=uuid4(),
        organization_id=org.id,
        email="delivery@example.test",
        hashed_password="synthetic",
        role="super_admin",
        is_active=True,
    )
    app.dependency_overrides[get_current_active_user] = lambda: CurrentUser(
        f.user, f.permissions, scoped=f.scoped
    )

    async def session():
        yield db_session

    app.dependency_overrides[get_session] = session
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


async def request(f):
    return await f.client.get(f"/firewall/gateways/{f.gateway.id}/config/download")


def invalid_result(kind):
    return {
        "failure": AdapterResult.fail(SECRET),
        "exception": RuntimeError(SECRET),
        "none": None,
        "envelope": {"success": True, "data": {"config_xml": SECRET}},
        "no-data": AdapterResult.ok(),
        "empty": AdapterResult.ok({}),
        "list": AdapterResult.ok([]),
        "text": AdapterResult.ok(SECRET),
        "metadata": AdapterResult.ok({"note": SECRET}),
    }[kind]


@pytest.mark.parametrize(
    "kind",
    ["failure", "exception", "none", "envelope", "no-data", "empty", "list", "text", "metadata"],
)
async def test_failed_and_malformed_exports_are_not_success(delivery, kind, caplog):
    f = delivery
    f.result = invalid_result(kind)
    response = await request(f)
    assert response.status_code == 502
    assert SECRET not in response.text and SECRET not in caplog.text
    assert "config" not in response.json() and f.created == f.closed == 1


@pytest.mark.parametrize("value", [None, True, 123, "  ", "", b"<config/>"])
async def test_xml_content_must_be_nonempty_text(delivery, value):
    f = delivery
    f.result = AdapterResult.ok({"config_xml": value})
    response = await request(f)
    assert response.status_code == 502 and "config" not in response.json()
    assert f.created == f.closed == 1


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "text",
        "none",
        "mutable",
        "wrong-format",
        "missing-format",
        "wrong-scope",
        "missing-scope",
    ],
)
async def test_invalid_archive_representation_is_refused(delivery, kind):
    f = delivery
    data = {"backup_data": b"owned-bytes", "format": "tar.gz", "scope": "/etc/config/"}
    if kind in ["empty", "text", "none", "mutable"]:
        data["backup_data"] = {
            "empty": b"",
            "text": SECRET,
            "none": None,
            "mutable": bytearray(b"owned"),
        }[kind]
    elif kind.startswith("wrong-"):
        data[kind[6:]] = SECRET
    else:
        data.pop(kind[8:])
    f.result = AdapterResult.ok(data)
    response = await request(f)
    assert response.status_code == 502 and SECRET not in response.text
    assert f.created == f.closed == 1


@pytest.mark.parametrize("kind", ["xml", "archive"])
async def test_large_export_is_bounded_by_bytes(delivery, kind):
    f = delivery
    data = (
        {"config_xml": "α" * (LIMIT // 2 + 1)}
        if kind == "xml"
        else {"backup_data": b"x" * (LIMIT + 1), "format": "tar.gz", "scope": "/etc/config/"}
    )
    f.result = AdapterResult.ok(data)
    response = await request(f)
    assert response.status_code == 502 and "config" not in response.json()
    assert f.created == f.closed == 1


@pytest.mark.parametrize("code", ["NOT_SUPPORTED", "NOT_IMPLEMENTED"])
async def test_explicitly_unsupported_export_is_501(delivery, code):
    f = delivery
    f.result = AdapterResult.fail(SECRET, error_code=code)
    response = await request(f)
    assert response.status_code == 501 and SECRET not in response.text
    assert f.created == f.closed == 1


@pytest.mark.parametrize("value", [XML, "<opnsense/>"])
async def test_xml_export_is_preserved_without_reserializing(delivery, value):
    f = delivery
    f.result = AdapterResult.ok({"config_xml": value})
    response = await request(f)
    assert response.status_code == 200
    assert response.json() == {
        "gateway_id": str(f.gateway.id),
        "vendor": "opnsense",
        "config": {"config_xml": value},
    }
    assert f.created == f.closed == 1


@pytest.mark.parametrize("value", [b"\x1f\x8b\x00\xffowned\x00\x80", b"owned-ascii-bytes"])
async def test_archive_bytes_have_explicit_lossless_json_encoding(delivery, value):
    f = delivery
    f.gateway.vendor = "openwrt"
    f.result = AdapterResult.ok({"backup_data": value, "format": "tar.gz", "scope": "/etc/config/"})
    response = await request(f)
    assert response.status_code == 200
    data = response.json()["config"]
    assert data == {
        "backup_data": base64.b64encode(value).decode("ascii"),
        "encoding": "base64",
        "format": "tar.gz",
        "scope": "/etc/config/",
    }
    assert base64.b64decode(data["backup_data"], validate=True) == value
    assert f.created == f.closed == 1


async def test_ambiguous_formats_are_refused(delivery):
    f = delivery
    f.result = AdapterResult.ok(
        {"config_xml": XML, "backup_data": b"owned", "format": "tar.gz", "scope": "/etc/config/"}
    )
    response = await request(f)
    assert response.status_code == 502 and "config" not in response.json()


async def test_uncontracted_adapter_fields_are_not_delivered(delivery):
    f = delivery
    f.result = AdapterResult.ok({"config_xml": XML, "diagnostics": SECRET})
    response = await request(f)
    assert response.status_code == 200 and response.json()["config"] == {"config_xml": XML}
    assert SECRET not in response.text


@pytest.mark.parametrize("failure", ["construct", "connect"])
async def test_construction_and_connection_failures_are_safe(delivery, failure, caplog):
    f = delivery
    f.failure = failure
    response = await request(f)
    assert response.status_code == 502 and SECRET not in response.text and SECRET not in caplog.text
    assert f.created == f.closed == (1 if failure == "connect" else 0)
    assert "download" not in f.calls


async def test_adapter_cancellation_propagates_and_closes(delivery):
    f = delivery
    f.result = asyncio.CancelledError("owned-cancel")
    with pytest.raises(asyncio.CancelledError):
        await GatewayService(f.db).download_live_config(f.gateway.id, f.org.id)
    assert f.created == f.closed == 1


async def test_parent_cancellation_propagates_and_closes(delivery):
    f = delivery
    entered = asyncio.Event()

    async def wait():
        entered.set()
        await asyncio.Event().wait()

    f.result = wait
    task = asyncio.create_task(GatewayService(f.db).download_live_config(f.gateway.id, f.org.id))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert f.created == f.closed == 1
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("denial", ["role", "permission", "organization"])
async def test_existing_admission_denials_do_not_contact_device(delivery, denial):
    f = delivery
    if denial == "role":
        f.user.role = "org_admin"
    elif denial == "permission":
        f.permissions = []
        f.scoped = True
    else:
        f.user.organization_id = uuid4()
    response = await request(f)
    assert response.status_code == (404 if denial == "organization" else 403)
    assert not f.calls and not f.created


async def test_existing_audit_precedes_device_io_without_export_content(delivery, caplog):
    f = delivery
    caplog.set_level(logging.WARNING, logger="freesdn.security.config_download")

    async def audited():
        assert "firewall config download requested" in caplog.text
        return AdapterResult.ok({"config_xml": XML})

    f.result = audited
    response = await request(f)
    assert response.status_code == 200
    assert XML not in caplog.text and "owned-secret" not in caplog.text
