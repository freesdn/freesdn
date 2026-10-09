"""Comparison availability over actual HTTP and PostgreSQL; adapters/auth are fixtures."""

import asyncio
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

SECRET = "owned-private-comparison-material"
CURRENT = "first\nnew\n"
BACKUP = "first\nold\n"


@pytest_asyncio.fixture
async def comparison(db_session, monkeypatch):
    org = Organization(name="Owned comparison", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    gateway = GatewayConnection(
        org_id=org.id,
        name="Owned comparison",
        vendor="opnsense",
        host="192.168.77.77",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict({"api_key": "owned-key", "api_secret": "owned-secret"}),
        settings={},
        sync_enabled=False,
    )
    db_session.add(gateway)
    await db_session.flush()
    f = SimpleNamespace(
        gateway=gateway,
        org=org,
        db=db_session,
        created=0,
        disconnected=0,
        calls=[],
        current=AdapterResult.ok({"config_xml": CURRENT}),
        history=AdapterResult.ok({"backups": [{"config_xml": BACKUP}]}),
    )

    async def result(name):
        f.calls.append(name)
        value = getattr(f, name)
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            return await value()
        return value

    class Adapter:
        async def connect(self):
            return True

        async def disconnect(self):
            f.disconnected += 1

        async def download_config(self):
            return await result("current")

        async def get_backup_list(self):
            return await result("history")

    def create(**kwargs):
        f.created += 1
        return Adapter()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    f.user = User(
        id=uuid4(),
        organization_id=org.id,
        email="owned-comparison@example.test",
        hashed_password="synthetic",
        role="super_admin",
        is_active=True,
    )
    f.permissions = ["controller:write"]
    f.scoped = False
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


def malformed(which):
    common = {
        "exception": RuntimeError(SECRET),
        "failure": AdapterResult.fail(SECRET),
        "none": None,
        "envelope": {"success": True, "data": {SECRET: SECRET}},
        "no-data": AdapterResult.ok(),
        "empty": AdapterResult.ok({}),
        "list-data": AdapterResult.ok([]),
    }
    if which in common:
        return common[which]
    if which.startswith("current-"):
        value = {"none": None, "integer": 123, "blank": "  ", "boolean": True}[which[8:]]
        return AdapterResult.ok({"config_xml": value})
    history = {
        "history-none": {"backups": None},
        "history-dict": {"backups": {}},
        "history-item": {"backups": [None]},
        "history-content": {"backups": [{"config_xml": 123}]},
    }
    return AdapterResult.ok(history[which])


async def request(f):
    return await f.client.get(f"/firewall/gateways/{f.gateway.id}/config/diff")


@pytest.mark.parametrize("field", ["current", "history"])
@pytest.mark.parametrize(
    "kind", ["exception", "failure", "none", "envelope", "no-data", "empty", "list-data"]
)
async def test_failed_or_malformed_sources_cannot_report_unchanged(comparison, field, kind):
    f = comparison
    setattr(f, field, malformed(kind))
    response = await request(f)
    assert response.status_code == 502
    assert SECRET not in response.text and "has_changes" not in response.text
    assert f.created == f.disconnected == 1


@pytest.mark.parametrize(
    "kind", ["current-none", "current-integer", "current-blank", "current-boolean"]
)
async def test_current_content_must_be_nonempty_text(comparison, kind):
    f = comparison
    f.current = malformed(kind)
    response = await request(f)
    assert response.status_code == 502 and "has_changes" not in response.text


@pytest.mark.parametrize(
    "kind", ["history-none", "history-dict", "history-item", "history-content"]
)
async def test_history_shape_and_content_must_be_valid(comparison, kind):
    f = comparison
    f.history = malformed(kind)
    response = await request(f)
    assert response.status_code == 502 and "has_changes" not in response.text


@pytest.mark.parametrize("field", ["current", "history"])
async def test_unsupported_source_is_explicit(comparison, field):
    f = comparison
    setattr(f, field, AdapterResult.fail(SECRET, error_code="NOT_SUPPORTED"))
    response = await request(f)
    assert response.status_code == 501 and SECRET not in response.text


@pytest.mark.parametrize(
    "backups", [[], [{}], [{"filename": "owned.xml"}], [{"config_xml": ""}], [{"content": "   "}]]
)
async def test_missing_baseline_cannot_report_no_changes(comparison, backups):
    f = comparison
    f.history = AdapterResult.ok({"backups": backups})
    response = await request(f)
    assert response.status_code == 409 and "has_changes" not in response.text


@pytest.mark.parametrize(
    "same,field",
    [(True, "config_xml"), (False, "config_xml"), (True, "content"), (False, "content")],
)
async def test_existing_complete_comparisons_keep_their_meaning(comparison, same, field):
    f = comparison
    f.history = AdapterResult.ok({"backups": [{field: CURRENT if same else BACKUP}]})
    response = await request(f)
    assert response.status_code == 200
    data = response.json()
    assert data["has_changes"] is not same
    assert data["current_size"] == len(CURRENT)
    assert data["backup_size"] == len(CURRENT if same else BACKUP)
    assert data["summary"] == ("0 additions, 0 deletions" if same else "1 additions, 1 deletions")
    assert bool(data["diff_lines"]) is not same
    assert f.created == f.disconnected == 1


async def test_success_explicitly_identifies_a_complete_comparison(comparison):
    response = await request(comparison)
    assert response.status_code == 200
    assert response.json().get("comparison_available") is True


@pytest.mark.parametrize("field", ["current", "history"])
async def test_child_cancellation_is_not_an_unchanged_result(comparison, field):
    f = comparison
    setattr(f, field, asyncio.CancelledError("owned-cancel"))
    with pytest.raises(asyncio.CancelledError):
        await GatewayService(f.db).get_config_diff(f.gateway.id, f.org.id)
    assert f.created == f.disconnected == 1


async def test_request_cancellation_still_closes_adapter(comparison):
    f = comparison
    entered = asyncio.Event()

    async def wait():
        entered.set()
        await asyncio.Event().wait()

    f.current = wait
    task = asyncio.create_task(GatewayService(f.db).get_config_diff(f.gateway.id, f.org.id))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert f.created == f.disconnected == 1
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("denial", ["role", "permission", "organization"])
async def test_existing_admission_denials_do_not_contact_device(comparison, denial):
    f = comparison
    if denial == "role":
        f.user.role = "org_admin"
    elif denial == "permission":
        f.permissions = []
        f.scoped = True
    else:
        f.user.organization_id = uuid4()
    response = await request(f)
    assert response.status_code == (404 if denial == "organization" else 403)
    assert not f.created and not f.calls


@pytest.mark.parametrize("field", ["current", "history"])
async def test_child_cancellation_takes_priority_over_another_source_failure(comparison, field):
    f = comparison
    setattr(f, field, asyncio.CancelledError("owned-cancel"))
    setattr(f, "history" if field == "current" else "current", AdapterResult.fail(SECRET))
    with pytest.raises(asyncio.CancelledError):
        await GatewayService(f.db).get_config_diff(f.gateway.id, f.org.id)
    assert f.created == f.disconnected == 1
