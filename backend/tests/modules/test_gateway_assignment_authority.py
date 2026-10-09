"""Gateway assignment uses real committed PG rows and routes; caller/dispatch are synthetic."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.middleware import setup_exception_handlers
from app.db import get_session
from app.db.session import CelerySessionLocal
from app.models.core import Organization, Site, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.models import GatewayConnection
from app.services import device_sync


@pytest_asyncio.fixture
async def assignment(monkeypatch):
    ids = [uuid4() for _ in range(6)]
    org, other, current, target, foreign, gateway = ids
    f = SimpleNamespace(
        org=org,
        other=other,
        current=current,
        target=target,
        foreign=foreign,
        gateway=gateway,
        grants=None,
        events=[],
        before_commit=None,
        after_preload=None,
        permissions=["firewall.manage_rules", "firewall.view"],
        anonymous=False,
    )
    async with CelerySessionLocal() as db:
        db.add_all(
            [Organization(id=oid, name="Owned assignment", slug=oid.hex) for oid in (org, other)]
        )
        await db.flush()
        db.add_all(
            [
                Site(id=sid, organization_id=owner, name="Owned assignment site", slug=sid.hex)
                for sid, owner in [(current, org), (target, org), (foreign, other)]
            ]
        )
        await db.flush()
        db.add(
            GatewayConnection(
                id=gateway,
                org_id=org,
                site_id=current,
                name="Owned original",
                vendor="opnsense",
                host="192.168.77.77",
                port=443,
                verify_ssl=True,
                credentials=encrypt_dict(
                    {"api_key": "owned-original-key", "api_secret": "owned-original-secret"}
                ),
                settings={},
                sync_enabled=False,
            )
        )
        await db.commit()
    monkeypatch.setattr(
        device_sync,
        "trigger_device_registry_sync",
        lambda name: f.events.append("registry:" + name),
    )
    from app.adapters.pool import adapter_pool
    from app.modules.firewall import gateway_service

    monkeypatch.setattr(
        adapter_pool, "invalidate_controller", lambda _name: f.events.append("evict")
    )

    def no_adapter(**kwargs):
        f.events.append("unexpected-adapter")
        raise AssertionError("Assignment must not contact a device")

    monkeypatch.setattr(gateway_service.adapter_registry, "create_adapter", no_adapter)
    user = User(
        id=uuid4(),
        organization_id=org,
        email="owned-assignment@example.test",
        hashed_password="synthetic",
        role="viewer",
        is_active=True,
    )
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    setup_exception_handlers(app)

    def identity():
        if f.anonymous:
            raise HTTPException(401, "Not authenticated")
        return CurrentUser(user, f.permissions, accessible_site_ids=f.grants)

    async def request_session():
        async with CelerySessionLocal() as db:
            if f.after_preload:
                # Hold the object strongly in the request identity map while a
                # distinct committed transaction changes its database parent.
                preloaded = await db.get(Site, f.target)
                assert preloaded is not None
                await f.after_preload()
                assert preloaded.organization_id == f.org and preloaded.is_active
            yield db
            if f.before_commit:
                await f.before_commit()
            await db.commit()

    app.dependency_overrides[get_current_active_user] = identity
    app.dependency_overrides[get_session] = request_session
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://owned-assignment",
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
            await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
            await db.commit()


async def request(f, operation, target):
    body = {
        "site_id": str(target) if target else None,
        "name": "Owned changed",
        "api_secret": "owned-new-secret",
    }
    if operation == "create":
        body.update(
            vendor="opnsense", host="192.168.77.77", api_key="owned-new-key", sync_enabled=False
        )
        return await f.client.post("/firewall/gateways", json=body)
    return await f.client.patch(f"/firewall/gateways/{f.gateway}", json=body)


async def snapshot(f):
    async with CelerySessionLocal() as db:
        return [
            dict(row)
            for row in (
                await db.execute(
                    select(GatewayConnection.__table__)
                    .where(GatewayConnection.org_id.in_([f.org, f.other]))
                    .order_by(GatewayConnection.id)
                )
            )
            .mappings()
            .all()
        ]


async def change_target(f, kind):
    values = (
        {"deleted_at": datetime.now(UTC)}
        if kind == "deleted"
        else {"is_active": False}
        if kind == "disabled"
        else {"organization_id": f.other}
    )
    async with CelerySessionLocal() as db:
        await db.execute(update(Site).where(Site.id == f.target).values(**values))
        await db.commit()


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("kind", ["deleted", "disabled", "foreign", "missing", "ungranted"])
async def test_invalid_assignment_target_refused_before_persistence(assignment, operation, kind):
    f = assignment
    target = f.target
    if kind in {"deleted", "disabled", "foreign"}:
        await change_target(f, kind)
    elif kind == "missing":
        target = uuid4()
    elif kind == "ungranted":
        f.grants = {f.current}
    before = await snapshot(f)
    response = await request(f, operation, target)
    assert (
        response.status_code == 404 and response.json()["error"]["message"] == "Gateway not found"
    )
    assert "owned-new-secret" not in response.text
    assert await snapshot(f) == before and not f.events


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("kind", ["deleted", "disabled"])
@pytest.mark.parametrize("assigned", [True, False])
async def test_inactive_organization_cannot_receive_gateway_edits(
    assignment, operation, kind, assigned
):
    f = assignment
    async with CelerySessionLocal() as db:
        await db.execute(
            update(Organization)
            .where(Organization.id == f.org)
            .values(
                **({"deleted_at": datetime.now(UTC)} if kind == "deleted" else {"is_active": False})
            )
        )
        if not assigned:
            await db.execute(
                update(GatewayConnection)
                .where(GatewayConnection.id == f.gateway)
                .values(site_id=None)
            )
        await db.commit()
    before = await snapshot(f)
    response = await request(f, operation, f.target if assigned else None)
    assert response.status_code == 404
    assert await snapshot(f) == before and not f.events


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize(
    "mode",
    ["unrestricted", "granted", "unassigned", "unassigned-limited", "permission", "anonymous"],
)
async def test_assignment_compatibility_controls(assignment, operation, mode):
    f = assignment
    target = f.target
    if mode == "granted":
        f.grants = {f.current, f.target}
    elif mode.startswith("unassigned"):
        target = None
        if mode == "unassigned-limited":
            f.grants = {f.current}
    elif mode == "permission":
        f.permissions = []
    elif mode == "anonymous":
        f.anonymous = True
    before = await snapshot(f)
    response = await request(f, operation, target)
    expected = (
        401
        if mode == "anonymous"
        else 403
        if mode == "permission"
        else 422
        if operation == "create" and mode == "unassigned-limited"
        else 201
        if operation == "create"
        else 200
    )
    assert response.status_code == expected
    assert "owned-new-secret" not in response.text
    if expected >= 400:
        assert await snapshot(f) == before and not f.events
    else:
        identity = UUID(response.json()["id"])
        rows = await snapshot(f)
        saved = next(row for row in rows if row["id"] == identity)
        assert saved["org_id"] == f.org
        assert saved["site_id"] == (target if operation == "create" or target else f.current)
        assert saved["name"] == "Owned changed"
        assert decrypt_dict(saved["credentials"])["api_secret"] == "owned-new-secret"
        assert f.events == (
            ["registry:firewall"] if operation == "create" else ["registry:firewall", "evict"]
        )
        assert len(rows) == (2 if operation == "create" else 1)


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("kind", ["deleted", "disabled", "foreign"])
async def test_assignment_ignores_stale_loaded_site_identity(assignment, operation, kind):
    f = assignment
    f.after_preload = lambda: change_target(f, kind)
    before = await snapshot(f)
    response = await request(f, operation, f.target)
    assert response.status_code == 404
    assert await snapshot(f) == before and not f.events


async def parent_write_lock_blocked(f, parent):
    table = "core.organizations" if parent == "organization" else "core.sites"
    identity = f.org if parent == "organization" else f.target
    async with CelerySessionLocal() as other:
        try:
            # FK KEY SHARE locks alone do NOT block non-key status changes.
            await other.execute(
                text(f"SELECT id FROM {table} WHERE id=:identity FOR NO KEY UPDATE NOWAIT"),
                {"identity": identity},
            )
        except DBAPIError as exc:
            assert getattr(exc.orig, "sqlstate", None) == "55P03"
            return True
        return False


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("parent", ["organization", "site"])
async def test_parent_status_bound_until_request_commit(assignment, operation, parent):
    f = assignment
    observed = []

    async def during_commit():
        observed.append(await parent_write_lock_blocked(f, parent))

    f.before_commit = during_commit
    response = await request(f, operation, f.target)
    assert response.status_code == (201 if operation == "create" else 200)
    assert observed == [True]
    assert await parent_write_lock_blocked(f, parent) is False
