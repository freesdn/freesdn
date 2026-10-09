"""Real independent PostgreSQL transactions; synthetic ASGI identity, no devices."""

import asyncio
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.dml import Update

from app.api.v1.endpoints.credentials import router
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.db.session import create_test_engine
from app.models.core import Credential, Organization, Site, User


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["post", "put"])
@pytest.mark.parametrize("site_bound", [False, True])
@pytest.mark.parametrize("vendor", [None, "omada"])
async def test_concurrent_promotions_leave_one_default(method, site_bound, vendor):
    engine = create_test_engine()
    first_demoted = asyncio.Event()
    release_first = asyncio.Event()
    tasks = []
    org_ids = []
    second_name = "owned-default-second-" + uuid4().hex

    class PausingSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            result = await super().execute(statement, *args, **kwargs)
            if (
                self.info.get("role") == "first"
                and isinstance(statement, Update)
                and statement.table.name == "credentials"
                and not first_demoted.is_set()
            ):
                # Hold only the first real transaction after its real demotion.
                # The second request can finish or block in PostgreSQL. No SQL
                # response, lock or commit is mocked.
                first_demoted.set()
                await asyncio.wait_for(release_first.wait(), timeout=20)
            return result

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            orgs = [Organization(name="Owned concurrency", slug=uuid4().hex) for _ in range(2)]
            seed.add_all(orgs)
            await seed.flush()
            org_ids = [o.id for o in orgs]
            sites = [
                Site(name="Owned site", slug=uuid4().hex, organization_id=orgs[0].id)
                for _ in range(2)
            ]
            seed.add_all(sites)
            await seed.flush()
            site_id = sites[0].id if site_bound else None
            user = User(
                username=uuid4().hex,
                email=uuid4().hex + "@owned.example.test",
                hashed_password="synthetic-no-login",
                organization_id=orgs[0].id,
                role="org_admin",
                is_active=True,
            )
            targets = [
                Credential(
                    organization_id=orgs[0].id,
                    site_id=site_id,
                    name="Target " + str(i),
                    credential_type="basic_auth",
                    scope="global",
                    vendor=vendor,
                    is_default=False,
                )
                for i in range(2)
            ]
            controls = [
                Credential(
                    organization_id=orgs[1].id,
                    name="Foreign org",
                    credential_type="basic_auth",
                    scope="global",
                    vendor=vendor,
                    is_default=True,
                ),
                Credential(
                    organization_id=orgs[0].id,
                    site_id=sites[1].id,
                    name="Other site",
                    credential_type="basic_auth",
                    scope="global",
                    vendor=vendor,
                    is_default=True,
                ),
                Credential(
                    organization_id=orgs[0].id,
                    site_id=site_id,
                    name="Other vendor",
                    credential_type="basic_auth",
                    scope="global",
                    vendor="unifi",
                    is_default=True,
                ),
            ]
            seed.add_all([user, *targets, *controls])
            await seed.commit()
            principal = CurrentUser(
                user,
                permissions=["settings:write"],
                accessible_site_ids={s.id for s in sites},
                scoped=False,
            )
            target_ids = [c.id for c in targets]
            control_ids = [c.id for c in controls]

        app = FastAPI()
        app.include_router(router, prefix="/credentials")
        app.dependency_overrides[get_current_active_user] = lambda: principal

        async def session(request: Request):
            role = request.headers["x-owned-role"]
            async with PausingSession(engine, expire_on_commit=False, info={"role": role}) as db:
                name = second_name if role == "second" else "owned-default-first-" + uuid4().hex
                await db.execute(
                    text("SELECT set_config('application_name', :name, true)"), {"name": name}
                )
                try:
                    yield db
                except BaseException:
                    await db.rollback()
                    raise

        app.dependency_overrides[get_session] = session
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned") as client:

            async def promote(role, index):
                if method == "post":
                    return await client.post(
                        "/credentials/",
                        headers={"x-owned-role": role},
                        json={
                            "name": "Created " + role,
                            "scope": "global",
                            "site_id": str(site_id) if site_id else None,
                            "vendor": vendor,
                            "is_default": True,
                            "password": "owned-concurrency-secret",
                        },
                    )
                return await client.put(
                    "/credentials/" + str(target_ids[index]),
                    headers={"x-owned-role": role},
                    json={"is_default": True},
                )

            first = asyncio.create_task(promote("first", 0))
            tasks.append(first)
            await asyncio.wait_for(first_demoted.wait(), timeout=10)
            second = asyncio.create_task(promote("second", 1))
            tasks.append(second)
            deadline = asyncio.get_running_loop().time() + 10
            while not second.done():
                async with engine.connect() as observer:
                    blocked = (
                        await observer.execute(
                            text(
                                "SELECT count(*) FROM pg_stat_activity WHERE application_name=:name AND wait_event_type='Lock'"
                            ),
                            {"name": second_name},
                        )
                    ).scalar_one()
                if blocked:
                    break
                assert asyncio.get_running_loop().time() < deadline, (
                    "Second transaction neither completed nor reached a database lock"
                )
                await asyncio.sleep(0.01)
            release_first.set()
            responses = await asyncio.wait_for(asyncio.gather(first, second), timeout=15)
            assert [r.status_code for r in responses] == [201 if method == "post" else 200] * 2

        async with AsyncSession(engine) as verify:
            defaults = (
                (
                    await verify.execute(
                        select(Credential.id).where(
                            Credential.organization_id == org_ids[0],
                            Credential.site_id == site_id,
                            Credential.scope == "global",
                            Credential.vendor == vendor,
                            Credential.is_default.is_(True),
                            Credential.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(defaults) == 1, (
                f"Concurrent requests left {len(defaults)} defaults in one group"
            )
            controls_after = (
                (await verify.execute(select(Credential).where(Credential.id.in_(control_ids))))
                .scalars()
                .all()
            )
            assert len(controls_after) == 3 and all(c.is_default for c in controls_after)
    finally:
        release_first.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if org_ids:
            async with AsyncSession(engine) as cleanup:
                for model in [Credential, User, Site]:
                    await cleanup.execute(delete(model).where(model.organization_id.in_(org_ids)))
                await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
                await cleanup.commit()
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["put", "delete"])
@pytest.mark.parametrize("change", ["move", "delete"])
async def test_waiting_write_rechecks_current_credential_binding(method, change):
    """An initially visible row can move out of scope before mutation."""
    from sqlalchemy.sql.selectable import Select

    engine = create_test_engine()
    first_read = asyncio.Event()
    release_first = asyncio.Event()
    tasks = []
    org_id = None

    class PausingSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            result = await super().execute(statement, *args, **kwargs)
            if (
                self.info.get("role") == "first"
                and isinstance(statement, Select)
                and any(d.get("entity") is Credential for d in statement.column_descriptions)
                and not first_read.is_set()
            ):
                # Materialize the real initial SELECT result before the other
                # transaction commits. Do not fabricate a row or SQL result.
                frozen = result.freeze()
                first_read.set()
                await asyncio.wait_for(release_first.wait(), timeout=20)
                return frozen()
            return result

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            org = Organization(name="Owned revalidation", slug=uuid4().hex)
            seed.add(org)
            await seed.flush()
            org_id = org.id
            sites = [
                Site(name="Owned site", slug=uuid4().hex, organization_id=org.id) for _ in range(2)
            ]
            users = [
                User(
                    username=uuid4().hex,
                    email=uuid4().hex + "@owned.example.test",
                    hashed_password="synthetic-no-login",
                    organization_id=org.id,
                    role=role,
                    is_active=True,
                )
                for role in ["operator", "org_admin"]
            ]
            seed.add_all([*sites, *users])
            await seed.flush()
            credential = Credential(
                organization_id=org.id,
                site_id=sites[0].id,
                name="Original name",
                credential_type="basic_auth",
                scope="global",
                is_default=False,
            )
            seed.add(credential)
            await seed.commit()
            credential_id = credential.id
            site_b = sites[1].id
            principals = {
                "first": CurrentUser(
                    users[0], permissions=["settings:write"], accessible_site_ids={sites[0].id}
                ),
                "second": CurrentUser(
                    users[1],
                    permissions=["settings:write"],
                    accessible_site_ids={s.id for s in sites},
                ),
            }

        app = FastAPI()
        app.include_router(router, prefix="/credentials")

        async def identity(request: Request):
            return principals[request.headers["x-owned-role"]]

        async def session(request: Request):
            async with PausingSession(
                engine, expire_on_commit=False, info={"role": request.headers["x-owned-role"]}
            ) as db:
                try:
                    yield db
                except BaseException:
                    await db.rollback()
                    raise

        app.dependency_overrides[get_current_active_user] = identity
        app.dependency_overrides[get_session] = session
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned") as client:
            path = "/credentials/" + str(credential_id)
            first = asyncio.create_task(
                client.request(
                    method,
                    path,
                    headers={"x-owned-role": "first"},
                    **({"json": {"name": "Unauthorized late edit"}} if method == "put" else {}),
                )
            )
            tasks.append(first)
            await asyncio.wait_for(first_read.wait(), timeout=10)
            second = await asyncio.wait_for(
                client.request(
                    "put" if change == "move" else "delete",
                    path,
                    headers={"x-owned-role": "second"},
                    **({"json": {"site_id": str(site_b)}} if change == "move" else {}),
                ),
                timeout=10,
            )
            assert second.status_code == 200
            async with AsyncSession(engine) as observer:
                changed = (
                    await observer.execute(select(Credential).where(Credential.id == credential_id))
                ).scalar_one()
                committed_deleted_at = changed.deleted_at
            release_first.set()
            response = await asyncio.wait_for(first, timeout=10)
            assert response.status_code == 404, (
                "Waiting request changed a moved or deleted credential"
            )
            assert response.json() == {"detail": "Credential not found"}

        async with AsyncSession(engine) as verify:
            current = (
                await verify.execute(select(Credential).where(Credential.id == credential_id))
            ).scalar_one()
            assert current.name == "Original name"
            assert current.deleted_at == committed_deleted_at
            assert current.site_id == (site_b if change == "move" else sites[0].id)
    finally:
        release_first.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if org_id:
            async with AsyncSession(engine) as cleanup:
                for model in [Credential, User, Site]:
                    await cleanup.execute(delete(model).where(model.organization_id == org_id))
                await cleanup.execute(delete(Organization).where(Organization.id == org_id))
                await cleanup.commit()
        await engine.dispose()


@pytest.mark.asyncio
async def test_other_organization_can_write_while_first_write_is_held():
    """A stalled tenant's credential write must not serialize other tenants."""
    engine = create_test_engine()
    first_demoted = asyncio.Event()
    release_first = asyncio.Event()
    tasks = []
    org_ids = []

    class PausingSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            result = await super().execute(statement, *args, **kwargs)
            if (
                self.info.get("role") == "first"
                and isinstance(statement, Update)
                and statement.table.name == "credentials"
                and not first_demoted.is_set()
            ):
                first_demoted.set()
                await asyncio.wait_for(release_first.wait(), timeout=20)
            return result

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            orgs = [
                Organization(name="Independent organization", slug=uuid4().hex) for _ in range(2)
            ]
            seed.add_all(orgs)
            await seed.flush()
            org_ids = [org.id for org in orgs]
            users = [
                User(
                    username=uuid4().hex,
                    email=uuid4().hex + "@owned.example.test",
                    hashed_password="synthetic-no-login",
                    organization_id=org.id,
                    role="org_admin",
                    is_active=True,
                )
                for org in orgs
            ]
            seed.add_all(users)
            await seed.commit()
            principals = dict(
                zip(
                    ["first", "second"],
                    [CurrentUser(user, permissions=["settings:write"]) for user in users],
                    strict=True,
                )
            )

        app = FastAPI()
        app.include_router(router, prefix="/credentials")

        async def identity(request: Request):
            return principals[request.headers["x-owned-role"]]

        async def session(request: Request):
            async with PausingSession(
                engine, expire_on_commit=False, info={"role": request.headers["x-owned-role"]}
            ) as db:
                try:
                    yield db
                except BaseException:
                    await db.rollback()
                    raise

        app.dependency_overrides[get_current_active_user] = identity
        app.dependency_overrides[get_session] = session
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned") as client:
            payload = {"name": "Owned independent default", "is_default": True}
            first = asyncio.create_task(
                client.post("/credentials/", headers={"x-owned-role": "first"}, json=payload)
            )
            tasks.append(first)
            await asyncio.wait_for(first_demoted.wait(), timeout=10)
            second = await asyncio.wait_for(
                client.post("/credentials/", headers={"x-owned-role": "second"}, json=payload),
                timeout=5,
            )
            assert second.status_code == 201
            assert not first.done()
            release_first.set()
            assert (await asyncio.wait_for(first, timeout=10)).status_code == 201
        async with AsyncSession(engine) as verify:
            rows = (
                (
                    await verify.execute(
                        select(Credential).where(Credential.organization_id.in_(org_ids))
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 2 and all(row.is_default for row in rows)
            assert {row.organization_id for row in rows} == set(org_ids)
    finally:
        release_first.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if org_ids:
            async with AsyncSession(engine) as cleanup:
                for model in [Credential, User]:
                    await cleanup.execute(delete(model).where(model.organization_id.in_(org_ids)))
                await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
                await cleanup.commit()
        await engine.dispose()


@pytest.mark.asyncio
async def test_create_without_owner_organization_is_refused():
    """Platform authority alone must not create an ownerless credential."""
    engine = create_test_engine()
    user_id = None
    name = "Owned missing-org-" + uuid4().hex
    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            user = User(
                username=uuid4().hex,
                email=uuid4().hex + "@owned.example.test",
                hashed_password="synthetic-no-login",
                organization_id=None,
                role="super_admin",
                is_active=True,
            )
            seed.add(user)
            await seed.commit()
            user_id = user.id
            principal = CurrentUser(user, permissions=["*"])
        app = FastAPI()
        app.include_router(router, prefix="/credentials")
        app.dependency_overrides[get_current_active_user] = lambda: principal

        async def session():
            async with AsyncSession(engine, expire_on_commit=False) as db:
                try:
                    yield db
                except BaseException:
                    await db.rollback()
                    raise

        app.dependency_overrides[get_session] = session
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned"
        ) as client:
            response = await client.post("/credentials/", json={"name": name, "is_default": True})
            assert response.status_code == 403
            assert response.json() == {"detail": "Organization context required"}
        async with AsyncSession(engine) as verify:
            assert (
                await verify.execute(select(Credential.id).where(Credential.name == name))
            ).scalar_one_or_none() is None
    finally:
        if user_id:
            async with AsyncSession(engine) as cleanup:
                await cleanup.execute(delete(Credential).where(Credential.name == name))
                await cleanup.execute(delete(User).where(User.id == user_id))
                await cleanup.commit()
        await engine.dispose()
