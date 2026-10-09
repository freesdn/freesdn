"""Independent real transactions cover refreshed secrets, scope and rollback."""

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.dml import Update

from app.db.session import create_test_engine
from app.models.core import Organization
from app.models.notification import NotificationProviderRecord as Provider
from app.services.notification import NotificationService


async def clean(engine, ids, orgs):
    async with AsyncSession(engine) as session:
        if ids:
            await session.execute(delete(Provider).where(Provider.id.in_(ids)))
        if orgs:
            await session.execute(delete(Provider).where(Provider.organization_id.in_(orgs)))
            await session.execute(delete(Organization).where(Organization.id.in_(orgs)))
        await session.commit()
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", [False, True])
async def test_waiting_provider_edit_keeps_a_concurrently_replaced_secret(platform):
    engine = create_test_engine()
    flushed, release = asyncio.Event(), asyncio.Event()
    ids, orgs, tasks = [], [], []
    second_name = "owned-provider-config-second-" + uuid4().hex

    class PausingSession(AsyncSession):
        async def flush(self, *args, **kwargs):
            await super().flush(*args, **kwargs)
            if self.info.get("role") == "first" and not flushed.is_set():
                flushed.set()
                await asyncio.wait_for(release.wait(), timeout=20)

    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            org = Organization(name="Owned secret merge", slug=uuid4().hex)
            session.add(org)
            await session.flush()
            orgs = [org.id]
            owner = None if platform else org.id
            row = await NotificationService(session).create_provider(
                name="Owned config merge",
                provider_type="smtp",
                config={"password": "old-owned-secret", "host": "initial.example.test"},
                organization_id=owner,
            )
            await session.commit()
            ids = [row.id]

        async def edit(role, values):
            async with PausingSession(
                engine, expire_on_commit=False, info={"role": role}
            ) as session:
                await session.execute(
                    text("SELECT set_config('application_name', :name, true)"),
                    {"name": second_name if role == "second" else "owned-provider-config-first"},
                )
                row = await NotificationService(session).update_provider(
                    ids[0], organization_id=owner, config=values
                )
                assert row is not None
                await session.commit()

        first = asyncio.create_task(edit("first", {"password": "new-owned-secret"}))
        tasks.append(first)
        await asyncio.wait_for(flushed.wait(), timeout=10)
        second = asyncio.create_task(edit("second", {"host": "updated.example.test"}))
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
            assert asyncio.get_running_loop().time() < deadline
            await asyncio.sleep(0.01)
        release.set()
        await asyncio.wait_for(asyncio.gather(first, second), timeout=15)
        async with AsyncSession(engine) as session:
            row = (
                await session.execute(select(Provider).where(Provider.id == ids[0]))
            ).scalar_one()
            config = NotificationService(session)._decrypt_sensitive_config(row.config)
            assert config["password"] == "new-owned-secret", (
                "A waiting metadata edit restored the old provider secret"
            )
            assert config["host"] == "updated.example.test"
            assert row.config["password"] != "new-owned-secret"
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await clean(engine, ids, orgs)


@pytest.mark.asyncio
@pytest.mark.parametrize("second_platform", [False, True])
async def test_provider_writes_in_another_owner_do_not_wait(second_platform):
    engine = create_test_engine()
    held, release = asyncio.Event(), asyncio.Event()
    ids, orgs, tasks = [], [], []

    class HeldSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            value = await super().execute(statement, *args, **kwargs)
            if (
                isinstance(statement, Update)
                and statement.table.name == "notification_providers"
                and not held.is_set()
            ):
                held.set()
                await asyncio.wait_for(release.wait(), timeout=20)
            return value

    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            rows = [
                Organization(name="Owned independent scope", slug=uuid4().hex) for _ in range(2)
            ]
            session.add_all(rows)
            await session.commit()
            orgs = [r.id for r in rows]

        async def first_write():
            async with HeldSession(engine, expire_on_commit=False) as session:
                row = await NotificationService(session).create_provider(
                    name="Owned held",
                    provider_type="smtp",
                    config={},
                    is_default=True,
                    organization_id=orgs[0],
                )
                await session.commit()
                return row.id

        first = asyncio.create_task(first_write())
        tasks.append(first)
        await asyncio.wait_for(held.wait(), timeout=10)

        async def second_write():
            async with AsyncSession(engine, expire_on_commit=False) as session:
                row = await NotificationService(session).create_provider(
                    name="Owned independent",
                    provider_type="smtp",
                    config={},
                    is_default=True,
                    organization_id=None if second_platform else orgs[1],
                )
                await session.commit()
                return row.id

        second = asyncio.create_task(second_write())
        tasks.append(second)
        ids.append(await asyncio.wait_for(asyncio.shield(second), timeout=5))
        assert not first.done() and not release.is_set()
        release.set()
        ids.append(await asyncio.wait_for(first, timeout=10))
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        values = await asyncio.gather(*tasks, return_exceptions=True)
        ids.extend(v for v in values if not isinstance(v, BaseException))
        await clean(engine, ids, orgs)


@pytest.mark.asyncio
async def test_provider_scope_lock_releases_after_a_rolled_back_writer():
    engine = create_test_engine()
    held, release = asyncio.Event(), asyncio.Event()
    ids, orgs, tasks = [], [], []

    class RollbackSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            value = await super().execute(statement, *args, **kwargs)
            if (
                isinstance(statement, Update)
                and statement.table.name == "notification_providers"
                and not held.is_set()
            ):
                held.set()
                await asyncio.wait_for(release.wait(), timeout=20)
                raise RuntimeError("owned intentional rollback")
            return value

    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            row = Organization(name="Owned provider rollback", slug=uuid4().hex)
            session.add(row)
            await session.commit()
            orgs = [row.id]

        async def failed_write():
            async with RollbackSession(engine) as session:
                with pytest.raises(RuntimeError, match="owned intentional rollback"):
                    await NotificationService(session).create_provider(
                        name="Must roll back",
                        provider_type="smtp",
                        config={},
                        is_default=True,
                        organization_id=orgs[0],
                    )
                await session.rollback()

        first = asyncio.create_task(failed_write())
        tasks.append(first)
        await asyncio.wait_for(held.wait(), timeout=10)

        async def second_write():
            async with AsyncSession(engine, expire_on_commit=False) as session:
                row = await NotificationService(session).create_provider(
                    name="Owned survivor",
                    provider_type="smtp",
                    config={},
                    is_default=True,
                    organization_id=orgs[0],
                )
                await session.commit()
                return row.id

        second = asyncio.create_task(second_write())
        tasks.append(second)
        # The first writer explicitly rolls back; the second must still finish.
        await asyncio.sleep(0.05)
        release.set()
        await asyncio.wait_for(first, timeout=10)
        ids.append(await asyncio.wait_for(second, timeout=10))
        async with AsyncSession(engine) as session:
            rows = (
                (await session.execute(select(Provider).where(Provider.organization_id == orgs[0])))
                .scalars()
                .all()
            )
            assert len(rows) == 1 and rows[0].is_default and rows[0].name == "Owned survivor"
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        values = await asyncio.gather(*tasks, return_exceptions=True)
        ids.extend(v for v in values if v is not None and not isinstance(v, BaseException))
        await clean(engine, ids, orgs)
