"""Actual PostgreSQL provider-management transactions; no notification sends."""

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation,owner,caller",
    [
        ("create", "platform", "platform"),
        ("create", "a", "a"),
        ("update", "platform", "platform"),
        ("update", "a", "platform"),
        ("update", "a", "a"),
    ],
)
async def test_provider_default_promotion_changes_only_actual_owner(operation, owner, caller):
    engine = create_test_engine()
    orgs, ids = [], []
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            organizations = [
                Organization(name="Owned default probe", slug=uuid4().hex) for _ in range(2)
            ]
            session.add_all(organizations)
            await session.flush()
            orgs = [o.id for o in organizations]
            owners = {"platform": None, "a": orgs[0], "b": orgs[1]}
            defaults = [
                Provider(
                    name="Owned " + k,
                    organization_id=v,
                    provider_type="smtp",
                    channel="email",
                    config={},
                    is_default=True,
                )
                for k, v in owners.items()
            ]
            target = Provider(
                name="Owned target",
                organization_id=owners[owner],
                provider_type="smtp",
                channel="email",
                config={},
                is_default=False,
            )
            other_channel = Provider(
                name="Owned webhook",
                organization_id=owners[owner],
                provider_type="webhook",
                channel="webhook",
                config={},
                is_default=True,
            )
            session.add_all([*defaults, target, other_channel])
            await session.commit()
            ids = [p.id for p in [*defaults, target, other_channel]]
            expected = {p.id for p in defaults if p.organization_id != owners[owner]} | {
                other_channel.id
            }
            if operation == "create":
                row = await NotificationService(session).create_provider(
                    name="Owned promoted",
                    provider_type="smtp",
                    config={},
                    is_default=True,
                    organization_id=owners[caller],
                )
                ids.append(row.id)
            else:
                row = await NotificationService(session).update_provider(
                    target.id, organization_id=owners[caller], is_default=True
                )
            assert row is not None
            expected.add(row.id)
            await session.commit()
        async with AsyncSession(engine) as observer:
            actual = set(
                (
                    await observer.execute(
                        select(Provider.id).where(
                            Provider.id.in_(ids), Provider.is_default.is_(True)
                        )
                    )
                ).scalars()
            )
            assert actual == expected, (
                "Promotion changed default providers outside the target's actual owner/channel"
            )
    finally:
        async with AsyncSession(engine) as session:
            if ids:
                await session.execute(delete(Provider).where(Provider.id.in_(ids)))
            if orgs:
                await session.execute(delete(Provider).where(Provider.organization_id.in_(orgs)))
                await session.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await session.commit()
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("platform", [False, True])
async def test_concurrent_empty_provider_group_keeps_one_default(operation, platform):
    engine = create_test_engine()
    first_demoted = asyncio.Event()
    release_first = asyncio.Event()
    tasks, ids, orgs = [], [], []
    second_name = "owned-provider-second-" + uuid4().hex

    class PausingSession(AsyncSession):
        async def execute(self, statement, *args, **kwargs):
            value = await super().execute(statement, *args, **kwargs)
            if (
                self.info.get("role") == "first"
                and isinstance(statement, Update)
                and statement.table.name == "notification_providers"
                and not first_demoted.is_set()
            ):
                first_demoted.set()
                await asyncio.wait_for(release_first.wait(), timeout=20)
            return value

    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            org = Organization(name="Owned concurrent provider", slug=uuid4().hex)
            session.add(org)
            await session.flush()
            orgs = [org.id]
            owner = None if platform else org.id
            targets = [
                Provider(
                    name="Owned target " + str(i),
                    organization_id=owner,
                    provider_type="smtp",
                    channel="email",
                    config={},
                    is_default=False,
                )
                for i in range(2)
            ]
            session.add_all(targets)
            await session.commit()
            ids = [p.id for p in targets]

        async def promote(role, index):
            async with PausingSession(
                engine, expire_on_commit=False, info={"role": role}
            ) as session:
                await session.execute(
                    text("SELECT set_config('application_name', :name, true)"),
                    {"name": second_name if role == "second" else "owned-provider-first"},
                )
                service = NotificationService(session)
                if operation == "create":
                    row = await service.create_provider(
                        name="Owned concurrent " + role,
                        provider_type="smtp",
                        config={},
                        is_default=True,
                        organization_id=owner,
                    )
                else:
                    row = await service.update_provider(
                        ids[index], organization_id=owner, is_default=True
                    )
                assert row is not None
                await session.commit()
                return row.id

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
            assert asyncio.get_running_loop().time() < deadline
            await asyncio.sleep(0.01)
        release_first.set()
        promoted = await asyncio.wait_for(asyncio.gather(first, second), timeout=15)
        ids.extend(promoted)
        async with AsyncSession(engine) as observer:
            rows = (
                (
                    await observer.execute(
                        select(Provider.id).where(
                            Provider.id.in_(ids), Provider.is_default.is_(True)
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1, (
                f"Concurrent requests left {len(rows)} provider defaults in an empty group"
            )
    finally:
        release_first.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        ids.extend(value for value in outcomes if not isinstance(value, BaseException))
        async with AsyncSession(engine) as session:
            if ids:
                await session.execute(delete(Provider).where(Provider.id.in_(ids)))
            if orgs:
                await session.execute(delete(Provider).where(Provider.organization_id.in_(orgs)))
                await session.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await session.commit()
        await engine.dispose()
