"""Real DB transactions with synthetic notification transports; no external sends."""

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_test_engine
from app.models.core import Organization
from app.models.notification import NotificationProviderRecord as Provider
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationService,
)

CASES = [
    (method, outcome, change, platform)
    for method in ["verify", "test"]
    for outcome in [False, True]
    for change in ["unchanged", "config"]
    for platform in [False, True]
] + [
    (method, True, change, False) for method in ["verify", "test"] for change in ["delete", "owner"]
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,outcome,change,platform", CASES)
async def test_provider_probe_cannot_verify_or_annotate_a_changed_record(
    method, outcome, change, platform, monkeypatch
):
    engine = create_test_engine()
    entered = asyncio.Event()
    release = asyncio.Event()
    tasks = []
    ids = []
    orgs = []

    class OwnedTransport:
        async def verify(self):
            entered.set()
            await asyncio.wait_for(release.wait(), 15)
            return outcome, "Synthetic old transport result"

        async def send(self, *args):
            entered.set()
            await asyncio.wait_for(release.wait(), 15)
            return DeliveryResult(
                success=outcome,
                channel=NotificationChannel.EMAIL,
                status=DeliveryStatus.SENT if outcome else DeliveryStatus.FAILED,
                error=None if outcome else "Synthetic old transport result",
            )

    monkeypatch.setattr(
        NotificationService, "_build_runtime_provider", lambda *_args: OwnedTransport()
    )
    try:
        async with AsyncSession(engine, expire_on_commit=False) as s:
            organizations = [
                Organization(name="Owned provider probe", slug=uuid4().hex) for _ in range(2)
            ]
            s.add_all(organizations)
            await s.flush()
            orgs = [o.id for o in organizations]
            owner = None if platform else orgs[0]
            row = await NotificationService(s).create_provider(
                name="Owned original",
                provider_type="smtp",
                config={"host": "old.example.test", "password": "old-synthetic-secret"},
                organization_id=owner,
            )
            await s.commit()
            ids = [row.id]

        async def probe():
            async with AsyncSession(engine, expire_on_commit=False) as s:
                service = NotificationService(s)
                value = (
                    await service.verify_stored_provider(ids[0], organization_id=owner)
                    if method == "verify"
                    else await service.test_stored_provider(
                        ids[0], "owned@example.test", organization_id=owner
                    )
                )
                await s.commit()
                return value

        task = asyncio.create_task(probe())
        tasks.append(task)
        await asyncio.wait_for(entered.wait(), 10)

        async def mutate():
            async with AsyncSession(engine) as s:
                service = NotificationService(s)
                if change == "config":
                    await service.update_provider(
                        ids[0],
                        organization_id=owner,
                        config={"host": "new.example.test", "password": "new-synthetic-secret"},
                    )
                elif change == "delete":
                    assert await service.delete_provider(ids[0], organization_id=owner)
                elif change == "owner":
                    await s.execute(
                        update(Provider)
                        .where(Provider.id == ids[0])
                        .values(organization_id=orgs[1])
                    )
                await s.commit()

        # Management must be able to change/delete a provider during slow network I/O.
        await asyncio.wait_for(mutate(), 5)
        release.set()
        value = await asyncio.wait_for(task, 10)
        async with AsyncSession(engine) as s:
            row = (
                await s.execute(select(Provider).where(Provider.id == ids[0]))
            ).scalar_one_or_none()
            if change == "delete":
                assert row is None
            elif change == "unchanged":
                assert row.is_verified is outcome
                assert (row.last_error is None) is outcome
                assert (row.last_verified_at is not None) is (method == "verify" or outcome)
            else:
                assert not row.is_verified, "Old probe certified a changed or reassigned provider"
                assert row.last_verified_at is None, (
                    "Old probe wrote a timestamp onto a changed provider"
                )
                assert row.last_error is None, (
                    "Old failure replaced diagnostics of a changed provider"
                )
                if change == "config":
                    assert (
                        NotificationService(s)._decrypt_sensitive_config(row.config)["password"]
                        == "new-synthetic-secret"
                    )
            if method == "verify" and change != "unchanged":
                assert value[0] is False, "Old verification was reported as current after mutation"
            if method == "test":
                assert value.success is outcome, (
                    "Already dispatched test outcome must not be rewritten as a delivery failure"
                )
    finally:
        release.set()
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        async with AsyncSession(engine) as s:
            if ids:
                await s.execute(delete(Provider).where(Provider.id.in_(ids)))
            if orgs:
                await s.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await s.commit()
        await engine.dispose()
