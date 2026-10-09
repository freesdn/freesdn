# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Provider loading for delivery must never mean an all-tenant management list.

Actual mapped SELECTs run against a small SQLite fixture; provider transport and
delivery tracking are mocked. Production-schema acceptance runs separately.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, update
from sqlalchemy.orm import Session

from app.models.notification import NotificationProviderRecord
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationService,
)


@pytest.fixture
def provider_scope(monkeypatch):
    engine = create_engine("sqlite://")
    connection = engine.connect()
    connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS core")
    columns = ", ".join('"' + c.name + '"' for c in NotificationProviderRecord.__table__.columns)
    connection.exec_driver_sql(f"CREATE TABLE core.notification_providers ({columns})")
    org_a, org_b = uuid4(), uuid4()
    ids = {name: uuid4() for name in ["a", "b", "platform"]}
    for index, (name, org) in enumerate([("platform", None), ("a", org_a), ("b", org_b)], 1):
        connection.execute(
            NotificationProviderRecord.__table__.insert().values(
                id=ids[name],
                organization_id=org,
                name=name,
                channel="email",
                provider_type="smtp",
                config={},
                is_enabled=True,
                is_default=name != "platform",
                created_at=datetime(2026, 1, index, tzinfo=UTC),
            )
        )
    connection.commit()
    session = Session(bind=connection)
    faults = {}
    sends = []

    class Database:
        async def execute(self, statement):
            if faults.get("lookup"):
                raise RuntimeError("owned lookup fault")
            return session.execute(statement)

    def build(record):
        if faults.get("builder"):
            raise RuntimeError("owned builder fault")

        async def send(_recipient, _payload):
            sends.append(record.id)
            return DeliveryResult(
                True, NotificationChannel.EMAIL, DeliveryStatus.SENT, message_id=str(record.id)
            )

        return SimpleNamespace(provider_type="smtp", send=AsyncMock(side_effect=send))

    builder = MagicMock(side_effect=build)
    monkeypatch.setattr(NotificationService, "_build_runtime_provider", builder)
    monkeypatch.setattr(NotificationService, "_track_delivery", AsyncMock())
    service = NotificationService(Database())

    def change(identity, **values):
        session.execute(
            update(NotificationProviderRecord)
            .where(NotificationProviderRecord.id == identity)
            .values(**values)
        )
        session.commit()

    try:
        yield SimpleNamespace(
            service=service,
            ids=ids,
            org_a=org_a,
            org_b=org_b,
            session=session,
            change=change,
            faults=faults,
            sends=sends,
        )
    finally:
        session.close()
        connection.close()
        engine.dispose()


async def send(service, org):
    return await service.send(
        channel=NotificationChannel.EMAIL,
        recipient="owned@example.invalid",
        title="Owned title",
        body="Synthetic scope probe",
        organization_id=org,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["platform", "a", "b", "missing"])
async def test_send_loads_only_the_requested_provider_scope(provider_scope, scope):
    f = provider_scope
    org = {"platform": None, "a": f.org_a, "b": f.org_b, "missing": uuid4()}[scope]
    await f.service.load_providers_from_db(org)
    result = await send(f.service, org)
    if scope == "missing":
        assert not result.success and not f.sends
    else:
        assert result.success and f.sends == [f.ids[scope]]


@pytest.mark.asyncio
async def test_scope_reload_cannot_keep_another_tenants_nondefault_channel(provider_scope):
    f = provider_scope
    await f.service.load_providers_from_db(f.org_a)
    f.change(f.ids["b"], is_default=False)
    await f.service.load_providers_from_db(f.org_b)
    result = await send(f.service, f.org_b)
    assert result.success and f.sends == [f.ids["b"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["disabled", "removed"])
async def test_reloading_withdrawn_provider_removes_delivery_authority(provider_scope, state):
    f = provider_scope
    await f.service.load_providers_from_db(f.org_a)
    if state == "disabled":
        f.change(f.ids["a"], is_enabled=False)
    else:
        f.session.execute(
            delete(NotificationProviderRecord).where(NotificationProviderRecord.id == f.ids["a"])
        )
        f.session.commit()
    await f.service.load_providers_from_db(f.org_a)
    result = await send(f.service, f.org_a)
    assert not result.success and not f.sends


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["lookup", "builder"])
async def test_failed_reload_cannot_reuse_old_delivery_configuration(provider_scope, fault):
    f = provider_scope
    await f.service.load_providers_from_db(f.org_a)
    f.faults[fault] = True
    with pytest.raises(RuntimeError):
        await f.service.load_providers_from_db(f.org_b)
    result = await send(f.service, f.org_b)
    assert not result.success and not f.sends


@pytest.mark.asyncio
async def test_duplicate_defaults_resolve_to_newest_provider_deterministically(provider_scope):
    f = provider_scope
    f.change(f.ids["b"], organization_id=f.org_a)
    await f.service.load_providers_from_db(f.org_a)
    result = await send(f.service, f.org_a)
    assert result.success and f.sends == [f.ids["b"]]


@pytest.mark.asyncio
async def test_management_listing_retains_all_tenant_visibility(provider_scope):
    f = provider_scope
    records = await f.service.list_providers(organization_id=None)
    assert {r.id for r in records} == set(f.ids.values())
