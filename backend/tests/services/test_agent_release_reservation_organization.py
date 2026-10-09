"""Planned destination lifecycle contracts on the same owned native fixture."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text, update

from app.models.core import Organization
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services.test_agent_release_reservation import (
    call,
    journal,
    request_for,
)
from tests.services.test_agent_release_reservation import reservation as reservation
from tests.services.test_agent_signing_lifecycle import headers


@pytest.mark.parametrize("state", ["missing", "deleted", "inactive", "active"])
async def test_new_reservation_requires_a_current_live_destination(reservation, state):
    f = reservation
    target = uuid4() if state == "missing" else f.other_org
    f.publication = request_for(target)
    if state in ("deleted", "inactive"):
        fields = {"deleted_at": datetime.now(UTC)} if state == "deleted" else {"is_active": False}
        async with f.engine.begin() as db:
            await db.execute(update(Organization).where(Organization.id == target).values(**fields))
    response = await call(f, await headers(f))
    retained = await journal(f)
    assert response.status_code == (200 if state == "active" else 404)
    assert len(retained) == (1 if state == "active" else 0) and not f.root.exists()


async def test_unscoped_platform_global_publication_keeps_nullable_scope(reservation):
    f = reservation
    f.publication = request_for(None)
    response = await call(f, await headers(f))
    retained = await journal(f)
    assert response.status_code == 200 and len(retained) == 1
    assert retained[0]["organization_id"] is None and not f.root.exists()


async def test_retiring_destination_does_not_prevent_historical_inspection_or_cancellation(reservation):
    f = reservation
    f.publication = request_for(f.other_org)
    credential = await headers(f)
    assert (await call(f, credential)).status_code == 200
    before = await journal(f)
    async with f.engine.begin() as db:
        await db.execute(update(Organization).where(Organization.id == f.other_org)
                         .values(deleted_at=datetime.now(UTC), is_active=False))
    replay = await call(f, credential)
    assert replay.status_code == 200 and replay.json()["created"] is False and await journal(f) == before
    f.action = "cancel"
    cancelled = await call(f, credential)
    after = await journal(f)
    assert cancelled.status_code == 200 and len(after) == 1 and after[0]["decision"] == "cancelled"
    assert after[0]["organization_id"] == f.other_org and after[0]["requested_by"] == before[0]["requested_by"]
    assert not f.root.exists()


async def test_destination_writer_refuses_without_partial_reservation_then_allows_explicit_retry(reservation):
    f = reservation
    f.publication = request_for(f.other_org)
    credential = await headers(f)
    async with f.engine.connect() as holder, holder.begin():
        await holder.execute(text("SELECT id FROM core.organizations WHERE id=:id FOR UPDATE"), {"id": f.other_org})
        refused = await call(f, credential)
        assert refused.status_code == 503 and await journal(f) == []
    retried = await call(f, credential)
    assert retried.status_code == 200 and len(await journal(f)) == 1 and not f.root.exists()
