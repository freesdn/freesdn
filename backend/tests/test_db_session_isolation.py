"""Request commits must not leak fixtures into another test or test run."""

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_test_engine
from app.models.core import Organization


@pytest.mark.asyncio
async def test_application_commit_stays_inside_fixture_transaction(db_session: AsyncSession):
    organization_id = uuid4()
    db_session.add(
        Organization(id=organization_id, name="Isolation check", slug=f"isolation-{organization_id}")
    )
    await db_session.commit()
    # The application can still read its own committed data within this test.
    assert await db_session.get(Organization, organization_id) is not None

    engine = create_test_engine()
    try:
        async with engine.connect() as connection:
            visible_id = await connection.scalar(
                select(Organization.id).where(Organization.id == organization_id)
            )
        assert visible_id is None, "Session.commit() must not publish test fixtures to other sessions"
    finally:
        await engine.dispose()
