# SPDX-License-Identifier: AGPL-3.0-only
"""Independent PostgreSQL transactions must serialize catalog authorization."""

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_test_engine
from app.models.marketplace import MarketplaceCatalogState
from app.services import marketplace_catalog as policy
from tests.services.test_marketplace_replay_regression import _catalog_setup


@pytest.mark.parametrize("first,second,expected", [(8, 7, 8), (7, 8, 8)])
async def test_concurrent_serials_cannot_rewind_committed_floor(
    monkeypatch, first, second, expected
):
    # This fixture commits real independent connections, unlike the surrounding
    # savepoint-based endpoint tests. Refuse to use an existing state row and
    # delete only the exact fixture identity it created.
    make, _ = _catalog_setup(monkeypatch)
    identity = uuid4().hex + uuid4().hex
    engine = create_test_engine()
    locked, waiting, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    tasks = []
    try:
        async with AsyncSession(engine) as check:
            assert (
                await check.execute(select(MarketplaceCatalogState))
            ).scalar_one_or_none() is None

        async def writer(serial, leader):
            async with AsyncSession(engine, expire_on_commit=False) as session:
                envelope = policy.validate_envelope(make(serial, ()), 0)
                if not leader:
                    await locked.wait()
                    waiting.set()
                state = await policy.lock_catalog(session)
                if leader:
                    policy.accept_envelope(state, envelope, identity, 0)
                    locked.set()
                    await release.wait()
                else:
                    policy.accept_envelope(state, envelope, identity, 0)
                await session.commit()
                return serial

        tasks = [
            asyncio.create_task(writer(first, True)),
            asyncio.create_task(writer(second, False)),
        ]
        await asyncio.wait_for(waiting.wait(), 5)
        await asyncio.sleep(0.1)
        assert not tasks[1].done(), "second connection bypassed the catalog lock"
        release.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
        assert results[0] == first
        if second < first:
            assert isinstance(results[1], HTTPException) and results[1].status_code == 409
        else:
            assert results[1] == second
        async with AsyncSession(engine) as check:
            state = (await check.execute(select(MarketplaceCatalogState))).scalar_one()
            assert state.serial == expected and state.identity == identity
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(
                delete(MarketplaceCatalogState).where(MarketplaceCatalogState.identity == identity)
            )
            await cleanup.commit()
        await engine.dispose()
