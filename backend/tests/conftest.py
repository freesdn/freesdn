# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi.dependencies import models as dependency_models
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_test_engine, get_session
from app.main import app


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol():
    yield
    # Run after fixture teardown and pytest's release of item.funcargs. FastAPI's
    # bounded classifier caches otherwise retain per-case dependency closures,
    # including completed sessions and entire owned application graphs. Clearing
    # only these test-process caches leaves production caching, GC and request
    # deadlines unchanged while allowing finished fixtures to be collected.
    dependency_models._is_gen_callable_cached.cache_clear()
    dependency_models._is_async_gen_callable_cached.cache_clear()
    dependency_models._is_coroutine_callable_cached.cache_clear()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession]:
    """Provide an isolated AsyncSession for request/DB integration tests."""
    engine = create_test_engine()
    # An outer connection transaction survives application Session.commit().
    # Each session transaction uses a savepoint, so teardown can roll back all
    # request writes instead of leaking committed fixtures into later runs.
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                async with AsyncSession(
                    bind=connection,
                    expire_on_commit=False,
                    autoflush=False,
                    join_transaction_mode="create_savepoint",
                ) as session:
                    yield session
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
    # The app code under test (the security audit-trail writes in the auth
    # endpoints) calls the GLOBAL ``async_session_factory()`` directly — its
    # connections pool on the global engine bound to THIS test's event loop.
    # Dispose it here too, otherwise those pooled connections surface as
    # "Event loop is closed" when a later test's (new) loop finalizes them.
    from app.db.session import engine as _global_engine

    await _global_engine.dispose()


@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient]:
    """HTTPX client bound to the app with the test session injected."""

    async def _override_get_session() -> AsyncGenerator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_session] = _override_get_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_session, None)
