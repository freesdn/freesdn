# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.session import create_test_engine, get_session
from app.main import app


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession]:
    """Provide an isolated AsyncSession for request/DB integration tests."""
    engine = create_test_engine()
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()
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
