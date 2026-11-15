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


@pytest.fixture(autouse=True)
def _backup_files_may_live_in_the_temp_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow the system temp dir as a local backup root, as an operator would.

    Local backup storage is confined to /data/backups plus the server setting
    BACKUP_LOCAL_EXTRA_ROOTS. Tests keep their backup files under pytest's
    tmp_path, which lives in the system temp dir, so the test environment adds
    that root through the same setting. Tests of the confinement itself set
    their own value.
    """
    import tempfile

    from app.core.config import settings

    monkeypatch.setattr(settings, "BACKUP_LOCAL_EXTRA_ROOTS", tempfile.gettempdir())


@pytest.fixture(scope="session", autouse=True)
def _slot_store_is_bound_before_any_test_stubs_redis() -> None:
    """Bind the shared slot/lock client to the real Valkey once, up front.

    ``celery_app._get_solo_redis`` caches the first client it builds. Several
    tests replace ``redis_client.get_sync_redis`` with a stub while a poller
    runs; if that poller's device slot were the first caller, the stub would
    become every later test's slot store.
    """
    from app.core.celery_app import _get_solo_redis

    _get_solo_redis()


@pytest.fixture(autouse=True)
def _device_slots_are_private_to_each_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own device-slot namespace in Valkey.

    Slots are keyed by device address, and tests reuse the same documentation
    addresses (192.0.2.1, 10.0.0.1) all over the suite. A test that fails while
    holding a slot would otherwise make an unrelated later test see that device
    as busy until the lease expired.
    """
    import uuid

    from app.core import device_slot
    from app.services import device_live_read

    run = uuid.uuid4().hex
    monkeypatch.setattr(device_slot, "_PREFIX", f"freesdn:devslot:test-{run}:")
    # Remembered live answers too: a page read in one test must never be
    # served as "as of" data in another that reuses the same URL.
    monkeypatch.setattr(device_live_read, "_CACHE_PREFIX", f"freesdn:liveread:test-{run}:")


@pytest.fixture(autouse=True)
def _device_write_records_join_the_test_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Write staging-ledger rows and device-action audit records in the caller's session.

    In production they get a session of their own (app.services.device_writes
    .ledger_session), so the chokepoint's commits never commit the request's own
    changes early. A test's data lives in the db_session fixture's uncommitted
    outer transaction, which another connection cannot see, so here the record
    joins that transaction instead. test_device_writes_ledger_session.py covers
    the production path.
    """
    import contextlib

    import app.services.device_writes as device_writes

    monkeypatch.setattr(
        device_writes, "ledger_session_factory", lambda db: contextlib.nullcontext(db)
    )
