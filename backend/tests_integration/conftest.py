"""
FreeSDN Integration Test Infrastructure
========================================

Spins up real Postgres + Redis via testcontainers, runs the full Alembic
migration chain, and yields a clean transaction-rollback session per test.

Why this exists:
    The unit suite under ``tests/`` mocks SQLAlchemy heavily — it catches
    type drift but cannot catch race conditions, tenant leaks, RLS gaps,
    or migration breakage. This suite hits real infrastructure to close
    that gap.

How it runs:
    pytest tests_integration/ -m integration

Requirements:
    - Docker Desktop running (testcontainers spawns containers).
    - Images postgres:18.3-trixie and redis:8.6.2-trixie locally; both
      are already pulled by the main FreeSDN compose stack so first run
      is fast.

Design notes:
    - Containers are session-scoped: one Postgres + one Redis for the
      whole pytest invocation. Migrations run once.
    - Env vars are set in ``pytest_configure`` (a pytest hook that fires
      AFTER conftest module load but BEFORE any test imports app code).
      This way ``app.core.config.settings`` picks up the testcontainer
      URL when it is first imported by a test.
    - Each test gets its own SQLAlchemy session bound to a SAVEPOINT;
      every test's writes roll back at teardown so tests cannot pollute
      each other.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
import pytest_asyncio

# Containers are started in pytest_configure (below) and the handles
# are stashed here so fixtures can read them without re-starting.
_CONTAINERS: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# pytest_configure — runs once per session, before any test imports app code
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    """Start Postgres + Redis containers and set env BEFORE app imports.

    This hook fires after conftest module load but before pytest collects
    individual test modules. Any ``from app...`` import inside a test
    module sees the environment we set here, so ``settings`` resolves
    DATABASE_URL / REDIS_URL to our testcontainer endpoints.
    """
    # Skip when not running the integration suite (e.g. unit pytest run).
    if not _is_integration_run(config):
        return

    # ── CI fast path ────────────────────────────────────────────────────
    # On GitHub Actions the workflow already declares Postgres + Redis as
    # service containers and exports POSTGRES_HOST=localhost etc. into
    # the job environment. Setting ``CI_REUSE_SERVICES=1`` tells us to
    # skip the local testcontainers spin-up (which would require Docker-
    # in-Docker) and run migrations directly against the provided
    # services.
    if os.environ.get("CI_REUSE_SERVICES") == "1":
        _run_migrations()
        return

    from testcontainers.postgres import PostgresContainer
    from testcontainers.redis import RedisContainer

    pg = PostgresContainer(
        image="postgres:18.3-trixie",
        username="freesdn_test",
        password="freesdn_test",
        dbname="freesdn_test",
        port=5432,
        driver="asyncpg",
    )
    pg.start()
    _CONTAINERS["postgres"] = pg

    redis = RedisContainer(image="redis:8.6.2-trixie")
    redis.start()
    _CONTAINERS["redis"] = redis

    pg_host = pg.get_container_host_ip()
    pg_port = pg.get_exposed_port(5432)
    redis_host = redis.get_container_host_ip()
    redis_port = redis.get_exposed_port(6379)

    # Map container endpoints into pydantic-settings env vars (no prefix —
    # see app/core/config.py for naming).
    os.environ["POSTGRES_HOST"] = pg_host
    os.environ["POSTGRES_PORT"] = str(pg_port)
    os.environ["POSTGRES_USER"] = "freesdn_test"
    os.environ["POSTGRES_PASSWORD"] = "freesdn_test"
    os.environ["POSTGRES_DB"] = "freesdn_test"
    os.environ["LOGDB_URL"] = (
        f"postgresql+asyncpg://freesdn_test:freesdn_test@{pg_host}:{pg_port}/freesdn_test"
    )
    os.environ["REDIS_HOST"] = redis_host
    os.environ["REDIS_PORT"] = str(redis_port)
    os.environ["REDIS_PASSWORD"] = ""
    # NB: must be development/staging/production — the config validator
    # fail-closes on "testing" (mirrors the unit-test CI env + scripts/migrate).
    os.environ["ENVIRONMENT"] = "development"
    os.environ["SECRET_KEY"] = (
        "integration-test-secret-key-min-32-chars-not-for-real-use"
    )
    os.environ["ENCRYPTION_SALT"] = "integration-test-encryption-salt-not-real"
    os.environ["STRICT_STARTUP"] = "false"

    # Run alembic migrations against the fresh database. Bootstrapping the
    # 18-schema layout takes ~3-5s on the first run.
    _run_migrations()


def pytest_unconfigure(config: pytest.Config) -> None:
    """Stop containers when pytest exits."""
    pg = _CONTAINERS.pop("postgres", None)
    if pg is not None:
        pg.stop()
    redis = _CONTAINERS.pop("redis", None)
    if redis is not None:
        redis.stop()


def _is_integration_run(config: pytest.Config) -> bool:
    """Only spin up containers when the user actually runs integration tests."""
    # Common cases: explicit `-m integration`, explicit tests_integration path,
    # or `--collect-only` that reaches into tests_integration.
    args: list[str] = list(config.invocation_params.args)
    if any("tests_integration" in a for a in args):
        return True
    markexpr = config.getoption("markexpr", default="") or ""
    if "integration" in markexpr:
        return True
    return False


def _run_migrations() -> None:
    """Bootstrap a fresh test database using the same approach as
    ``scripts/migrate.py``: create every table via ``Base.metadata
    .create_all`` and stamp Alembic to head.

    Running raw ``alembic upgrade head`` would re-execute migrations
    002-008 against tables that ``001_initial.create_all`` already
    materialized, raising ``DuplicateTableError``. The production
    ``scripts/migrate.py`` avoids this by stamping to head without
    running migrations on fresh databases — we mirror that here.
    """
    import re

    from sqlalchemy import create_engine, text

    from alembic import command
    from alembic.config import Config
    from app.core.config import settings
    from app.db.base import Base

    # Force-import every models module so all tables register on metadata.
    import app.models  # noqa: F401
    import app.modules.access_control.models  # noqa: F401
    import app.modules.ai.models  # noqa: F401
    import app.modules.cameras.models  # noqa: F401
    import app.modules.firewall.models  # noqa: F401
    import app.modules.gateway.models  # noqa: F401
    import app.modules.hypervisor.models  # noqa: F401
    import app.modules.voip.models  # noqa: F401

    # Derive the schema set from the registered models so it can NEVER drift: a
    # hand-kept list silently missed ``fabric`` (create_all then failed with
    # ``schema "fabric" does not exist``) — the same trap 001_initial._model_schemas()
    # already fixed for the migration path. Union with the historical list so no
    # previously-created (model-less) schema regresses.
    _declared = {t.schema for t in Base.metadata.tables.values() if t.schema}
    schemas = sorted(
        _declared
        | {
            "core", "devices", "network", "events", "agents", "analytics",
            "vpn", "audit", "cameras", "firewall", "voip", "access", "backup",
            "gateway", "ai", "collector", "enterprise", "hypervisor",
        }
    )

    # asyncpg → psycopg sync driver for the synchronous create_all path
    sync_url = re.sub(
        r"postgresql\+asyncpg://", "postgresql+psycopg://",
        str(settings.DATABASE_URL),
    )
    engine = create_engine(sync_url)
    try:
        with engine.begin() as conn:
            for schema in schemas:
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
            Base.metadata.create_all(bind=conn)

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL))
        command.stamp(cfg, "head")
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Session-scoped engine fixture (lazy import)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def _reset_redis_state() -> AsyncGenerator[None]:
    """Flush Redis between tests so rate-limit counters, blacklists, and
    cached state from one test do not leak into the next.

    The auth rate limiter uses ``auth:ratelimit:<ip>`` keys in Redis with
    a 60-second TTL; without a flush, the 5-attempts-per-minute cap fires
    on the second test. Fast (<5ms) so we run it autouse.
    """
    import redis.asyncio as aioredis

    from app.core.config import settings

    client = aioredis.from_url(str(settings.REDIS_URL), decode_responses=True)
    try:
        await client.flushdb()
        yield
    finally:
        await client.aclose()


@pytest_asyncio.fixture
async def integration_engine() -> AsyncGenerator[Any]:
    """Async SQLAlchemy engine bound to the testcontainer Postgres.

    Function-scoped + ``NullPool`` so each test gets a fresh connection.
    pytest-asyncio creates a new event loop per test, and asyncpg
    connections are bound to the loop they were opened on — reusing a
    pool across loops raises ``AttributeError: 'NoneType' object has
    no attribute 'send'`` from the underlying transport.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    from app.core.config import settings

    engine = create_async_engine(
        str(settings.DATABASE_URL),
        echo=False,
        poolclass=NullPool,
        connect_args={"statement_cache_size": 0},
    )
    try:
        yield engine
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Per-test transactional session — rolls back at teardown
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def integration_db(integration_engine: Any) -> AsyncGenerator[Any]:
    """Per-test AsyncSession.

    Each test runs inside an outer transaction that is rolled back on
    teardown, so writes never leak between tests. Nested commits inside
    services are translated into SAVEPOINTs (begin_nested) which respect
    the outer rollback.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    async with integration_engine.connect() as conn:
        outer_tx = await conn.begin()
        try:
            session = AsyncSession(bind=conn, expire_on_commit=False)
            # Translate session.commit() → SAVEPOINT release so rollback works.
            await conn.begin_nested()

            from sqlalchemy import event

            @event.listens_for(session.sync_session, "after_transaction_end")
            def _restart_savepoint(sess: Any, trans: Any) -> None:  # noqa: ARG001
                if trans.nested and not trans._parent.nested:  # type: ignore[attr-defined]
                    sess.begin_nested()

            try:
                yield session
            finally:
                await session.close()
        finally:
            await outer_tx.rollback()


# ---------------------------------------------------------------------------
# HTTP client bound to the FastAPI app, with the test session injected
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def integration_client(integration_db: Any) -> AsyncGenerator[Any]:
    """HTTPX client that routes requests through the live FastAPI app.

    The ``get_session`` dependency is overridden to yield the per-test
    transactional session so endpoint writes participate in the rollback.
    """
    from httpx import ASGITransport, AsyncClient

    from app.db.session import get_session
    from app.main import app

    async def _override_get_session() -> AsyncGenerator[Any]:
        yield integration_db

    app.dependency_overrides[get_session] = _override_get_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_session, None)


# ---------------------------------------------------------------------------
# Auth helper — creates a super_admin via the setup wizard, returns tokens
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def super_admin(integration_client: Any) -> dict[str, Any]:
    """Bootstrap a super_admin via the public setup wizard.

    Returns a dict with ``email``, ``password``, ``access_token``, and
    ``user_id`` so tests can authenticate without re-implementing the
    bootstrap flow.
    """
    email = "admin@integration.example.com"
    password = "IntegrationTestP@ssw0rd!"

    # POST /setup/admin to create the super_admin (matches AdminCreateRequest)
    resp = await integration_client.post(
        "/api/v1/setup/admin",
        json={
            "email": email,
            "username": "integration_admin",
            "password": password,
            "first_name": "Integration",
            "last_name": "Admin",
        },
    )
    assert resp.status_code in (200, 201), (
        f"setup/admin failed: {resp.status_code} {resp.text}"
    )
    setup_body = resp.json()

    # Login to obtain tokens (LoginRequest takes ``login``, not ``email``)
    login = await integration_client.post(
        "/api/v1/auth/login",
        json={"login": email, "password": password},
    )
    assert login.status_code == 200, f"login failed: {login.status_code} {login.text}"
    body = login.json()
    # Login returns a SLIM body — the JWTs are set as httpOnly
    # cookies (freesdn_access / freesdn_refresh), not echoed in the body. Read them
    # from the cookies, falling back to the body for any older response shape.
    access_token = login.cookies.get("freesdn_access") or body.get("access_token")
    refresh_token = login.cookies.get("freesdn_refresh") or body.get("refresh_token")

    return {
        "email": email,
        "username": "integration_admin",
        "password": password,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": setup_body.get("user_id"),
        "headers": {"Authorization": f"Bearer {access_token}"},
    }


# ---------------------------------------------------------------------------
# Marker registration — lets `pytest -m integration` filter
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-mark every test in this directory as ``integration``."""
    integration_marker = pytest.mark.integration
    for item in items:
        if "tests_integration" in str(item.fspath):
            item.add_marker(integration_marker)
