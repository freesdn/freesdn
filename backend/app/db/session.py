# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Database Session Management
==========================================

Async SQLAlchemy engine and session configuration with connection pooling.

Dual-database architecture:
  - Primary (PostgreSQL)  : relational data (users, devices, config, etc.)
  - LogDB  (TimescaleDB)  : time-series data (metrics, health checks, events)
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger(__name__)

# =========================================================================
# Primary Database (PostgreSQL) — relational data
# =========================================================================

# Create async engine with connection pooling
engine = create_async_engine(
    str(settings.DATABASE_URL),
    echo=settings.DEBUG,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_pre_ping=True,  # Verify connections before use
    # Disable prepared statements — required for PgBouncer transaction mode
    connect_args={"statement_cache_size": 0},
)

# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Alias for backwards compatibility
AsyncSessionLocal = async_session_factory

# Best-effort audit-trail engine — a DEDICATED NullPool engine for the
# fire-and-forget security audit writes (auth failed-login + login-event records)
# that run on their OWN short-lived session, decoupled from the request
# transaction. NullPool means each write opens and CLOSES its own connection, so a
# connection is never left bound to a finished event loop — which under the
# per-test-event-loop harness would otherwise surface as "Event loop is closed"
# when a later test's loop finalizes a pooled connection. Audit writes are
# infrequent + best-effort, so the connect-per-write cost is irrelevant.
_audit_engine = create_async_engine(
    str(settings.DATABASE_URL),
    poolclass=NullPool,
    connect_args={"statement_cache_size": 0},
)
audit_session_factory = async_sessionmaker(
    _audit_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Structural soft-delete defence (Pattern 1). Registered on the global Session
# class so it covers every factory above (main / celery / readiness); only
# affects SoftDeleteMixin entities, so LogDB/other sessions are untouched.
# Default OFF — see app/db/soft_delete_filter.py.
if settings.ENABLE_SOFT_DELETE_GLOBAL_FILTER:
    from app.db.soft_delete_filter import register_soft_delete_filter

    register_soft_delete_filter()
    logger.info(
        "Soft-delete global filter ENABLED — 'deleted_at IS NULL' injected into "
        "ORM selects/get/relationship loads (opt out per query with "
        "execution_options(include_deleted=True))"
    )


# -------------------------------------------------------------------------
# Readiness-probe engine (fail-fast)
# -------------------------------------------------------------------------
# The /health/ready DB gate must FAIL FAST on a FROZEN database (disk-full,
# failover-in-progress, network partition — a hang, not a clean refusal). The
# main pooled engine is wrong for this: pool checkout + pool_pre_ping hang on a
# frozen peer, and even asyncio.wait_for can't unblock it — cancelling an asyncpg
# op stuck on a frozen socket waits on a cancel handshake to the same frozen
# server. So readiness uses a DEDICATED NullPool engine with asyncpg-level
# ``timeout`` (connect) + ``command_timeout`` (query): asyncpg bounds the op at
# the protocol layer and a frozen DB yields a clean error in ~3s instead of
# hanging the probe (and the gunicorn worker) for the OS TCP timeout.
_READINESS_TIMEOUT_S = 3
readiness_engine = create_async_engine(
    str(settings.DATABASE_URL),
    poolclass=NullPool,
    connect_args={
        "timeout": _READINESS_TIMEOUT_S,
        "command_timeout": _READINESS_TIMEOUT_S,
        "statement_cache_size": 0,
    },
)


# -------------------------------------------------------------------------
# Celery / background-task session factory  (NullPool – no connection reuse)
# -------------------------------------------------------------------------
# asyncio.run() creates a fresh event loop every call.  Pooled connections
# from the "main" engine are still bound to the *previous* loop, which
# triggers "Future attached to a different loop".  NullPool avoids this by
# opening (and closing) a new connection for every session.

_celery_engine = create_async_engine(
    str(settings.DATABASE_URL),
    echo=settings.DEBUG,
    poolclass=NullPool,
    pool_pre_ping=True,
    connect_args={"statement_cache_size": 0},
)

celery_session_factory = async_sessionmaker(
    _celery_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

CelerySessionLocal = celery_session_factory


# =========================================================================
# LogDB (TimescaleDB) — time-series data  (MANDATORY)
# =========================================================================
# LogDB is required for all time-series operations (metrics, health checks,
# heartbeats, events).  Config validates LOGDB_URL in production/staging.
# In development without LOGDB_URL, engines are None and callers will
# receive a clear RuntimeError rather than silently routing to primary.

logdb_engine = None
logdb_session_factory = None
LogDBSessionLocal = None
# Dedicated fail-fast LogDB engine for the readiness probe (see readiness_engine).
readiness_logdb_engine = None

_celery_logdb_engine = None
celery_logdb_session_factory = None
CeleryLogDBSessionLocal = None

if settings.LOGDB_URL:
    logdb_engine = create_async_engine(
        settings.LOGDB_URL,
        echo=settings.DEBUG,
        pool_size=settings.LOGDB_POOL_SIZE,
        max_overflow=settings.LOGDB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,
        connect_args={"statement_cache_size": 0},
    )
    readiness_logdb_engine = create_async_engine(
        settings.LOGDB_URL,
        poolclass=NullPool,
        connect_args={
            "timeout": _READINESS_TIMEOUT_S,
            "command_timeout": _READINESS_TIMEOUT_S,
            "statement_cache_size": 0,
        },
    )
    logdb_session_factory = async_sessionmaker(
        logdb_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    LogDBSessionLocal = logdb_session_factory

    _celery_logdb_engine = create_async_engine(
        settings.LOGDB_URL,
        echo=settings.DEBUG,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={"statement_cache_size": 0},
    )
    celery_logdb_session_factory = async_sessionmaker(
        _celery_logdb_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    CeleryLogDBSessionLocal = celery_logdb_session_factory
    logger.info("LogDB (TimescaleDB) engine configured: %s", settings.LOGDB_URL.split("@")[-1])
else:
    logger.warning("LOGDB_URL not set — time-series features will be unavailable")


def get_logdb_celery_factory() -> async_sessionmaker[AsyncSession]:
    """Return the Celery logdb session factory.  Raises if LogDB is not configured."""
    if CeleryLogDBSessionLocal is None:
        raise RuntimeError("LogDB is not configured. Set LOGDB_URL to enable time-series features.")
    return CeleryLogDBSessionLocal


def get_logdb_factory() -> async_sessionmaker[AsyncSession]:
    """Return the logdb session factory.  Raises if LogDB is not configured."""
    if logdb_session_factory is None:
        raise RuntimeError("LogDB is not configured. Set LOGDB_URL to enable time-series features.")
    return logdb_session_factory


async def get_session() -> AsyncGenerator[AsyncSession]:
    """
    FastAPI dependency for primary database sessions.

    Yields an async session and ensures proper cleanup.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_logdb_session() -> AsyncGenerator[AsyncSession]:
    """
    FastAPI dependency for LogDB (TimescaleDB) sessions.

    Raises RuntimeError if LOGDB_URL is not configured.
    """
    factory = get_logdb_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession]:
    """
    Context manager for database sessions outside of FastAPI.

    Useful for Celery tasks and background jobs.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# For testing - create engine without connection pooling
def create_test_engine() -> Any:
    """Create a test engine without connection pooling."""
    return create_async_engine(
        str(settings.DATABASE_URL),
        echo=True,
        poolclass=NullPool,
    )
