"""Batch limits must survive PostgreSQL's choice of join strategy."""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.security_audit import FailedLoginRecord, SecurityAnomalyRecord, SecurityEventRecord
from app.services.audit_retention import delete_security_batch


@pytest.mark.parametrize("kind", ["security_events", "failed_logins", "anomalies"])
async def test_batch_limit_with_rescannable_nested_loop(kind):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    old = datetime.now(UTC) - timedelta(days=120)
    model, fields = {
        "security_events": (SecurityEventRecord, {"timestamp": old, "event_type": "owned_batch"}),
        "failed_logins": (
            FailedLoginRecord,
            {"timestamp": old, "username": "owned_batch", "ip_address": "192.0.2.123"},
        ),
        "anomalies": (
            SecurityAnomalyRecord,
            {"detected_at": old, "anomaly_type": "owned_batch", "title": "Owned", "resolved": True},
        ),
    }[kind]
    ids = [uuid4() for _ in range(1001)]
    try:
        async with AsyncSession(engine) as session:
            session.add_all(model(id=ident, **fields) for ident in ids)
            await session.flush()
            # These are supported planner choices, also reachable with ordinary
            # table statistics. Force the rescan case independent of test order.
            for setting in (
                "enable_hashjoin",
                "enable_mergejoin",
                "enable_material",
                "enable_hashagg",
                "enable_sort",
                "enable_incremental_sort",
            ):
                await session.execute(text(f"SET LOCAL {setting} = off"))
            await session.execute(text(f"ANALYZE audit.{model.__tablename__}"))
            removed = await delete_security_batch(session, kind, datetime.now(UTC))
            remaining = await session.scalar(
                select(func.count()).select_from(model).where(model.id.in_(ids))
            )
            assert removed == 1000
            assert remaining == 1
            assert await delete_security_batch(session, kind, datetime.now(UTC)) == 1
            # Session exit rolls back only this case's rows and planner settings.
    finally:
        await engine.dispose()
