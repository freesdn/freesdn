"""Adapted original10 window assertions for explicit local retained-state semantics.

Original input retained verbatim outside selection. No limits/order/bounds or
row mutations changed. Prefix deletion must now be detected by sealed count.
"""
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService


def engine():
    return create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)


async def require_empty(db):
    async with db.connect() as connection:
        assert await connection.scalar(select(func.count()).select_from(AuditLogRecord)) == 0


async def remove_owned(db, ids):
    async with db.begin() as connection:
        await connection.execute(text("DELETE FROM audit.audit_logs WHERE id=ANY(:ids)"), {"ids": ids})
    await db.dispose()


@pytest.mark.parametrize("window", ["full", "limit", "middle", "equal_time", "missing_start",
                                    "missing_end", "reverse", "predecessor_tamper",
                                    "position_tamper", "deleted_prefix"])
async def test_actual_window_boundaries_and_signed_order(window, record_property):
    db = engine()
    ids = [uuid4() for _ in range(3)]
    stamp = datetime.now(UTC)
    try:
        await require_empty(db)
        async with AsyncSession(db) as session:
            for number, identity in enumerate(ids):
                when = stamp if window == "equal_time" else stamp - timedelta(days=number)
                await AuditService(session).persist_record(AuditLogRecord(
                    id=identity, timestamp=when, action="owned_window", resource_type="owned_window",
                ))
            await session.commit()
        if window in {"predecessor_tamper", "position_tamper", "deleted_prefix"}:
            async with db.begin() as connection:
                statement = {
                    "predecessor_tamper": "UPDATE audit.audit_logs SET action='owned_altered' WHERE id=:id",
                    "position_tamper": "UPDATE audit.audit_logs SET append_sequence=append_sequence+1000000 WHERE id=:id",
                    "deleted_prefix": "DELETE FROM audit.audit_logs WHERE id=:id",
                }[window]
                await connection.execute(text(statement), {"id": ids[0]})
        kwargs = {
            "limit": {"limit": 1},
            "middle": {"start_id": ids[1], "end_id": ids[1]},
            "equal_time": {"start_id": ids[1], "end_id": ids[1]},
            "missing_start": {"start_id": uuid4()}, "missing_end": {"end_id": uuid4()},
            "reverse": {"start_id": ids[2], "end_id": ids[0]},
            "predecessor_tamper": {"start_id": ids[1]},
        }.get(window, {})
        async with AsyncSession(db) as session:
            verdict = await AuditService(session).validate_audit_chain(**kwargs)
        record_property("actual_window_verdict", json.dumps(verdict))
        if window in {"missing_start", "missing_end", "reverse", "predecessor_tamper", "position_tamper"}:
            assert not verdict["valid"] and not verdict["retained_history_authenticated"]
        elif window == "deleted_prefix":
            assert not verdict["valid"] and not verdict["boundary_verified"]
            assert not verdict["history_authenticated"]
        elif window == "full":
            assert verdict["valid"] and verdict["complete"] and verdict["retained_history_authenticated"]
            assert not verdict["history_authenticated"] and not verdict["external_immutability_proven"]
            assert verdict["checked"] == 3
        else:
            assert verdict["valid"] and verdict["checked"] == 1 and not verdict["complete"]
            assert not verdict["retained_history_authenticated"] and verdict["boundary_verified"]
            if window == "limit":
                assert verdict["next_start_id"] == str(ids[1])
    finally:
        await remove_owned(db, ids)
