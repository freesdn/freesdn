"""Actual DB waits for composed security-review + audit-write transactions.

Real service methods, no authentication/HTTP/customer operations. The existing
HTTP review route commits separately; these probes qualify safe service-level
composition and do not claim a current external exploit or endpoint deadlock.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization, User
from app.models.security_audit import AuditLogRecord, SecurityEventRecord
from app.services.audit import AuditService
from app.services.security_audit import PersistentSecurityAuditService as Legacy


def failure(exc):
    original = getattr(exc, "orig", None)
    return {"type": type(exc).__name__, "sqlstate": getattr(original, "sqlstate", None)}


@pytest.mark.parametrize("commit_writer", [True, False])
@pytest.mark.parametrize("cleaner", ["main", "legacy"])
async def test_cleanup_and_security_writer_have_no_inverse_chain_wait(cleaner, commit_writer, record_property):
    db = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org, user, event, old_id, new_id = (uuid4() for _ in range(5))
    waiting = None
    try:
        async with AsyncSession(db) as seed:
            assert await seed.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            assert await seed.scalar(select(func.count()).select_from(SecurityEventRecord)) == 0
            seed.add(Organization(id=org, name="Owned retention race", slug="owned-" + org.hex))
            await seed.flush()
            seed.add(User(id=user, organization_id=org, username="owned-" + user.hex,
                          email="owned-" + user.hex + "@example.invalid", hashed_password="!DISABLED", is_active=False))
            await seed.flush()
            seed.add(SecurityEventRecord(id=event, timestamp=datetime.now(UTC) - timedelta(days=120),
                event_type="owned_review", organization_id=org))
            await seed.flush()
            await AuditService(seed).persist_record(AuditLogRecord(
                id=old_id, timestamp=datetime.now(UTC) - timedelta(days=120),
                action="owned_old", resource_type="owned_cleanup", organization_id=org,
            ))
            await seed.commit()
        async with db.connect() as wc, db.connect() as cc, db.connect() as observer:
            async with AsyncSession(wc, expire_on_commit=False) as writer, AsyncSession(cc) as maintenance:
                try:
                    actor = await Legacy.review_security_event(writer, event, user, "owned review", organization_id=org)
                    assert actor is not None
                    writer_pid = await writer.scalar(text("SELECT pg_backend_pid()"))
                    cleaner_pid = await maintenance.scalar(text("SELECT pg_backend_pid()"))
                    observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
                    assert len({writer_pid, cleaner_pid, observer_pid}) == 3
                    async def cleanup():
                        try:
                            if cleaner == "main":
                                value = await AuditService(maintenance).cleanup_old_entries(90)
                            else:
                                value = await Legacy.cleanup_old_entries(maintenance, 90)
                            await maintenance.commit()
                            return {"error": None, "result": value}
                        except Exception as exc:
                            value = failure(exc)
                            await maintenance.rollback()
                            return {"error": value, "result": None}
                    waiting = asyncio.create_task(cleanup())
                    genuine_wait = False
                    async with asyncio.timeout(12):
                        while True:
                            if waiting.done():
                                pytest.fail("Cleanup finished before a genuine security-row wait: " + str(await waiting))
                            blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": cleaner_pid})
                            if writer_pid in blockers:
                                genuine_wait = True
                                break
                            await asyncio.sleep(0.02)
                    writer_error = None
                    async with asyncio.timeout(12):
                        try:
                            await AuditService(writer).persist_record(AuditLogRecord(
                                id=new_id, timestamp=datetime.now(UTC), action="owned_review_audit",
                                resource_type="owned_cleanup", organization_id=org,
                            ))
                            if commit_writer:
                                await writer.commit()
                            else:
                                await writer.rollback()
                        except Exception as exc:
                            writer_error = failure(exc)
                            await writer.rollback()
                        cleaned = await waiting
                        waiting = None
                finally:
                    if waiting is not None:
                        waiting.cancel()
                        await asyncio.gather(waiting, return_exceptions=True)
                        waiting = None
                    await writer.rollback()
                    await maintenance.rollback()
        async with AsyncSession(db) as reader:
            new = await reader.get(AuditLogRecord, new_id)
            old = await reader.get(AuditLogRecord, old_id)
            remaining_event = await reader.get(SecurityEventRecord, event)
            verdict = await AuditService(reader).validate_audit_chain()
        observation = {"genuine_security_row_wait": genuine_wait,
            "physical_PIDs": [writer_pid, cleaner_pid, observer_pid], "writer_error": writer_error,
            "cleaner": cleaned, "new_audit_committed": new is not None,
            "old_audit_retained": old is not None, "old_event_retained": remaining_event is not None,
            "actual_final_verdict": verdict}
        record_property("actual_retention_writer_observation", json.dumps(observation))
        assert writer_error is None and cleaned["error"] is None
        assert (new is not None) is commit_writer
        assert old is None and remaining_event is None
        assert verdict["valid"] and verdict["boundary_verified"]
    finally:
        if waiting is not None:
            waiting.cancel()
            await asyncio.gather(waiting, return_exceptions=True)
        async with db.begin() as connection:
            await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.id.in_([old_id, new_id])))
            await connection.execute(delete(SecurityEventRecord).where(SecurityEventRecord.id == event))
            await connection.execute(delete(User).where(User.id == user))
            await connection.execute(delete(Organization).where(Organization.id == org))
        await db.dispose()
