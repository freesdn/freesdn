"""Planned actual PG append-order probes; no timestamp/auth/device replacement."""
from __future__ import annotations

import asyncio
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac


@pytest.mark.parametrize("prior_tail", [False, True])
@pytest.mark.parametrize("schedule", ["serial", "autoflush_wait_commit", "autoflush_wait_rollback"])
async def test_real_audit_append_order(prior_tail, schedule, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_id = uuid4()
    waiting = None
    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert await seed.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            seed.add(Organization(id=org_id, name="Owned audit order",
                                  slug="owned-audit-order-" + org_id.hex))
            await seed.commit()
            if prior_tail:
                await AuditService(seed).log(action="owned_genesis", resource_type="organization",
                                             resource_id=org_id, organization_id=org_id)
                await seed.commit()

        async with AsyncSession(engine, expire_on_commit=False) as first, \
                AsyncSession(engine, expire_on_commit=False) as holder, \
                engine.connect() as observer:
            try:
                # A already has a physical connection and an ordinary ORM row.
                # Its own dirty mutation is not flushed until begin_nested().
                first_org = await first.get(Organization, org_id)
                first_pid = await first.scalar(text("SELECT pg_backend_pid()"))
                holder_org = await holder.get(Organization, org_id)
                holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
                observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
                assert len({first_pid, holder_pid, observer_pid}) == 3

                async def append_first():
                    entry = await AuditService(first).log(
                        action="owned_first", resource_type="organization",
                        resource_id=org_id, organization_id=org_id,
                    )
                    await first.commit()
                    return entry

                genuine_wait = False
                if schedule == "serial":
                    first_entry = await append_first()
                    holder_entry = await AuditService(holder).log(
                        action="owned_holder", resource_type="organization",
                        resource_id=org_id, organization_id=org_id,
                    )
                    await holder.commit()
                else:
                    holder_org.description = "Owned holder before audit"
                    await holder.flush()
                    first_org.description = "Owned caller waiting during audit autoflush"
                    waiting = asyncio.create_task(append_first())
                    async with asyncio.timeout(10):
                        while True:
                            if waiting.done():
                                await waiting
                                pytest.fail("Caller completed before an actual database wait")
                            blockers = await observer.scalar(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": first_pid},
                            )
                            if holder_pid in blockers:
                                genuine_wait = True
                                break
                            await asyncio.sleep(0.02)
                    holder_entry = await AuditService(holder).log(
                        action="owned_holder", resource_type="organization",
                        resource_id=org_id, organization_id=org_id,
                    )
                    if schedule == "autoflush_wait_commit":
                        await holder.commit()
                    else:
                        await holder.rollback()
                    async with asyncio.timeout(10):
                        first_entry = await waiting
                    waiting = None

            finally:
                if waiting is not None:
                    waiting.cancel()
                    await asyncio.gather(waiting, return_exceptions=True)
                    waiting = None

        async with AsyncSession(engine, expire_on_commit=False) as reader:
            rows = list((await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org_id,
            ).order_by(AuditLogRecord.timestamp, AuditLogRecord.id))).all())
            hashes_valid = all(row.row_hmac == _compute_row_hmac(row.prev_hash, row) for row in rows)
            before_third = await AuditService(reader).validate_audit_chain()
            await reader.rollback()
            # Observe both the first chain verdict and a subsequent genuine
            # append before any assertion about the desired ordering contract.
            await AuditService(reader).log(action="owned_third", resource_type="organization",
                                           resource_id=org_id, organization_id=org_id)
            await reader.commit()
            after_third = await AuditService(reader).validate_audit_chain()
            record_property("genuine_autoflush_row_wait", genuine_wait)
            record_property("physical_connection_PIDs", json.dumps([first_pid, holder_pid, observer_pid]))
            record_property("actual_first_timestamp", first_entry.timestamp.isoformat())
            record_property("actual_holder_timestamp", holder_entry.timestamp.isoformat())
            record_property("individually_valid_HMACs", hashes_valid)
            record_property("before_third", json.dumps(before_third, sort_keys=True))
            record_property("after_third", json.dumps(after_third, sort_keys=True))
            expected = int(prior_tail) + (1 if schedule.endswith("rollback") else 2)
            assert len(rows) == expected
            assert hashes_valid
            if schedule != "serial":
                assert genuine_wait
                assert first_entry.timestamp < holder_entry.timestamp
            assert before_third["valid"] is True, before_third
            assert before_third["checked"] == expected
            assert after_third["valid"] is True, after_third
            assert after_third["checked"] == expected + 1
    finally:
        if waiting is not None:
            waiting.cancel()
            await asyncio.gather(waiting, return_exceptions=True)
        async with engine.begin() as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
        await engine.dispose()
