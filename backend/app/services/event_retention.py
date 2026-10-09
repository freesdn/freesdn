# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded event-history cleanup; never infer completeness from skipped locks."""

from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any

from sqlalchemy import Result, delete, select, text, tuple_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.events import EventRecord

BATCH_SIZE = 1000
MAX_BATCHES = 100
RUN_BUDGET_SECONDS = 200


def retention_cutoff(days: int) -> datetime:
    # bool is an int in Python; accepting False would erase today's history.
    if type(days) is not int or not 1 <= days <= 36500:
        raise ValueError("Event retention days must be an integer between 1 and 36500")
    return datetime.now(UTC) - timedelta(days=days)


async def prune_event_history(
    factory: async_sessionmaker[AsyncSession], days: int = 90
) -> dict[str, int | str | bool]:
    """Commit at most 1,000 expired rows at once, at most 100 batches per call.

    The timestamp belongs to the primary key: matching only id could also delete
    a recent row with the same UUID in a different Timescale chunk. Database
    timeouts bound statements/lock waits; cancellation rolls back the current
    batch while retaining earlier committed progress. No implicit unbounded
    catch-up pass runs when this call reaches its budget.
    """
    cutoff = retention_cutoff(days)
    deadline = monotonic() + RUN_BUDGET_SECONDS
    deleted = batches = 0
    async with factory() as session:
        while batches < MAX_BATCHES and monotonic() < deadline:
            async with session.begin():
                await session.execute(text("SET LOCAL statement_timeout = '10s'"))
                await session.execute(text("SET LOCAL lock_timeout = '1s'"))
                victims = (
                    select(EventRecord.id, EventRecord.__table__.c.timestamp)
                    .where(EventRecord.__table__.c.timestamp < cutoff)
                    .order_by(EventRecord.__table__.c.timestamp, EventRecord.id)
                    .limit(BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                    .cte("expired_event_batch")
                    .prefix_with("MATERIALIZED")
                )
                result: Result[Any] = await session.execute(
                    delete(EventRecord)
                    .where(
                        tuple_(EventRecord.id, EventRecord.__table__.c.timestamp).in_(
                            select(victims.c.id, victims.c.timestamp)
                        )
                    )
                    .returning(EventRecord.id)
                    .execution_options(synchronize_session=False)
                )
                count = len(result.scalars().all())
            # Count only committed batches. An exception propagates, not success.
            deleted += count
            batches += 1
            if count < BATCH_SIZE:
                break
        async with session.begin():
            await session.execute(text("SET LOCAL statement_timeout = '10s'"))
            await session.execute(text("SET LOCAL lock_timeout = '1s'"))
            remaining = (
                await session.scalar(
                    select(EventRecord.id)
                    .where(EventRecord.__table__.c.timestamp < cutoff)
                    .limit(1)
                )
            ) is not None
    return {
        "success": True,
        "deleted": deleted,
        "batches": batches,
        "batch_size": BATCH_SIZE,
        "cutoff_date": cutoff.isoformat(),
        "remaining_expired": remaining,
        "complete": not remaining,
    }
