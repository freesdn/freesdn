# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded retention for the webhook delivery log and dead-letter queue.

Owner decision 2026-11-13: events are kept 30 days (``EVENT_RETENTION_DAYS``),
and a webhook delivery record is a record of an event. Two tables:

* ``core.webhook_dead_letters``: an entry older than the cutoff is deleted,
  replayed or not. It is an event older than the retention window.
* ``core.webhook_deliveries``: a row older than the cutoff is deleted unless a
  dead letter still points at it. Dead letters reference deliveries with
  ``ON DELETE CASCADE``, so deleting the delivery would silently delete a dead
  letter that is still inside the window (a delivery made on day 0 whose last
  retry failed on day 1 and is waiting for the operator). That is why the
  unused ``PersistentWebhookService.cleanup_old_deliveries``, a plain
  ``DELETE ... WHERE created_at < cutoff``, was not simply wired up.

Same shape as ``app.services.event_retention``: at most 1,000 rows per
committed batch, a statement and lock timeout per batch, rows another
transaction holds are skipped and reported, never waited on.
"""

from __future__ import annotations

from time import monotonic
from typing import Any

from sqlalchemy import Result, delete, exists, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.webhooks import WebhookDeadLetter, WebhookDelivery
from app.services.event_retention import retention_cutoff

BATCH_SIZE = 1000
MAX_BATCHES = 100
RUN_BUDGET_SECONDS = 200


async def _prune(
    session: AsyncSession,
    model: Any,
    conditions: list[Any],
    deadline: float,
) -> tuple[int, int]:
    deleted = batches = 0
    while batches < MAX_BATCHES and monotonic() < deadline:
        async with session.begin():
            await session.execute(text("SET LOCAL statement_timeout = '10s'"))
            await session.execute(text("SET LOCAL lock_timeout = '1s'"))
            # A materialized CTE, as in event_retention: a plain subquery on the
            # DELETE's own table would be correlated to the row being deleted.
            victims = (
                select(model.id)
                .where(*conditions)
                .order_by(model.created_at, model.id)
                .limit(BATCH_SIZE)
                .with_for_update(skip_locked=True)
                .cte(f"expired_{model.__tablename__}_batch")
                .prefix_with("MATERIALIZED")
            )
            result: Result[Any] = await session.execute(
                delete(model)
                .where(model.id.in_(select(victims.c.id)))
                .returning(model.id)
                .execution_options(synchronize_session=False)
            )
            count = len(result.scalars().all())
        deleted += count
        batches += 1
        if count < BATCH_SIZE:
            break
    return deleted, batches


async def prune_webhook_records(
    factory: async_sessionmaker[AsyncSession], days: int
) -> dict[str, Any]:
    """Delete dead letters, then deliveries, older than ``days`` days."""
    cutoff = retention_cutoff(days)
    deadline = monotonic() + RUN_BUDGET_SECONDS
    old_dead_letter = [WebhookDeadLetter.created_at < cutoff]
    old_delivery = [
        WebhookDelivery.created_at < cutoff,
        ~exists().where(WebhookDeadLetter.delivery_id == WebhookDelivery.id),
    ]
    async with factory() as session:
        dead, dead_batches = await _prune(session, WebhookDeadLetter, old_dead_letter, deadline)
        sent, sent_batches = await _prune(session, WebhookDelivery, old_delivery, deadline)
        async with session.begin():
            await session.execute(text("SET LOCAL statement_timeout = '10s'"))
            remaining = (
                await session.scalar(select(WebhookDeadLetter.id).where(*old_dead_letter).limit(1))
                is not None
                or await session.scalar(select(WebhookDelivery.id).where(*old_delivery).limit(1))
                is not None
            )
    return {
        "success": True,
        "deleted_dead_letters": dead,
        "deleted_deliveries": sent,
        "batches": dead_batches + sent_batches,
        "cutoff_date": cutoff.isoformat(),
        "remaining_expired": remaining,
        "complete": not remaining,
    }
