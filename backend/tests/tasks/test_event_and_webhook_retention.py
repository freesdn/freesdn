# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Events and webhook delivery records are kept ``EVENT_RETENTION_DAYS`` (30) days.

Before: ``cleanup_old_events`` defaulted to 90 days and the daily beat entry
passes no argument, so event history was kept 90 days; and nothing deleted
webhook delivery or dead-letter rows at all
(``PersistentWebhookService.cleanup_old_deliveries`` had no caller), so
``core.webhook_deliveries`` grew by a row per event per webhook forever.

The webhook test runs on real PostgreSQL. Dead letters reference deliveries
with ``ON DELETE CASCADE``, so it also pins that pruning an old delivery never
takes a dead letter that is still inside the window with it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import settings
from app.db.session import CelerySessionLocal
from app.models.core import Organization
from app.models.webhooks import DeliveryStatus, Webhook, WebhookDeadLetter, WebhookDelivery
from app.services.webhook_retention import prune_webhook_records


def test_the_retention_setting_defaults_to_thirty_days() -> None:
    assert settings.EVENT_RETENTION_DAYS == 30


def test_event_history_is_pruned_at_the_setting_not_at_ninety_days(monkeypatch) -> None:
    from app.tasks import maintenance

    seen: list[int] = []

    async def _prune(_factory, days):
        seen.append(days)
        return {"remaining_expired": False, "deleted": 0, "batches": 0}

    monkeypatch.setattr("app.services.event_retention.prune_event_history", _prune)
    monkeypatch.setattr(maintenance, "_get_logdb", lambda: object())
    monkeypatch.setattr(settings, "EVENT_RETENTION_DAYS", 30)

    maintenance.cleanup_old_events.run()  # what the beat entry sends: no arguments
    monkeypatch.setattr(settings, "EVENT_RETENTION_DAYS", 45)
    maintenance.cleanup_old_events.run()

    assert seen == [30, 45]


def test_webhook_records_are_pruned_daily_with_the_same_setting(monkeypatch) -> None:
    from app.tasks import maintenance

    entries = [
        e
        for e in celery_app.conf.beat_schedule.values()
        if e["task"] == "app.tasks.maintenance.cleanup_webhook_deliveries"
    ]
    assert len(entries) == 1 and entries[0]["options"]["queue"] == "default"

    seen: list[int] = []

    async def _prune(_factory, days):
        seen.append(days)
        return {"remaining_expired": False, "deleted_deliveries": 0, "deleted_dead_letters": 0}

    monkeypatch.setattr("app.services.webhook_retention.prune_webhook_records", _prune)
    monkeypatch.setattr(settings, "EVENT_RETENTION_DAYS", 30)
    maintenance.cleanup_webhook_deliveries.run()
    assert seen == [30]


@pytest.mark.parametrize("days", [0, -1, True, "30"])
def test_an_invalid_retention_is_refused_before_any_delete(monkeypatch, days) -> None:
    from app.tasks import maintenance

    monkeypatch.setattr(settings, "EVENT_RETENTION_DAYS", days)
    with pytest.raises(ValueError, match="retention days"):
        maintenance.cleanup_webhook_deliveries.run()


@pytest_asyncio.fixture
async def webhook():
    org_id = uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org_id, name="Retention fixture", slug="ret-" + org_id.hex))
        await db.flush()
        wh = Webhook(name="n8n", url="https://198.51.100.7/hook", organization_id=org_id)
        db.add(wh)
        await db.commit()
        webhook_id = wh.id
    try:
        yield webhook_id
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(Webhook).where(Webhook.id == webhook_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()
        from app.db.session import engine

        await engine.dispose()


async def test_webhook_records_older_than_the_window_are_deleted(webhook) -> None:
    now = datetime.now(UTC)
    old, recent = now - timedelta(days=40), now - timedelta(days=2)

    def delivery(created_at):
        return WebhookDelivery(
            webhook_id=webhook,
            event_id=str(uuid4()),
            event_type="device.status.changed",
            status=DeliveryStatus.FAILED,
            created_at=created_at,
            updated_at=created_at,
        )

    async with CelerySessionLocal() as db:
        rows = {
            "old": delivery(old),
            "old_with_recent_dead_letter": delivery(old),
            "old_with_old_dead_letter": delivery(old),
            "recent": delivery(recent),
        }
        db.add_all(rows.values())
        await db.flush()
        letters = {
            "recent": WebhookDeadLetter(
                webhook_id=webhook,
                delivery_id=rows["old_with_recent_dead_letter"].id,
                event_type="device.status.changed",
                attempt_count=4,
                final_attempt_at=recent,
                created_at=recent,
            ),
            "old": WebhookDeadLetter(
                webhook_id=webhook,
                delivery_id=rows["old_with_old_dead_letter"].id,
                event_type="device.status.changed",
                attempt_count=4,
                final_attempt_at=old,
                created_at=old,
            ),
        }
        db.add_all(letters.values())
        await db.commit()
        ids = {k: v.id for k, v in rows.items()}
        letter_ids = {k: v.id for k, v in letters.items()}

    result = await prune_webhook_records(CelerySessionLocal, 30)

    async with CelerySessionLocal() as db:
        left = set(
            (
                await db.execute(
                    select(WebhookDelivery.id).where(WebhookDelivery.webhook_id == webhook)
                )
            )
            .scalars()
            .all()
        )
        letters_left = set(
            (
                await db.execute(
                    select(WebhookDeadLetter.id).where(WebhookDeadLetter.webhook_id == webhook)
                )
            )
            .scalars()
            .all()
        )

    assert left == {ids["old_with_recent_dead_letter"], ids["recent"]}
    assert letters_left == {letter_ids["recent"]}
    assert result["complete"] is True
    assert result["deleted_deliveries"] >= 2 and result["deleted_dead_letters"] >= 1
