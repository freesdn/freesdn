# SPDX-License-Identifier: AGPL-3.0-only
"""Independent PostgreSQL sessions prove committed claims and lost-result safety."""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.dependencies import CurrentUser
from app.db.session import create_test_engine
from app.models.core import Organization, User
from app.models.notification import NotificationProviderRecord
from app.models.sla import SLAReportDelivery
from app.services.sla_report_delivery import enqueue_notices, process_one
from app.services.sla_report_mail import MailOutcome
from app.services.sla_reports import SLAReportGenerator


@pytest.fixture
async def committed_delivery(monkeypatch, tmp_path):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "app.services.sla_report_delivery.settings.SLA_REPORT_DELIVERY_EPOCH", str(uuid4())
    )
    monkeypatch.setattr(
        "app.services.sla_report_delivery.settings.FRONTEND_URL", "https://console.example.test"
    )
    engine = create_test_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    org_id, provider_id = uuid4(), uuid4()
    try:
        async with factory() as db:
            db.add(Organization(id=org_id, name="SMTP concurrency", slug=uuid4().hex))
            await db.flush()
            actor = User(
                organization_id=org_id,
                username=uuid4().hex,
                email=uuid4().hex + "@example.test",
                hashed_password="not-a-login",
                role="org_admin",
                is_active=True,
            )
            db.add_all(
                [
                    actor,
                    NotificationProviderRecord(
                        id=provider_id,
                        organization_id=org_id,
                        name="Test relay",
                        channel="email",
                        provider_type="smtp",
                        is_enabled=True,
                        is_verified=True,
                        rate_limit_per_hour=0,
                        rate_limit_per_day=0,
                        config={"use_tls": True, "from_email": "sender@example.test"},
                    ),
                ]
            )
            await db.flush()
            schedule = await SLAReportGenerator(db).create_schedule(
                org_id,
                {
                    "name": "Report",
                    "recipients": [actor.email],
                    "delivery_enabled": True,
                    "delivery_provider_id": provider_id,
                },
                current_user=CurrentUser(actor, ["*"]),
            )
            report = await SLAReportGenerator(db).generate_report(
                org_id,
                datetime.now(UTC) - timedelta(days=1),
                datetime.now(UTC),
                report_format="csv",
            )
            await enqueue_notices(db, schedule, report)
            delivery = await db.scalar(
                select(SLAReportDelivery).where(SLAReportDelivery.report_id == report.id)
            )
            assert delivery is not None
            # Claim a due notice even when the database host clock is ahead.
            delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            identifier = delivery.id
            await db.commit()
        yield factory, identifier
    finally:
        async with factory() as db:
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.execute(
                delete(NotificationProviderRecord).where(
                    NotificationProviderRecord.id == provider_id
                )
            )
            await db.commit()
        await engine.dispose()


async def test_competing_workers_observe_durable_claim(committed_delivery, monkeypatch):
    factory, identifier = committed_delivery
    sending, finish = asyncio.Event(), asyncio.Event()

    async def sender(*args):
        sending.set()
        await finish.wait()
        return MailOutcome("accepted")

    mock = AsyncMock(side_effect=sender)
    monkeypatch.setattr("app.services.sla_report_delivery.send_notice", mock)
    task = asyncio.create_task(process_one(factory))
    try:
        await asyncio.wait_for(sending.wait(), 10)
        async with factory() as db:
            row = await db.get(SLAReportDelivery, identifier)
            assert row.state == "sending" and row.attempts == 1
        assert not await process_one(factory)
        finish.set()
        assert await task
        assert not await process_one(factory)
        assert mock.await_count == 1
    finally:
        finish.set()
        await task


async def test_accepted_mail_with_failed_result_commit_is_not_resent(
    committed_delivery, monkeypatch
):
    factory, identifier = committed_delivery
    calls = 0

    @asynccontextmanager
    async def failing_factory():
        nonlocal calls
        calls += 1
        async with factory() as db:
            if calls == 2:
                monkeypatch.setattr(
                    db, "commit", AsyncMock(side_effect=RuntimeError("synthetic DB outage"))
                )
            yield db

    mock = AsyncMock(return_value=MailOutcome("accepted"))
    monkeypatch.setattr("app.services.sla_report_delivery.send_notice", mock)
    with pytest.raises(RuntimeError, match="synthetic DB outage"):
        await process_one(failing_factory)
    async with factory() as db:
        row = await db.get(SLAReportDelivery, identifier)
        assert row.state == "sending"
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    assert not await process_one(factory)
    async with factory() as db:
        row = await db.get(SLAReportDelivery, identifier)
        assert row.state == "unknown" and row.error_code == "worker_interrupted"
    assert mock.await_count == 1


@pytest.mark.parametrize("original_state", ["pending", "sending"])
async def test_recovery_skips_a_locked_notice(committed_delivery, monkeypatch, original_state):
    factory, identifier = committed_delivery
    async with factory() as db:
        row = await db.get(SLAReportDelivery, identifier)
        row.delivery_epoch = None
        row.state = original_state
        if original_state == "sending":
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    mock = AsyncMock(return_value=MailOutcome("accepted"))
    monkeypatch.setattr("app.services.sla_report_delivery.send_notice", mock)
    async with factory() as owner:
        await owner.scalar(
            select(SLAReportDelivery).where(SLAReportDelivery.id == identifier).with_for_update()
        )
        assert not await asyncio.wait_for(process_one(factory), timeout=3)
        await owner.rollback()
    assert await process_one(factory)
    async with factory() as db:
        row = await db.get(SLAReportDelivery, identifier)
        assert row.state == "unknown" and row.error_code == "delivery_recovery_review_required"
    mock.assert_not_awaited()
