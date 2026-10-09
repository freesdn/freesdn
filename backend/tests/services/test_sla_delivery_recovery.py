# SPDX-License-Identifier: AGPL-3.0-only
"""Recovery identifiers must never authorize replay of pre-restore mail."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.config import Settings, settings
from app.models.sla import SLAReport, SLAReportDelivery
from app.services.sla_report_delivery import ReportDeliveryError, process_one
from tests.services.test_sla_report_delivery import delivery_fixture as delivery_fixture


@pytest.mark.parametrize("epoch", ["not-a-uuid", "00000000-0000-0000-0000-000000000000"])
def test_bad_epoch_configuration_refuses_startup(epoch):
    with pytest.raises(ValidationError, match="SLA_REPORT_DELIVERY_EPOCH"):
        Settings.model_validate({**settings.model_dump(), "SLA_REPORT_DELIVERY_EPOCH": epoch})


def test_epoch_configuration_canonicalizes_uuid4_and_allows_opt_out():
    epoch = str(uuid4())
    configured = Settings.model_validate(
        {**settings.model_dump(), "SLA_REPORT_DELIVERY_EPOCH": epoch.upper()}
    )
    assert epoch == configured.SLA_REPORT_DELIVERY_EPOCH
    assert (
        Settings.model_validate(
            {**settings.model_dump(), "SLA_REPORT_DELIVERY_EPOCH": ""}
        ).SLA_REPORT_DELIVERY_EPOCH
        == ""
    )


@pytest.mark.parametrize("original_state", ["pending", "retry", "sending"])
@pytest.mark.parametrize("boundary", ["rotated", "unconfigured", "legacy"])
async def test_restored_active_notice_is_quarantined_without_smtp(
    db_session, delivery_fixture, monkeypatch, original_state, boundary
):
    factory, _gen, _schedule, _report, row, *_rest, send = delivery_fixture
    row.state = original_state
    row.attempts = 0 if original_state == "pending" else 2
    # Even future retries/unexpired leases must be quarantined, not scheduled.
    row.next_attempt_at = datetime.now(UTC) + timedelta(days=1)
    row.lease_expires_at = datetime.now(UTC) + timedelta(minutes=10)
    identity = (row.id, row.report_id, row.recipient_email, row.attempts)
    if boundary == "legacy":
        row.delivery_epoch = None
    else:
        monkeypatch.setattr(
            settings, "SLA_REPORT_DELIVERY_EPOCH", str(uuid4()) if boundary == "rotated" else ""
        )
    await db_session.commit()
    assert await process_one(factory)
    assert not await process_one(factory)
    await db_session.refresh(row)
    assert (row.id, row.report_id, row.recipient_email, row.attempts) == identity
    assert (row.state, row.error_code) == ("unknown", "delivery_recovery_review_required")
    assert row.lease_expires_at is None and row.accepted_at is None
    send.assert_not_awaited()


async def test_reapproval_cannot_reauthorize_old_notice(db_session, delivery_fixture, monkeypatch):
    factory, gen, schedule, _report, old, *_rest, principal, send = delivery_fixture
    original_epoch = old.delivery_epoch
    monkeypatch.setattr(settings, "SLA_REPORT_DELIVERY_EPOCH", str(uuid4()))
    # Reapprove first, before the recovery worker has seen the restored notice.
    await gen.update_schedule(
        schedule.id, {"enabled": True}, org_id=schedule.organization_id, current_user=principal
    )
    await db_session.commit()
    assert old.delivery_epoch == original_epoch
    assert await process_one(factory)
    await db_session.refresh(old)
    assert old.state == "unknown"
    send.assert_not_awaited()
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    assert len(await gen.generate_scheduled()) == 1
    await db_session.commit()
    assert await process_one(factory)
    assert send.await_count == 1
    await db_session.refresh(old)
    assert old.state == "unknown"
    rows = list(
        (
            await db_session.scalars(
                select(SLAReportDelivery).where(SLAReportDelivery.schedule_id == schedule.id)
            )
        ).all()
    )
    assert len(rows) == 2
    assert {row.state for row in rows} == {"unknown", "accepted"}


@pytest.mark.parametrize("boundary", ["rotated", "unconfigured", "legacy_approval"])
async def test_unreviewed_schedule_pauses_before_rendering(
    db_session, delivery_fixture, monkeypatch, boundary
):
    _factory, gen, schedule, *_rest = delivery_fixture
    if boundary == "legacy_approval":
        schedule.delivery_approval = {**schedule.delivery_approval, "version": 1}
    else:
        monkeypatch.setattr(
            settings, "SLA_REPORT_DELIVERY_EPOCH", str(uuid4()) if boundary == "rotated" else ""
        )
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    render = AsyncMock()
    monkeypatch.setattr(gen, "generate_report", render)
    assert await gen.generate_scheduled() == []
    render.assert_not_awaited()
    assert not schedule.enabled
    assert schedule.execution_error in {"delivery_epoch_required", "delivery_reapproval_required"}


async def test_missing_epoch_blocks_opt_in_but_allows_pause(
    db_session, delivery_fixture, monkeypatch
):
    _factory, gen, schedule, *_rest, principal, _send = delivery_fixture
    monkeypatch.setattr(settings, "SLA_REPORT_DELIVERY_EPOCH", "")
    with pytest.raises(ReportDeliveryError, match="delivery_epoch_required"):
        async with db_session.begin_nested():
            await gen.update_schedule(
                schedule.id,
                {"enabled": True},
                org_id=schedule.organization_id,
                current_user=principal,
            )
    await db_session.refresh(schedule)
    await gen.update_schedule(
        schedule.id, {"enabled": False}, org_id=schedule.organization_id, current_user=principal
    )
    assert not schedule.enabled and schedule.delivery_approval is None


@pytest.mark.parametrize("state", ["accepted", "failed", "cancelled", "skipped", "unknown"])
async def test_recovery_keeps_terminal_evidence(db_session, delivery_fixture, monkeypatch, state):
    factory, _gen, _schedule, _report, row, *_rest, send = delivery_fixture
    row.state, row.error_code, row.attempts = state, "prior_evidence", 1
    row.accepted_at = datetime.now(UTC) if state == "accepted" else None
    await db_session.commit()
    accepted_at = row.accepted_at
    monkeypatch.setattr(settings, "SLA_REPORT_DELIVERY_EPOCH", str(uuid4()))
    assert not await process_one(factory)
    await db_session.refresh(row)
    assert (row.state, row.error_code, row.attempts, row.accepted_at) == (
        state,
        "prior_evidence",
        1,
        accepted_at,
    )
    send.assert_not_awaited()


async def test_quarantine_is_bounded_and_does_not_starve_current_epoch(
    db_session, delivery_fixture
):
    factory, _gen, schedule, _report, valid, *_rest, send = delivery_fixture
    for _ in range(205):
        db_session.add(
            SLAReportDelivery(
                organization_id=schedule.organization_id,
                recipient_email="synthetic@example.test",
                approval_revision=str(uuid4()),
                delivery_epoch=None,
                state="pending",
            )
        )
    await db_session.commit()
    assert await process_one(factory)
    await db_session.refresh(valid)
    assert valid.state == "accepted" and send.await_count == 1
    count = await db_session.scalar(
        select(func.count())
        .select_from(SLAReportDelivery)
        .where(
            SLAReportDelivery.organization_id == schedule.organization_id,
            SLAReportDelivery.state == "unknown",
        )
    )
    assert count == 100
    assert await process_one(factory)
    assert await process_one(factory)
    assert not await process_one(factory)
    count = await db_session.scalar(
        select(func.count())
        .select_from(SLAReportDelivery)
        .where(
            SLAReportDelivery.organization_id == schedule.organization_id,
            SLAReportDelivery.state == "unknown",
        )
    )
    assert count == 205 and send.await_count == 1


async def test_generation_only_without_epoch_still_works(db_session, delivery_fixture, monkeypatch):
    _factory, gen, schedule, *_rest, principal, send = delivery_fixture
    monkeypatch.setattr(settings, "SLA_REPORT_DELIVERY_EPOCH", "")
    await gen.update_schedule(
        schedule.id,
        {"delivery_enabled": False},
        org_id=schedule.organization_id,
        current_user=principal,
    )
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    reports = await gen.generate_scheduled()
    assert len(reports) == 1
    assert await db_session.get(SLAReport, reports[0].id)
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(SLAReportDelivery)
            .where(SLAReportDelivery.report_id == reports[0].id)
        )
        == 0
    )
    send.assert_not_awaited()
