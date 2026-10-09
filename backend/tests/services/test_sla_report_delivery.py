# SPDX-License-Identifier: AGPL-3.0-only
"""Real database coverage of report outbox authorization and failure boundaries."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from app.core.dependencies import CurrentUser, _load_user_permissions
from app.core.site_access import current_user_var
from app.models.core import Organization, Site, User, UserSiteAccess
from app.models.notification import NotificationPreference, NotificationProviderRecord
from app.models.sla import SLAPolicy, SLAReportDelivery
from app.services.sla_report_delivery import (
    ReportDeliveryError,
    process_one,
    report_origin,
)
from app.services.sla_report_mail import MailOutcome
from app.services.sla_reports import SLAReportGenerator


@pytest.fixture
async def delivery_fixture(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "app.services.sla_report_delivery.settings.SLA_REPORT_DELIVERY_EPOCH", str(uuid4())
    )
    monkeypatch.setattr(
        "app.services.sla_report_delivery.settings.FRONTEND_URL", "https://console.example.test"
    )
    org = Organization(name="Report delivery", slug="delivery-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name="Private site", slug="delivery")
    actor, reader = [
        User(
            organization_id=org.id,
            email=uuid4().hex + "@example.test",
            username=uuid4().hex,
            hashed_password="not-a-login",
            role="site_admin",
            is_active=True,
        )
        for _ in range(2)
    ]
    provider = NotificationProviderRecord(
        organization_id=org.id,
        name="Synthetic SMTP",
        channel="email",
        provider_type="smtp",
        is_enabled=True,
        is_verified=True,
        rate_limit_per_hour=0,
        rate_limit_per_day=0,
        config={
            "host": "localhost",
            "port": 587,
            "use_tls": True,
            "from_email": "sender@example.test",
        },
    )
    db_session.add_all([site, actor, reader, provider])
    await db_session.flush()
    policy = SLAPolicy(organization_id=org.id, name="Site SLA", scope="site", scope_id=site.id)
    db_session.add_all(
        [
            policy,
            UserSiteAccess(user_id=actor.id, site_id=site.id),
            UserSiteAccess(user_id=reader.id, site_id=site.id),
        ]
    )
    await db_session.flush()
    principal = CurrentUser(
        actor, await _load_user_permissions(actor), accessible_site_ids={site.id}
    )
    gen = SLAReportGenerator(db_session)
    schedule = await gen.create_schedule(
        org.id,
        {
            "name": "Scheduled report",
            "sla_policy_ids": [policy.id],
            "recipients": [reader.email, reader.email.upper()],
            "delivery_enabled": True,
            "delivery_provider_id": provider.id,
            "next_run_at": datetime.now(UTC) - timedelta(minutes=1),
        },
        created_by=actor.id,
        current_user=principal,
    )
    reports = await gen.generate_scheduled()
    assert len(reports) == 1
    delivery = await db_session.scalar(
        select(SLAReportDelivery).where(SLAReportDelivery.report_id == reports[0].id)
    )
    assert delivery is not None
    # These cases exercise a due notice. The database default uses its clock,
    # which need not equal the application host clock to the millisecond.
    delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    @asynccontextmanager
    async def factory():
        yield db_session

    send = AsyncMock(return_value=MailOutcome("accepted"))
    monkeypatch.setattr("app.services.sla_report_delivery.send_notice", send)
    return (
        factory,
        gen,
        schedule,
        reports[0],
        delivery,
        actor,
        reader,
        site,
        policy,
        provider,
        principal,
        send,
    )


async def test_generation_enqueues_once_and_send_observes_committed_claim(
    db_session, delivery_fixture
):
    factory, gen, schedule, report, delivery, *_rest, send = delivery_fixture
    assert schedule.recipients == [delivery.recipient_email]
    assert await gen.generate_scheduled() == []

    async def inspect_claim(*args):
        await db_session.refresh(delivery)
        assert delivery.state == "sending" and delivery.attempts == 1
        assert args[1] == delivery.recipient_email
        assert args[2].endswith(f"/sla/reports?report={report.id}")
        assert args[3] == f"<sla-report-{delivery.id}@freesdn.invalid>"
        return MailOutcome("accepted")

    send.side_effect = inspect_claim
    assert await process_one(factory)
    assert not await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "accepted" and delivery.accepted_at is not None
    assert send.await_count == 1


@pytest.mark.parametrize(
    "change",
    [
        "actor_disabled",
        "actor_grant",
        "recipient_disabled",
        "recipient_deleted",
        "recipient_grant",
        "recipient_email",
        "recipient_role",
        "schedule_disabled",
        "delivery_disabled",
        "schedule_deleted",
        "provider_disabled",
        "provider_unverified",
        "provider_org",
        "provider_config",
        "provider_tls",
        "origin",
        "scope",
        "reapproval",
    ],
)
async def test_reauthorization_cancels_without_sending(
    db_session, delivery_fixture, change, monkeypatch
):
    (
        factory,
        gen,
        schedule,
        report,
        delivery,
        actor,
        reader,
        site,
        policy,
        provider,
        principal,
        send,
    ) = delivery_fixture
    if change == "actor_disabled":
        actor.is_active = False
    elif change == "actor_grant":
        await db_session.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id == actor.id))
    elif change == "recipient_disabled":
        reader.is_active = False
    elif change == "recipient_deleted":
        reader.deleted_at = datetime.now(UTC)
    elif change == "recipient_grant":
        await db_session.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id == reader.id))
    elif change == "recipient_email":
        reader.email = "changed@example.test"
    elif change == "recipient_role":
        reader.role = "guest"
    elif change == "schedule_disabled":
        schedule.enabled = False
    elif change == "delivery_disabled":
        schedule.delivery_enabled = False
    elif change == "schedule_deleted":
        await db_session.delete(schedule)
    elif change == "provider_disabled":
        provider.is_enabled = False
    elif change == "provider_unverified":
        provider.is_verified = False
    elif change == "provider_org":
        provider.organization_id = None
    elif change == "provider_config":
        provider.config = {**provider.config, "host": "changed.example.test"}
    elif change == "provider_tls":
        provider.config = {**provider.config, "use_tls": False}
    elif change == "origin":
        monkeypatch.setattr(
            "app.services.sla_report_delivery.settings.FRONTEND_URL", "https://changed.example.test"
        )
    elif change == "scope":
        report.report_data = {
            **report.report_data,
            "access_scope": {"version": 1, "site_ids": [str(uuid4())]},
        }
    elif change == "reapproval":
        await gen.update_schedule(
            schedule.id, {"name": "Reviewed"}, schedule.organization_id, current_user=principal
        )
    await db_session.commit()
    assert await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "cancelled"
    assert delivery.error_code and delivery.attempts == 0
    send.assert_not_awaited()


async def test_retry_checks_new_revocation(db_session, delivery_fixture):
    factory, _, _, _, delivery, _, reader, *_rest, send = delivery_fixture
    send.return_value = MailOutcome("retry", "smtp_refused")
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "retry" and delivery.attempts == 1
    assert delivery.next_attempt_at > datetime.now(UTC) + timedelta(minutes=14)
    delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    reader.is_active = False
    await db_session.commit()
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "cancelled" and send.await_count == 1


@pytest.mark.parametrize("state", ["unknown", "failed", "accepted"])
async def test_terminal_outcomes_never_retry(db_session, delivery_fixture, state):
    factory, _, _, _, delivery, *_rest, send = delivery_fixture
    send.return_value = MailOutcome(state, None if state == "accepted" else "smtp_test")
    await process_one(factory)
    assert not await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == state and send.await_count == 1


async def test_expired_claim_becomes_unknown_without_sending(db_session, delivery_fixture):
    factory, _, _, _, delivery, *_rest, send = delivery_fixture
    delivery.state, delivery.attempts = "sending", 1
    delivery.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    assert not await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "unknown" and delivery.error_code == "worker_interrupted"
    send.assert_not_awaited()


async def test_bounded_retry_exhaustion(db_session, delivery_fixture):
    factory, _, _, _, delivery, *_rest, send = delivery_fixture
    delivery.attempts = 4
    send.return_value = MailOutcome("retry", "smtp_refused")
    await db_session.commit()
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "failed" and delivery.attempts == 5
    assert delivery.error_code == "retry_exhausted"


@pytest.mark.parametrize(
    "preference,expected", [("empty", "skipped"), ("muted", "skipped"), ("quiet", "retry")]
)
async def test_preferences_do_not_send_or_consume_attempt(
    db_session, delivery_fixture, preference, expected
):
    factory, _, _, _, delivery, _, reader, *_rest, send = delivery_fixture
    hour = datetime.now(UTC).hour
    record = NotificationPreference(
        user_id=reader.id,
        enabled_channels=[] if preference == "empty" else ["email"],
        category_settings={"reports": {"muted_until": None}} if preference == "muted" else {},
        quiet_hours={"start": hour, "end": (hour + 1) % 24} if preference == "quiet" else None,
    )
    db_session.add(record)
    await db_session.commit()
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == expected and delivery.attempts == 0
    send.assert_not_awaited()


async def test_rate_limit_outage_defers_mail(db_session, delivery_fixture, monkeypatch):
    factory, _, _, _, delivery, *_rest, provider, principal, send = delivery_fixture
    provider.rate_limit_per_hour = 2
    await db_session.commit()

    def unavailable(**kwargs):
        raise ConnectionError("synthetic-secret-must-not-be-stored")

    monkeypatch.setattr("app.core.redis_client.get_async_redis", unavailable)
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "retry" and delivery.attempts == 0
    assert delivery.error_code == "provider_rate_limit_or_unavailable"
    send.assert_not_awaited()


async def test_existing_recipient_metadata_does_not_opt_in(db_session, delivery_fixture):
    _, gen, schedule, _, _, actor, reader, _, policy, *_ = delivery_fixture
    legacy = await gen.create_schedule(
        schedule.organization_id,
        {"name": "Legacy", "recipients": [reader.email], "sla_policy_ids": [policy.id]},
        created_by=actor.id,
    )
    assert not legacy.delivery_enabled and legacy.delivery_approval is None


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "http://console.example.test",
        "https://user:secret@console.example.test",
        "https://console.example.test/path",
        "https://console.example.test?redirect=x",
        "https://console.example.test/#fragment",
        "https://console.example.test:bad",
        "https://console.example.test\n",
    ],
)
def test_origin_validation_rejects_insecure_or_ambiguous_links(monkeypatch, origin):
    monkeypatch.setattr("app.services.sla_report_delivery.settings.FRONTEND_URL", origin)
    with pytest.raises(ReportDeliveryError, match="https_frontend_origin_required"):
        report_origin()


async def test_status_and_cancel_respect_archive_grants(db_session, delivery_fixture):
    from fastapi import HTTPException

    from app.api.v1.endpoints.sla_reports import cancel_report_delivery, list_report_deliveries

    _, _, _, report, delivery, actor, *_rest, principal, send = delivery_fixture
    token = current_user_var.set(principal)
    try:
        assert (await list_report_deliveries(report.id, db_session, principal))[0].id == delivery.id
        assert (
            await cancel_report_delivery(report.id, delivery.id, db_session, principal)
        ).state == "cancelled"
        with pytest.raises(HTTPException) as exc:
            await cancel_report_delivery(report.id, delivery.id, db_session, principal)
        assert exc.value.status_code == 409
        outsider = CurrentUser(actor, ["config:write"], accessible_site_ids={uuid4()})
        current_user_var.set(outsider)
        with pytest.raises(HTTPException) as exc:
            await list_report_deliveries(report.id, db_session, outsider)
        assert exc.value.status_code == 404
    finally:
        current_user_var.reset(token)


async def test_missing_archive_never_announces_a_ready_report(db_session, delivery_fixture):
    from pathlib import Path

    factory, _, _, report, delivery, *_rest, send = delivery_fixture
    Path(report.file_path).unlink()
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "cancelled" and delivery.error_code == "report_file_unavailable"
    send.assert_not_awaited()


async def test_corrupt_approval_cannot_poison_other_deliveries(db_session, delivery_fixture):
    factory, _, schedule, _, delivery, *_rest, send = delivery_fixture
    schedule.delivery_approval = {**schedule.delivery_approval, "recipients": ["invalid"]}
    await db_session.commit()
    assert await process_one(factory)
    assert not await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "failed" and delivery.error_code == "delivery_configuration_invalid"
    send.assert_not_awaited()


async def test_pause_is_possible_after_provider_is_broken(db_session, delivery_fixture):
    factory, gen, schedule, _, delivery, *_rest, provider, principal, send = delivery_fixture
    provider.is_verified = False
    await gen.update_schedule(
        schedule.id, {"enabled": False}, schedule.organization_id, current_user=principal
    )
    await db_session.commit()
    assert not schedule.enabled
    await process_one(factory)
    await db_session.refresh(delivery)
    assert delivery.state == "cancelled"
    send.assert_not_awaited()
