# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise schedule authorization and DB failures against real PostgreSQL."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.core.dependencies import CurrentUser, _load_user_permissions
from app.core.site_access import current_user_var
from app.models.core import Organization, Site, User, UserSiteAccess
from app.models.sla import SLAPolicy, SLAReport
from app.services.sla_reports import SLAReportGenerator


@pytest.fixture
async def schedule_fixture(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    org = Organization(name="Schedule execution", slug="schedule-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    user = User(
        organization_id=org.id,
        email=uuid4().hex + "@example.test",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role="site_admin",
        is_active=True,
    )
    sites = [Site(organization_id=org.id, name=f"Site {i}", slug=str(i)) for i in range(2)]
    db_session.add_all([user, *sites])
    await db_session.flush()
    grant = UserSiteAccess(user_id=user.id, site_id=sites[0].id)
    policies = [
        SLAPolicy(organization_id=org.id, scope="site", scope_id=s.id, name=s.name) for s in sites
    ]
    db_session.add_all([grant, *policies])
    await db_session.flush()
    principal = CurrentUser(
        user, await _load_user_permissions(user), accessible_site_ids={sites[0].id}
    )
    assert principal.has_permission("config:write")
    gen = SLAReportGenerator(db_session)
    schedule = await gen.create_schedule(
        org.id,
        {
            "name": "Customer report",
            "sla_policy_ids": [policies[0].id],
            "next_run_at": datetime.now(UTC) - timedelta(days=1),
        },
        created_by=user.id,
        current_user=principal,
    )
    return gen, schedule, user, sites, policies, principal, tmp_path


async def test_live_actor_is_recorded_and_request_context_restored(db_session, schedule_fixture):
    gen, schedule, user, _, policies, _, tmp_path = schedule_fixture
    sentinel = object()
    token = current_user_var.set(sentinel)
    try:
        reports = await gen.generate_scheduled()
        assert current_user_var.get() is sentinel
    finally:
        current_user_var.reset(token)
    assert len(reports) == 1
    assert reports[0].generated_by == user.id
    assert [p["id"] for p in reports[0].report_data["policies"]] == [str(policies[0].id)]
    assert Path(reports[0].file_path).read_bytes().startswith(b"%PDF-")
    assert schedule.next_run_at > datetime.now(UTC)
    assert await gen.generate_scheduled() == []
    assert len(list(tmp_path.rglob("*.pdf"))) == 1


@pytest.mark.parametrize(
    "change",
    [
        "disabled",
        "soft_deleted",
        "deleted",
        "demoted",
        "organization",
        "last_grant_revoked",
        "policy_moved",
        "policy_became_org_wide",
        "policy_deleted",
        "legacy",
        "credential_ceiling",
        "promoted_scope_moved",
        "corrupt_filter",
    ],
)
async def test_changed_authority_pauses_without_rendering(
    db_session, schedule_fixture, monkeypatch, change
):
    gen, schedule, user, sites, policies, _, _ = schedule_fixture
    due = schedule.next_run_at
    if change == "disabled":
        user.is_active = False
    elif change == "soft_deleted":
        user.deleted_at = datetime.now(UTC)
    elif change == "deleted":
        await db_session.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id == user.id))
        await db_session.execute(delete(User).where(User.id == user.id))
    elif change == "demoted":
        user.role = "viewer"
    elif change == "organization":
        user.organization_id = None
    elif change == "last_grant_revoked":
        await db_session.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id == user.id))
    elif change in {"policy_moved", "promoted_scope_moved"}:
        policies[0].scope_id = sites[1].id
        if change == "promoted_scope_moved":
            user.role = "org_admin"
    elif change == "policy_became_org_wide":
        policies[0].scope = "organization"
        policies[0].scope_id = schedule.organization_id
    elif change == "policy_deleted":
        await db_session.delete(policies[0])
    elif change == "legacy":
        schedule.execution_scope = None
    elif change == "credential_ceiling":
        user.role = "super_admin"
        schedule.execution_scope = {**schedule.execution_scope, "permissions": ["config:read"]}
    else:
        schedule.sla_policy_ids = ["not-a-uuid"]
    await db_session.flush()
    render = AsyncMock()
    monkeypatch.setattr(gen, "generate_report", render)
    assert await gen.generate_scheduled() == []
    render.assert_not_awaited()
    assert not schedule.enabled
    assert schedule.execution_error
    assert schedule.next_run_at == due
    assert schedule.last_generated_at is None


async def test_one_database_error_does_not_poison_other_schedules(
    db_session, schedule_fixture, monkeypatch
):
    gen, bad, user, _, policies, principal, _ = schedule_fixture
    good = await gen.create_schedule(
        bad.organization_id,
        {
            "name": "Healthy schedule",
            "sla_policy_ids": [policies[0].id],
            "next_run_at": bad.next_run_at + timedelta(seconds=1),
        },
        created_by=user.id,
        current_user=principal,
    )
    original = gen.generate_report

    async def injected(**kwargs):
        if kwargs["title"].startswith("Customer report"):
            await db_session.execute(text("SELECT 1 / 0"))
        return await original(**kwargs)

    monkeypatch.setattr(gen, "generate_report", injected)
    reports = await gen.generate_scheduled()
    assert len(reports) == 1
    assert reports[0].title.startswith("Healthy schedule")
    assert bad.enabled and bad.execution_error == "generation_failed"
    assert bad.last_generated_at is None
    assert good.last_generated_at is not None
    assert await db_session.scalar(select(SLAReport.id).where(SLAReport.id == reports[0].id))


async def test_reapproval_records_the_new_responsible_operator(db_session, schedule_fixture):
    gen, schedule, user, _, _, _, _ = schedule_fixture
    schedule.execution_scope = None
    await db_session.flush()
    assert await gen.generate_scheduled() == []
    admin = User(
        organization_id=schedule.organization_id,
        email=uuid4().hex + "@example.test",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role="org_admin",
        is_active=True,
    )
    db_session.add(admin)
    await db_session.flush()
    principal = CurrentUser(admin, await _load_user_permissions(admin))
    await gen.update_schedule(
        schedule.id, {"enabled": True}, schedule.organization_id, current_user=principal
    )
    assert schedule.execution_scope["actor_id"] == str(admin.id)
    assert schedule.created_by == user.id
    assert schedule.updated_by == admin.id
    assert schedule.execution_error is None
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.flush()
    assert (await gen.generate_scheduled())[0].generated_by == admin.id


async def test_concurrent_workers_cannot_generate_the_same_due_schedule(tmp_path, monkeypatch):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.db.session import create_test_engine
    from app.models.sla import SLAReportSchedule

    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    engine = create_test_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    org_id = uuid4()
    try:
        async with factory() as seed:
            org = Organization(
                id=org_id, name="Concurrent reports", slug="concurrent-" + uuid4().hex
            )
            user = User(
                organization_id=org_id,
                email=uuid4().hex + "@example.test",
                username=uuid4().hex,
                hashed_password="not-a-login",
                role="org_admin",
                is_active=True,
            )
            seed.add(org)
            await seed.flush()
            seed.add(user)
            await seed.flush()
            principal = CurrentUser(user, await _load_user_permissions(user))
            await SLAReportGenerator(seed).create_schedule(
                org_id,
                {"name": "Concurrent", "next_run_at": datetime.now(UTC) - timedelta(days=1)},
                created_by=user.id,
                current_user=principal,
            )
            await seed.commit()
        # These sessions acquire independent pooled connections. Sharing the
        # db_session fixture's connection would not exercise PostgreSQL row locks.
        async with factory() as first, factory() as second:
            first_pid = await first.scalar(text("SELECT pg_backend_pid()"))
            second_pid = await second.scalar(text("SELECT pg_backend_pid()"))
            assert first_pid != second_pid
            await second.execute(text("SET LOCAL statement_timeout = '2s'"))
            assert len(await SLAReportGenerator(first).generate_scheduled()) == 1
            assert await SLAReportGenerator(second).generate_scheduled() == []
            assert (
                await second.execute(select(SLAReport).where(SLAReport.organization_id == org_id))
            ).scalars().all() == []
            await first.commit()
            await second.commit()
        async with factory() as restarted:
            assert await SLAReportGenerator(restarted).generate_scheduled() == []
            rows = (
                (
                    await restarted.execute(
                        select(SLAReport).where(SLAReport.organization_id == org_id)
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1
        assert len(list(tmp_path.rglob("*.pdf"))) == 1
    finally:
        async with factory() as cleanup:
            for model in [SLAReport, SLAReportSchedule, SLAPolicy, User]:
                await cleanup.execute(delete(model).where(model.organization_id == org_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup.commit()
        await engine.dispose()


async def test_unrestricted_approver_still_cannot_reference_missing_policies(
    db_session, schedule_fixture
):
    from fastapi import HTTPException

    from app.api.v1.endpoints.sla_reports import _assert_schedule_policies_accessible

    _, schedule, user, _, _, principal, _ = schedule_fixture
    user.role = "org_admin"
    with pytest.raises(HTTPException) as exc:
        await _assert_schedule_policies_accessible(
            db_session, principal, schedule.organization_id, [uuid4()]
        )
    assert exc.value.status_code == 404


async def test_invalid_timing_pauses_without_generating(schedule_fixture):
    gen, schedule, _, _, _, _, tmp_path = schedule_fixture
    schedule.timezone = "No/Such_Zone"
    due = schedule.next_run_at
    assert await gen.generate_scheduled() == []
    assert schedule.enabled is False
    assert schedule.execution_error == "invalid_schedule_timing"
    assert schedule.next_run_at == due
    assert not list(tmp_path.rglob("*.pdf"))


async def test_timing_edit_is_persisted_and_changes_next_run(schedule_fixture):
    from app.services.sla_calendar import ReportCalendar

    gen, schedule, _, _, _, principal, _ = schedule_fixture
    updated = await gen.update_schedule(
        schedule.id,
        {
            "frequency": "weekly",
            "day_of_week": 4,
            "timezone": "Asia/Kathmandu",
            "time_of_day": "08:15",
        },
        org_id=schedule.organization_id,
        current_user=principal,
    )
    await gen.db.refresh(updated)
    assert updated.timezone == "Asia/Kathmandu"
    assert updated.time_of_day == "08:15"
    local = updated.next_run_at.astimezone(ReportCalendar.from_schedule(updated).timezone)
    assert (local.weekday(), local.hour, local.minute) == (4, 8, 15)
    assert updated.next_run_at > datetime.now(UTC)


async def test_late_worker_uses_complete_period_and_does_not_repeat(schedule_fixture):
    from app.services.sla_calendar import ReportCalendar

    gen, schedule, _, _, _, _, _ = schedule_fixture
    schedule.timezone = "America/New_York"
    schedule.frequency = "monthly"
    schedule.day_of_month = 1
    schedule.next_run_at = datetime.now(UTC) - timedelta(days=95)
    expected = ReportCalendar.from_schedule(schedule).report_period(datetime.now(UTC))
    reports = await gen.generate_scheduled()
    assert len(reports) == 1
    assert (reports[0].period_start, reports[0].period_end) == expected
    assert await gen.generate_scheduled() == []


async def test_reenable_preserves_explicit_first_run(schedule_fixture):
    gen, schedule, _, _, _, principal, _ = schedule_fixture
    explicit = datetime.now(UTC) + timedelta(hours=2)
    updated = await gen.update_schedule(
        schedule.id,
        {"enabled": True, "next_run_at": explicit},
        org_id=schedule.organization_id,
        current_user=principal,
    )
    assert updated.next_run_at == explicit
