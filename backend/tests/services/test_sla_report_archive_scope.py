# SPDX-License-Identifier: AGPL-3.0-only
"""Stored report aggregates and background filters must not widen site access."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.site_access import current_user_var
from app.models.core import Organization, Site
from app.models.sla import SLAPolicy, SLAReport, SLAReportSchedule
from app.services.sla_reports import SLAReportGenerator


@pytest.fixture
async def scoped_reports(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    org = Organization(name="Archive scope", slug="archive-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    sites = [uuid4(), uuid4()]
    policies = [
        SLAPolicy(organization_id=org.id, name=f"Site {i}", scope="site", scope_id=site)
        for i, site in enumerate(sites)
    ]
    db_session.add_all(policies)
    await db_session.flush()
    user = SimpleNamespace(organization_id=org.id, is_site_limited=True, accessible_site_ids={sites[0]})
    return SLAReportGenerator(db_session), org, sites, policies, user


async def test_archive_list_count_and_download_share_original_scope(db_session, scoped_reports):
    gen, org, sites, policies, user = scoped_reports
    start = datetime(2026, 9, 1, tzinfo=UTC)
    end = start + timedelta(days=1)
    own = await gen.generate_report(org.id, start, end, policy_ids=[policies[0].id], report_format="csv")
    mixed = await gen.generate_report(org.id, start, end, report_format="csv")
    legacy = SLAReport(
        organization_id=org.id, title="Legacy", period_start=start, period_end=end,
        format="csv", report_data={"policies": []},
    )
    db_session.add(legacy)
    # Moving the policy now cannot erase the historical aggregate's other site.
    policies[1].scope_id = sites[0]
    await db_session.flush()
    token = current_user_var.set(user)
    try:
        reports, count = await gen.list_reports(org.id)
        assert count == 1
        assert [report.id for report in reports] == [own.id]
        assert await gen.get_report(own.id) is own
        assert await gen.get_report(mixed.id) is None
        assert await gen.get_report(legacy.id) is None
        user.accessible_site_ids = {sites[1]}
        assert await gen.get_report(own.id) is None
        assert await gen.list_reports(org.id) == ([], 0)
    finally:
        current_user_var.reset(token)
    assert (await gen.list_reports(org.id))[1] == 3
    assert await gen.get_report(legacy.id) is legacy


async def test_explicit_empty_report_filter_has_empty_measurements(scoped_reports):
    gen, org, _, _, _ = scoped_reports
    start = datetime(2026, 9, 1, tzinfo=UTC)
    report = await gen.generate_report(org.id, start, start + timedelta(days=1), policy_ids=[], report_format="csv")
    assert report.report_data["policies"] == []
    assert report.report_data["compliance"]["snapshot_count"] == 0
    assert report.report_data["access_scope"] == {"version": 1, "site_ids": []}


async def test_schedule_scope_applies_to_list_get_update_and_delete(db_session, scoped_reports):
    gen, org, _, policies, user = scoped_reports
    scopes = [[], [policies[0].id], [policies[1].id], [p.id for p in policies]]
    schedules = [
        await gen.create_schedule(org.id, {"name": f"Schedule {i}", "sla_policy_ids": ids})
        for i, ids in enumerate(scopes)
    ]
    assert schedules[1].sla_policy_ids == [str(policies[0].id)]
    token = current_user_var.set(user)
    try:
        visible, total = await gen.list_schedules(org.id)
        assert total == 1
        assert [item.id for item in visible] == [schedules[1].id]
        assert await gen.get_schedule(schedules[1].id, org.id) is schedules[1]
        for schedule in [schedules[0], schedules[2], schedules[3]]:
            assert await gen.get_schedule(schedule.id, org.id) is None
            assert await gen.update_schedule(schedule.id, {"enabled": False}, org.id) is None
            assert not await gen.delete_schedule(schedule.id, org.id)
    finally:
        current_user_var.reset(token)


async def test_corrupt_scheduled_policy_filter_never_becomes_org_wide(db_session, scoped_reports, monkeypatch):
    gen, org, _, _, _ = scoped_reports
    due = datetime.now(UTC) - timedelta(days=1)
    schedule = SLAReportSchedule(
        organization_id=org.id, name="Corrupt filter", frequency="monthly",
        enabled=True, next_run_at=due, sla_policy_ids=["not-a-uuid"],
    )
    db_session.add(schedule)
    await db_session.flush()
    render = AsyncMock()
    monkeypatch.setattr(gen, "generate_report", render)
    assert await gen.generate_scheduled() == []
    render.assert_not_awaited()
    assert schedule.next_run_at == due
    assert schedule.last_generated_at is None


@pytest.mark.parametrize("scope", ["device_group", "camera", "nvr"])
async def test_resource_scope_uses_owning_site_for_generation_archive_and_schedule(db_session, scoped_reports, scope):
    from fastapi import HTTPException

    from app.api.v1.endpoints.sla_reports import _assert_schedule_policies_accessible
    from app.models.enterprise import DeviceGroup
    from app.modules.cameras.models import NVR, Camera

    gen, org, sites, _, user = scoped_reports
    db_session.add_all([
        Site(id=site, organization_id=org.id, name=f"Site {index}", slug=f"site-{index}")
        for index, site in enumerate(sites)
    ])
    await db_session.flush()
    model = {"device_group": DeviceGroup, "camera": Camera, "nvr": NVR}[scope]
    resources = [
        model(organization_id=org.id, site_id=site, name=f"Resource {index}",
              **({"ip_address": f"192.0.2.{index + 1}"} if scope != "device_group" else {}))
        for index, site in enumerate(sites)
    ]
    db_session.add_all(resources)
    await db_session.flush()
    policies = [
        SLAPolicy(organization_id=org.id, name=f"Resource policy {index}", scope=scope, scope_id=resource.id)
        for index, resource in enumerate(resources)
    ]
    db_session.add_all(policies)
    await db_session.flush()
    start = datetime(2026, 9, 1, tzinfo=UTC)
    mixed = await gen.generate_report(org.id, start, start + timedelta(days=1), policy_ids=[p.id for p in policies], report_format="csv")
    assert set(mixed.report_data["access_scope"]["site_ids"]) == {str(site) for site in sites}
    token = current_user_var.set(user)
    try:
        report = await gen.generate_report(org.id, start, start + timedelta(days=1), policy_ids=[p.id for p in policies], report_format="csv")
        assert [p["id"] for p in report.report_data["policies"]] == [str(policies[0].id)]
        assert report.report_data["access_scope"]["site_ids"] == [str(sites[0])]
        assert await gen.get_report(mixed.id) is None
        assert (await gen.list_reports(org.id))[1] == 1
        await _assert_schedule_policies_accessible(db_session, user, org.id, [policies[0].id])
        with pytest.raises(HTTPException) as exc:
            await _assert_schedule_policies_accessible(db_session, user, org.id, [policies[1].id])
        assert exc.value.status_code == 404
        resources[1].site_id = sites[0]
        await db_session.flush()
        assert await gen.get_report(mixed.id) is None  # Original site scope survives a move.
    finally:
        current_user_var.reset(token)


@pytest.mark.parametrize("scope", ["site_group", "future_unknown_scope"])
async def test_unresolved_scope_never_becomes_an_org_wide_archive(db_session, scoped_reports, scope):
    gen, org, _, _, user = scoped_reports
    policy = SLAPolicy(organization_id=org.id, name="Unresolved", scope=scope, scope_id=uuid4())
    db_session.add(policy)
    await db_session.flush()
    start = datetime(2026, 9, 1, tzinfo=UTC)
    report = await gen.generate_report(org.id, start, start + timedelta(days=1), policy_ids=[policy.id], report_format="csv")
    token = current_user_var.set(user)
    try:
        assert await gen.get_report(report.id) is None
        assert (await gen.list_reports(org.id))[1] == 0
        filtered = await gen.generate_report(org.id, start, start + timedelta(days=1), policy_ids=[policy.id], report_format="csv")
        assert filtered.report_data["policies"] == []
    finally:
        current_user_var.reset(token)
