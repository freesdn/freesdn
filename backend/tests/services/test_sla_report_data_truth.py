# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise report metrics against PostgreSQL, including empty filters and boundaries."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app.models.core import Organization
from app.models.sla import SLABreach, SLAPolicy, SLASnapshot
from app.services.sla_reports import SLAReportGenerator


@pytest.fixture
async def report_data(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    org = Organization(name="Report validation", slug="report-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    policy = SLAPolicy(organization_id=org.id, name="Service availability", scope="organization")
    db_session.add(policy)
    await db_session.flush()
    start = datetime(2026, 9, 1, tzinfo=UTC)
    return SLAReportGenerator(db_session), org, policy, start


async def test_zero_compliance_is_a_measurement_not_missing(db_session, report_data):
    gen, org, policy, start = report_data
    db_session.add(SLASnapshot(policy_id=policy.id, recorded_at=start, compliance_percent=0))
    await db_session.flush()
    report = await gen.generate_report(
        org.id, start, start + timedelta(days=1), report_format="csv"
    )
    assert report.report_data["compliance"] == {
        "avg_compliance_percent": 0.0,
        "min_compliance_percent": 0.0,
        "max_compliance_percent": 0.0,
        "snapshot_count": 1,
    }
    assert "Average Compliance %,0.0" in Path(report.file_path).read_text()


async def test_unknown_policy_filter_cannot_include_other_policies(db_session, report_data):
    gen, org, policy, start = report_data
    db_session.add(SLASnapshot(policy_id=policy.id, recorded_at=start, compliance_percent=42))
    db_session.add(
        SLABreach(
            policy_id=policy.id,
            organization_id=org.id,
            started_at=start,
            violated_metric="uptime",
            threshold_value=99,
            actual_value=42,
            deviation_percent=57,
        )
    )
    await db_session.flush()
    report = await gen.generate_report(
        org.id, start, start + timedelta(days=1), policy_ids=[uuid4()], report_format="csv"
    )
    assert report.report_data["policies"] == []
    assert report.report_data["compliance"]["snapshot_count"] == 0
    assert report.report_data["breaches"]["total"] == 0


async def test_boundary_snapshot_is_counted_in_only_one_report(db_session, report_data):
    gen, org, policy, start = report_data
    boundary = start + timedelta(days=1)
    db_session.add(SLASnapshot(policy_id=policy.id, recorded_at=boundary, compliance_percent=99))
    await db_session.flush()
    previous = await gen.generate_report(org.id, start, boundary, report_format="csv")
    following = await gen.generate_report(
        org.id, boundary, boundary + timedelta(days=1), report_format="csv"
    )
    assert previous.report_data["compliance"]["snapshot_count"] == 0
    assert following.report_data["compliance"]["snapshot_count"] == 1


async def test_breaches_overlapping_period_are_counted(db_session, report_data):
    gen, org, policy, start = report_data
    end = start + timedelta(days=1)
    for began, ended in [
        (start - timedelta(hours=2), start + timedelta(hours=2)),  # overlaps
        (start - timedelta(hours=2), None),  # ongoing throughout period
        (start - timedelta(hours=2), start),  # resolved before interval
        (end, None),  # begins next interval
    ]:
        db_session.add(
            SLABreach(
                policy_id=policy.id,
                organization_id=org.id,
                started_at=began,
                resolved_at=ended,
                violated_metric="uptime",
                threshold_value=99,
                actual_value=42,
                deviation_percent=57,
            )
        )
    await db_session.flush()
    report = await gen.generate_report(org.id, start, end, report_format="csv")
    assert report.report_data["breaches"]["total"] == 2


async def test_large_incident_payloads_are_counted_without_loading_them(db_session, report_data):
    """A historical count must not hydrate thousands of incident JSON/text payloads."""
    from sqlalchemy import event, insert

    gen, org, policy, start = report_data
    rows = [
        {
            "id": uuid4(), "policy_id": policy.id, "organization_id": org.id,
            "severity": "critical" if index % 2 else "warning",
            "status": "active" if index % 3 else "acknowledged",
            "started_at": start, "violated_metric": "uptime", "threshold_value": 99,
            "actual_value": 42, "deviation_percent": 57,
            "notes": "x" * 4096, "context": {"payload": "y" * 4096},
        }
        for index in range(1025)
    ]
    await db_session.execute(insert(SLABreach), rows)
    await db_session.flush()

    def unexpected_payload_load(*args):
        raise AssertionError("Report hydrated a full incident instead of counting in the database")

    event.listen(SLABreach, "load", unexpected_payload_load)
    try:
        report = await gen.generate_report(
            org.id, start, start + timedelta(days=1), report_format="csv"
        )
    finally:
        event.remove(SLABreach, "load", unexpected_payload_load)
    assert report.report_data["breaches"] == {
        "total": 1025,
        "by_severity": {"warning": 513, "critical": 512},
        "by_status": {"acknowledged": 342, "active": 683},
    }
