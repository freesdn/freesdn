# SPDX-License-Identifier: AGPL-3.0-only
"""Expected calendar dates and reporting windows, including DST discontinuities."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.api.v1.endpoints.sla_reports import SLAReportScheduleCreate, SLAReportScheduleUpdate
from app.services.sla_calendar import ReportCalendar, ScheduleTimingError


def calendar(**overrides):
    fields = {
        "frequency": "weekly",
        "timezone": "UTC",
        "time_of_day": "09:00",
        "day_of_week": 0,
        "day_of_month": 1,
    }
    fields.update(overrides)
    return ReportCalendar.from_schedule(SimpleNamespace(**fields))


def at(value):
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


@pytest.mark.parametrize(
    ("settings", "now", "expected"),
    [
        ({}, "2026-09-14T08:59:59", "2026-09-14T09:00:00"),
        ({}, "2026-09-14T09:00:00", "2026-09-21T09:00:00"),
        ({"day_of_week": 4}, "2026-09-15T12:00:00", "2026-09-18T09:00:00"),
        (
            {"frequency": "monthly", "day_of_month": 31},
            "2026-01-31T09:00:00",
            "2026-02-28T09:00:00",
        ),
        (
            {"frequency": "monthly", "day_of_month": 31},
            "2028-01-31T09:00:00",
            "2028-02-29T09:00:00",
        ),
        (
            {"frequency": "monthly", "day_of_month": 31},
            "2026-02-28T09:00:00",
            "2026-03-31T09:00:00",
        ),
        ({"frequency": "quarterly"}, "2026-09-15T12:00:00", "2026-10-01T09:00:00"),
        (
            {"frequency": "quarterly", "day_of_month": 31},
            "2026-01-31T09:00:00",
            "2026-04-30T09:00:00",
        ),
        ({"frequency": "quarterly"}, "2026-10-01T09:00:00", "2027-01-01T09:00:00"),
        ({"timezone": "Asia/Kathmandu"}, "2026-09-14T03:00:00", "2026-09-14T03:15:00"),
        # Spring-forward gap: 02:30 local runs once at 03:30 local.
        (
            {"timezone": "America/New_York", "day_of_week": 6, "time_of_day": "02:30"},
            "2026-03-08T06:00:00",
            "2026-03-08T07:30:00",
        ),
        (
            {"timezone": "America/New_York", "day_of_week": 6, "time_of_day": "02:30"},
            "2026-03-08T07:30:00",
            "2026-03-15T06:30:00",
        ),
        # Fall-back fold: never fire again at the repeated 01:30.
        (
            {"timezone": "America/New_York", "day_of_week": 6, "time_of_day": "01:30"},
            "2026-11-01T04:00:00",
            "2026-11-01T05:30:00",
        ),
        (
            {"timezone": "America/New_York", "day_of_week": 6, "time_of_day": "01:30"},
            "2026-11-01T05:45:00",
            "2026-11-08T06:30:00",
        ),
        # Lord Howe has a 30-minute DST gap, not a one-hour gap.
        (
            {"timezone": "Australia/Lord_Howe", "day_of_week": 6, "time_of_day": "02:15"},
            "2026-10-03T14:00:00",
            "2026-10-03T15:45:00",
        ),
    ],
)
def test_next_occurrence(settings, now, expected):
    assert calendar(**settings).next_run(at(now)) == at(expected)


@pytest.mark.parametrize(
    ("settings", "now", "start", "end"),
    [
        ({}, "2026-09-16T20:00:00", "2026-09-07T00:00:00", "2026-09-14T00:00:00"),
        (
            {"frequency": "monthly"},
            "2028-03-15T12:00:00",
            "2028-02-01T00:00:00",
            "2028-03-01T00:00:00",
        ),
        (
            {"frequency": "monthly", "day_of_month": 15},
            "2026-09-14T12:00:00",
            "2026-07-01T00:00:00",
            "2026-08-01T00:00:00",
        ),
        (
            {"frequency": "quarterly"},
            "2027-01-03T12:00:00",
            "2026-10-01T00:00:00",
            "2027-01-01T00:00:00",
        ),
        (
            {"timezone": "America/New_York", "day_of_week": 6},
            "2026-03-15T14:00:00",
            "2026-03-08T05:00:00",
            "2026-03-15T04:00:00",
        ),
        (
            {"timezone": "America/New_York", "day_of_week": 6},
            "2026-11-08T15:00:00",
            "2026-11-01T04:00:00",
            "2026-11-08T05:00:00",
        ),
    ],
)
def test_complete_periods_do_not_drift_with_worker_delay(settings, now, start, end):
    assert calendar(**settings).report_period(at(now)) == (at(start), at(end))


def test_reference_offsets_and_legacy_naive_utc_are_equivalent():
    schedule = calendar()
    instant = at("2026-09-14T08:00:00")
    assert schedule.next_run(instant) == schedule.next_run(instant.replace(tzinfo=None))
    assert schedule.next_run(instant) == schedule.next_run(
        datetime.fromisoformat("2026-09-14T10:00:00+02:00")
    )


def test_next_occurrence_remains_strict_across_a_full_year():
    schedule = calendar(timezone="America/New_York", day_of_week=6, time_of_day="01:30")
    previous = at("2026-01-01T00:00:00")
    for _ in range(60):
        current = schedule.next_run(previous)
        assert timedelta(days=6) < current - previous <= timedelta(days=8) or previous.day == 1
        assert current > previous
        previous = current


@pytest.mark.parametrize(
    "field,value",
    [
        ("timezone", "No/Such_Zone"),
        ("timezone", "/etc/passwd"),
        ("time_of_day", "24:00"),
        ("time_of_day", "9:00"),
        ("frequency", "daily"),
        ("day_of_week", 7),
        ("day_of_month", 0),
    ],
)
def test_invalid_persisted_calendar_fails_closed(field, value):
    with pytest.raises(ScheduleTimingError, match="invalid_schedule_timing"):
        calendar(**{field: value})


@pytest.mark.parametrize("schema", [SLAReportScheduleCreate, SLAReportScheduleUpdate])
@pytest.mark.parametrize(
    "field,value",
    [
        ("timezone", "No/Such_Zone"),
        ("timezone", ""),
        ("timezone", None),
        ("time_of_day", "24:00"),
        ("time_of_day", "09:60"),
        ("time_of_day", None),
    ],
)
def test_api_rejects_invalid_clock_settings(schema, field, value):
    with pytest.raises(ValidationError):
        schema.model_validate({"name": "Report", field: value})


def test_api_accepts_and_preserves_explicit_first_run():
    body = SLAReportScheduleCreate(
        name="Report",
        timezone="America/New_York",
        time_of_day="08:30",
        next_run_at="2026-10-01T08:00:00-04:00",
    )
    assert body.timezone == "America/New_York"
    assert body.time_of_day == "08:30"
    assert body.next_run_at == at("2026-10-01T12:00:00")


async def test_resume_with_invalid_stored_timing_returns_conflict_without_committing(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock
    from uuid import uuid4

    from fastapi import HTTPException

    from app.api.v1.endpoints import sla_reports

    service = MagicMock()
    service.get_schedule = AsyncMock(return_value=SimpleNamespace(sla_policy_ids=[]))
    service.update_schedule = AsyncMock(side_effect=ScheduleTimingError("invalid_schedule_timing"))
    monkeypatch.setattr(sla_reports, "SLAReportGenerator", lambda _db: service)
    monkeypatch.setattr(sla_reports, "_org_id", lambda _user: uuid4())
    monkeypatch.setattr(sla_reports, "_assert_schedule_policies_accessible", AsyncMock())
    db = AsyncMock()
    with pytest.raises(HTTPException) as error:
        await sla_reports.update_schedule(
            uuid4(), SLAReportScheduleUpdate(enabled=True), db=db, user=object()
        )
    assert error.value.status_code == 409
    assert "corrected calendar settings" in error.value.detail
    db.commit.assert_not_awaited()
