"""Backup wall-clock promises, validation and UTC persistence boundaries."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas.backup import BackupScheduleCreate, BackupScheduleUpdate
from app.services import backup


@pytest.mark.parametrize(
    ("timezone", "cron", "now", "expected"),
    [
        ("UTC", "0 2 * * *", "2026-01-15T04:00:00Z", "2026-01-16T02:00:00Z"),
        ("America/New_York", "0 2 * * *", "2026-01-15T04:00:00Z", "2026-01-15T07:00:00Z"),
        ("America/New_York", "0 2 * * *", "2026-07-15T04:00:00Z", "2026-07-15T06:00:00Z"),
        ("Asia/Kathmandu", "0 2 * * *", "2026-09-26T00:00:00Z", "2026-09-26T20:15:00Z"),
        ("Europe/Berlin", "0 4 * * *", "2026-03-28T12:00:00Z", "2026-03-29T02:00:00Z"),
        ("Europe/Berlin", "0 4 * * *", "2026-10-24T12:00:00Z", "2026-10-25T03:00:00Z"),
        # Croniter runs a missing spring clock time at the transition, and both
        # real instants in a repeated autumn hour are distinct cron occurrences.
        ("America/New_York", "30 2 * * *", "2026-03-08T06:00:00Z", "2026-03-08T07:00:00Z"),
        ("America/New_York", "30 1 * * *", "2026-11-01T04:00:00Z", "2026-11-01T05:30:00Z"),
        ("America/New_York", "30 1 * * *", "2026-11-01T05:40:00Z", "2026-11-01T06:30:00Z"),
    ],
)
def test_next_backup_matches_local_calendar(monkeypatch, timezone, cron, now, expected):
    instant = datetime.fromisoformat(now)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz) if tz else instant.replace(tzinfo=None)

    monkeypatch.setattr(backup, "datetime", FrozenDatetime)
    result = backup.BackupService(None)._calculate_next_run(cron, timezone)
    assert result == datetime.fromisoformat(expected)
    assert result.tzinfo is UTC
    assert result > instant


@pytest.mark.parametrize("timezone", ["No/Such_Zone", "", "../UTC", "/etc/passwd"])
@pytest.mark.parametrize("schema", [BackupScheduleCreate, BackupScheduleUpdate])
def test_schedule_schema_rejects_unknown_or_non_iana_timezone(schema, timezone):
    with pytest.raises(ValidationError, match="timezone"):
        schema(name="Owned schedule", cron_expression="0 2 * * *", timezone=timezone)


@pytest.mark.parametrize("schema", [BackupScheduleCreate, BackupScheduleUpdate])
def test_schedule_schema_rejects_calendar_with_no_occurrence(schema):
    with pytest.raises(ValidationError, match="cron_expression"):
        schema(name="Owned schedule", cron_expression="0 2 31 2 *")


@pytest.mark.parametrize(
    ("cron", "timezone"),
    [("not a schedule", "UTC"), ("0 2 31 2 *", "UTC"), ("0 2 * * *", "No/Such_Zone")],
)
def test_invalid_stored_timing_never_silently_becomes_two_am_utc(cron, timezone):
    with pytest.raises(ValueError):
        backup.BackupService(None)._calculate_next_run(cron, timezone)


def test_update_omitted_or_null_timing_preserves_existing_values():
    assert BackupScheduleUpdate(name="Renamed").model_dump(exclude_unset=True) == {
        "name": "Renamed"
    }
    assert BackupScheduleUpdate(timezone=None).timezone is None
    assert BackupScheduleCreate(name="UTC", cron_expression="0 2 * * *").timezone == "UTC"


def test_leap_day_remains_a_supported_calendar(monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 26, tzinfo=UTC).astimezone(tz)

    monkeypatch.setattr(backup, "datetime", FrozenDatetime)
    assert backup.BackupService(None)._calculate_next_run("0 2 29 2 *") == datetime(
        2028, 2, 29, 2, tzinfo=UTC
    )
