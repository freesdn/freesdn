"""Exercise the deployed Beat entry's calendar, including non-quarter minutes."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.celery_app import celery_app


@pytest.mark.parametrize("minute", range(60))
def test_due_backup_picker_is_dispatched_each_minute(monkeypatch, minute):
    entry = celery_app.conf.beat_schedule["backup-run-scheduled"]
    now = datetime(2026, 9, 26, 2, minute, tzinfo=UTC)
    schedule = entry["schedule"]
    monkeypatch.setattr(schedule, "nowfun", lambda: now)
    due, next_check = schedule.is_due(now - timedelta(minutes=1))
    assert due, f"Backup dispatch misses minute {minute}; due archives will be late"
    assert 0 < next_check <= 60
    assert entry["task"] == "backup.run_scheduled"
    assert entry["options"]["queue"] in {q.name for q in celery_app.conf.task_queues}


def test_backup_picker_does_not_spin_between_minute_boundaries(monkeypatch):
    schedule = celery_app.conf.beat_schedule["backup-run-scheduled"]["schedule"]
    boundary = datetime(2026, 9, 26, 2, 2, tzinfo=UTC)
    monkeypatch.setattr(schedule, "nowfun", lambda: boundary + timedelta(seconds=20))
    due, next_check = schedule.is_due(boundary)
    assert not due
    assert 0 < next_check <= 40
