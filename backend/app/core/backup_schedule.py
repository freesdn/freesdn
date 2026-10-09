# SPDX-License-Identifier: AGPL-3.0-only
"""Validate backup calendars and convert their next local occurrence to UTC."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import CroniterError, croniter

from app.core.security_utils import validate_cron_expression


def validate_backup_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("Use an installed IANA timezone, such as America/New_York or UTC") from exc
    return value


def next_backup_run(cron_expression: str, timezone: str, *, after: datetime) -> datetime:
    """Return a strictly future UTC instant; invalid timing must be corrected.

    Croniter's timezone-aware semantics apply: missing spring times run at the
    clock transition, and the two instants in a repeated autumn hour are distinct
    occurrences. Use UTC when a schedule must be independent of clock changes.
    """
    expression = validate_cron_expression(cron_expression)
    if expression is None:
        raise ValueError("Invalid cron expression")
    zone = ZoneInfo(validate_backup_timezone(timezone))
    if after.tzinfo is None:
        raise ValueError("Backup schedule reference must include a timezone")
    try:
        # Five-field calendars have no year field. Eight years covers leap-day
        # schedules while bounding searches for impossible dates such as Feb 31.
        next_run: datetime = croniter(
            expression, after.astimezone(zone), max_years_between_matches=8
        ).get_next(datetime)
    except (CroniterError, ValueError) as exc:
        raise ValueError("Cron expression has no valid upcoming occurrence") from exc
    return next_run.astimezone(UTC)


def validate_backup_cron(value: str) -> str:
    # Use the execution parser too, so an impossible calendar is rejected by
    # the API instead of being accepted and then failing every worker tick.
    next_backup_run(value, "UTC", after=datetime.now(UTC))
    return value.strip()
