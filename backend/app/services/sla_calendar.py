# SPDX-License-Identifier: AGPL-3.0-only
"""Calendar semantics for SLA reports, independent of worker polling delays."""

import calendar
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.models.sla import SLAReportSchedule


class ScheduleTimingError(ValueError):
    """A stored schedule needs correction before it can execute."""


def validate_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("Use an installed IANA timezone, such as America/New_York or UTC") from exc
    return value


@dataclass(frozen=True)
class ReportCalendar:
    frequency: str
    timezone: ZoneInfo
    clock: time
    weekday: int
    monthday: int

    @classmethod
    def from_schedule(cls, schedule: SLAReportSchedule) -> "ReportCalendar":
        # Defaults also cover model instances before SQLAlchemy applies defaults.
        timezone = getattr(schedule, "timezone", None)
        clock = getattr(schedule, "time_of_day", None)
        weekday = getattr(schedule, "day_of_week", None)
        monthday = getattr(schedule, "day_of_month", None)
        timezone = "UTC" if timezone is None else timezone
        clock = "09:00" if clock is None else clock
        weekday = 0 if weekday is None else weekday
        monthday = 1 if monthday is None else monthday
        try:
            if (
                schedule.frequency not in {"weekly", "monthly", "quarterly"}
                or not isinstance(clock, str)
                or re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", clock) is None
                or not isinstance(weekday, int)
                or not 0 <= weekday <= 6
                or not isinstance(monthday, int)
                or not 1 <= monthday <= 31
            ):
                raise ValueError("Invalid report calendar")
            return cls(
                schedule.frequency,
                ZoneInfo(validate_timezone(timezone)),
                time.fromisoformat(clock),
                weekday,
                monthday,
            )
        except (TypeError, ValueError) as exc:
            raise ScheduleTimingError("invalid_schedule_timing") from exc

    def _matches(self, day: date) -> bool:
        if self.frequency == "weekly":
            return day.weekday() == self.weekday
        if self.frequency == "quarterly" and day.month not in {1, 4, 7, 10}:
            return False
        return day.day == min(self.monthday, calendar.monthrange(day.year, day.month)[1])

    def _utc(self, day: date, clock: time) -> datetime:
        # fold=0 selects the first occurrence when clocks go back. In a forward
        # gap its pre-transition offset shifts the run forward by the gap (e.g.
        # 02:30 becomes 03:30), rather than dropping or duplicating the run.
        return datetime.combine(day, clock, self.timezone).replace(fold=0).astimezone(UTC)

    def _occurrence(self, reference: datetime, *, forward: bool) -> datetime:
        reference = (
            reference.replace(tzinfo=UTC) if reference.tzinfo is None else reference.astimezone(UTC)
        )
        local_day = reference.astimezone(self.timezone).date()
        for offset in range(370):
            day = local_day + timedelta(days=offset if forward else -offset)
            if self._matches(day):
                candidate = self._utc(day, self.clock)
                if (forward and candidate > reference) or (not forward and candidate <= reference):
                    return candidate
        raise ScheduleTimingError("invalid_schedule_timing")

    def next_run(self, after: datetime) -> datetime:
        """Next strictly future occurrence; never rerun the second DST fold."""
        return self._occurrence(after, forward=True)

    def report_period(self, now: datetime) -> tuple[datetime, datetime]:
        """Latest due report's complete local week, month or calendar quarter.

        Missed runs coalesce into one latest due report; this is not historical
        backfill. Worker delay does not extend the reporting window into today.
        """
        due = self._occurrence(now, forward=False).astimezone(self.timezone).date()
        if self.frequency == "weekly":
            end = due
            start = end - timedelta(days=7)
        else:
            month = due.month if self.frequency == "monthly" else ((due.month - 1) // 3) * 3 + 1
            end = date(due.year, month, 1)
            previous = due.year * 12 + month - 1 - (1 if self.frequency == "monthly" else 3)
            start = date(previous // 12, previous % 12 + 1, 1)
        return self._utc(start, time.min), self._utc(end, time.min)
