# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Timezone & Datetime Formatting Service
=====================================================

Provides site-aware datetime formatting based on site timezone
and format preferences.

Usage:
    from app.core.timezone import SiteDateTimeFormatter

    formatter = SiteDateTimeFormatter(
        timezone="America/New_York",
        time_format="12h",
        date_format="MM/DD/YYYY"
    )

    formatted = formatter.format_datetime(datetime.now(UTC))
"""

from datetime import UTC, datetime
from typing import Literal
from zoneinfo import ZoneInfo

from babel import dates as babel_dates

# Common timezone aliases for user convenience
TIMEZONE_ALIASES = {
    "EST": "America/New_York",
    "PST": "America/Los_Angeles",
    "CST": "America/Chicago",
    "MST": "America/Denver",
    "CET": "Europe/Paris",
    "GMT": "Europe/London",
    "JST": "Asia/Tokyo",
    "IST": "Asia/Kolkata",
    "AEST": "Australia/Sydney",
}

# Date format patterns to strftime/babel conversion
DATE_FORMAT_MAP = {
    "YYYY-MM-DD": "%Y-%m-%d",  # 2024-12-31
    "DD/MM/YYYY": "%d/%m/%Y",  # 31/12/2024
    "MM/DD/YYYY": "%m/%d/%Y",  # 12/31/2024
    "DD-MM-YYYY": "%d-%m-%Y",  # 31-12-2024
    "DD.MM.YYYY": "%d.%m.%Y",  # 31.12.2024
    "YYYY/MM/DD": "%Y/%m/%d",  # 2024/12/31
}

TimeFormat = Literal["12h", "24h"]
DateFormatPattern = Literal[
    "YYYY-MM-DD",
    "DD/MM/YYYY",
    "MM/DD/YYYY",
    "DD-MM-YYYY",
    "DD.MM.YYYY",
    "YYYY/MM/DD",
]


def resolve_timezone(tz_str: str) -> ZoneInfo:
    """
    Resolve a timezone string to ZoneInfo.

    Supports:
    - IANA timezone names (America/New_York)
    - Common aliases (EST, PST, CET)
    - UTC as default fallback
    """
    if not tz_str:
        return ZoneInfo("UTC")

    # Check if it's an alias
    if tz_str.upper() in TIMEZONE_ALIASES:
        tz_str = TIMEZONE_ALIASES[tz_str.upper()]

    try:
        return ZoneInfo(tz_str)
    except (KeyError, ValueError):
        return ZoneInfo("UTC")


class SiteDateTimeFormatter:
    """
    Site-aware datetime formatter.

    Formats datetimes according to site's timezone, time format, and date format preferences.
    """

    def __init__(
        self,
        timezone: str = "UTC",
        time_format: TimeFormat = "24h",
        date_format: DateFormatPattern = "YYYY-MM-DD",
        locale: str = "en",
    ):
        self.tz = resolve_timezone(timezone)
        self.timezone_name = timezone
        self.time_format = time_format
        self.date_format = date_format
        self.locale = locale
        self._strftime_date = DATE_FORMAT_MAP.get(date_format, "%Y-%m-%d")

    def to_site_timezone(self, dt: datetime) -> datetime:
        """
        Convert a datetime to the site's timezone.

        If the datetime is naive, assumes UTC.
        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(self.tz)

    def format_date(self, dt: datetime) -> str:
        """
        Format date according to site's date format preference.

        Args:
            dt: Datetime to format (will be converted to site timezone)

        Returns:
            Formatted date string
        """
        site_dt = self.to_site_timezone(dt)
        return site_dt.strftime(self._strftime_date)

    def format_time(self, dt: datetime) -> str:
        """
        Format time according to site's time format preference (12h/24h).

        Args:
            dt: Datetime to format

        Returns:
            Formatted time string (e.g., "14:30" or "2:30 PM")
        """
        site_dt = self.to_site_timezone(dt)

        if self.time_format == "12h":
            return site_dt.strftime("%I:%M %p").lstrip("0")
        else:
            return site_dt.strftime("%H:%M")

    def format_datetime(self, dt: datetime, include_seconds: bool = False) -> str:
        """
        Format full datetime with date and time.

        Args:
            dt: Datetime to format
            include_seconds: Whether to include seconds

        Returns:
            Formatted datetime string
        """
        site_dt = self.to_site_timezone(dt)

        date_str = site_dt.strftime(self._strftime_date)

        if self.time_format == "12h":
            time_fmt = "%I:%M:%S %p" if include_seconds else "%I:%M %p"
            time_str = site_dt.strftime(time_fmt).lstrip("0")
        else:
            time_fmt = "%H:%M:%S" if include_seconds else "%H:%M"
            time_str = site_dt.strftime(time_fmt)

        return f"{date_str} {time_str}"

    def format_relative(self, dt: datetime) -> str:
        """
        Format as relative time (e.g., "2 hours ago").

        Uses Babel for locale-aware relative time formatting.
        """
        # Ensure we compare in same timezone
        site_dt = self.to_site_timezone(dt)
        now = datetime.now(self.tz)
        delta = now - site_dt

        return str(
            babel_dates.format_timedelta(
                -delta,  # Negative for "ago"
                locale=self.locale,
                add_direction=True,
            )
        )

    def format_time_with_zone(self, dt: datetime) -> str:
        """
        Format time with timezone abbreviation.

        Returns:
            Formatted time with zone (e.g., "14:30 EST")
        """
        site_dt = self.to_site_timezone(dt)
        time_str = self.format_time(dt)
        zone_abbr = site_dt.strftime("%Z") or self.timezone_name
        return f"{time_str} {zone_abbr}"

    def get_current_time(self) -> datetime:
        """Get the current time in the site's timezone."""
        return datetime.now(self.tz)

    def get_utc_offset(self) -> str:
        """
        Get the current UTC offset for the site's timezone.

        Returns:
            Offset string like "+05:00" or "-08:00"
        """
        now = datetime.now(self.tz)
        offset = now.strftime("%z")
        # Format as +HH:MM
        return f"{offset[:3]}:{offset[3:]}"


def get_all_timezones() -> list[dict[str, str]]:
    """
    Get list of all available timezones grouped by region.

    Returns:
        List of timezone dicts with code, name, and offset
    """
    from zoneinfo import available_timezones

    timezones = []
    now = datetime.now(UTC)

    for tz_name in sorted(available_timezones()):
        # Skip some obscure zones
        if tz_name.startswith(("Etc/", "SystemV/", "posix/", "right/")):
            continue

        try:
            zone = ZoneInfo(tz_name)
            local_now = now.astimezone(zone)
            offset = local_now.strftime("%z")
            offset_formatted = f"{offset[:3]}:{offset[3:]}"

            timezones.append(
                {
                    "code": tz_name,
                    "name": tz_name.replace("_", " "),
                    "offset": offset_formatted,
                    "display": f"(UTC{offset_formatted}) {tz_name.replace('_', ' ')}",
                }
            )
        except (KeyError, ValueError):
            continue

    # Sort by offset, then by name
    timezones.sort(key=lambda x: (x["offset"], x["name"]))

    return timezones


def get_date_formats() -> list[dict[str, str]]:
    """Get list of available date format options."""
    return [
        {"code": "YYYY-MM-DD", "example": "2024-12-31", "description": "ISO 8601"},
        {"code": "DD/MM/YYYY", "example": "31/12/2024", "description": "European"},
        {"code": "MM/DD/YYYY", "example": "12/31/2024", "description": "US"},
        {"code": "DD-MM-YYYY", "example": "31-12-2024", "description": "European Alt"},
        {"code": "DD.MM.YYYY", "example": "31.12.2024", "description": "German/Swiss"},
        {"code": "YYYY/MM/DD", "example": "2024/12/31", "description": "Japanese"},
    ]


def get_time_formats() -> list[dict[str, str]]:
    """Get list of available time format options."""
    return [
        {"code": "24h", "example": "14:30", "description": "24-hour clock"},
        {"code": "12h", "example": "2:30 PM", "description": "12-hour clock"},
    ]
