"""Validation of complete, normalized read-only trust and ACME inventories."""

import asyncio
import math
from typing import Any

from app.adapters.base import AdapterResult


def inventory_data(result: Any) -> dict[str, Any]:
    if isinstance(result, asyncio.CancelledError):
        raise result
    if (
        not isinstance(result, AdapterResult)
        or result.success is not True
        or not isinstance(result.data, dict)
    ):
        raise ValueError("Inventory is unavailable")
    return result.data


def public_metadata(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    selected = {key: row[key] for key in fields if key in row}
    if any(
        value is not None
        and (
            not isinstance(value, (str, int, float, bool))
            or isinstance(value, float)
            and not math.isfinite(value)
        )
        for value in selected.values()
    ):
        raise ValueError("Invalid inventory metadata")
    return selected


def inventory_rows(result: Any, key: str) -> list[dict[str, Any]]:
    data = inventory_data(result)
    rows = data.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Invalid inventory rows")
    if type(data.get("count")) is not int or data["count"] != len(rows):
        raise ValueError("Incomplete inventory")
    for row in rows:
        public_metadata(row, tuple(row))
    return rows


def inventory_settings(result: Any) -> dict[str, Any]:
    settings = inventory_data(result).get("acme_settings")
    if not isinstance(settings, dict) or any(
        type(settings.get(key)) is not bool for key in ("enabled", "auto_renewal")
    ):
        raise ValueError("ACME settings are unavailable")
    return public_metadata(
        settings,
        (
            "enabled",
            "auto_renewal",
            "environment",
            "log_level",
            "renew_interval",
            "challenge_port",
            "tls_challenge_port",
        ),
    )
