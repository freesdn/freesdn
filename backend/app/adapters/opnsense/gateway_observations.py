"""Interpret raw monitor states without treating missing measurements as zero."""

import math
from typing import Any

from app.adapters.opnsense.models import GatewayStatus
from app.adapters.opnsense.plugin_reads import text


def measurement(value: Any, unit: str, *, maximum: float | None = None) -> float | None:
    if value is None or value in ("", "~"):
        return None
    if type(value) not in (int, float, str):
        raise ValueError("Invalid gateway measurement")
    raw = str(value).strip()
    if raw.endswith(unit):
        raw = raw[: -len(unit)].strip()
    number = float(raw)
    if not math.isfinite(number) or number < 0 or (maximum is not None and number > maximum):
        raise ValueError("Invalid gateway measurement")
    return number


def gateway_observation(row: dict[str, Any]) -> dict[str, Any]:
    state = text(row.get("status")).strip().lower()
    if not state:
        raise ValueError("Gateway monitor state is unavailable")
    values = {
        "loss_pct": measurement(row.get("loss"), "%", maximum=100),
        "delay_ms": measurement(row.get("delay"), "ms"),
        "stddev_ms": measurement(row.get("stddev"), "ms"),
    }
    states = {
        "online": GatewayStatus.ONLINE,
        "down": GatewayStatus.OFFLINE,
        "force_down": GatewayStatus.OFFLINE,
        "offline": GatewayStatus.OFFLINE,
        "pending": GatewayStatus.PENDING,
        "loss": GatewayStatus.LOSS,
        "delay": GatewayStatus.DELAY,
        "delay+loss": GatewayStatus.LOSS,
        "unknown": GatewayStatus.UNKNOWN,
    }
    # dpinger uses none both for a disabled monitor and for no active alarm.
    # The latter has reported samples; preserve measured zero as well.
    if state == "none":
        status = (
            GatewayStatus.ONLINE
            if any(v is not None for v in values.values())
            else GatewayStatus.NONE
        )
    else:
        status = states.get(state, GatewayStatus.UNKNOWN)
    return {"status": status, **values}
