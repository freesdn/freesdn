"""Validate normalized firmware and monitor observations at the live-read boundary."""

import math
from typing import Any


def firmware_payload(data: dict[str, Any]) -> dict[str, Any]:
    # Existing adapters use current_version, product_version (OpenWrt) or version.
    versions = [data[k] for k in ("current_version", "product_version", "version") if k in data]
    if not versions or any(not isinstance(v, str) or not v.strip() for v in versions):
        raise ValueError("Firmware version is unavailable")
    for key in ("needs_update", "update_available", "upgrade_available"):
        if data.get(key) is not None and type(data[key]) is not bool:
            raise ValueError("Invalid firmware availability")
    for key in ("latest_version", "new_version", "last_check", "product_name"):
        if data.get(key) is not None and not isinstance(data[key], str):
            raise ValueError("Invalid firmware metadata")
    return {"firmware": {k: v for k, v in data.items() if k not in {"gateway_id", "vendor"}}}


def health_payload(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("gateways")
    if (
        not isinstance(rows, list)
        or type(data.get("count")) is not int
        or data["count"] != len(rows)
    ):
        raise ValueError("Incomplete gateway health inventory")
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid gateway health row")
        name = row.get("name")
        if not isinstance(name, str) or not name.strip() or name != name.strip() or name in names:
            raise ValueError("Ambiguous gateway health identity")
        names.add(name)
        state = row.get("status")
        if not isinstance(state, str) or not state.strip():
            raise ValueError("Gateway health state is unavailable")
        for key in ("address", "interface", "monitor_ip", "status_text"):
            if key in row and not isinstance(row[key], str):
                raise ValueError("Invalid gateway health metadata")
        if "default_gateway" in row and type(row["default_gateway"]) is not bool:
            raise ValueError("Invalid default gateway flag")
        for key in ("loss_pct", "delay_ms", "stddev_ms"):
            value = row.get(key)
            if value is not None and (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value < 0
                or key == "loss_pct"
                and value > 100
            ):
                raise ValueError("Invalid gateway health measurement")
    return {"gateways": rows, "count": len(rows)}
