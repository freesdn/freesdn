"""Validate normalized aggregate envelopes before exposing live gateway reads."""

import math
from typing import Any

from app.adapters.base import AdapterResult
from app.adapters.trust_inventory import inventory_data, inventory_rows
from app.modules.firewall.gateway_system_reads import firmware_payload, health_payload
from app.services.adapter_redaction import redact_secrets


def _json_value(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("Invalid aggregate nesting")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _json_value(item, depth + 1)
        return
    raise ValueError("Invalid aggregate metadata")


def _count(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Invalid aggregate count")
    return value


def _booleans(data: dict[str, Any], *keys: str) -> None:
    if any(type(data.get(key)) is not bool for key in keys):
        raise ValueError("Missing aggregate status")


def _bounded_crowdsec_window(body: dict[str, Any]) -> None:
    for prefix in ("alert", "decision"):
        total_key, truncated_key = prefix + "_total", prefix + "_truncated"
        if total_key not in body and truncated_key not in body:
            continue  # Existing normalized adapters may not supply window metadata.
        total = _count(body.get(total_key))
        count = _count(body.get(prefix + "_count"))
        truncated = body.get(truncated_key)
        if type(truncated) is not bool or truncated != (total > count):
            raise ValueError("Invalid CrowdSec window metadata")
        if count != min(total, 50):
            raise ValueError("Incomplete CrowdSec window")


def _rows(data: dict[str, Any], key: str, count: str | None) -> list[dict[str, Any]]:
    rows = data.get(key)
    value = data.get(count) if count else len(rows) if isinstance(rows, list) else None
    return inventory_rows(AdapterResult.ok({key: rows, "count": value}), key)


def _openwrt_summary(data: dict[str, Any]) -> None:
    """Validate the existing OpenWrt parser contract without inventing WAN state."""
    counts = {
        key: _count(data.get(key))
        for key in (
            "interfaces_total",
            "interfaces_up",
            "uptime",
            "memory_total",
            "memory_free",
            "services_total",
        )
    }
    if counts["interfaces_up"] > counts["interfaces_total"]:
        raise ValueError("Invalid OpenWrt interface summary")
    if counts["memory_free"] > counts["memory_total"]:
        raise ValueError("Invalid OpenWrt memory summary")
    if not all(isinstance(data.get(key), str) for key in ("hostname", "model", "version")):
        raise ValueError("OpenWrt summary is missing")
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict) or any(
        not isinstance(key, str) or type(value) is not bool for key, value in capabilities.items()
    ):
        raise ValueError("Invalid OpenWrt capability summary")


def aggregate_payload(result: Any, kind: str, *, vendor: str) -> dict[str, Any]:
    """Preserve normalized successful contracts; refuse absent or inconsistent data.

    This validates the normalized service envelope. Individual adapter parsers
    remain responsible for firmware-specific successful response schemas.
    """
    data = inventory_data(result)
    payload: dict[str, Any]
    if kind == "firmware":
        payload = firmware_payload(data)
    elif kind == "health":
        payload = health_payload(data)
    elif kind == "vpn":
        # Vendors have different VPN payloads; do not manufacture empty tunnels.
        if not data:
            raise ValueError("VPN status is missing")
        data = {key: value for key, value in data.items() if key not in {"gateway_id", "vendor"}}
        if not data:
            raise ValueError("VPN status is missing")
        payload = {"tunnels": data}
    elif kind == "device-summary":
        if vendor == "openwrt":
            _openwrt_summary(data)
        else:
            counts = [
                _count(data.get(key))
                for key in ("interface_count", "interfaces_up", "interfaces_down")
            ]
            unknown = _count(data.get("interfaces_unknown", 0))
            if counts[0] != counts[1] + counts[2] + unknown:
                raise ValueError("Device interface summary is incomplete")
            if not all(
                isinstance(data.get(key), str) for key in ("hostname", "version", "wan_status")
            ):
                raise ValueError("Device summary is missing")
        payload = {
            "summary": {
                key: value for key, value in data.items() if key not in {"gateway_id", "vendor"}
            }
        }
    elif kind in {"servers", "backends", "frontends"}:
        rows = _rows(data, kind, "count")
        payload = {kind: rows, "count": len(rows)}
    else:
        body = data.get(kind)
        if not isinstance(body, dict) or not body:
            raise ValueError("Aggregate status is missing")
        if kind == "haproxy":
            fields = {
                "servers": "server_count",
                "backends": "backend_count",
                "frontends": "frontend_count",
                "acls": None,
                "actions": None,
            }
        elif kind == "crowdsec":
            _booleans(body, "running")
            _bounded_crowdsec_window(body)
            fields = {"alerts": "alert_count", "decisions": "decision_count"}
        elif kind == "monit":
            _booleans(body, "running")
            fields = {"services": "service_count", "tests": "test_count", "alerts": "alert_count"}
        else:
            fields = {}
        for key, count in fields.items():
            _rows(body, key, count)
        if kind == "tailscale":
            _booleans(body, "running")
            settings = body.get("settings")
            if not isinstance(settings, dict):
                raise ValueError("Tailscale settings are missing")
            _booleans(settings, "enabled")
        elif kind == "proxy":
            _booleans(
                body,
                "enabled",
                "running",
                "ssl_inspection",
                "transparent_mode",
                "cache_enabled",
                "logging",
            )
        elif kind == "telegraf":
            _booleans(
                body,
                "enabled",
                "running",
                "output_influxdb",
                "output_graphite",
                "output_prometheus",
            )
        elif kind == "netflow":
            _booleans(body, "enabled", "collect_enabled", "running")
        payload = {kind: body}
    _json_value(payload)
    redacted = redact_secrets(payload)
    if not isinstance(redacted, dict):
        raise ValueError("Invalid aggregate envelope")
    return redacted
