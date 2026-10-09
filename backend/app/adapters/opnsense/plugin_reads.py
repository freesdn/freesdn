"""Normalize the documented read-only plugin response contracts.

Unknown or incomplete data must not become a disabled or empty service.
Only explicitly selected public fields leave these parsers.
"""

from typing import Any
from urllib.parse import urlsplit, urlunsplit


def object_at(value: Any, *keys: str) -> dict[str, Any]:
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise ValueError("Required plugin settings are missing")
        value = value[key]
    if not isinstance(value, dict):
        raise ValueError("Invalid plugin settings")
    return value


def flag(value: Any) -> bool:
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return value == 1
    if isinstance(value, str) and value in ("0", "1"):
        return value == "1"
    raise ValueError("Invalid plugin boolean")


def text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid plugin text")
    return value


def service_running(value: Any, *, netflow: bool = False) -> bool:
    status = object_at(value).get("status")
    allowed = (
        {"active": True, "inactive": False}
        if netflow
        else {"running": True, "stopped": False, "disabled": False}
    )
    if not isinstance(status, str) or status not in allowed:
        raise ValueError("Plugin service state is unavailable")
    return allowed[status]


def selected_options(value: Any, *, labels: bool = False) -> list[str]:
    options = object_at(value)
    selected = []
    for key, row in options.items():
        text(key)
        item = object_at(row)
        label = text(item.get("value"))
        if flag(item.get("selected")):
            selected.append(label if labels else key)
    return selected


def recordset(value: Any, *, limit: int | None = None) -> tuple[list[dict[str, Any]], int]:
    data = object_at(value)
    rows, total = data.get("rows"), data.get("total")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Invalid plugin inventory")
    if type(total) is not int or total < 0:
        raise ValueError("Missing plugin inventory total")
    if type(data.get("current")) is not int or data["current"] != 1:
        raise ValueError("Unexpected plugin inventory page")
    page_size = data.get("rowCount")
    if type(page_size) is not int or page_size < -1:
        raise ValueError("Invalid plugin inventory page size")
    if page_size != -1 and page_size < len(rows):
        raise ValueError("Inconsistent plugin inventory page size")
    if len(rows) != (min(total, limit) if limit is not None else total):
        raise ValueError("Incomplete plugin inventory")
    return rows, total


def public_rows(
    rows: list[dict[str, Any]], fields: tuple[str, ...], *, identity: str
) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for row in rows:
        key = row.get(identity)
        if type(key) not in (str, int) or key == "" or str(key) in seen:
            raise ValueError("Invalid plugin inventory identity")
        seen.add(str(key))
        item = {identity: key}
        for field in fields:
            item[field] = text(row.get(field, ""))
        result.append(item)
    return result


def public_url(value: Any) -> str:
    """Omit URL user info, query and fragment; never expose output credentials."""
    raw = text(value)
    if not raw:
        return ""
    url = urlsplit(raw)
    if url.scheme not in {"http", "https"} or not url.hostname:
        raise ValueError("Invalid metrics endpoint")
    host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname
    if url.port is not None:
        host += f":{url.port}"
    return urlunsplit((url.scheme, host, url.path, "", ""))


def tailscale(settings_raw: Any, status_raw: Any) -> dict[str, Any]:
    settings = object_at(settings_raw, "settings")
    flags = {
        "enabled": "enabled",
        "accept_dns": "acceptDNS",
        "advertise_exit_node": "advertiseExitNode",
        "accept_subnet_routes": "acceptSubnetRoutes",
        "enable_ssh": "enableSSH",
        "disable_snat": "disableSNAT",
    }
    result: dict[str, Any] = {key: flag(settings.get(wire)) for key, wire in flags.items()}
    result.update(
        listen_port=text(settings.get("listenPort")),
        login_timeout=text(settings.get("loginTimeout")),
        use_exit_node=selected_options(settings.get("useExitNode"), labels=True),
    )
    return {"settings": result, "running": service_running(status_raw)}


def proxy(settings_raw: Any, status_raw: Any) -> dict[str, Any]:
    settings = object_at(settings_raw, "proxy")
    general, forward = object_at(settings, "general"), object_at(settings, "forward")
    logging = object_at(general, "logging", "enable")
    access_log, store_log = flag(logging.get("accessLog")), flag(logging.get("storeLog"))
    port = text(forward.get("port"))
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid proxy port")
    return {
        "enabled": flag(general.get("enabled")),
        "running": service_running(status_raw),
        "port": port,
        "ssl_inspection": flag(forward.get("sslbump")),
        "transparent_mode": flag(forward.get("transparentMode")),
        "cache_enabled": flag(object_at(general, "cache", "local").get("enabled")),
        "logging": access_log or store_log,
        "access_log_enabled": access_log,
        "store_log_enabled": store_log,
    }


def crowdsec(status_raw: Any, alerts_raw: Any, decisions_raw: Any) -> dict[str, Any]:
    alerts, alert_total = recordset(alerts_raw, limit=50)
    decisions, decision_total = recordset(decisions_raw, limit=50)
    normalized_alerts = public_rows(alerts, ("value", "reason", "created"), identity="id")
    normalized_decisions = public_rows(
        decisions, ("scope_value", "action", "source", "expiration"), identity="id"
    )
    for row in normalized_alerts:
        row["scope"], _, row["value"] = row["value"].partition(":")
        row["scenario"], row["created_at"] = row.pop("reason"), row.pop("created")
    for row in normalized_decisions:
        row["scope"], _, row["value"] = row.pop("scope_value").partition(":")
        row["type"], row["origin"], row["duration"] = (
            row.pop("action"),
            row.pop("source"),
            row.pop("expiration"),
        )
    return {
        "running": service_running(status_raw),
        "alerts": normalized_alerts,
        "decisions": normalized_decisions,
        "alert_count": len(alerts),
        "decision_count": len(decisions),
        "alert_total": alert_total,
        "decision_total": decision_total,
        "alert_truncated": alert_total > len(alerts),
        "decision_truncated": decision_total > len(decisions),
    }


def telegraf(general_raw: Any, output_raw: Any, status_raw: Any) -> dict[str, Any]:
    general, output = object_at(general_raw, "general"), object_at(output_raw, "output")
    v1, v2 = flag(output.get("influx_enable")), flag(output.get("influx_v2_enable"))
    return {
        "enabled": flag(general.get("enabled")),
        "running": service_running(status_raw),
        "output_influxdb": v1 or v2,
        "output_influxdb_v1": v1,
        "output_influxdb_v2": v2,
        "output_graphite": flag(output.get("graphite_enable")),
        "output_prometheus": flag(output.get("prometheus_enable")),
        "influx_url": public_url(output.get("influx_url", "")),
        "influx_database": text(output.get("influx_database", "")),
        "influx_v2_url": public_url(output.get("influx_v2_url", "")),
    }


def monit(services_raw: Any, tests_raw: Any, alerts_raw: Any, status_raw: Any) -> dict[str, Any]:
    services, _ = recordset(services_raw)
    tests, _ = recordset(tests_raw)
    alerts, _ = recordset(alerts_raw)
    normalized_services = public_rows(
        services, ("name", "type", "address", "description"), identity="uuid"
    )
    normalized_tests = public_rows(tests, ("name", "condition", "action"), identity="uuid")
    normalized_alerts = public_rows(alerts, ("recipient", "events", "description"), identity="uuid")
    for originals, normalized in [(services, normalized_services), (alerts, normalized_alerts)]:
        for original, row in zip(originals, normalized, strict=True):
            row["enabled"] = flag(original.get("enabled"))
    return {
        "running": service_running(status_raw),
        "services": normalized_services,
        "tests": normalized_tests,
        "alerts": normalized_alerts,
        "service_count": len(services),
        "test_count": len(tests),
        "alert_count": len(alerts),
    }


def netflow(settings_raw: Any, status_raw: Any) -> dict[str, Any]:
    settings = object_at(settings_raw, "netflow")
    capture, collect = object_at(settings, "capture"), object_at(settings, "collect")
    targets = text(capture.get("targets"))
    interfaces = selected_options(capture.get("interfaces"))
    egress = selected_options(capture.get("egress_only"))
    version = selected_options(capture.get("version"))
    if len(version) != 1 or version[0] not in {"v5", "v9"}:
        raise ValueError("Invalid NetFlow version")
    return {
        "enabled": bool(interfaces and targets.strip()),
        "running": service_running(status_raw, netflow=True),
        "interfaces": ", ".join(interfaces),
        "egress_interfaces": ", ".join(egress),
        "egress_only": bool(egress),
        "version": version[0][1:],
        "collect_enabled": flag(collect.get("enable")),
    }
