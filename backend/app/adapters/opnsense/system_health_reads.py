"""Normalize documented system, firmware and gateway-monitor read responses."""

from typing import Any

from app.adapters.opnsense.aggregate_inventory import complete_rows
from app.adapters.opnsense.device_summary_reads import required_text
from app.adapters.opnsense.gateway_observations import gateway_observation
from app.adapters.opnsense.models import (
    NormalizedFirmwareInfo,
    NormalizedGateway,
    NormalizedSystemInfo,
)
from app.adapters.opnsense.plugin_reads import flag, object_at, text


def product_metadata(raw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    firmware = object_at(raw)
    product = object_at(firmware, "product")
    required_text(product.get("product_version"))
    for key in (
        "product_name",
        "product_arch",
        "product_latest",
        "product_id",
        "product_target",
        "product_series",
    ):
        if key in product and product[key] is not None:
            text(product[key])
    return firmware, product


def firmware_info(raw: Any) -> dict[str, Any]:
    firmware, product = product_metadata(raw)
    state = required_text(firmware.get("status"))
    if state not in {"none", "update", "upgrade"}:
        raise ValueError("Firmware status is unavailable")
    checked = product.get("product_check")
    if checked is not None and not isinstance(checked, dict):
        raise ValueError("Invalid firmware check metadata")
    available = state in {"update", "upgrade"} if state != "none" or checked is not None else None
    data: dict[str, Any] = {
        "current_version": product["product_version"],
        "latest_version": product.get("product_latest") or None,
        "update_available": available,
        "needs_update": available,
    }
    for source, target in [
        ("product_name", "product_name"),
        ("product_id", "product_id"),
        ("product_target", "product_target"),
    ]:
        if product.get(source) is not None:
            data[target] = product[source]
    # Repository URLs can contain subscription credentials. Do not expose raw
    # firmware/product/check metadata or infer fields that were not observed.
    return NormalizedFirmwareInfo(**data).model_dump(exclude_unset=True)


def system_info(information: Any, clock: Any, firmware: Any) -> dict[str, Any]:
    info, times = object_at(information), object_at(clock)
    _, product = product_metadata(firmware)
    name = required_text(info.get("name"))
    data: dict[str, Any] = {
        "hostname": name,
        "fqdn": name,
        "version": product["product_version"],
        "uptime_text": required_text(times.get("uptime")),
    }
    for source, target in [
        ("product_arch", "architecture"),
        ("product_name", "product_name"),
        ("product_series", "product_series"),
    ]:
        if product.get(source) is not None:
            data[target] = product[source]
    return NormalizedSystemInfo(**data).model_dump(exclude_unset=True)


def gateway_health(raw: Any, routing: Any) -> dict[str, Any]:
    status = object_at(raw)
    items = status.get("items")
    if status.get("status") != "ok" or not isinstance(items, list):
        raise ValueError("Gateway status is unavailable")
    configured: dict[str, dict[str, Any]] = {}
    for row in complete_rows(routing, identity="uuid"):
        name = required_text(row.get("name"))
        if name in configured or name != name.strip():
            raise ValueError("Ambiguous gateway identity")
        if required_text(row.get("ipprotocol")) not in {"inet", "inet6"}:
            raise ValueError("Unknown gateway address family")
        configured[name] = {
            "interface": text(row.get("interface")),
            "default_gateway": flag(row.get("defaultgw")) and not flag(row.get("disabled")),
        }
        # Validate disabled even if defaultgw is false (no short-circuit escape).
        flag(row.get("disabled"))
    gateways = []
    names: set[str] = set()
    for value in items:
        row = object_at(value)
        name = required_text(row.get("name"))
        if name in names or name != name.strip() or name not in configured:
            raise ValueError("Gateway inventory is inconsistent")
        names.add(name)
        address = text(row.get("address", ""))
        monitor = text(row.get("monitor", ""))
        data = {
            "name": name,
            "address": "" if address == "~" else address,
            "monitor_ip": "" if monitor == "~" else monitor,
            "status_text": text(row.get("status_translated", "")),
            **configured[name],
            **gateway_observation(row),
        }
        gateways.append(NormalizedGateway(**data).model_dump(exclude_unset=True))
    return {"gateways": gateways, "count": len(gateways)}
