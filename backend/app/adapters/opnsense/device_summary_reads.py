"""Build a summary from observed identity, inventory and active-route data only."""

from ipaddress import ip_address, ip_interface
from typing import Any

from app.adapters.opnsense.aggregate_inventory import complete_rows
from app.adapters.opnsense.gateway_observations import gateway_observation
from app.adapters.opnsense.models import GatewayStatus, NormalizedDeviceSummary
from app.adapters.opnsense.plugin_reads import flag, object_at, text


def required_text(value: Any) -> str:
    result = text(value)
    if not result.strip():
        raise ValueError("Required device summary text is missing")
    return result


def device_summary(
    information: Any, clock: Any, firmware: Any, status: Any, interfaces: Any, routing: Any
) -> dict[str, Any]:
    info, times, fw = object_at(information), object_at(clock), object_at(firmware)
    product = object_at(fw, "product")
    result: dict[str, Any] = {
        "hostname": required_text(info.get("name")),
        "uptime_text": required_text(times.get("uptime")),
        "version": required_text(product.get("product_version")),
        "wan_status": GatewayStatus.UNKNOWN,
    }
    if not isinstance(interfaces, list):
        raise ValueError("Interface export is unavailable")
    up = down = unknown = 0
    configured: dict[str, dict[str, Any]] = {}
    for value in interfaces:
        row = object_at(value)
        state = required_text(row.get("status")).lower()
        identifier = text(row.get("identifier"))
        if identifier:
            if identifier in configured:
                raise ValueError("Duplicate configured interface")
            configured[identifier] = row
        if state in {"up", "associated"}:
            up += 1
        elif state in {"down", "no carrier"}:
            down += 1
        else:
            unknown += 1
    result.update(
        interface_count=len(interfaces),
        interfaces_up=up,
        interfaces_down=down,
        interfaces_unknown=unknown,
    )
    update_state = required_text(fw.get("status"))
    check = product.get("product_check")
    if check is not None and not isinstance(check, dict):
        raise ValueError("Invalid firmware check metadata")
    if update_state in {"update", "upgrade"}:
        result["firmware_update_available"] = True
    elif update_state == "none" and check is not None:
        result["firmware_update_available"] = False
    elif update_state not in {"none", "error"}:
        raise ValueError("Unknown firmware status")

    gateway_status = object_at(status)
    items = gateway_status.get("items")
    if gateway_status.get("status") != "ok" or not isinstance(items, list):
        raise ValueError("Gateway status is unavailable")
    reported: dict[str, dict[str, Any]] = {}
    for value in items:
        row = object_at(value)
        name = required_text(row.get("name"))
        if name in reported:
            raise ValueError("Duplicate gateway status")
        required_text(row.get("status"))
        reported[name] = row
    defaults: dict[str, list[dict[str, Any]]] = {"inet": [], "inet6": []}
    names: set[str] = set()
    for row in complete_rows(routing, identity="uuid"):
        name = required_text(row.get("name"))
        if name in names:
            raise ValueError("Duplicate configured gateway")
        names.add(name)
        family = required_text(row.get("ipprotocol"))
        if family not in defaults:
            raise ValueError("Unknown gateway address family")
        text(row.get("interface"))
        text(row.get("gateway"))
        active = flag(row.get("defaultgw"))
        disabled = flag(row.get("disabled"))
        if active and not disabled:
            defaults[family].append(row)
    # Prefer the explicit active IPv4 default; use IPv6 when no IPv4 default exists.
    selected = defaults["inet"] or defaults["inet6"]
    selection = "none" if not selected else "ambiguous" if len(selected) != 1 else "active_default"
    if len(selected) == 1:
        gateway = selected[0]
        name = gateway["name"]
        if name not in reported or gateway["interface"] not in configured:
            raise ValueError("Active gateway inventory is inconsistent")
        live, interface = reported[name], configured[gateway["interface"]]
        observation = gateway_observation(live)
        result["wan_status"] = observation["status"]
        family = gateway["ipprotocol"]
        version = 4 if family == "inet" else 6
        address = text(interface.get("addr4" if version == 4 else "addr6", ""))
        if address:
            parsed = ip_interface(address)
            if parsed.version != version:
                raise ValueError("WAN interface address family is inconsistent")
            result["wan_ip"] = str(parsed.ip)
        router = text(gateway["gateway"])
        if router and router != "~":
            parsed_router = ip_address(router)
            if parsed_router.version != version:
                raise ValueError("Gateway address family is inconsistent")
            result["wan_gateway"] = str(parsed_router)
        for source, target in [("loss_pct", "wan_loss_pct"), ("delay_ms", "wan_delay_ms")]:
            if observation[source] is not None:
                result[target] = observation[source]
    # Exclude model defaults for metrics, counters and settings not collected here.
    payload = NormalizedDeviceSummary(**result).model_dump(exclude_unset=True)
    return {**payload, "wan_selection": selection}
