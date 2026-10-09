"""Read-only client contracts from pinned OPNsense producers, not device captures.

Core cdde38bee141a71733638a645600f68126ce1af7: Core/FirmwareController,
Diagnostics/SystemController, Routing/SettingsController, gateway_status.php
and src/etc/inc/plugins.inc.d/dpinger.inc (none also means no monitor alarm).
"""

import asyncio
import copy
import json

import pytest

from tests.adapters.test_opnsense_remaining_inventory_contracts import (
    read,
    recordset,
    summary_wire,
)

FIRMWARE = "/api/core/firmware/status"
INFORMATION = "/api/diagnostics/system/system_information"
TIME = "/api/diagnostics/system/system_time"
HEALTH = "/api/routes/gateway/status"
ROUTING = "/api/routing/settings/search_gateway"
METHODS = {
    "get_system_info": [INFORMATION, TIME, FIRMWARE],
    "get_firmware_info": [FIRMWARE],
    "get_gateway_status": [HEALTH, ROUTING],
}


def wire():
    data = summary_wire()
    data[FIRMWARE]["product"].update(
        product_name="OPNsense",
        product_arch="amd64",
        product_id="opnsense",
        product_series="26.7",
        product_latest="26.7.1",
    )
    data[HEALTH]["items"] = [data[HEALTH]["items"][1]]
    data[HEALTH]["items"][0].update(stddev="0.1 ms", monitor="192.0.2.1")
    return data


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,check,available",
    [
        ("none", None, None),
        ("none", {}, False),
        ("update", {}, True),
        ("upgrade", {}, True),
    ],
)
async def test_firmware_uses_nested_product_and_check_state(state, check, available):
    data = wire()
    data[FIRMWARE]["status"] = state
    data[FIRMWARE]["product"]["product_check"] = check
    # Reboot requirements do not determine whether an update is available.
    data[FIRMWARE].update(needs_reboot="1", upgrade_needs_reboot="1")
    result, requests = await read("get_firmware_info", data)
    assert result.success and result.data["current_version"] == "26.7"
    assert result.data["latest_version"] == "26.7.1"
    assert result.data.get("update_available") is available
    assert result.data.get("needs_update") is available
    assert requests == [("GET", FIRMWARE)]


@pytest.mark.asyncio
async def test_firmware_missing_latest_and_uncollected_fields_stay_unknown():
    data = wire()
    del data[FIRMWARE]["product"]["product_latest"]
    result, _ = await read("get_firmware_info", data)
    assert result.success and result.data["current_version"] == "26.7"
    assert result.data.get("latest_version") is None
    assert result.data.get("last_check") is None
    assert result.data.get("download_size") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        [],
        {"status": "error"},
        {"status": "error", "product": {"product_version": "26.7"}},
        {"status": "none", "product": {}},
        {"product_version": "26.7"},
        {"status": "unexpected", "product": {"product_version": "26.7"}},
    ],
)
async def test_missing_or_failed_firmware_cannot_be_success(bad):
    data = wire()
    data[FIRMWARE] = bad
    result, _ = await read("get_firmware_info", data)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["product_version", "product_latest", "product_name", "product_arch"]
)
@pytest.mark.parametrize("bad", [False, [], {"private": "owned-marker"}])
async def test_invalid_firmware_product_fields_are_not_coerced(field, bad):
    data = wire()
    data[FIRMWARE]["product"][field] = bad
    result, _ = await read("get_firmware_info", data)
    assert not result.success


@pytest.mark.asyncio
async def test_firmware_does_not_expose_mirror_subscription_or_extra_metadata():
    data = wire()
    for target in [data[FIRMWARE], data[FIRMWARE]["product"]]:
        target.update(
            product_mirror="https://subscription:owned-marker@example.test/",
            product_repo={"password": "owned-marker"},
            api_secret="owned-marker",
        )
    result, _ = await read("get_firmware_info", data)
    assert result.success and "owned-marker" not in json.dumps(result.data)
    assert result.data.get("mirror_url") is None


@pytest.mark.asyncio
async def test_system_info_reads_identity_time_and_structured_product():
    data = wire()
    data[INFORMATION]["versions"] = ["translated opaque version text"]
    result, requests = await read("get_system_info", data)
    assert result.success
    assert result.data["hostname"] == result.data["fqdn"] == "owned-fw.example.test"
    assert result.data["version"] == "26.7" and result.data["architecture"] == "amd64"
    assert result.data["uptime_text"] == "1 day"
    assert result.data.get("domain") in (None, "")
    assert result.data.get("cpu_usage_pct") is None and result.data.get("uptime") is None
    assert result.data.get("kernel_version") in (None, "")
    assert set(requests) == {("GET", p) for p in METHODS["get_system_info"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,field", [(INFORMATION, "name"), (TIME, "uptime")])
@pytest.mark.parametrize("bad", [None, "", " ", False, [], {}])
async def test_required_system_information_cannot_be_blank_or_coerced(endpoint, field, bad):
    data = wire()
    data[endpoint][field] = bad
    result, _ = await read("get_system_info", data)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,expected",
    [
        ("none", "online"),
        ("online", "online"),
        ("down", "offline"),
        ("force_down", "offline"),
        ("pending", "pending"),
        ("loss", "loss"),
        ("delay", "delay"),
        ("delay+loss", "loss"),
        ("future-state", "unknown"),
    ],
)
async def test_health_uses_machine_status_and_real_default_inventory(state, expected):
    data = wire()
    data[HEALTH]["items"][0].update(status=state, status_translated="En ligne")
    result, requests = await read("get_gateway_status", data)
    assert result.success and result.data["count"] == 1
    row = result.data["gateways"][0]
    assert row["status"] == expected
    assert row["default_gateway"] is True and row["interface"] == "wan"
    assert row["loss_pct"] == row["delay_ms"] == 0 and row["stddev_ms"] == 0.1
    assert set(requests) == {("GET", HEALTH), ("GET", ROUTING)}


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get_gateway_status", "get_device_summary"])
@pytest.mark.parametrize("missing", [None, "~", ""])
async def test_none_without_monitor_samples_does_not_mean_healthy_zero(method, missing):
    data = wire()
    data[HEALTH]["items"][0].update(status="none", loss=missing, delay=missing, stddev=missing)
    result, _ = await read(method, data)
    assert result.success
    row = result.data["gateways"][0] if method == "get_gateway_status" else result.data
    prefix = "" if method == "get_gateway_status" else "wan_"
    assert row[prefix + "status"] == "none"
    assert row.get(prefix + "loss_pct") is None and row.get(prefix + "delay_ms") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "loss,delay", [("0.0 %", "2.1 ms"), ("0%", "0 ms"), ("~", "0 ms"), ("0%", "~")]
)
async def test_summary_preserves_reported_no_alarm_samples(loss, delay):
    data = wire()
    data[HEALTH]["items"][0].update(status="none", loss=loss, delay=delay)
    result, _ = await read("get_device_summary", data)
    assert result.success and result.data["wan_status"] == "online"
    assert result.data.get("wan_loss_pct") == (None if loss == "~" else 0)
    assert result.data.get("wan_delay_ms") == (
        None if delay == "~" else float(delay.removesuffix(" ms"))
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["none", "online"])
@pytest.mark.parametrize("field", ["loss", "delay", "stddev"])
@pytest.mark.parametrize("bad", ["nan", "inf", "-1", False, [], {"private": "owned-marker"}])
async def test_malformed_monitor_values_are_unavailable(state, field, bad):
    data = wire()
    data[HEALTH]["items"][0].update(status=state, **{field: bad})
    result, _ = await read("get_gateway_status", data)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        [],
        {"status": "failed", "items": []},
        {"status": "ok", "items": [None]},
        {"status": "ok", "items": [{}]},
    ],
)
async def test_health_inventory_is_complete_or_unavailable(bad):
    data = wire()
    data[HEALTH] = bad
    result, _ = await read("get_gateway_status", data)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "duplicate-status",
        "duplicate-config",
        "truncated-config",
        "invalid-default",
        "missing-name",
        "loss-over-100",
    ],
)
async def test_health_ambiguity_and_invalid_flags_cannot_be_silently_accepted(change):
    data = wire()
    if change == "duplicate-status":
        data[HEALTH]["items"].append(copy.deepcopy(data[HEALTH]["items"][0]))
    elif change == "duplicate-config":
        rows = data[ROUTING]["rows"]
        data[ROUTING] = recordset([rows[0], copy.deepcopy(rows[0])])
    elif change == "truncated-config":
        data[ROUTING]["total"] = 2
    elif change == "invalid-default":
        data[ROUTING]["rows"][0]["defaultgw"] = "unknown"
    elif change == "missing-name":
        data[HEALTH]["items"][0]["name"] = ""
    else:
        data[HEALTH]["items"][0]["loss"] = "101%"
    result, _ = await read("get_gateway_status", data)
    assert not result.success


@pytest.mark.asyncio
async def test_explicit_empty_health_inventory_is_valid():
    data = wire()
    data[HEALTH]["items"] = []
    data[ROUTING] = recordset([])
    result, _ = await read("get_gateway_status", data)
    assert result.success and result.data == {"gateways": [], "count": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize("method,endpoint", [(m, p) for m, paths in METHODS.items() for p in paths])
@pytest.mark.parametrize("cancel", [False, True])
async def test_each_required_read_failure_is_safe_and_cancellation_propagates(
    method, endpoint, cancel, caplog
):
    data = wire()
    data[endpoint] = (
        asyncio.CancelledError() if cancel else RuntimeError("owned-private-diagnostic")
    )
    if cancel:
        with pytest.raises(asyncio.CancelledError):
            await read(method, data)
    else:
        result, _ = await read(method, data)
        assert not result.success
        assert "owned-private-diagnostic" not in json.dumps(result.data)
        assert "owned-private-diagnostic" not in caplog.text
