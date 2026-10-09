# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native guest/host contracts, incomplete visibility and bounded read behavior."""

import asyncio
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from app.adapters.proxmox import sdn_attachments as attachments
from tests.adapters.test_proxmox_write_outcomes import connected

DIGEST = "a" * 40


def fixture(request):
    assert request.method == "GET"
    path, params = request.url.path, request.url.params
    if path == "/cluster/resources":
        if params["type"] == "node":
            return [{"type": "node", "node": "pve1"}, {"type": "node", "node": "pve2"}]
        return [
            {"type": "qemu", "node": "pve1", "vmid": 101},
            {"type": "lxc", "node": "pve2", "vmid": 102},
        ]
    if path == "/cluster/sdn/vnets":
        return [{"vnet": "old" if params.get("running") else "new", "password": "hidden-vnet"}]
    if path.endswith("/network"):
        assert dict(params) == {"type": "include_sdn"}
        return [
            {
                "iface": "old" if "/pve1/" in path else "new",
                "type": "vnet",
                "active": "1",
                "exists": 0,
                "bridge_ports": "none",
                "options": ["secret-option"],
                "address": "hidden-address",
                "comments": "hidden-comment",
            }
        ]
    assert path.endswith("/config")
    if "/qemu/" in path:
        net = "virtio=AA:BB:CC:DD:EE:FF,bridge=old,tag=20,trunks=10;30-40,firewall=0,link_down=1"
        return {
            "digest": DIGEST,
            "net0": net if params.get("current") else net.replace("bridge=old", "bridge=new"),
            "cipassword": "hidden-password",
            "args": "hidden-args",
            "sshkeys": "hidden-keys",
        }
    return (
        {"digest": DIGEST, "net1": "name=eth0,bridge=new,ip=10.0.0.2/24,gw=10.0.0.1"}
        if params.get("current")
        else {"digest": DIGEST}
    )


async def inspect(dispatch):
    adapter, client = connected(dispatch)
    try:
        return await adapter.inspect_sdn_attachments(uuid4())
    finally:
        await client._http.aclose()


async def test_current_pending_removal_and_node_scoped_links_withhold_unrelated_config():
    calls = []

    def dispatch(request):
        calls.append(request)
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    assert len(calls) == result.requests_made == 10
    assert result.request_limit == 76
    assert not result.connectivity_verified and not result.dependency_graph_complete
    assert not result.atomic_snapshot and not result.writes_enabled
    assert result.guest_inventory.visible_count == result.guest_inventory.selected == 2
    assert result.guest_inventory.visibility_complete is False
    current, pending, lxc, deleted = result.guests
    assert current.view == "current" and pending.view == "pending_merged"
    assert current.nics[0].running_vnet == current.nics[0].host_interface == "visible"
    assert current.nics[0].configured_vnet == "not_visible"
    assert pending.nics[0].configured_vnet == "visible"
    assert pending.nics[0].host_interface == "not_visible"  # Same name exists on pve2, not pve1.
    assert current.nics[0].firewall is False and current.nics[0].link_down is True
    assert current.nics[0].trunks == "10;30-40" and current.nics[0].tag == 20
    assert lxc.nics[0].host_interface == "visible" and deleted.nics == []
    assert (
        "hidden-" not in result.model_dump_json()
        and "secret-option" not in result.model_dump_json()
    )
    assert "AA:BB" not in result.model_dump_json() and DIGEST not in result.model_dump_json()
    assert result.hosts[0].interfaces[0].exists is False
    assert result.hosts[0].interfaces[0].bridge_ports == []
    assert result.hosts[0].omitted_fields > 0 and current.omitted_fields > 0


@pytest.mark.parametrize(
    "path",
    [
        "/cluster/resources",
        "/cluster/sdn/vnets",
        "/nodes/pve1/network",
        "/nodes/pve1/qemu/101/config",
    ],
)
@pytest.mark.parametrize(
    "status,expected", [(403, "denied"), (404, "unsupported_or_missing"), (500, "unavailable")]
)
async def test_denied_missing_and_failed_reads_are_not_empty(path, status, expected):
    def dispatch(request):
        if request.url.path == path:
            return httpx.Response(status, json={"errors": {"secret": "hidden-diagnostic"}})
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    if path == "/cluster/resources":
        assert result.guest_inventory.status == result.node_inventory.status == expected
        assert (
            result.guest_inventory.visible_count is None and not result.guests and not result.hosts
        )
    elif path == "/cluster/sdn/vnets":
        assert all(v.status == expected and v.identities is None for v in result.vnets)
        assert result.guests[0].nics[0].configured_vnet == "target_unavailable"
    elif path.endswith("/network"):
        assert result.hosts[0].status == expected and result.hosts[0].interfaces is None
        assert result.guests[0].nics[0].host_interface == "target_unavailable"
    else:
        assert result.guests[0].status == expected and result.guests[0].nics is None
        assert result.guests[2].status == "available"
    assert "hidden-diagnostic" not in result.model_dump_json()


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        [None],
        [{"type": "qemu", "vmid": True, "node": "pve1"}],
        [{"type": "qemu", "vmid": 101, "node": "../escape"}],
        [{"type": "lxc", "vmid": 101}],
        [{"type": "qemu", "vmid": 101, "node": "pve1"}] * 2,
    ],
)
async def test_invalid_inventory_never_forms_a_guest_path(raw):
    calls = []

    def dispatch(request):
        calls.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "data": raw
                if request.url.path == "/cluster/resources" and request.url.params["type"] == "vm"
                else fixture(request)
            },
        )

    result = await inspect(dispatch)
    assert (
        result.guest_inventory.status == "invalid" and result.guest_inventory.visible_count is None
    )
    assert not result.guests and not any("/config" in path for path in calls)


@pytest.mark.parametrize(
    "value",
    [
        "bridge=x,bridge=y",
        "bridge=../escape",
        "bridge=",
        "tag=4095",
        "tag=True",
        "trunks=40-30",
        "trunks=1;5000",
        "firewall=yes",
        "link_down=2",
        "bridge=ok\nsecret",
        "virtio,model=e1000",
        {"bridge": "x"},
    ],
)
def test_ambiguous_or_malformed_nic_fields_are_rejected(value):
    with pytest.raises(ValueError):
        attachments.nics({"digest": DIGEST, "net0": value})


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {"digest": True},
        {"digest": DIGEST, "net256": "bridge=x"},
        {"digest": DIGEST, "net01": "bridge=x"},
        {"digest": DIGEST, "password": "x" * 262145},
    ],
)
def test_malformed_or_oversized_config_is_not_no_nics(raw):
    with pytest.raises(ValueError):
        attachments.nics(raw)


def test_default_model_no_bridge_and_native_member_fields():
    rows, _ = attachments.nics(
        {"digest": DIGEST, "net0": "virtio,firewall=1", "net1": "bridge=deleted"}
    )
    assert "bridge" not in rows[0] and rows[1]["bridge"] == "deleted"
    rows, omitted = attachments.interfaces(
        [
            {
                "iface": "bond0.20",
                "type": "OVSBond",
                "slaves": "enp1s0 enp2s0",
                "ovs_ports": "tap101i0",
                "ovs_bonds": "bond0",
                "vlan-raw-device": "bond0",
                "active": 0,
                "options6": ["hidden"],
            }
        ]
    )
    assert rows[0]["slaves"] == ["enp1s0", "enp2s0"] and rows[0]["vlan_raw_device"] == "bond0"
    assert omitted == 1


@pytest.mark.parametrize(
    "raw",
    [
        {},
        [None],
        [{"iface": "x", "type": "bridge", "active": "false"}],
        [{"iface": "x", "type": "bridge", "bridge_ports": ["x"]}],
        [{"iface": "x", "type": "bridge"}] * 2,
    ],
)
def test_malformed_interface_report_is_rejected(raw):
    with pytest.raises(ValueError):
        attachments.interfaces(raw)


async def test_no_bridge_and_literal_deleted_vnet_are_not_confused_with_pending_removal():
    def dispatch(request):
        data = fixture(request)
        if request.url.path.endswith("/config"):
            data = {"digest": DIGEST, "net0": "virtio", "net1": "bridge=deleted"}
        if request.url.path.endswith("/vnets"):
            data = [{"vnet": "deleted"}]
        return httpx.Response(200, json={"data": data})

    result = await inspect(dispatch)
    assert (
        result.guests[0].nics[0].configured_vnet
        == result.guests[0].nics[0].host_interface
        == "no_bridge"
    )
    assert result.guests[0].nics[1].configured_vnet == "visible"


async def test_selection_limits_are_deterministic_and_never_promote_completeness():
    calls = []

    def dispatch(request):
        calls.append(request)
        data = fixture(request)
        if request.url.path == "/cluster/resources":
            data = (
                [{"type": "node", "node": f"pve{i}"} for i in range(9)]
                if request.url.params["type"] == "node"
                else [
                    {"type": "qemu", "node": "pve8", "vmid": i} for i in reversed(range(100, 135))
                ]
            )
        return httpx.Response(200, json={"data": data})

    result = await inspect(dispatch)
    assert result.requests_made == 76 and len(calls) == 76
    assert (
        result.guest_inventory.omitted_by_limit == 3 and result.node_inventory.omitted_by_limit == 1
    )
    assert {g.vmid for g in result.guests} == set(range(100, 132))
    assert result.guests[0].nics[0].host_interface == "not_observed"
    assert not result.dependency_graph_complete


async def test_aggregate_budget_discards_collection_instead_of_truncating_silently(monkeypatch):
    monkeypatch.setattr(attachments, "MAX_BYTES", 1)
    result = await inspect(lambda r: httpx.Response(200, json={"data": fixture(r)}))
    assert result.response_limit_reached and result.guest_inventory.reason == "response_limit"
    assert result.guest_inventory.visible_count is None and not result.guests
    assert all(v.identities is None and v.status == "not_observed" for v in result.vnets)


async def test_global_deadline_limits_concurrency_and_queued_reads(monkeypatch):
    monkeypatch.setattr(attachments, "DEADLINE_SECONDS", 0.03)
    active = peak = calls = 0

    async def dispatch(request):
        nonlocal active, peak, calls
        calls += 1
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(1)
            return httpx.Response(200, json={"data": fixture(request)})
        finally:
            active -= 1

    result = await inspect(dispatch)
    assert active == 0 and peak == 3 and calls == result.requests_made == 3
    assert result.guest_inventory.reason == result.node_inventory.reason == "inspection_deadline"
    assert all(v.reason == "inspection_deadline" for v in result.vnets)


async def test_cancellation_propagates_and_drains_native_reads():
    entered = asyncio.Event()
    active = 0

    async def dispatch(request):
        nonlocal active
        active += 1
        entered.set()
        try:
            await asyncio.sleep(10)
            return httpx.Response(200, json={"data": fixture(request)})
        finally:
            active -= 1

    task = asyncio.create_task(inspect(dispatch))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert active == 0


async def test_retry_counter_is_logical_not_http_attempts(monkeypatch):
    attempts = 0

    def dispatch(request):
        nonlocal attempts
        if request.url.path == "/cluster/sdn/vnets" and not request.url.params:
            attempts += 1
            if attempts < 3:
                return httpx.Response(503, json={"errors": "hidden-retry-error"})
        return httpx.Response(200, json={"data": fixture(request)})

    adapter, client = connected(dispatch)
    monkeypatch.setattr(client, "_retry_backoff", AsyncMock())
    try:
        result = await adapter.inspect_sdn_attachments(uuid4())
    finally:
        await client._http.aclose()
    assert result.requests_made == 10 and attempts == 3
    assert result.vnets[0].status == "available" and "hidden-retry" not in result.model_dump_json()
