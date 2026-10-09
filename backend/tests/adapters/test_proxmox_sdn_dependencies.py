# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native read contracts, bounded fan-out and explicit incomplete dependency views."""

import asyncio
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from app.adapters.proxmox import sdn_dependencies as deps
from tests.adapters.test_proxmox_write_outcomes import connected


def fixture(request):
    assert request.method == "GET"
    path = request.url.path
    if path == "/cluster/sdn/route-maps/entries":
        return [
            {
                "route-map-id": "rm1",
                "order": 10,
                "action": "permit",
                "match": ["key=ip-address-prefix-list,value=pl1"],
                "set": [],
            }
        ]
    if path == "/cluster/sdn/prefix-lists" and request.url.params.get("verbose") == "1":
        return [
            {
                "id": "pl1",
                "entries": ["action=permit,prefix=10.0.0.0/8,seq=10"],
                "password": "hidden-policy-secret",
            }
        ]
    if path.endswith("/subnets"):
        parent = path.split("/")[-2]
        return [{"subnet": "z1-10.0.0.0-24", "vnet": parent, "gateway": "10.0.0.1", "snat": 0}]
    return {
        "/cluster/sdn/zones": [{"zone": "z1", "ipam": "ip1", "dns": "dns1", "controller": "c1"}],
        "/cluster/sdn/vnets": [{"vnet": "v1", "zone": "z1"}],
        "/cluster/sdn/controllers": [{"controller": "c1", "password": "hidden-controller-secret"}],
        "/cluster/sdn/ipams": [
            {
                "ipam": "ip1",
                "type": "netbox",
                "token": "hidden-ipam-secret",
                "url": "https://hidden.invalid/",
            }
        ],
        "/cluster/sdn/dns": [{"dns": "dns1", "type": "powerdns", "key": "hidden-dns-secret"}],
        "/cluster/sdn/fabrics/all": {
            "fabrics": [{"id": "f1", "protocol": "openfabric", "route_filter": "pl1"}],
            "nodes": [
                {
                    "node_id": "pve1",
                    "fabric_id": "f1",
                    "protocol": "openfabric",
                    "private_key": "hidden-wireguard-secret",
                }
            ],
        },
        "/cluster/sdn/prefix-lists": [{"id": "pl1", "entries": [{"private": "hidden-entry"}]}],
        "/cluster/sdn/route-maps": [{"id": "rm1"}],
    }[path]


async def inspect(handler):
    adapter, client = connected(handler)
    try:
        return await adapter.inspect_sdn_dependencies(uuid4())
    finally:
        await client._http.aclose()


async def test_native_endpoint_views_references_and_secret_allowlist():
    calls = []

    def dispatch(request):
        calls.append(request)
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    assert len(calls) == result.requests_made == 28
    assert (
        not result.writes_enabled
        and not result.atomic_snapshot
        and not result.dependency_graph_complete
    )
    assert (
        result.pending_state == "unknown"
    )  # Identical catalogues do not prove nested policies unchanged.
    assert not result.subnet_parent_inventory_complete
    assert result.subnet_parents_selected == 1
    assert result.references and all(r.status == "visible" for r in result.references)
    assert "hidden-" not in result.model_dump_json()
    assert sum(c.omitted_fields for c in result.collections) > 0
    for request in calls:
        if request.url.path.endswith(("/ipams", "/dns")):
            assert not request.url.params
        if request.url.path.endswith("/route-maps"):
            assert "pending" not in request.url.params
        if request.url.path.endswith("/prefix-lists"):
            assert request.url.params["verbose"] in ("0", "1")
    not_exposed = [c for c in result.collections if c.reason == "view_not_exposed"]
    assert len(not_exposed) == 5 and all(c.items is None for c in not_exposed)
    assert "policy_evaluation_and_enforcement" in result.unobserved_dependencies


async def test_collection_read_count_does_not_claim_to_count_transport_retries(monkeypatch):
    calls = []
    ipam_attempts = 0

    def dispatch(request):
        nonlocal ipam_attempts
        calls.append(request)
        if request.url.path.endswith("/ipams"):
            ipam_attempts += 1
            if ipam_attempts < 3:
                return httpx.Response(503, json={"errors": {"secret": "withheld-transient-error"}})
        return httpx.Response(200, json={"data": fixture(request)})

    adapter, client = connected(dispatch)
    monkeypatch.setattr(client, "_retry_backoff", AsyncMock())
    try:
        result = await adapter.inspect_sdn_dependencies(uuid4())
    finally:
        await client._http.aclose()
    assert result.requests_made == 28 and len(calls) == 30 and ipam_attempts == 3
    assert all(request.method == "GET" for request in calls)
    assert "withheld-transient-error" not in result.model_dump_json()
    assert next(c for c in result.collections if c.resource == "ipams").status == "available"


@pytest.mark.parametrize(
    "path",
    ["zones", "vnets", "controllers", "ipams", "dns", "fabrics/all", "prefix-lists", "route-maps"],
)
@pytest.mark.parametrize(
    "status,expected", [(403, "denied"), (404, "unsupported_or_missing"), (500, "unavailable")]
)
async def test_failed_collections_are_not_successful_empty_inventory(path, status, expected):
    def dispatch(request):
        if request.url.path == "/cluster/sdn/" + path:
            return httpx.Response(status, json={"errors": {"secret": "never-return-diagnostic"}})
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    resource = path.split("/")[0]
    failed = [
        c for c in result.collections if c.resource == resource and c.reason != "view_not_exposed"
    ]
    assert failed and all(c.status == expected and c.items is None for c in failed)
    assert "never-return" not in result.model_dump_json()
    assert result.pending_state == "unknown" and not result.dependency_graph_complete
    if path == "vnets":
        assert not result.subnet_parents_selected
        assert any(c.reason == "parent_inventory_unavailable" for c in result.collections)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        [None],
        [{"id": "../escape"}],
        [{"id": "x"}, {"id": "x"}],
        [{"id": "x", "state": "OK"}],
        [{"id": "x", "pending": []}],
        [{"id": "x", "secret": "x" * 262145}],
    ],
)
def test_malformed_or_oversized_catalogues_fail_closed(raw):
    with pytest.raises(ValueError):
        deps.collection(raw, "route-maps")


@pytest.mark.parametrize(
    "raw", [[], {"fabrics": []}, {"fabrics": [], "nodes": [], "credentials": "secret"}]
)
async def test_fabric_envelope_does_not_guess_a_missing_node_collection(raw):
    def dispatch(request):
        return httpx.Response(
            200,
            json={"data": raw if request.url.path.endswith("/fabrics/all") else fixture(request)},
        )

    result = await inspect(dispatch)
    assert all(
        c.status == "invalid" and c.items is None
        for c in result.collections
        if c.resource in ("fabrics", "fabric-nodes")
    )


@pytest.mark.parametrize("value", ["../escape", "vnet/other", "bad\nname", 1, {"secret": True}])
def test_unsafe_vnet_references_are_rejected(value):
    with pytest.raises(ValueError):
        deps.collection([{"vnet": "v1", "zone": value}], "vnets")


@pytest.mark.parametrize(
    "subnet", ["z1-10.0.0.0-24", "z1-2001:db8::-64", "10.0.0.0/24", "2001:db8::/64"]
)
def test_native_subnet_id_formats_are_displayed_without_building_urls(subnet):
    rows, _ = deps.collection([{"subnet": subnet, "vnet": "v1", "snat": "0"}], "subnets", "v1")
    assert rows[0]["subnet"] == subnet and rows[0]["snat"] is False


@pytest.mark.parametrize(
    "row",
    [
        {"subnet": "../bad", "vnet": "v1"},
        {"subnet": "z1-10.0.0.0-99", "vnet": "v1"},
        {"subnet": "z1-10.0.0.0-24", "vnet": "v2"},
        {"subnet": "z1-10.0.0.0-24", "vnet": "v1", "pending": {"vnet": "v2"}},
        {"subnet": "z1-10.0.0.0-24", "vnet": "v1", "gateway": "https://private.invalid"},
        {"subnet": "z1-10.0.0.0-24", "vnet": "v1", "snat": "false"},
    ],
)
def test_subnet_identity_parent_and_flag_validation(row):
    with pytest.raises(ValueError):
        deps.collection([row], "subnets", "v1")


async def test_subnet_fanout_uses_union_of_all_visible_vnet_views_and_is_bounded(monkeypatch):
    monkeypatch.setattr(deps, "MAX_VNETS", 2)
    calls = []

    def dispatch(request):
        calls.append(request)
        raw = fixture(request)
        if request.url.path.endswith("/vnets"):
            raw = [
                {
                    "vnet": "new"
                    if not request.url.params
                    else "old"
                    if "running" in request.url.params
                    else "third",
                    "zone": "z1",
                }
            ]
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    assert result.subnet_parents_selected == 2 and result.subnet_parents_omitted_by_limit == 1
    parents = {r.url.path.split("/")[-2] for r in calls if r.url.path.endswith("/subnets")}
    assert parents == {"new", "old"}
    assert result.requests_made == 31 and result.pending_state == "changes_detected"


async def test_concurrency_deadline_preserves_completed_reads_without_late_dispatch(monkeypatch):
    monkeypatch.setattr(deps, "DEADLINE_SECONDS", 0.03)
    active = maximum = 0
    calls = []

    async def dispatch(request):
        nonlocal active, maximum
        calls.append(request)
        active += 1
        maximum = max(maximum, active)
        try:
            if not request.url.path.endswith("/zones"):
                await asyncio.Future()
            return httpx.Response(200, json={"data": fixture(request)})
        finally:
            active -= 1

    result = await asyncio.wait_for(inspect(dispatch), 1)
    assert maximum <= 3 and active == 0
    assert any(c.resource == "zones" and c.status == "available" for c in result.collections)
    assert any(c.reason == "inspection_deadline" and c.items is None for c in result.collections)
    assert len(calls) == result.requests_made < 19


async def test_external_cancellation_is_not_converted_to_a_successful_report():
    entered = asyncio.Event()

    async def dispatch(request):
        assert request.method == "GET"
        entered.set()
        await asyncio.Future()

    task = asyncio.create_task(inspect(dispatch))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("limit", ["MAX_TOTAL_ITEMS", "MAX_RESULT_BYTES"])
async def test_aggregate_item_limits_are_visible_not_silent_truncation(monkeypatch, limit):
    monkeypatch.setattr(deps, limit, 1)
    result = await inspect(lambda request: httpx.Response(200, json={"data": fixture(request)}))
    assert result.response_limit_reached
    assert any(c.reason == "response_limit" and c.items is None for c in result.collections)
    assert not result.dependency_graph_complete


@pytest.mark.parametrize(
    "mode,expected", [("empty", "not_visible"), ("denied", "target_unavailable")]
)
async def test_unresolved_reference_is_not_claimed_to_be_a_nonexistent_resource(mode, expected):
    def dispatch(request):
        if request.url.path.endswith("/ipams"):
            return httpx.Response(403 if mode == "denied" else 200, json={"data": []})
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    refs = [r for r in result.references if r.target_resource == "ipams"]
    assert refs and all(r.status == expected and r.target_view == "configured" for r in refs)


async def test_pending_subnet_deletion_is_kept_and_counts_as_a_visible_change():
    def dispatch(request):
        raw = fixture(request)
        if request.url.path.endswith("/subnets") and "pending" in request.url.params:
            raw[0].update(
                state="changed", pending={"gateway": "deleted", "password": "hidden-pending-secret"}
            )
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    subnet = next(c for c in result.collections if c.resource == "subnets" and c.view == "pending")
    assert subnet.items[0]["pending"] == {"gateway": "deleted"}
    assert result.pending_state == "changes_detected" and "hidden-" not in result.model_dump_json()


async def test_configured_reference_named_deleted_is_not_a_pending_removal_marker():
    def dispatch(request):
        raw = fixture(request)
        if request.url.path.endswith("/zones"):
            raw[0]["ipam"] = "deleted"
        if request.url.path.endswith("/ipams"):
            raw[0]["ipam"] = "deleted"
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    refs = [r for r in result.references if r.target_resource == "ipams"]
    assert len(refs) == 2  # Configured and running; no pending graph is inferred.
    assert all(r.target_id == "deleted" and r.status == "visible" for r in refs)


@pytest.mark.parametrize("parent", ["v1", "deleted"])
def test_subnet_parent_literal_deleted_is_not_a_configured_removal_marker(parent):
    raw = [{"subnet": "z1-10.0.0.0-24", "vnet": "deleted", "pending": {"vnet": parent}}]
    if parent == "deleted":
        rows, _ = deps.collection(raw, "subnets", parent)
        assert rows[0]["vnet"] == "deleted"
    else:
        with pytest.raises(ValueError, match="Ambiguous subnet parent"):
            deps.collection(raw, "subnets", parent)
