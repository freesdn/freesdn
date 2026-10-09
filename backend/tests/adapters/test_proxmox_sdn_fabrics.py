# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native fabric shapes, composite identity, secret boundaries and scoped references."""

import json

import httpx
import pytest

from app.adapters.proxmox import sdn_dependencies as deps
from app.adapters.proxmox import sdn_fabrics as fabric
from tests.adapters.test_proxmox_sdn_dependencies import fixture, inspect


def node(**fields):
    return {
        "fabric_id": "f1",
        "node_id": "pve1",
        "protocol": "wireguard",
        "role": "internal",
        **fields,
    }


def test_node_identity_is_scoped_to_fabric():
    rows, _ = fabric.collection([node(), node(fabric_id="f2")], "fabric-nodes")
    assert [r["node_key"] for r in rows] == ["f1_pve1", "f2_pve1"]
    with pytest.raises(ValueError):
        fabric.collection([node(), node()], "fabric-nodes")


def test_native_peer_properties_keep_only_known_nonsecret_fields():
    rows, omitted = fabric.collection(
        [
            node(
                interfaces=[
                    "name=wg0,listen_port=51820,public_key=hidden-key,ip6_ll=true,ip=192.0.2.1/24"
                ],
                peers=[
                    'type=internal,node=pve2,iface=wg0,node_iface=wg1,skip_route_generation=false,endpoint=hidden-endpoint,allowed_ips="192.0.2.0/24,2001:db8::/32"'
                ],
                private_key="hidden-private",
            )
        ],
        "fabric-nodes",
    )
    assert rows[0]["interfaces"] == [{"name": "wg0", "listen_port": 51820, "ip6_ll": True}]
    assert rows[0]["peers"] == [
        {
            "type": "internal",
            "node": "pve2",
            "iface": "wg0",
            "node_iface": "wg1",
            "skip_route_generation": False,
        }
    ]
    assert omitted == 5
    assert "hidden-" not in json.dumps(rows) and "192.0.2" not in json.dumps(rows)
    assert fabric.references(rows[0]) == [("peers[0].node", "fabric-nodes", "f1_pve2")]


@pytest.mark.parametrize(
    "resource,overlay,key",
    [
        ("fabrics", {"id": "f1", "protocol": "wireguard"}, "id"),
        ("fabric-nodes", node(), "node_key"),
    ],
)
def test_new_pending_identity_is_extracted_without_merging_fields(resource, overlay, key):
    rows, _ = fabric.collection([{"state": "new", "pending": overlay}], resource)
    assert rows[0][key] == ("f1" if key == "id" else "f1_pve1")
    assert rows[0]["identity_source"] == "pending"
    assert "protocol" not in rows[0] and rows[0]["pending"]["protocol"] == "wireguard"
    with pytest.raises(ValueError):
        fabric.collection([{"state": "changed", "pending": overlay}], resource)


def test_native_protocol_specific_interface_fields():
    cases = [
        (
            "openfabric",
            "name=eth0,hello_multiplier=10,ip=192.0.2.1/24",
            {"name": "eth0", "hello_multiplier": 10},
        ),
        (
            "ospf",
            "name=eth0,network_type=point-to-point,ip=192.0.2.1/24",
            {"name": "eth0", "network_type": "point-to-point"},
        ),
        ("bgp", "name=eth0,secret=hidden", {"name": "eth0"}),
    ]
    for protocol, value, expected in cases:
        rows, omitted = fabric.collection(
            [node(protocol=protocol, interfaces=[value])], "fabric-nodes"
        )
        assert rows[0]["interfaces"] == [expected] and omitted >= 1


def test_unknown_protocol_is_explicit_and_its_details_are_withheld():
    rows, omitted = fabric.collection(
        [node(protocol="future", interfaces=[{"password": "hidden"}], peers=["hidden"])],
        "fabric-nodes",
    )
    assert rows[0]["details_status"] == "unsupported_protocol"
    assert "interfaces" not in rows[0] and "peers" not in rows[0] and omitted == 3


def test_unknown_pending_protocol_is_not_decoded_as_the_running_protocol():
    rows, omitted = fabric.collection(
        [
            node(
                state="changed",
                pending={"protocol": "future", "interfaces": [{"secret": "hidden"}]},
            )
        ],
        "fabric-nodes",
    )
    assert rows[0]["protocol"] == "wireguard"
    assert rows[0]["pending"] == {"protocol": "future", "details_status": "unsupported_protocol"}
    assert omitted == 1 and "hidden" not in json.dumps(rows)


def test_pending_deletions_stay_in_overlay_and_identity_conflicts_fail():
    rows, _ = fabric.collection(
        [node(state="changed", pending={"interfaces": "deleted", "peers": None})], "fabric-nodes"
    )
    assert rows[0]["pending"] == {"interfaces": "deleted", "peers": None}
    with pytest.raises(ValueError):
        fabric.collection([node(pending={"fabric_id": "other"})], "fabric-nodes")


@pytest.mark.parametrize("target_fabric,status", [("f1", "visible"), ("f2", "not_observed")])
def test_interface_name_matches_stay_within_the_source_fabric(target_fabric, status):
    rows, _ = fabric.collection(
        [
            node(
                interfaces=["name=wg0"], peers=["type=internal,node=pve2,iface=wg0,node_iface=wg1"]
            ),
            node(fabric_id=target_fabric, node_id="pve2", interfaces=["name=wg1"]),
        ],
        "fabric-nodes",
    )
    fabric.annotate_interfaces(rows)
    peer = rows[0]["peers"][0]
    assert peer["local_interface_visibility"] == "visible"
    assert peer["remote_interface_visibility"] == status


def test_local_missing_and_external_peer_interfaces_are_distinct():
    rows, _ = fabric.collection(
        [node(peers=["type=external,node=offsite,iface=wg0"])], "fabric-nodes"
    )
    fabric.annotate_interfaces(rows)
    peer = rows[0]["peers"][0]
    assert peer["local_interface_visibility"] == "not_visible"
    assert peer["remote_interface_visibility"] == "not_applicable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("interfaces", ["name=../evil"]),
        ("interfaces", ["name=wg0,ip6_ll=yes"]),
        ("interfaces", ["name=wg0,listen_port=65536"]),
        ("interfaces", ["name=wg0"] * 2),
        ("interfaces", ["name=wg0"] * 65),
        ("peers", ["type=internal,node=pve2,iface=wg0"]),
        ("peers", ["type=external,node=../evil,iface=wg0"]),
        ("peers", ["type=external,node=pve2,iface=wg0,skip_route_generation=perhaps"]),
        ("peers", ["type=external,node=pve2,iface=wg0"] * 2),
    ],
)
def test_malformed_known_details_are_rejected(field, value):
    with pytest.raises(ValueError):
        fabric.collection([node(**{field: value})], "fabric-nodes")


async def test_native_fabric_memberships_and_peer_names_are_scoped_without_extra_requests():
    calls = []

    def dispatch(request):
        calls.append(request)
        raw = fixture(request)
        if request.url.path.endswith("/fabrics/all"):
            raw = {
                "fabrics": [
                    {"id": "f1", "protocol": "wireguard"},
                    {"id": "f2", "protocol": "wireguard"},
                ],
                "nodes": [
                    node(
                        interfaces=["name=wg0,public_key=hidden-key,listen_port=51820"],
                        peers=[
                            "type=internal,node=pve2,iface=wg0,node_iface=wg1,endpoint=hidden-endpoint"
                        ],
                    ),
                    node(fabric_id="f2", interfaces=["name=wg0"]),
                    node(fabric_id="f2", node_id="pve2", interfaces=["name=wg1"]),
                ],
            }
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    assert result.requests_made == len(calls) == 28 and result.request_limit == 121
    assert all(c.method == "GET" for c in calls)
    observations = [c for c in result.collections if c.resource == "fabric-nodes"]
    assert len(observations) == 3 and all(
        c.status == "available" and len(c.items) == 3 for c in observations
    )
    for observation in observations:
        peer = observation.items[0]["peers"][0]
        if observation.view == "pending":
            assert (
                "local_interface_visibility" not in peer
                and "remote_interface_visibility" not in peer
            )
        else:
            assert peer["local_interface_visibility"] == "visible"
            assert peer["remote_interface_visibility"] == "not_observed"
    refs = [r for r in result.references if r.field == "peers[0].node"]
    assert len(refs) == 2 and all(
        r.source_id == "f1_pve1" and r.target_id == "f1_pve2" and r.status == "not_visible"
        for r in refs
    )
    assert "hidden-" not in result.model_dump_json()
    assert result.pending_state == "unknown" and not result.dependency_graph_complete


async def test_native_new_pending_fabric_and_node_identity_is_preserved_without_graph_resolution():
    def dispatch(request):
        raw = fixture(request)
        if request.url.path.endswith("/fabrics/all") and "pending" in request.url.params:
            raw = {
                "fabrics": [{"state": "new", "pending": {"id": "new", "protocol": "wireguard"}}],
                "nodes": [
                    {
                        "state": "new",
                        "pending": node(
                            fabric_id="new",
                            interfaces=["name=wg0"],
                            peers=["type=external,node=offsite,iface=wg0"],
                            private_key="hidden-pending",
                        ),
                    }
                ],
            }
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    pending = [
        c
        for c in result.collections
        if c.view == "pending" and c.resource in {"fabrics", "fabric-nodes"}
    ]
    assert all(
        c.status == "available" and c.items[0]["identity_source"] == "pending" for c in pending
    )
    member = next(c.items[0] for c in pending if c.resource == "fabric-nodes")
    assert member["node_key"] == "new_pve1" and "interfaces" not in member
    assert member["pending"]["interfaces"] == [{"name": "wg0"}]
    assert "visibility" not in json.dumps(member["pending"]["peers"])
    assert not any(r.view == "pending" for r in result.references)
    assert result.pending_state == "changes_detected" and "hidden-" not in result.model_dump_json()


@pytest.mark.parametrize(
    "status,expected", [(403, "denied"), (404, "unsupported_or_missing"), (500, "unavailable")]
)
async def test_unreadable_native_fabrics_are_not_empty_or_leaked(status, expected):
    def dispatch(request):
        if request.url.path.endswith("/fabrics/all"):
            return httpx.Response(status, json={"errors": {"secret": "hidden-error"}})
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    failed = [c for c in result.collections if c.resource in {"fabrics", "fabric-nodes"}]
    assert len(failed) == 6 and all(c.status == expected and c.items is None for c in failed)
    assert "hidden-" not in result.model_dump_json()


@pytest.mark.parametrize(
    "bad",
    [
        node(interfaces=[{"name": "wg0"}]),
        node(interfaces=["name=wg0"] * 65),
        node(pending={"node_id": "other"}),
        {"fabric_id": "f1", "node_id": "pve1"},
    ],
)
async def test_invalid_node_details_do_not_discard_an_independent_valid_fabric_collection(bad):
    def dispatch(request):
        raw = fixture(request)
        if request.url.path.endswith("/fabrics/all"):
            raw["nodes"] = [bad]
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    assert all(c.status == "available" for c in result.collections if c.resource == "fabrics")
    assert all(
        c.status == "invalid" and c.items is None
        for c in result.collections
        if c.resource == "fabric-nodes"
    )


async def test_fabric_nested_details_use_the_shared_retention_budget(monkeypatch):
    monkeypatch.setattr(deps, "MAX_TOTAL_ITEMS", 2)

    class Client:
        async def get(self, path, params=None):
            return {
                "fabrics": [{"id": "f1", "protocol": "wireguard"}],
                "nodes": [node(interfaces=["name=wg0", "name=wg1"])],
            }

    result = await deps.Reader(Client()).read("fabrics", "configured")
    assert result[0].status == "available"
    assert result[1].status == "not_observed" and result[1].reason == "response_limit"
    assert result[1].items is None


def test_peer_interface_with_a_different_protocol_is_not_substituted():
    rows, _ = fabric.collection(
        [
            node(peers=["type=internal,node=pve2,iface=wg0,node_iface=wg1"]),
            node(node_id="pve2", protocol="ospf", interfaces=["name=wg1"]),
        ],
        "fabric-nodes",
    )
    fabric.annotate_interfaces(rows)
    assert rows[0]["peers"][0]["remote_interface_visibility"] == "not_observed"


@pytest.mark.parametrize(
    "protocol,properties",
    [
        ("openfabric", "name=eth0,hello_multiplier=1"),
        ("openfabric", "name=eth0,hello_multiplier=101"),
        ("ospf", "name=eth0,network_type=unknown"),
        ("wireguard", "name=wgtoolong"),
        ("bgp", "name=interface-is-too-long"),
    ],
)
def test_protocol_specific_interface_constraints_are_not_guessed(protocol, properties):
    with pytest.raises(ValueError):
        fabric.collection([node(protocol=protocol, interfaces=[properties])], "fabric-nodes")


async def test_remote_interface_matching_never_borrows_from_another_configuration_view():
    def dispatch(request):
        raw = fixture(request)
        if request.url.path.endswith("/fabrics/all"):
            remote_iface = "wg2" if "running" in request.url.params else "wg1"
            raw["nodes"] = [
                node(peers=["type=internal,node=pve2,iface=wg0,node_iface=wg1"]),
                node(node_id="pve2", interfaces=[f"name={remote_iface}"]),
            ]
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    for observation in result.collections:
        if observation.resource == "fabric-nodes" and observation.view != "pending":
            peer = observation.items[0]["peers"][0]
            assert peer["remote_interface_visibility"] == (
                "not_visible" if observation.view == "running" else "visible"
            )
    assert result.pending_state == "changes_detected"
