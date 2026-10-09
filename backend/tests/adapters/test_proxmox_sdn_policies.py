# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native policy wire shapes, partial visibility and bounded read-only observations."""

import copy
import json

import httpx
import pytest

from app.adapters.proxmox import sdn_dependencies as deps
from app.adapters.proxmox import sdn_policies as policy
from tests.adapters.test_proxmox_sdn_dependencies import fixture, inspect

PREFIX = "prefix-list-entries"
ROUTE = "route-map-entries"


def route(**fields):
    return {"route-map-id": "rm1", "order": 10, "action": "permit", **fields}


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        [None],
        [route()] * 257,
        [route(secret="x" * 262145)],
        [route(secret=float("nan"))],
        [{"state": "new", "pending": {"route-map-id": "rm1", "order": 10}}],
    ],
)
def test_invalid_or_oversized_native_collections_are_rejected(raw):
    with pytest.raises(ValueError):
        policy.collection(raw, ROUTE)


def test_prefix_property_strings_preserve_numeric_order_ipv4_ipv6_and_empty_vectors():
    raw = [
        {"id": "empty"},
        {
            "id": "pl1",
            "entries": [
                "action=deny,prefix=2001:db8::/32,ge=48,le=64,seq=100",
                "action=permit,prefix=192.0.2.0/24,le=32,seq=2",
                "action=permit,prefix=0.0.0.0/0,seq=0",
            ],
        },
    ]
    before = copy.deepcopy(raw)
    rows, omitted = policy.collection(raw, PREFIX)
    assert raw == before and omitted == 0
    assert rows[0] == {"id": "empty", "entries": []}
    assert rows[1]["entries"] == [
        {"action": "permit", "prefix": "0.0.0.0/0", "seq": 0},
        {"action": "permit", "prefix": "192.0.2.0/24", "le": 32, "seq": 2},
        {"action": "deny", "prefix": "2001:db8::/32", "ge": 48, "le": 64, "seq": 100},
    ]


@pytest.mark.parametrize(
    "entries",
    [
        None,
        "action=permit,prefix=10.0.0.0/8,seq=10",
        [{"action": "permit", "prefix": "10.0.0.0/8", "seq": 10}],
        ["action=permit,prefix=10.0.0.0/8"],
        ["action=permit,prefix=10.0.0.0/8,seq=-1"],
        ["action=permit,prefix=10.0.0.0/8,seq=4294967296"],
        ["action=execute,prefix=10.0.0.0/8,seq=1"],
        ["action=permit,prefix=10.0.0.0/8,seq=1,seq=2"],
        ["action=permit,prefix=10.0.0.0/8,seq=1,ge=7"],
        ["action=permit,prefix=10.0.0.0/8,seq=1,le=33"],
        ["action=permit,prefix=2001:db8::/32,seq=1,le=129"],
        ["action=permit,prefix=10.0.0.0/8,seq=1,ge=24,le=16"],
        ["action=permit,prefix=10.0.0.0,seq=1"],
        ["action=permit,prefix=fe80::%eth0/64,seq=1"],
        ["action=permit,prefix=10.0.0.0/8,seq=1\n"],
        ["action=permit,prefix=10.0.0.0/8,seq=1,"],
        ["action=permit,prefix=10.0.0.0/8,seq=1"] * 2,
        ["action=permit,prefix=10.0.0.0/8,seq=1"] * 257,
    ],
)
def test_malformed_or_ambiguous_prefix_rules_fail_the_collection(entries):
    with pytest.raises(ValueError):
        policy.collection([{"id": "pl1", "entries": entries}], PREFIX)


def test_known_route_clauses_decode_without_exposing_property_strings_or_unknown_fields():
    rows, omitted = policy.collection(
        [
            route(
                match=[
                    "key=ip-address-prefix-list,value=pl1",
                    "key=ip6-address-prefix-list,value=pl6",
                    "key=ip-next-hop-prefix-list,value=nh1",
                    "key=ip6-next-hop-prefix-list,value=nh6",
                    "key=ip-next-hop-address,value=192.0.2.1",
                    "key=ip6-next-hop-address,value=2001:db8::1",
                    "key=route-type,value=macip",
                    "key=vni,value=16777215",
                    "key=tag,value=untagged",
                    "key=metric,value=4294967295",
                    "key=local-preference,value=0",
                    "key=peer,value=local",
                    "key=peer,value=192.0.2.2",
                ],
                **{
                    "set": [
                        "key=ip-next-hop-peer-address",
                        "key=ip-next-hop-unchanged",
                        "key=ip6-next-hop-peer-address",
                        "key=ip6-next-hop-prefer-global",
                        "key=ip-next-hop,value=192.0.2.3",
                        "key=ip6-next-hop,value=2001:db8::3",
                        "key=local-preference,value=+20",
                        "key=metric,value=-2147483648",
                        "key=weight,value=4294967295",
                        "key=src,value=2001:db8::4",
                        "key=tag,value=42",
                    ],
                    "call": "rm2",
                    "exit-action": "key=on-match-goto,value=65535",
                },
            )
        ],
        ROUTE,
    )
    assert omitted == 0 and rows[0]["entry_id"] == "rm1_10"
    assert len(rows[0]["match"]) == 13 and len(rows[0]["set"]) == 11
    assert rows[0]["set"][6] == {"key": "local-preference", "value": "+20"}
    assert rows[0]["set"][7] == {"key": "metric", "value": "-2147483648"}
    assert rows[0]["exit-action"] == {"key": "on-match-goto", "value": 65535}
    assert "key=" not in json.dumps(rows)


@pytest.mark.parametrize("metric", ["rtt", "+rtt", "-rtt", "igp", "aigp", "4294967295"])
def test_native_set_metric_forms_are_observations_not_evaluated(metric):
    rows, _ = policy.collection([route(**{"set": [f"key=metric,value={metric}"]})], ROUTE)
    assert rows[0]["set"] == [{"key": "metric", "value": metric}]


@pytest.mark.parametrize(
    "fields",
    [
        {"order": True},
        {"order": -1},
        {"order": 65536},
        {"action": None},
        {"route-map-id": "../escape"},
        {"call": "https://private.invalid"},
        {"match": [{"key": "metric", "value": 10}]},
        {"match": ["key=metric,value=1,value=2"]},
        {"match": ["key=metric,value=+1"]},
        {"match": ["key=metric,value=4294967296"]},
        {"match": ["key=ip-next-hop-address,value=2001:db8::1"]},
        {"match": ["key=ip6-next-hop-address,value=fe80::1%eth0"]},
        {"match": ["key=vni,value=0"]},
        {"match": ["key=route-type,value=unknown"]},
        {"match": ["key=ip-address-prefix-list,value=../other"]},
        {"match": ["key=metric,value=1"] * 65},
        {"set": ["key=metric,value=+2147483648"]},
        {"set": ["key=metric,value=-2147483649"]},
        {"set": ["key=ip-next-hop-unchanged,value=yes"]},
        {"set": ["key=weight"]},
        {"exit-action": "key=on-match-next,value=2"},
        {"exit-action": "key=continue,value=65536"},
        {"pending": []},
        {"state": "complete"},
        {"state": "changed", "pending": {"order": 11}},
    ],
)
def test_malformed_known_policy_fields_are_not_silently_reinterpreted(fields):
    with pytest.raises(ValueError):
        policy.collection([route(**fields)], ROUTE)


def test_unknown_fields_clauses_and_unconstrained_peer_values_are_withheld_and_counted():
    raw = [
        route(
            secret="hidden-top",
            match=[
                "key=peer,value=hidden-peer",
                "key=future-option,value=hidden-match",
                "key=metric,value=1,password=hidden-clause",
            ],
            **{
                "exit-action": "key=future-exit,value=hidden-exit",
                "pending": {"secret": "hidden-overlay", "call": "rm2"},
            },
        )
    ]
    rows, omitted = policy.collection(raw, ROUTE)
    assert omitted == 6 and "hidden-" not in json.dumps(rows)
    assert rows[0]["match"] == [{"key": "metric", "value": 1}]
    assert rows[0]["pending"] == {"call": "rm2"}
    prefixes, omitted = policy.collection(
        [{"id": "pl1", "entries": ["action=permit,prefix=0.0.0.0/0,seq=1,secret=hidden-prefix"]}],
        PREFIX,
    )
    assert omitted == 1 and "hidden-" not in json.dumps(prefixes)


def test_native_quoted_values_and_escapes_do_not_create_fields_or_leak_unknown_content():
    rows, omitted = policy.collection(
        [
            route(
                match=[
                    'key="ip-address-prefix-list",value="pl1"',
                    r'key=peer,value="hidden-peer,token=hidden-token,quote=\"slash=\\line=\n"',
                    'key=future-option,value="hidden-content,call=evil"',
                    'key=metric,value="42",secret="hidden-extra,call=evil"',
                ]
            )
        ],
        ROUTE,
    )
    assert omitted == 3 and "hidden-" not in json.dumps(rows) and "evil" not in json.dumps(rows)
    assert rows[0]["match"] == [
        {"key": "ip-address-prefix-list", "value": "pl1"},
        {"key": "metric", "value": 42},
    ]
    assert policy.references(rows[0]) == [
        ("route-map-id", "route-maps", "rm1"),
        ("match[0].ip-address-prefix-list", "prefix-lists", "pl1"),
    ]
    prefixes, omitted = policy.collection(
        [
            {
                "id": "pl1",
                "entries": [
                    'action="permit",prefix="10.0.0.0/8",seq="1",secret="hidden-prefix,seq=2"'
                ],
            }
        ],
        PREFIX,
    )
    assert prefixes[0]["entries"][0]["seq"] == 1 and omitted == 1
    assert "hidden-" not in json.dumps(prefixes)


@pytest.mark.parametrize(
    "value",
    [
        'key=metric,value="42',
        'key=metric,value="42"junk',
        r'key=peer,value="hidden\ttext"',
        r'key=peer,value="hidden\u0041"',
        'key=peer,value="hidden\\',
        'key=metric,value="42",value="43"',
    ],
)
def test_malformed_native_quoted_property_strings_fail_closed(value):
    with pytest.raises(ValueError):
        policy.collection([route(match=[value])], ROUTE)


@pytest.mark.parametrize(
    "resource,overlay,expected",
    [
        (PREFIX, {"id": "pl1", "entries": []}, {"id": "pl1"}),
        (
            ROUTE,
            {"route-map-id": "rm1", "order": "10", "action": "permit"},
            {"route-map-id": "rm1", "order": 10, "entry_id": "rm1_10"},
        ),
    ],
)
def test_new_pending_objects_get_identity_from_overlay_without_merging_policy(
    resource, overlay, expected
):
    rows, _ = policy.collection([{"state": "new", "pending": overlay}], resource)
    assert rows[0] == {
        **expected,
        "identity_source": "pending",
        "state": "new",
        "pending": {k: v for k, v in overlay.items() if k not in expected},
    }
    with pytest.raises(ValueError):
        policy.collection([{"state": "changed", "pending": overlay}], resource)


def test_pending_deletions_and_configured_literal_deleted_are_distinct():
    rows, _ = policy.collection(
        [
            route(
                call="deleted",
                state="changed",
                pending={"match": "deleted", "call": "deleted", "set": None},
            )
        ],
        ROUTE,
    )
    assert rows[0]["call"] == "deleted"
    assert rows[0]["pending"] == {"match": "deleted", "call": "deleted", "set": None}
    assert ("call", "route-maps", "deleted") in policy.references(rows[0])
    prefixes, _ = policy.collection(
        [{"id": "pl1", "state": "changed", "pending": {"entries": "deleted"}}], PREFIX
    )
    assert prefixes[0]["pending"]["entries"] == "deleted"


def test_composite_identity_and_numeric_order_keep_distinct_entries():
    rows, _ = policy.collection([route(order="100"), route(order=2), route(order=0)], ROUTE)
    assert [r["entry_id"] for r in rows] == ["rm1_0", "rm1_2", "rm1_100"]
    with pytest.raises(ValueError):
        policy.collection([route(order=10), route(order="10")], ROUTE)
    with pytest.raises(ValueError):
        policy.collection([route(state="new", pending={"route-map-id": "other"})], ROUTE)


async def test_nested_views_use_fixed_get_endpoints_with_native_query_parameters():
    calls = []

    def dispatch(request):
        calls.append(request)
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    assert result.request_limit == 121 and result.requests_made == 28
    prefix = [
        r
        for r in calls
        if r.url.path.endswith("/prefix-lists") and r.url.params.get("verbose") == "1"
    ]
    routes = [r for r in calls if r.url.path.endswith("/route-maps/entries")]
    assert [dict(r.url.params) for r in prefix] == [
        {"verbose": "1"},
        {"running": "1", "verbose": "1"},
        {"pending": "1", "verbose": "1"},
    ]
    assert [dict(r.url.params) for r in routes] == [{}, {"running": "1"}, {"pending": "1"}]
    assert all(r.method == "GET" for r in calls)
    assert all(
        c.content_scope == "allowlisted_fields"
        for c in result.collections
        if c.resource in (PREFIX, ROUTE)
    )


@pytest.mark.parametrize("resource", [PREFIX, ROUTE])
@pytest.mark.parametrize(
    "status,expected",
    [(403, "denied"), (404, "unsupported_or_missing"), (500, "unavailable"), (200, "invalid")],
)
async def test_unreadable_policy_is_not_empty_and_native_errors_are_withheld(
    resource, status, expected
):
    def dispatch(request):
        selected = (
            request.url.path.endswith("/route-maps/entries")
            if resource == ROUTE
            else request.url.path.endswith("/prefix-lists")
            and request.url.params.get("verbose") == "1"
        )
        if selected:
            return httpx.Response(
                status,
                json={"data": {"password": "hidden-error"}, "errors": {"secret": "hidden-error"}},
            )
        return httpx.Response(200, json={"data": fixture(request)})

    result = await inspect(dispatch)
    collections = [c for c in result.collections if c.resource == resource]
    assert len(collections) == 3 and all(
        c.status == expected and c.items is None for c in collections
    )
    assert "hidden-" not in result.model_dump_json()
    assert not result.dependency_graph_complete and result.pending_state == "unknown"


async def test_policy_references_are_same_view_catalogue_observations_not_enforcement():
    def dispatch(request):
        raw = fixture(request)
        path = request.url.path
        if path.endswith("/route-maps/entries"):
            raw[0]["call"] = "deleted"
            if "pending" in request.url.params:
                raw = [
                    {
                        "state": "new",
                        "pending": {
                            "route-map-id": "new",
                            "order": 0,
                            "action": "deny",
                            "call": "unresolved",
                        },
                    }
                ]
        elif path.endswith("/route-maps"):
            raw.append({"id": "deleted"})
            if "running" in request.url.params:
                raw = []  # Native entry/catalogue ACL filtering need not agree.
        elif (
            path.endswith("/prefix-lists")
            and request.url.params.get("verbose") == "0"
            and "running" in request.url.params
        ):
            return httpx.Response(403, json={"errors": {"secret": "hidden-denial"}})
        elif path.endswith("/controllers"):
            raw[0]["route-map-in"] = "rm1"
        elif path.endswith("/fabrics/all"):
            raw["fabrics"][0]["route_map_out"] = "rm1"
        return httpx.Response(200, json={"data": raw})

    result = await inspect(dispatch)
    refs = [r for r in result.references if r.source_resource == ROUTE]
    assert len(refs) == 6 and not any(r.view == "pending" for r in refs)
    assert all(
        r.status == "visible" and r.target_view == "configured"
        for r in refs
        if r.view == "configured"
    )
    assert all(
        r.status == ("not_visible" if r.target_resource == "route-maps" else "target_unavailable")
        and r.target_view == "running"
        for r in refs
        if r.view == "running"
    )
    assert any(
        r.field == "route-map-in" and r.source_resource == "controllers" for r in result.references
    )
    assert any(
        r.field == "route_map_out" and r.source_resource == "fabrics" for r in result.references
    )
    pending = next(c for c in result.collections if c.resource == ROUTE and c.view == "pending")
    assert pending.items[0]["identity_source"] == "pending"
    assert result.pending_state == "changes_detected" and "hidden-" not in result.model_dump_json()


async def test_nested_rules_count_against_retained_object_budget(monkeypatch):
    # One prefix-list row containing two rules is three retained objects.
    monkeypatch.setattr(deps, "MAX_TOTAL_ITEMS", 2)

    class Client:
        async def get(self, path, params=None):
            return [
                {
                    "id": "pl1",
                    "entries": [
                        "action=permit,prefix=0.0.0.0/0,seq=1",
                        "action=deny,prefix=10.0.0.0/8,seq=2",
                    ],
                }
            ]

    reader = deps.Reader(Client())
    result = await reader.read(PREFIX, "configured")
    assert result[0].status == "not_observed" and result[0].reason == "response_limit"
    assert result[0].items is None and reader.items == 0 and reader.limited
