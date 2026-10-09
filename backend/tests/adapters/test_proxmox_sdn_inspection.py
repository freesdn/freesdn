# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real adapter/client HTTP parsing; all provider traffic must remain GET-only."""

import asyncio
from uuid import uuid4

import httpx
import pytest

from app.adapters.proxmox import sdn
from tests.adapters.test_proxmox_write_outcomes import connected


@pytest.mark.parametrize(
    "resource,method,identity",
    [
        ("zones", "get_sdn_zones", "zone"),
        ("vnets", "get_sdn_vnets", "vnet"),
        ("controllers", "get_sdn_controllers", "controller"),
    ],
)
@pytest.mark.parametrize("bad", [None, {}, "failure", [None], [{"wrong": "identity"}], [1]])
async def test_legacy_reads_do_not_report_malformed_as_empty(resource, method, identity, bad):
    calls = []

    def dispatch(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(200, json={"data": bad})

    adapter, client = connected(dispatch)
    try:
        result = await getattr(adapter, method)()
        assert not result.success and result.data is None
        assert calls == [("GET", "/cluster/sdn/" + resource)]
    finally:
        await client._http.aclose()


@pytest.mark.parametrize(
    "bad",
    [
        [{"zone": "z", "vlanaware": "false"}],
        [{"zone": "z", "mtu": True}],
        [{"zone": "z", "pending": []}],
        [{"zone": "z", "pending": {"mtu": "wrong"}}],
        [{"zone": "z", "state": "success"}],
        [{"zone": "z", "nodes": "pve1\nsecret"}],
        [{"zone": "../x"}],
        [{"zone": "z"}, {"zone": "z"}],
        [{"zone": "z", "mtu": -1}],
        [{"zone": "z", "type": {"secret": "value"}}],
        [{"zone": "z"}] * 513,
        [{"zone": "z", "password": "x" * 262145}],
    ],
)
def test_unsafe_or_oversized_provider_rows_are_rejected(bad):
    with pytest.raises(ValueError):
        sdn.collection(bad, "zones")


async def test_inspection_preserves_native_pending_deletion_and_withholds_secrets():
    cid, calls = uuid4(), []

    def dispatch(request):
        calls.append((request.method, request.url.path, dict(request.url.params)))
        path = request.url.path
        if path == "/access/permissions":
            raw = {"/sdn": {"SDN.Audit": 1, "SDN.Allocate": "0"}}
        elif path.endswith("/zones"):
            raw = [{"zone": "z1", "type": "vlan", "bridge": "vmbr0", "mtu": 1500}]
            if request.url.params.get("pending"):
                raw[0].update(
                    state="changed", pending={"mtu": "deleted", "private_key": "secret-pending"}
                )
            if not request.url.params:
                raw[0].pop("mtu")
        elif path.endswith("/vnets"):
            raw = [{"vnet": "v1", "zone": "z1", "vlanaware": "0"}]
        else:
            raw = [
                {
                    "controller": "bgp1",
                    "type": "bgp",
                    "password": "secret-running",
                    "unknown_sensitive_field": "secret-future",
                }
            ]
        return httpx.Response(200, json={"data": raw})

    adapter, client = connected(dispatch)
    try:
        result = await adapter.inspect_sdn(cid)
        assert (
            result.controller_id == cid and not result.writes_enabled and not result.atomic_snapshot
        )
        assert (
            result.visibility == "partial_or_unverified"
            and result.pending_state == "changes_detected"
        )
        assert result.audit_at_sdn is True and result.allocate_at_sdn is True
        assert result.audit_propagates is True and result.allocate_propagates is False
        assert result.resources[0].pending.items[0]["pending"] == {"mtu": "deleted"}
        assert result.resources[1].configured.items[0]["vlanaware"] is False
        assert result.resources[2].configured.omitted_fields == 2
        assert "secret-" not in result.model_dump_json()
        assert len(calls) == 10 and all(method == "GET" for method, _, _ in calls)
        for resource in sdn.IDENTITY:
            params = [p for _, path, p in calls if path.endswith("/" + resource)]
            assert params == [{}, {"running": "1"}, {"pending": "1"}]
    finally:
        await client._http.aclose()


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "denied"),
        (403, "denied"),
        (404, "unsupported_or_missing"),
        (501, "unsupported_or_missing"),
        (400, "unavailable"),
        (500, "unavailable"),
    ],
)
async def test_failed_view_is_not_clean_or_empty(status, expected):
    def dispatch(request):
        if request.url.path.endswith("/zones"):
            return httpx.Response(
                status, json={"errors": {"detail": "never-print-provider-secret"}}
            )
        return httpx.Response(
            200, json={"data": {"/sdn": {}} if request.url.path == "/access/permissions" else []}
        )

    adapter, client = connected(dispatch)
    try:
        result = await adapter.inspect_sdn(uuid4())
        assert (
            result.resources[0].running.status == expected
            and result.resources[0].running.items is None
        )
        assert result.pending_state == "unknown" and "never-print" not in result.model_dump_json()
        assert result.resources[1].running.items == []
    finally:
        await client._http.aclose()


@pytest.mark.parametrize(
    "raw", [{"/unrelated": {}}, [], {"/sdn": None}, {"/sdn": {"SDN.Audit": "false"}}]
)
async def test_permission_shape_is_not_truthiness(raw):
    def dispatch(request):
        return httpx.Response(
            200, json={"data": raw if request.url.path == "/access/permissions" else []}
        )

    adapter, client = connected(dispatch)
    try:
        result = await adapter.inspect_sdn(uuid4())
        assert (
            result.permissions_status == "invalid"
            and result.audit_at_sdn is None
            and result.allocate_at_sdn is None
        )
        assert result.visibility == "partial_or_unverified" and not result.writes_enabled
    finally:
        await client._http.aclose()


async def test_empty_acl_filtered_lists_do_not_claim_complete_inventory():
    def dispatch(request):
        return httpx.Response(
            200, json={"data": {"/sdn": {}} if request.url.path == "/access/permissions" else []}
        )

    adapter, client = connected(dispatch)
    try:
        result = await adapter.inspect_sdn(uuid4())
        assert (
            result.pending_state == "no_visible_changes"
            and result.visibility == "partial_or_unverified"
        )
        assert not result.audit_at_sdn and not result.writes_enabled
        assert "subnets" in result.unobserved_resources
    finally:
        await client._http.aclose()


async def test_read_timeout_keeps_other_views_and_cancellation_is_not_swallowed(monkeypatch):
    monkeypatch.setattr(sdn, "READ_TIMEOUT", 0.01)

    async def dispatch(request):
        if request.url.path.endswith("/zones"):
            await asyncio.Future()
        return httpx.Response(
            200, json={"data": {"/sdn": {}} if request.url.path == "/access/permissions" else []}
        )

    adapter, client = connected(dispatch)
    try:
        result = await asyncio.wait_for(adapter.inspect_sdn(uuid4()), 1)
        assert result.resources[0].configured.status == "unavailable"
        assert result.resources[1].running.items == [] and result.pending_state == "unknown"
        task = asyncio.create_task(adapter.inspect_sdn(uuid4()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        await client._http.aclose()


async def test_dry_run_is_get_only_and_never_returns_secret_diff_contents():
    cid, calls = uuid4(), []

    def dispatch(request):
        calls.append((request.method, request.url.path, dict(request.url.params)))
        return httpx.Response(
            200,
            json={
                "data": {
                    "interfaces-diff": "--- old\n+++ new\n-post-up secret-old\n+post-up secret-new\n",
                    "frr-diff": "+neighbor 1.2.3.4 password secret-auth\n",
                }
            },
        )

    adapter, client = connected(dispatch)
    try:
        result = await adapter.get_sdn_dry_run(cid, "pve1")
        assert result.interfaces.added_lines == result.interfaces.removed_lines == 1
        assert result.frr.changed and result.frr.added_lines == 1
        assert "secret" not in result.model_dump_json() and result.content_withheld
        assert not result.connectivity_verified
        assert calls == [("GET", "/cluster/sdn/dry-run", {"node": "pve1"})]
    finally:
        await client._http.aclose()


@pytest.mark.parametrize(
    "raw", [None, [], {"extra": "private"}, {"interfaces-diff": []}, {"frr-diff": "x" * 131073}]
)
async def test_dry_run_invalid_is_not_no_changes(raw):
    adapter, client = connected(lambda _: httpx.Response(200, json={"data": raw}))
    try:
        result = await adapter.get_sdn_dry_run(uuid4(), "pve1")
        assert result.status == "invalid" and result.interfaces is None and result.frr is None
    finally:
        await client._http.aclose()


@pytest.mark.parametrize("node", ["..", "pve/1", "pve?secret", "pve..1", "", "x" * 64])
async def test_dry_run_rejects_path_injection_before_any_native_call(node):
    calls = []
    adapter, client = connected(lambda r: calls.append(r))
    try:
        with pytest.raises(ValueError):
            await adapter.get_sdn_dry_run(uuid4(), node)
        assert not calls
    finally:
        await client._http.aclose()


@pytest.mark.parametrize(
    "permissions,granted,propagates",
    [
        ({}, False, None),
        ({"/sdn": {}}, False, None),
        ({"/sdn": {"SDN.Audit": 0}}, True, False),
        ({"/sdn": {"SDN.Audit": 1}}, True, True),
    ],
)
async def test_native_permissions_distinguish_grant_from_propagation(
    permissions, granted, propagates
):
    def dispatch(request):
        return httpx.Response(
            200, json={"data": permissions if request.url.path == "/access/permissions" else []}
        )

    adapter, client = connected(dispatch)
    try:
        result = await adapter.inspect_sdn(uuid4())
        assert result.permissions_status == "available"
        assert result.audit_at_sdn is granted and result.audit_propagates is propagates
        assert not result.writes_enabled and result.visibility == "partial_or_unverified"
    finally:
        await client._http.aclose()
