# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native permission response contracts, including cross-path contamination."""

import httpx
import pytest

from app.adapters.proxmox.permissions import has_privileges, permissions_at_path
from tests.adapters.test_proxmox_write_outcomes import connected


@pytest.mark.parametrize("value", [0, 1, False, True, "0", "1"])
def test_grant_and_inheritance_are_separate(value):
    granted = permissions_at_path({"/nodes/pve1": {"Sys.Modify": value}}, "/nodes/pve1")
    assert has_privileges(granted, "Sys.Modify")
    assert has_privileges(granted, "Sys.Modify", propagate=True) is (value in (1, True, "1"))
    assert not has_privileges(granted, "Sys.Audit", "Sys.Modify")


@pytest.mark.parametrize("value", [None, 1.0, 0.0, 2, -1, "false", "true", "", [], {}])
def test_malformed_flags_are_neither_grants_nor_inheritance(value):
    with pytest.raises(ValueError):
        permissions_at_path({"/vms/101": {"VM.Audit": value}}, "/vms/101")
    assert not has_privileges({"VM.Audit": value}, "VM.Audit")
    assert not has_privileges({"VM.Audit": value}, "VM.Audit", propagate=True)


@pytest.mark.parametrize("response", [{}, {"/vms/101": {}}])
def test_absent_privilege_is_denied(response):
    assert not has_privileges(permissions_at_path(response, "/vms/101"), "VM.Audit")


@pytest.mark.parametrize(
    "response",
    [None, [], {"/vms/101": None}, {"/vms/101": []}, {"/": {"VM.Audit": 1}}],
)
def test_missing_or_wrong_scope_is_not_inherited_locally(response):
    with pytest.raises(ValueError):
        permissions_at_path(response, "/vms/101")


# Each reviewed workflow queries its exact native path. A response to a root
# query must never supply/overwrite permissions belonging to a storage or node.
METHODS = ["firewall", "task", "storage", "backup", "cluster"]


async def read_state(adapter, family):
    if family == "firewall":
        return await adapter.get_firewall_permissions({"scope": "node", "node": "pve1"})
    if family == "task":
        return await adapter.get_task_control_permissions("pve1")
    if family == "storage":
        return await adapter.get_storage_operation_state("pve1", "local")
    if family == "backup":
        return await adapter.get_backup_job_review_state("pve1", "local", [101])
    return await adapter.get_cluster_operation_state()


@pytest.mark.parametrize("family", METHODS)
@pytest.mark.parametrize("fault", ["foreign_only", "foreign_extra", "null_leaf", "float_flag"])
async def test_adapter_rejects_ambiguous_path_or_malformed_permissions(family, fault):
    calls = []

    def dispatch(request):
        assert request.method == "GET"
        calls.append(str(request.url))
        data = []
        if request.url.path == "/access/permissions":
            path = request.url.params["path"]
            data = {path: {"Sys.Audit": 0}}
            if fault == "foreign_only":
                data = {"/foreign": {"Sys.Audit": 1}}
            elif fault == "foreign_extra":
                data["/foreign"] = {"Sys.Audit": 1}
            elif fault == "null_leaf":
                data[path] = None
            else:
                data[path]["Sys.Audit"] = 1.0
        return httpx.Response(200, json={"data": data})

    adapter, client = connected(dispatch)
    try:
        result = await read_state(adapter, family)
        assert not result.success
        assert calls and any("/access/permissions" in call for call in calls)
    finally:
        await client._http.aclose()


@pytest.mark.parametrize("family", ["storage", "backup"])
async def test_later_response_cannot_replace_a_separately_read_path(family):
    paths = []

    def dispatch(request):
        assert request.method == "GET"
        data = []
        if request.url.path == "/access/permissions":
            path = request.url.params["path"]
            paths.append(path)
            data = {path: {}}
            if len(paths) == 2:
                data[paths[0]] = {"Sys.Audit": 1, "Sys.Modify": 1, "Datastore.Allocate": 1}
        return httpx.Response(200, json={"data": data})

    adapter, client = connected(dispatch)
    try:
        assert not (await read_state(adapter, family)).success
        assert len(paths) == 2
    finally:
        await client._http.aclose()


@pytest.mark.parametrize("family", METHODS)
async def test_empty_permission_response_remains_empty(family):
    def dispatch(request):
        assert request.method == "GET"
        return httpx.Response(200, json={"data": {}})

    adapter, client = connected(dispatch)
    try:
        result = await read_state(adapter, family)
        assert result.success  # The operation service, not this reader, requires the grants.
        granted = result.data if family in ("firewall", "task") else result.data["permissions"]
        assert not granted or all(value == {} for value in granted.values())
    finally:
        await client._http.aclose()
