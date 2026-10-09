# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed guest deletion. Provider DELETE has no atomic digest precondition.

A fresh digest reduces stale-review risk; it cannot close the race with external
operators after that read. Never force-stop, purge jobs, skip locks or request
unreferenced disk destruction. A completed task is not proof of storage erasure.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.validation import validate_id
from app.services.adapter_preflight_common import payload_confirmed

FEATURES = {"proxmox.vm.destroy", "proxmox.container.destroy"}


def is_reviewed_deletion(change: Any) -> bool:
    version = (change.payload or {}).get("deletion_version")
    return change.feature in FEATURES and type(version) is int and version == 1


def validated_plan(change: Any) -> dict[str, Any]:
    """Old or tampered generic staging payloads must not bypass reviewed deletion."""
    from app.modules.hypervisor.schemas import DeleteVMRequest

    raw = change.payload or {}
    try:
        if not is_reviewed_deletion(change):
            raise ValueError("version")
        body = DeleteVMRequest(request_id=UUID(int=0), expected_digest=raw["expected_digest"])
        vm_type = "qemu" if change.feature == "proxmox.vm.destroy" else "lxc"
        node = validate_id(raw["node"], label="node")
        if len(node) > 63 or type(raw["vmid"]) is not int or not 100 <= raw["vmid"] <= 999999999:
            raise ValueError("target")
        plan = {
            "deletion_version": 1,
            "node": node,
            "vmid": raw["vmid"],
            "vm_type": vm_type,
            "expected_digest": body.expected_digest,
        }
        if (
            change.operation != "delete"
            or str(change.target_id) != str(raw["vmid"])
            or {k: v for k, v in raw.items() if k != "confirmed"} != plan
        ):
            raise ValueError("contract")
        return plan
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(
            400,
            detail="Deletion requires a valid reviewed plan; discard legacy intent and review again",
        ) from None


def matches_task(upid: Any, plan: dict[str, Any]) -> bool:
    from app.services.proxmox_task_tracking import task_node

    if not isinstance(upid, str) or task_node(upid) != plan["node"]:
        return False
    fields = upid.split(":")
    return fields[5] == ("qmdestroy" if plan["vm_type"] == "qemu" else "vzdestroy") and fields[
        6
    ] == str(plan["vmid"])


async def apply_deletion(domain: Any, change: Any) -> AdapterResult:
    from app.services.adapter_proxmox_preflight import enforce_proxmox_preflight
    from app.services.adapter_proxmox_vm import close_proxmox_adapter

    plan = validated_plan(change)
    enforce_proxmox_preflight(
        change.feature, change.operation, {"confirmed": payload_confirmed(change.payload)}
    )
    ctrl = await domain._get_controller(change.controller_id, change.organization_id)
    adapter = None
    try:
        adapter = await domain._get_proxmox_adapter(ctrl)
        # The inventory establishes node/type; never dispatch an old path after migration.
        result = await adapter.get_cluster_resources("vm")
        if not result.success or not isinstance(result.data, list):
            raise HTTPException(502, detail="Guest location could not be verified")
        guests = [
            g
            for g in result.data
            if isinstance(g, dict) and str(g.get("vmid")) == str(plan["vmid"])
        ]
        if (
            len(guests) != 1
            or guests[0].get("node") != plan["node"]
            or guests[0].get("type") != plan["vm_type"]
        ):
            raise HTTPException(409, detail="Guest location or type changed; review again")
        if guests[0].get("status") != "stopped":
            raise HTTPException(409, detail="Stop the guest and review again before deletion")
        method = (
            adapter.get_vm_config if plan["vm_type"] == "qemu" else adapter.get_container_config
        )
        config = await method(plan["node"], plan["vmid"])
        if not config.success or not isinstance(config.data, dict):
            raise HTTPException(502, detail="Guest configuration could not be read")
        if config.data.get("digest") != plan["expected_digest"]:
            raise HTTPException(
                409, detail="Guest configuration changed since review; review again"
            )
        if config.data.get("lock") or config.data.get("protection", 0) not in (0, False, "0"):
            raise HTTPException(409, detail="Guest is locked or protected; deletion refused")
        result = await adapter.delete_vm(
            plan["node"], plan["vmid"], plan["vm_type"], confirmed=True, force=True
        )
        if not result.success:
            return AdapterResult.fail("Provider rejected guest deletion")
        upid = result.data.get("upid") if isinstance(result.data, dict) else None
        if not matches_task(upid, plan):
            raise AdapterOutcomeUnknownError(
                "Deletion acknowledgement has no matching task", adapter_id="proxmox"
            )
        return AdapterResult.ok({"upid": upid, "vmid": plan["vmid"]})
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any, upid: str) -> dict[str, str]:
    """Called only after this specific deletion task reports OK, never to replay it."""
    plan = validated_plan(change)
    if not matches_task(upid, plan):
        return {"status": "unknown", "detail": "task_identity_mismatch"}
    # Unlike /cluster/resources, nextid?vmid checks the allocation index without
    # filtering by guest permissions. An error/reused ID is uncertainty, not success.
    result = await adapter.assert_vmid_unused(plan["vmid"])
    if result.success and type(result.data) is int and result.data == plan["vmid"]:
        return {"status": "succeeded", "detail": "guest_deletion_verified"}
    return {"status": "unknown", "detail": "guest_absence_not_verified"}
