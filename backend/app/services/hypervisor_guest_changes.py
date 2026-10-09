# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed guest mutations and bounded readback; never replay a device write."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterConfirmationRequiredError, AdapterOutcomeUnknownError
from app.models.staging import AdapterPendingChange

_FEATURES = {
    "proxmox.vm.resize_disk",
    "proxmox.container.resize_disk",
    "proxmox.vm.config",
    "proxmox.container.config",
    "proxmox.vm.convert_to_template",
}
_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_MAX_BYTES = 2**53 - 1  # Exact in the browser as well as Python.


def is_reviewed_guest_change(change: AdapterPendingChange) -> bool:
    version = (change.payload or {}).get("guest_change_version")
    return change.feature in _FEATURES and type(version) is int and version == 1


def size_bytes(value: str) -> int:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]?)", value)
    if not match:
        raise HTTPException(400, detail="Invalid disk size")
    result = Decimal(match[1]) * _UNITS[match[2] or "G"]
    if result != int(result) or not 0 < result <= _MAX_BYTES:
        raise HTTPException(400, detail="Disk size is outside the supported range")
    return int(result)


def disk_bytes(config: dict[str, Any], disk: str) -> int:
    value = config.get(disk)
    if not isinstance(value, str) or "media=cdrom" in value:
        raise HTTPException(400, detail="Selected disk is unavailable or not resizable")
    match = re.search(r"(?:^|,)size=([^,]+)(?:,|$)", value)
    if not match:
        raise HTTPException(400, detail="Selected disk has no verifiable size")
    return size_bytes(match[1])


def build_plan(action: str, vm_type: str, body: Any) -> dict[str, Any]:
    if vm_type not in {"qemu", "lxc"}:
        raise HTTPException(400, detail="Unsupported guest type")
    plan: dict[str, Any] = {
        "guest_change_version": 1,
        "vm_type": vm_type,
        "action": action,
        "expected_digest": body.expected_digest,
    }
    if action == "resize":
        pattern = r"(?:scsi|virtio|ide|sata)\d+" if vm_type == "qemu" else r"(?:rootfs|mp\d+)"
        if not re.fullmatch(pattern, body.disk):
            raise HTTPException(400, detail="Disk name is not supported for this guest type")
        amount = size_bytes(body.size.lstrip("+"))
        target = amount + body.current_size_bytes if body.size.startswith("+") else amount
        if not body.current_size_bytes < target <= _MAX_BYTES or target % 1024:
            raise HTTPException(
                400, detail="Resize must grow the disk to a whole KiB within the supported range"
            )
        plan.update(
            disk=body.disk,
            current_size_bytes=body.current_size_bytes,
            target_size_bytes=target,
            requested_size=body.size,
        )
    elif action == "config":
        config = body.model_dump(
            exclude_none=True, exclude={"request_id", "force", "expected_digest"}
        )
        if not config:
            raise HTTPException(400, detail="No configuration changes provided")
        if vm_type == "lxc":
            if "balloon" in config:
                raise HTTPException(
                    400, detail="Container configuration does not support balloon memory"
                )
            if "name" in config:
                config["hostname"] = config.pop("name")
        plan["config"] = config
    elif action == "template":
        if body.confirmed is not True:
            raise AdapterConfirmationRequiredError(
                "Template conversion requires confirmed=true", adapter_id="proxmox"
            )
    else:
        raise HTTPException(400, detail="Unsupported guest change")
    return plan


def validated_plan(change: Any) -> dict[str, Any]:
    """Validate persisted plans too: generic staging is also an input boundary."""
    from app.adapters.validation import validate_id
    from app.modules.hypervisor.schemas import (
        ResizeDiskRequest,
        TemplateConversionRequest,
        UpdateConfigRequest,
    )

    raw = change.payload or {}
    try:
        if type(raw.get("guest_change_version")) is not int or raw["guest_change_version"] != 1:
            raise ValueError("version")
        action, vm_type = raw["action"], raw["vm_type"]
        common = {
            "request_id": UUID(int=0),
            "force": True,
            "expected_digest": raw["expected_digest"],
        }
        body: Any
        if action == "resize":
            body = ResizeDiskRequest(
                **common,
                disk=raw["disk"],
                size=raw["requested_size"],
                current_size_bytes=raw["current_size_bytes"],
            )
        elif action == "config":
            config = dict(raw["config"])
            if vm_type == "lxc" and "hostname" in config:
                config["name"] = config.pop("hostname")
            if set(config) - {
                "cores",
                "memory",
                "balloon",
                "name",
                "description",
                "tags",
                "onboot",
                "protection",
            }:
                raise ValueError("config fields")
            body = UpdateConfigRequest(**common, **config)
        elif action == "template":
            body = TemplateConversionRequest(**common, confirmed=True)
        else:
            raise ValueError("action")
        plan = build_plan(action, vm_type, body)
        if type(raw["vmid"]) is not int or not 100 <= raw["vmid"] <= 999999999:
            raise ValueError("vmid")
        plan.update(node=validate_id(raw["node"], label="node"), vmid=raw["vmid"])
        expected_feature = (
            "proxmox.vm.convert_to_template"
            if action == "template"
            else f"proxmox.{'vm' if vm_type == 'qemu' else 'container'}.{'resize_disk' if action == 'resize' else 'config'}"
        )
        if (
            change.feature != expected_feature
            or change.operation != ("create" if action == "template" else "update")
            or str(change.target_id) != str(plan["vmid"])
        ):
            raise ValueError("target")
        if {k: v for k, v in raw.items() if k != "confirmed"} != plan:
            raise ValueError("changed intent")
        if "confirmed" in raw:
            plan["confirmed"] = raw["confirmed"]
        return plan
    except (KeyError, TypeError, ValueError, AttributeError):
        raise HTTPException(400, detail="Invalid persisted guest change contract") from None


async def guard_guest_conflicts(db: AsyncSession, change: AdapterPendingChange) -> None:
    """Serialize reviewed guest changes and deletions across request IDs/actors.

    Other operation families retain their existing behavior. A reviewed change
    also refuses an already active or uncertain guest operation from those
    families. This is not a lock across independent controller registrations.
    """
    if change.feature not in _FEATURES | {
        "proxmox.vm.destroy",
        "proxmox.container.destroy",
        "proxmox.vm.create",
        "proxmox.container.create",
    }:
        return
    payload = change.payload or {}
    vmid = str(payload.get("vmid", change.target_id or ""))
    if not vmid.isdecimal():
        raise HTTPException(400, detail="A guest target is required")
    key = f"guest-change:{change.organization_id}:{change.controller_id}:{vmid}"
    lock = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big", signed=True)
    # Released only when the applying claim is committed or the request rolls back.
    await db.execute(select(func.pg_advisory_xact_lock(lock)))
    conflict = await db.scalar(
        select(AdapterPendingChange.id)
        .where(
            AdapterPendingChange.controller_id == change.controller_id,
            AdapterPendingChange.organization_id == change.organization_id,
            AdapterPendingChange.id != change.id,
            AdapterPendingChange.feature.startswith("proxmox."),
            AdapterPendingChange.payload["vmid"].astext == vmid,
            or_(
                AdapterPendingChange.status.in_(["applying", "reconciliation_required"]),
                (AdapterPendingChange.status == "applied")
                & AdapterPendingChange.provider_task.isnot(None)
                & AdapterPendingChange.provider_task["status"].astext.in_(
                    ["pending", "running", "unknown"]
                ),
            ),
        )
        .limit(1)
    )
    if conflict is not None:
        raise HTTPException(
            409,
            detail="Another guest operation is active or unresolved; inspect Pending Changes before retrying",
        )


async def _config(adapter: Any, plan: dict[str, Any], *, current: bool = False) -> dict[str, Any]:
    method = adapter.get_vm_config if plan["vm_type"] == "qemu" else adapter.get_container_config
    result = await method(plan["node"], plan["vmid"], **({"current": True} if current else {}))
    if not result.success or not isinstance(result.data, dict) or not result.data:
        raise HTTPException(502, detail="Guest configuration could not be read")
    return result.data


def _matches(actual: dict[str, Any], desired: dict[str, Any]) -> bool:
    for key, value in desired.items():
        actual_value = actual.get(key)
        if isinstance(value, bool):
            # Absent false flags use Proxmox's default false value.
            if actual_value is None and value is False:
                continue
            if str(actual_value).lower() not in ({"1", "true"} if value else {"0", "false"}):
                return False
        elif key == "tags":
            if set(str(actual_value or "").split(";")) != set(str(value).split(";")):
                return False
        elif value == "" and actual_value is None:
            continue
        elif str(actual_value) != str(value):
            return False
    return True


async def readback(adapter: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """Read desired and current configuration, never infer success from HTTP alone."""
    observation: dict[str, Any] = {"status": "unknown", "detail": "guest_state_not_verified"}
    latest = await _config(adapter, plan)
    if plan["action"] == "resize":
        if disk_bytes(latest, plan["disk"]) == plan["target_size_bytes"]:
            observation.update(status="succeeded", detail="guest_state_verified")
    elif plan["action"] == "template":
        if latest.get("template") in (1, True, "1"):
            observation.update(status="succeeded", detail="guest_state_verified")
    elif plan["action"] == "config" and _matches(latest, plan["config"]):
        current = await _config(adapter, plan, current=True)
        if _matches(current, plan["config"]):
            observation.update(status="succeeded", detail="guest_state_verified")
        else:
            observation.update(status="pending", detail="configuration_pending_restart")
    return observation


async def apply_guest_change(domain: Any, change: Any) -> AdapterResult:
    from app.services.adapter_proxmox_preflight import preflight_gate
    from app.services.adapter_proxmox_vm import close_proxmox_adapter
    from app.services.proxmox_task_tracking import task_node

    plan = validated_plan(change)
    if change.feature not in _FEATURES or plan.get("action") not in {
        "resize",
        "config",
        "template",
    }:
        raise HTTPException(400, detail="Invalid guest change contract")
    ctrl = await domain._get_controller(change.controller_id, change.organization_id)
    adapter = None
    try:
        adapter = await domain._get_proxmox_adapter(ctrl)
        await preflight_gate(adapter, change.feature, change.operation, plan)
        before = await _config(adapter, plan)
        if before.get("digest") != plan["expected_digest"]:
            raise HTTPException(
                409,
                detail="Guest configuration changed since review; reload and submit a new intent",
            )
        if before.get("lock"):
            raise HTTPException(409, detail="Guest is locked by another provider operation")
        node, vmid = plan["node"], plan["vmid"]
        if plan["action"] == "resize":
            if disk_bytes(before, plan["disk"]) != plan["current_size_bytes"]:
                raise HTTPException(409, detail="Disk size changed since review")
            method = (
                adapter.resize_vm_disk
                if plan["vm_type"] == "qemu"
                else adapter.resize_container_disk
            )
            result = await method(
                node,
                vmid,
                plan["disk"],
                f"{plan['target_size_bytes'] // 1024}K",
                digest=plan["expected_digest"],
                force=True,
            )
        elif plan["action"] == "config":
            method = (
                adapter.update_vm_config
                if plan["vm_type"] == "qemu"
                else adapter.update_container_config
            )
            result = await method(
                node, vmid, {**plan["config"], "digest": plan["expected_digest"]}, force=True
            )
        else:
            # Proxmox's template endpoint has no digest parameter. Its own
            # stopped-guest/config locks remain authoritative after this read.
            if plan.get("confirmed") is not True:
                raise AdapterConfirmationRequiredError(
                    "Template conversion requires confirmed=true", adapter_id="proxmox"
                )
            result = await adapter.convert_to_template(node, vmid, plan["vm_type"], force=True)
        if not result.success:
            return AdapterResult.fail("Provider rejected the guest change")
        candidate = result.data.get("upid") if isinstance(result.data, dict) else result.data
        if task_node(candidate):
            return AdapterResult.ok({"upid": candidate, "guest_change": {"status": "pending"}})
        try:
            outcome = await readback(adapter, plan)
        except Exception:
            raise AdapterOutcomeUnknownError(
                "Guest readback unavailable", adapter_id="proxmox"
            ) from None
        if outcome["status"] == "unknown":
            raise AdapterOutcomeUnknownError("Guest state not verified", adapter_id="proxmox")
        return AdapterResult.ok({"guest_change": outcome})
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


def accepted_readback(feature: str, data: Any) -> dict[str, Any] | None:
    if feature not in _FEATURES or not isinstance(data, dict):
        return None
    result = data.get("guest_change")
    if not isinstance(result, dict):
        return None
    if result.get("status") not in {"succeeded", "pending"}:
        return None
    now = datetime.now(UTC).isoformat()
    return {
        "status": result["status"],
        "detail": result.get("detail"),
        "checked_at": now,
        **({"finished_at": now} if result["status"] == "succeeded" else {}),
    }
