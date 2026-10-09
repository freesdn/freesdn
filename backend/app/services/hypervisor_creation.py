# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fixed-ID creation with encrypted credentials and read-only completion evidence.

The next-ID endpoint is a suggestion, never a reservation. Native creation must
remain non-overwriting. The description marker links readback to this operation;
it is not an immutable provider identity or proof of OS/application readiness.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.core.crypto import decrypt_credential, encrypt_credential

FEATURES = {"proxmox.vm.create", "proxmox.container.create"}


def is_reviewed_creation(change: Any) -> bool:
    version = (change.payload or {}).get("creation_version")
    return change.feature in FEATURES and type(version) is int and version == 1


def _validate_options(kind: str, options: dict[str, Any]) -> None:
    for field in ("storage", "net_bridge", "pool"):
        value = options[field]
        if (field != "pool" or value) and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
            raise ValueError("identifier")
    for field in ("name", "cpu_type", "machine") if kind == "qemu" else ("hostname",):
        if options[field] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", options[field]):
            raise ValueError("identifier")
    size = options["disk_size" if kind == "qemu" else "rootfs_size"]
    pattern = r"[0-9]+(?:\.[0-9]+)?G?" if kind == "qemu" else r"[0-9]+(?:\.[0-9]+)?"
    if not re.fullmatch(pattern, size) or not 0 < Decimal(size.removesuffix("G")) <= 1048576:
        raise ValueError("disk size")
    volume = options["iso" if kind == "qemu" else "ostemplate"]
    content = "iso" if kind == "qemu" else "vztmpl"
    if volume and (
        not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*:" + content + r"/[A-Za-z0-9][A-Za-z0-9_.-]*", volume
        )
        or ".." in volume
    ):
        raise ValueError("volume")
    if options["tags"] and not re.fullmatch(
        r"[a-z0-9_][a-z0-9_.+-]*(?:;[a-z0-9_][a-z0-9_.+-]*)*", options["tags"]
    ):
        raise ValueError("tags")
    if "\x00" in options["description"] or "FreeSDN creation:" in options["description"]:
        raise ValueError("description")
    if kind == "qemu" and options["balloon"] > options["memory"]:
        raise ValueError("balloon exceeds memory")
    if kind == "lxc":
        if options["net_ip"] not in {"dhcp", "manual"}:
            ipaddress.IPv4Interface(options["net_ip"])
        if any(c in options["ssh_public_keys"] for c in ("\x00", "PRIVATE KEY")):
            raise ValueError("public keys")


def build_plan(kind: str, body: Any, change_id: UUID) -> dict[str, Any]:
    try:
        if (
            kind not in {"qemu", "lxc"}
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", body.node)
            or ".." in body.node
        ):
            raise ValueError("target")
        options = body.model_dump(exclude={"request_id", "force", "node", "vmid", "password"})
        _validate_options(kind, options)
        plan = {
            "creation_version": 1,
            "node": body.node,
            "vmid": body.vmid,
            "vm_type": kind,
            "options": options,
        }
        if kind == "lxc":
            # Bind the token to this durable row. Redaction already masks the
            # password key; neither plaintext nor a password hash is persisted.
            secret = body.password.get_secret_value()
            plan["password"] = (
                encrypt_credential(json.dumps({"change_id": str(change_id), "password": secret}))
                if secret
                else ""
            )
        return plan
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, detail="Invalid guest creation options") from None


def _password(change: Any, plan: dict[str, Any]) -> str:
    token = plan.get("password", "")
    if not isinstance(token, str) or len(token) > 4096:
        raise ValueError("credential envelope")
    if not token:
        return ""
    value = json.loads(decrypt_credential(token))
    if (
        not isinstance(value, dict)
        or set(value) != {"change_id", "password"}
        or value["change_id"] != str(change.id)
    ):
        raise ValueError("credential binding")
    password = value["password"]
    if not isinstance(password, str) or len(password) > 128 or "\x00" in password:
        raise ValueError("credential")
    return password


def same_payload(change: Any, proposed: dict[str, Any]) -> bool:
    from app.services.hypervisor_certificates import FEATURES as CERTIFICATE_FEATURES
    from app.services.hypervisor_certificates import same_payload as certificate_payload

    if change.feature in CERTIFICATE_FEATURES:
        return certificate_payload(change, proposed)
    if change.feature not in FEATURES:
        return bool(change.payload == proposed)
    old = change.payload or {}
    if {k: v for k, v in old.items() if k != "password"} != {
        k: v for k, v in proposed.items() if k != "password"
    }:
        return False
    try:
        return hmac.compare_digest(
            _password(change, old).encode(), _password(change, proposed).encode()
        )
    except (ValueError, TypeError):
        return False


def validated_plan(change: Any) -> dict[str, Any]:
    from app.modules.hypervisor.schemas import CreateContainerRequest, CreateVMRequest

    raw = {k: v for k, v in (change.payload or {}).items() if k != "confirmed"}
    try:
        if not is_reviewed_creation(change) or change.operation != "create":
            raise ValueError("contract")
        kind = "qemu" if change.feature == "proxmox.vm.create" else "lxc"
        keys = {"creation_version", "node", "vmid", "vm_type", "options"} | (
            {"password"} if kind == "lxc" else set()
        )
        if set(raw) != keys or raw["vm_type"] != kind or str(change.target_id) != str(raw["vmid"]):
            raise ValueError("contract")
        schema = CreateVMRequest if kind == "qemu" else CreateContainerRequest
        body = schema(request_id=UUID(int=0), node=raw["node"], vmid=raw["vmid"], **raw["options"])
        rebuilt = build_plan(kind, body, change.id)
        if rebuilt["options"] != raw["options"]:
            raise ValueError("options")
        _password(change, raw)  # Reject plaintext/foreign tokens before credentials are acquired.
        return dict(raw)
    except (ValueError, KeyError, TypeError, AttributeError, HTTPException):
        raise HTTPException(
            400,
            detail="Creation requires a valid reviewed plan; discard legacy intent and review again",
        ) from None


def marker(change: Any) -> str:
    return f"FreeSDN creation: {change.id}"


def matches_task(upid: Any, plan: dict[str, Any]) -> bool:
    from app.services.proxmox_task_tracking import task_node

    return (
        isinstance(upid, str)
        and task_node(upid) == plan["node"]
        and upid.split(":")[5:7]
        == ["qmcreate" if plan["vm_type"] == "qemu" else "vzcreate", str(plan["vmid"])]
    )


async def apply_creation(domain: Any, change: Any) -> AdapterResult:
    from app.services.adapter_proxmox_vm import close_proxmox_adapter

    plan = validated_plan(change)
    ctrl = await domain._get_controller(change.controller_id, change.organization_id)
    adapter = None
    try:
        adapter = await domain._get_proxmox_adapter(ctrl)
        available = await adapter.assert_vmid_unused(plan["vmid"])
        if (
            not available.success
            or type(available.data) is not int
            or available.data != plan["vmid"]
        ):
            raise HTTPException(
                409, detail="VMID availability could not be verified; review allocation again"
            )
        options = dict(plan["options"])
        options["start"] = options.pop("start_after_create")
        options["description"] = (options["description"] + "\n\n" + marker(change)).strip()
        if plan["vm_type"] == "lxc":
            options["password"] = _password(change, plan)
        method = adapter.create_vm if plan["vm_type"] == "qemu" else adapter.create_container
        # force=True only opens FreeSDN's client gate. The adapter sends no
        # provider force/restore flag: Proxmox arbitrates allocation races.
        result = await method(plan["node"], plan["vmid"], force=True, **options)
        if not result.success:
            return AdapterResult.fail(
                "Provider rejected guest creation; inspect allocation before a new intent"
            )
        upid = result.data.get("upid") if isinstance(result.data, dict) else None
        if not matches_task(upid, plan):
            raise AdapterOutcomeUnknownError(
                "Creation acknowledgement has no matching task", adapter_id="proxmox"
            )
        return AdapterResult.ok({"upid": upid, "vmid": plan["vmid"]})
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any, upid: str) -> dict[str, str]:
    from app.services.hypervisor_guest_changes import disk_bytes, size_bytes

    plan = validated_plan(change)
    unknown = {"status": "unknown", "detail": "guest_creation_not_verified"}
    if not matches_task(upid, plan):
        return {"status": "unknown", "detail": "task_identity_mismatch"}
    inventory = await adapter.get_cluster_resources("vm")
    if not inventory.success or not isinstance(inventory.data, list):
        return unknown
    guests = [
        g for g in inventory.data if isinstance(g, dict) and str(g.get("vmid")) == str(plan["vmid"])
    ]
    o = plan["options"]
    if (
        len(guests) != 1
        or guests[0].get("node") != plan["node"]
        or guests[0].get("type") != plan["vm_type"]
        or (o["start_after_create"] and guests[0].get("status") != "running")
    ):
        return unknown
    method = adapter.get_vm_config if plan["vm_type"] == "qemu" else adapter.get_container_config
    result = await method(plan["node"], plan["vmid"])
    if not result.success or not isinstance(result.data, dict):
        return unknown
    config = result.data
    if marker(change) not in str(config.get("description", "")).splitlines() or config.get("lock"):
        return unknown
    name = "name" if plan["vm_type"] == "qemu" else "hostname"
    if o[name] and config.get(name) != o[name]:
        return unknown
    if any(str(config.get(k)) != str(o[k]) for k in ("cores", "memory")):
        return unknown
    disk = "scsi0" if plan["vm_type"] == "qemu" else "rootfs"
    try:
        if not str(config.get(disk, "")).startswith(o["storage"] + ":") or disk_bytes(
            config, disk
        ) < size_bytes(o["disk_size" if disk == "scsi0" else "rootfs_size"]):
            return unknown
    except HTTPException:
        return unknown
    return {"status": "succeeded", "detail": "guest_creation_verified"}
