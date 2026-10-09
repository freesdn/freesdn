# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed artifact storage operations, not direct guest disk manipulation.

There is no native conditional create/delete or immutable volume identity.
Controller claims serialize FreeSDN writes; external races and credential-scope
blind spots require controlled qualification. Readback is not secure erasure or
an independent hash of bytes at rest.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any
from uuid import UUID, uuid5

from fastapi import HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.proxmox.permissions import has_privileges
from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.modules.hypervisor.schemas import (
    StorageOperationRequest,
    StorageOperationResponse,
    StorageReviewRequest,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services import hypervisor_upload_blobs as blobs
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import _REQUEST_NAMESPACE, HypervisorOperationService

ACTIONS = {
    "delete": ("proxmox.storage.delete_volume", "delete"),
    "upload": ("proxmox.storage.upload", "create"),
}
FEATURES = {f for f, _ in ACTIONS.values()}
CONTROL = {"request_id", "expected_digest", "force", "confirmed"}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def target(node: str, storage: str, options: dict[str, Any]) -> tuple[str, str]:
    for value in (node, storage):
        validate_id(value)
        if len(value) > 63:
            raise HTTPException(400, detail="Invalid storage target")
    body = StorageReviewRequest(**options)
    if body.action == "upload":
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", body.filename)
            or ".." in body.filename
            or not body.filename.endswith(
                (".iso",) if body.content == "iso" else (".tar.gz", ".tar.xz", ".tar.zst")
            )
        ):
            raise HTTPException(
                400,
                detail="Use an unchanged ASCII ISO or template filename without path components",
            )
        return f"{storage}:{body.content}/{body.filename}", body.content
    prefix, sep, relative = body.volume.partition(":")
    category = relative.partition("/")[0]
    if (
        not sep
        or prefix != storage
        or category not in {"iso", "vztmpl", "backup"}
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", relative)
        or any(p in {"", ".", ".."} for p in relative.split("/"))
    ):
        raise HTTPException(
            400,
            detail="Only artifact volumes in this storage can be removed; manage guest disks through their guest",
        )
    return body.volume, category


def _inventory(raw: Any, storage: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > 100000:
        raise HTTPException(502, detail="Storage inventory unavailable or too large")
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("volid"), str):
            raise HTTPException(502, detail="Malformed storage inventory")
        volid = item["volid"]
        if not volid.startswith(storage + ":") or volid in seen:
            raise HTTPException(502, detail="Ambiguous storage inventory")
        seen.add(volid)
    return raw


def _state(
    raw: Any, storage: str, category: str, action: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(raw, dict):
        raise HTTPException(502, detail="Storage state unavailable")
    config, status, perms = (raw.get(k) for k in ("config", "status", "permissions"))
    if (
        not isinstance(config, dict)
        or config.get("storage") != storage
        or not isinstance(config.get("type"), str)
        or not config["type"]
        or not isinstance(status, dict)
        or status.get("active") != 1
        or status.get("enabled") != 1
        or config.get("disable", 0) not in (0, "0", False)
    ):
        raise HTTPException(409, detail="Storage identity or availability could not be verified")
    allowed = config.get("content")
    if not isinstance(allowed, str) or category not in allowed.split(","):
        raise HTTPException(409, detail="Storage does not support the requested content")
    if not isinstance(perms, dict):
        raise HTTPException(403, detail="Storage permissions could not be verified")
    rights = perms.get(f"/storage/{storage}", {})
    # /access/permissions returns effective privileges, including inherited ACLs.
    if not has_privileges(
        rights,
        "Datastore.Audit",
        "Datastore.Allocate" if action == "delete" else "Datastore.AllocateTemplate",
    ):
        raise HTTPException(403, detail="Storage audit and operation privileges are required")
    if category == "iso" and action == "delete":
        root = perms.get("/", {})
        # Exact-root access alone cannot authorize the fleet reference scan.
        if not has_privileges(root, "VM.Audit", propagate=True):
            raise HTTPException(403, detail="Global VM.Audit is required to check ISO references")
    return config, _inventory(raw.get("content"), storage)


async def review_state(
    adapter: Any, node: str, storage: str, options: dict[str, Any]
) -> dict[str, Any]:
    try:
        async with asyncio.timeout(45):
            return await _review_state(adapter, node, storage, options)
    except TimeoutError:
        raise HTTPException(
            504, detail="Storage review exceeded its deadline; no write was dispatched"
        ) from None


async def _review_state(
    adapter: Any, node: str, storage: str, options: dict[str, Any]
) -> dict[str, Any]:
    volume, category = target(node, storage, options)
    result = await adapter.get_storage_operation_state(node, storage)
    if not result.success:
        raise HTTPException(502, detail="Storage review unavailable")
    cluster = result.data.get("cluster") if isinstance(result.data, dict) else None
    if not isinstance(cluster, list):
        raise HTTPException(502, detail="Cluster identity unavailable")
    endpoints = [
        g.get("name")
        for g in cluster
        if isinstance(g, dict)
        and g.get("type") == "node"
        and g.get("local") == 1
        and g.get("online") == 1
    ]
    nodes = [
        g.get("name")
        for g in cluster
        if isinstance(g, dict) and g.get("type") == "node" and g.get("online") == 1
    ]
    if len(endpoints) != 1 or not isinstance(endpoints[0], str) or nodes.count(node) != 1:
        raise HTTPException(409, detail="Storage node or connected endpoint unavailable")
    validate_id(endpoints[0], label="endpoint node")
    config, items = _state(result.data, storage, category, options["action"])
    selected = next((i for i in items if i["volid"] == volume), None)
    refs_digest = _digest([])
    owner = None
    if options["action"] == "upload":
        if selected is not None:
            raise HTTPException(
                409, detail="Upload would overwrite an existing volume; use a new filename"
            )
        free = result.data["status"].get("avail")
        if type(free) is not int or free < options["size"]:
            raise HTTPException(409, detail="Destination capacity could not be verified")
        size = options["size"]
    else:
        if selected is None:
            raise HTTPException(404, detail="Volume not found in reviewed storage")
        if selected.get("protected", 0) not in (0, False, "0") or selected.get("parent"):
            raise HTTPException(409, detail="Protected or dependent volumes cannot be deleted")
        size = selected.get("size")
        if type(size) is not int or size < 0 or not isinstance(selected.get("format"), str):
            raise HTTPException(502, detail="Volume identity metadata unavailable")
        owner = selected.get("vmid")
        if owner is not None and (type(owner) is not int or not 100 <= owner <= 999999999):
            raise HTTPException(502, detail="Malformed volume owner")
        if category == "iso":
            refs = await adapter.get_storage_guest_configs()
            if not refs.success or not isinstance(refs.data, list):
                raise HTTPException(502, detail="Guest references could not be reviewed")
            # Conservative match: a reference in a description also blocks.
            if volume in json.dumps(refs.data, sort_keys=True):
                raise HTTPException(
                    409, detail="ISO is referenced by a guest or snapshot; detach and review again"
                )
            refs_digest = _digest(refs.data)
    snapshot = {
        "endpoint_node": endpoints[0],
        "node": node,
        "storage": storage,
        "action": options["action"],
        "volume": volume,
        "content": category,
        "size": size,
        "storage_type": config["type"],
        "storage_digest": _digest(config),
        "volume_digest": _digest(selected),
        "references_digest": refs_digest,
        "owner": owner,
    }
    return {
        "expected_digest": _digest({"snapshot": snapshot, "options": options}),
        "snapshot": snapshot,
    }


def is_reviewed_storage(change: Any) -> bool:
    v = (change.payload or {}).get("storage_version")
    return change.feature in FEATURES and type(v) is int and v == 1


def validated_plan(change: Any) -> dict[str, Any]:
    from app.modules.hypervisor.schemas import StorageReviewSnapshot

    raw = {k: v for k, v in (change.payload or {}).items() if k != "confirmed"}
    try:
        if not is_reviewed_storage(change) or set(raw) != {
            "storage_version",
            "node",
            "storage",
            "options",
            "expected_digest",
            "baseline",
            "checksum",
        }:
            raise ValueError("contract")
        body = StorageOperationRequest(
            request_id=UUID(int=0), expected_digest=raw["expected_digest"], **raw["options"]
        )
        volume, _ = target(raw["node"], raw["storage"], raw["options"])
        if (
            (change.feature, change.operation) != ACTIONS[body.action]
            or change.target_id
            != _digest({"node": raw["node"], "storage": raw["storage"], "volume": volume})
            or body.model_dump(exclude=CONTROL) != raw["options"]
        ):
            raise ValueError("identity")
        baseline = StorageReviewSnapshot(**raw["baseline"]).model_dump()
        if (
            baseline != raw["baseline"]
            or baseline["node"] != raw["node"]
            or baseline["storage"] != raw["storage"]
            or baseline["volume"] != volume
            or baseline["action"] != body.action
            or _digest({"snapshot": baseline, "options": raw["options"]}) != raw["expected_digest"]
        ):
            raise ValueError("review")
        if (body.action == "upload" and not re.fullmatch(r"[a-f0-9]{64}", raw["checksum"])) or (
            body.action == "delete" and raw["checksum"] is not None
        ):
            raise ValueError("checksum")
        return raw
    except (ValueError, TypeError, KeyError, AttributeError, HTTPException):
        raise HTTPException(
            400,
            detail="A complete reviewed storage plan is required; legacy file paths and deletion intents are refused",
        ) from None


def matches_task(upid: Any, plan: dict[str, Any]) -> bool:
    from app.services.proxmox_task_tracking import task_node

    node = (
        plan["baseline"]["endpoint_node"] if plan["options"]["action"] == "upload" else plan["node"]
    )
    if not isinstance(upid, str) or task_node(upid) != node:
        return False
    owner = plan["baseline"]["owner"]
    identity = (f"{owner}@" if owner is not None else "") + plan["storage"]
    return upid.split(":")[5:7] == (
        ["imgcopy", ""] if plan["options"]["action"] == "upload" else ["imgdel", identity]
    )


async def apply_storage(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Storage changes require explicit confirmation")
    row = (
        await domain.db.execute(
            select(Controller, Site)
            .join(Site, Site.id == Controller.site_id)
            .where(
                Controller.id == change.controller_id,
                Controller.controller_type.in_(("proxmox", "pve")),
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
                Site.id == change.site_id,
                Site.organization_id == change.organization_id,
                Site.deleted_at.is_(None),
                Site.is_active.is_(True),
            )
            .with_for_update(read=True, of=(Controller, Site))
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(404, detail="Active Proxmox controller not found")
    assert_site_access_for_request(row.Site.id, detail="site not found")
    adapter = handle = None
    try:
        options = plan["options"]
        if options["action"] == "upload":
            # Verify the exact descriptor that is sent, not a path reopened later.
            opening = asyncio.create_task(
                asyncio.to_thread(blobs.open_verified, change.id, plan["checksum"], options["size"])
            )
            try:
                handle = await asyncio.shield(opening)
            except asyncio.CancelledError:
                (await opening).close()
                raise
        adapter = await build_proxmox_adapter(row.Controller)
        current = await review_state(adapter, plan["node"], plan["storage"], options)
        if current["expected_digest"] != plan["expected_digest"]:
            raise HTTPException(
                409, detail="Storage or references changed since review; review again"
            )
        if options["action"] == "upload":
            assert handle is not None
            result = await adapter.upload_verified_storage_file(
                plan["node"],
                plan["storage"],
                options["filename"],
                options["content"],
                handle,
                plan["checksum"],
                force=True,
            )
        else:
            result = await adapter.delete_storage_volume(
                plan["node"], plan["storage"], options["volume"], force=True
            )
        if not result.success:
            return AdapterResult.fail("Provider rejected storage operation")
        if not matches_task(result.data, plan):
            raise AdapterOutcomeUnknownError(
                "Storage acknowledgement has no matching task", adapter_id="proxmox"
            )
        return AdapterResult.ok({"upid": result.data})
    finally:
        if handle is not None:
            handle.close()
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any, upid: str) -> dict[str, str]:
    plan = validated_plan(change)
    unknown = {"status": "unknown", "detail": "storage_state_not_verified"}
    if not matches_task(upid, plan):
        return {"status": "unknown", "detail": "task_identity_mismatch"}
    result = await adapter.get_storage_operation_state(plan["node"], plan["storage"])
    if not result.success:
        return unknown
    baseline, options = plan["baseline"], plan["options"]
    config, items = _state(result.data, plan["storage"], baseline["content"], options["action"])
    if _digest(config) != baseline["storage_digest"]:
        return unknown
    item = next((i for i in items if i["volid"] == baseline["volume"]), None)
    if options["action"] == "delete":
        return (
            {"status": "succeeded", "detail": "storage_volume_absence_verified"}
            if item is None
            else unknown
        )
    if item is None or type(item.get("size")) is not int or item["size"] != options["size"]:
        return unknown
    return {"status": "succeeded", "detail": "storage_upload_inventory_verified"}


class HypervisorStorageOperationService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    def _authorize(self) -> None:
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")

    async def review(
        self, controller_id: UUID, node: str, storage: str, body: StorageReviewRequest
    ) -> dict[str, Any]:
        self._authorize()
        options = body.model_dump(exclude=CONTROL)
        target(node, storage, options)
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(adapter, node, storage, options)
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self,
        controller_id: UUID,
        node: str,
        storage: str,
        body: StorageOperationRequest,
        file: UploadFile | None = None,
    ) -> StorageOperationResponse:
        from app.services.adapter_proxmox_storage import GatewayProxmoxStorageService

        self._authorize()
        options = body.model_dump(exclude=CONTROL)
        volume, _ = target(node, storage, options)
        if self.ops.staging.is_read_only() or body.force is not True:
            raise HTTPException(
                403, detail="Storage changes require ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True:
            raise HTTPException(409, detail="Storage changes require explicit confirmation")
        _, site = await self.ops._target(controller_id)
        change_id = uuid5(
            _REQUEST_NAMESPACE, f"{site.organization_id}:{self.ops.user.id}:{body.request_id}"
        )
        existing = await self.ops._existing(change_id)
        if existing is None:
            review = await self.review(controller_id, node, storage, body)
            if review["expected_digest"] != body.expected_digest:
                raise HTTPException(409, detail="Storage changed since review; review again")
            baseline = review["snapshot"]
        else:
            baseline = (existing.payload or {}).get("baseline")
            if not isinstance(baseline, dict):
                raise HTTPException(409, detail="request_id belongs to another operation")
        checksum = None
        if body.action == "upload":
            if file is None or file.filename != body.filename:
                raise HTTPException(400, detail="Upload filename differs from reviewed filename")
            checksum = await blobs.spool(file, change_id, body.size)
        elif file is not None:
            raise HTTPException(400, detail="Deletion must not include a file")
        plan = {
            "storage_version": 1,
            "node": node,
            "storage": storage,
            "options": options,
            "expected_digest": body.expected_digest,
            "baseline": baseline,
            "checksum": checksum,
        }
        feature, operation = ACTIONS[body.action]
        change = await self.ops._record(
            controller_id,
            body.request_id,
            feature,
            operation,
            _digest({"node": node, "storage": storage, "volume": volume}),
            plan,
        )
        if change.status == "pending":
            domain = GatewayProxmoxStorageService(self.ops.db)
            try:
                change = await self.ops.staging.apply_change(
                    change_id,
                    force=True,
                    confirmed=True,
                    actor_id=self.ops.user.id,
                    applier=self.ops.guard_applier(change, domain.build_applier(change)),
                )
            except HTTPException:
                saved = await self.ops._existing(change_id)
                if saved is None or saved.status == "pending":
                    raise
                change = saved
        # Keep pending sources for workers. Never change an uncertain outcome
        # into a retry merely because its source was removed.
        if checksum and change.status != "pending":
            await blobs.cleanup_committed(change)
        return StorageOperationResponse(
            action=body.action,
            target=volume,
            request_id=body.request_id,
            change_id=change.id,
            status=change.status,
            checksum=checksum,
            provider_task=ProviderTaskResponse.model_validate(change.provider_task)
            if change.provider_task
            else None,
            message="Request recorded. Completion requires the matching provider task and storage readback; inspect Pending Changes.",
        )
