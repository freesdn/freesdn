# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed task termination. A stopped worker is not a rolled-back operation."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.proxmox.permissions import has_privileges
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.modules.hypervisor.schemas import TaskStopRequest, TaskStopResponse, TaskStopTarget
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import HypervisorOperationService

FEATURE = "proxmox.cluster.task_stop"


def target_id(upid: str) -> str:
    # Native UPIDs can exceed the staging target column's 128 characters.
    # Preserve the complete identity in the payload; never truncate it.
    return hashlib.sha256(upid.encode()).hexdigest()


def is_reviewed_task_stop(change: Any) -> bool:
    version = (change.payload or {}).get("task_stop_version")
    return change.feature == FEATURE and type(version) is int and version == 1


def validated_plan(change: Any) -> dict[str, Any]:
    raw = change.payload or {}
    try:
        if not is_reviewed_task_stop(change):
            raise ValueError("version")
        target = TaskStopTarget(node=raw["node"], upid=raw["upid"])
        body = TaskStopRequest(request_id=UUID(int=0), expected_digest=raw["expected_digest"])
        plan = {
            "task_stop_version": 1,
            **target.model_dump(),
            "expected_digest": body.expected_digest,
        }
        if (
            change.operation != "create"
            or change.target_id != target_id(target.upid)
            or {k: v for k, v in raw.items() if k != "confirmed"} != plan
        ):
            raise ValueError("contract")
        return plan
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(
            400, detail="Use a reviewed task-stop request; review legacy intents again"
        ) from None


async def review_state(adapter: Any, target: TaskStopTarget) -> dict[str, Any]:
    async with asyncio.timeout(15):
        result = await adapter.get_task_status(target.node, target.upid)
        task = result.data
        if (
            not result.success
            or task is None
            or task.upid != target.upid
            or task.node != target.node
        ):
            raise HTTPException(502, detail="Task identity or status unavailable")
        if task.status != "running":
            raise HTTPException(409, detail="Task is no longer running; refresh the task list")
        if task.task_type != target.upid.split(":")[5]:
            raise HTTPException(502, detail="Task type does not match its identity")
        result = await adapter.get_task_control_permissions(target.node)
        permissions = result.data
        if not result.success or not isinstance(permissions, dict):
            raise HTTPException(502, detail="Task-control privileges unavailable")
        # Deliberately conservative: native PVE also allows an owner to stop
        # their own task. FreeSDN requires both privileges for this admin flow.
        if not has_privileges(permissions, "Sys.Audit", "Sys.Modify"):
            raise HTTPException(
                403, detail="Task control requires Sys.Audit and Sys.Modify on the node"
            )
        snapshot = {**target.model_dump(), "task_type": task.task_type, "status": "running"}
        digest = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "expected_digest": digest,
            "snapshot": snapshot,
            "warnings": [
                "Stopping a worker does not undo its changes or verify guest, storage or backup health.",
                "The task can finish before the stop request arrives. Acknowledgement is not termination proof.",
                "Inspect the original operation and task logs before attempting recovery; never blindly repeat a write.",
            ],
        }


async def apply_task_stop(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Task termination requires explicit confirmation")
    target = (
        await domain.db.execute(
            select(Controller, Site)
            .join(Site, Site.id == Controller.site_id)
            .where(
                Controller.id == change.controller_id,
                Controller.controller_type.in_(("proxmox", "pve")),
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
                Site.organization_id == change.organization_id,
                Site.id == change.site_id,
                Site.deleted_at.is_(None),
                Site.is_active.is_(True),
            )
            .with_for_update(read=True, of=(Controller, Site))
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if target is None:
        raise HTTPException(404, detail="Active Proxmox controller not found")
    assert_site_access_for_request(target.Site.id, detail="site not found")
    adapter = None
    try:
        adapter = await build_proxmox_adapter(target.Controller)
        current = await review_state(adapter, TaskStopTarget(node=plan["node"], upid=plan["upid"]))
        if current["expected_digest"] != plan["expected_digest"]:
            raise HTTPException(409, detail="Task changed since review; review again")
        result = await adapter.stop_task(plan["node"], plan["upid"], force=True)
        if not result.success:
            return result
        if result.data is not None:
            raise AdapterOutcomeUnknownError(
                "Task-stop acknowledgement not verified", adapter_id="proxmox"
            )
        return AdapterResult.ok({"task_stop": plan["upid"], "node": plan["node"]})
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any) -> dict[str, str]:
    plan = validated_plan(change)
    ack = (change.applied_response or {}).get("data", {})
    if not isinstance(ack, dict) or ack != {"task_stop": plan["upid"], "node": plan["node"]}:
        return {"status": "unknown", "detail": "task_stop_acknowledgement_unavailable"}
    result = await adapter.get_task_status(plan["node"], plan["upid"])
    task = result.data
    if not result.success or task is None or task.upid != plan["upid"] or task.node != plan["node"]:
        return {"status": "unknown", "detail": "task_stop_observation_unavailable"}
    if task.status == "running":
        return {"status": "running", "detail": "task_stop_requested_worker_still_running"}
    if task.status == "stopped":
        # Deliberately do not classify the original worker's exit code as the
        # stop request's outcome. It may have finished naturally or partially.
        return {"status": "succeeded", "detail": "task_no_longer_running_effects_unverified"}
    return {"status": "unknown", "detail": "task_stop_state_not_verified"}


class HypervisorTaskControlService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    async def review(self, controller_id: UUID, node: str, upid: str) -> dict[str, Any]:
        target = TaskStopTarget(node=node, upid=upid)
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(adapter, target)
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self, controller_id: UUID, node: str, upid: str, body: TaskStopRequest
    ) -> TaskStopResponse:
        from app.services.adapter_proxmox_cluster import GatewayProxmoxClusterService

        target = TaskStopTarget(node=node, upid=upid)
        if body.force is not True or self.ops.staging.is_read_only():
            raise HTTPException(
                403, detail="Task termination requires ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True:
            raise HTTPException(409, detail="Task termination requires explicit confirmation")
        change = await self.ops._record(
            controller_id,
            body.request_id,
            FEATURE,
            "create",
            target_id(upid),
            {
                "task_stop_version": 1,
                **target.model_dump(),
                "expected_digest": body.expected_digest,
            },
        )
        change_id = change.id
        if change.status == "pending":
            domain = GatewayProxmoxClusterService(self.ops.db)
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
        task = change.provider_task
        return TaskStopResponse(
            node=node,
            upid=upid,
            request_id=body.request_id,
            change_id=change_id,
            status=change.status,
            provider_task=ProviderTaskResponse.model_validate(task) if task else None,
            message="Request recorded. Check Pending Changes; a stopped task does not verify or undo its effects.",
        )
