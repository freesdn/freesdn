# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed schedule changes. Configuration verification is not backup verification.

Native job CRUD has no task ID or atomic digest precondition. Request claims
prevent FreeSDN replay; native operators and future scheduled runs remain outside
that boundary. Never infer recoverability from a successfully saved schedule.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
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
from app.modules.hypervisor.schemas import (
    BackupJobOperationRequest,
    BackupJobOperationResponse,
    BackupJobReviewRequest,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import HypervisorOperationService

FEATURE = "proxmox.backup.job"
_CONTROL = {"request_id", "expected_digest", "force", "confirmed"}
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_:-]{0,49}")
# Editing unfamiliar execution options must not silently enable hooks, select a
# broader estate or reset options not represented in review. Deletion only needs
# a matching definition and does not execute its hooks or remove archives.
_EDITABLE_KEYS = {
    "id",
    "type",
    "storage",
    "node",
    "schedule",
    "vmid",
    "mode",
    "compress",
    "enabled",
    "prune-backups",
    "maxfiles",
    "remove",
    "mailto",
    "mailnotification",
    "notification-mode",
    "notification-target",
    "comment",
    "repeat-missed",
}
_DISPLAY_KEYS = _EDITABLE_KEYS | {"all", "pool", "exclude"}


def _digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(data) > 131072:
        raise HTTPException(502, detail="Backup review is too large")
    return hashlib.sha256(data.encode()).hexdigest()


def _flag(value: Any) -> int:
    if type(value) in (int, bool) and value in (0, 1):
        return int(value)
    if isinstance(value, str) and value in ("0", "1"):
        return int(value)
    raise HTTPException(502, detail="Malformed backup configuration flag")


def _job(value: dict[str, Any]) -> dict[str, Any]:
    """Normalize documented omitted defaults and wire scalar representations."""
    result = {k: v for k, v in value.items() if k != "next-run"}
    result.setdefault("type", "vzdump")
    result.setdefault("enabled", 1)
    for key in ("enabled", "repeat-missed", "remove", "all"):
        if key in result:
            result[key] = _flag(result[key])
    if "compress" in result and (result["compress"] is False or result["compress"] == 0):
        result["compress"] = "0"
    if "vmid" in result:
        raw = result["vmid"]
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+(?:[,;\s]+[0-9]+)*", raw):
            raise HTTPException(502, detail="Malformed backup guest selection")
        ids = re.split(r"[,;\s]+", raw)
        if len(ids) != len(set(ids)) or any(not 100 <= int(v) <= 999999999 for v in ids):
            raise HTTPException(502, detail="Malformed backup guest selection")
        result["vmid"] = ",".join(sorted(ids, key=int))
    retention = result.get("prune-backups")
    if retention is not None:
        if not isinstance(retention, dict) or any(
            k
            not in {
                "keep-all",
                "keep-last",
                "keep-hourly",
                "keep-daily",
                "keep-weekly",
                "keep-monthly",
                "keep-yearly",
            }
            or type(v) not in (int, bool)
            or v < 0
            for k, v in retention.items()
        ):
            raise HTTPException(502, detail="Malformed backup retention policy")
        result["prune-backups"] = {k: int(v) for k, v in retention.items()}
    _digest(result)
    return result


async def _jobs(adapter: Any) -> list[dict[str, Any]]:
    result = await adapter.get_backup_job_configuration()
    values = result.data
    if (
        not result.success
        or not isinstance(values, list)
        or len(values) > 2000
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not _JOB_ID.fullmatch(row["id"])
            for row in values
        )
    ):
        raise HTTPException(502, detail="Backup configuration unavailable or malformed")
    if len({row["id"] for row in values}) != len(values):
        raise HTTPException(502, detail="Backup configuration contains duplicate identities")
    return values


def is_reviewed_backup_job(change: Any) -> bool:
    version = (change.payload or {}).get("backup_job_version")
    return change.feature == FEATURE and type(version) is int and version == 1


def validated_plan(change: Any) -> dict[str, Any]:
    raw = change.payload or {}
    try:
        if not is_reviewed_backup_job(change):
            raise ValueError("version")
        request = BackupJobOperationRequest(
            request_id=UUID(int=0),
            action=raw["action"],
            job_id=raw["job_id"],
            settings=raw["settings"],
            expected_digest=raw["expected_digest"],
        )
        plan = {
            "backup_job_version": 1,
            **request.model_dump(exclude={"request_id", "force", "confirmed"}),
        }
        if (
            change.operation != request.action
            or change.target_id != request.job_id
            or {k: v for k, v in raw.items() if k != "confirmed"} != plan
        ):
            raise ValueError("contract")
        return plan
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(
            400, detail="Use a reviewed backup job request; review legacy intents again"
        ) from None


def _require(permissions: Any, path: str, *required: str) -> None:
    granted = permissions.get(path) if isinstance(permissions, dict) else None
    if not has_privileges(granted, *required):
        raise HTTPException(403, detail="Backup job review requires explicit provider privileges")


async def review_state(adapter: Any, request: BackupJobReviewRequest) -> dict[str, Any]:
    async with asyncio.timeout(45):
        jobs = await _jobs(adapter)
        raw = next((j for j in jobs if j["id"] == request.job_id), None)
        if (request.action == "create") != (raw is None):
            raise HTTPException(409, detail="Backup job existence changed; review again")
        before = _job(raw) if raw is not None else None
        settings = request.settings
        ids = [int(v) for v in settings.vmid.split(",")] if settings else []
        state = await adapter.get_backup_job_review_state(
            settings.node if settings else None, settings.storage if settings else None, ids
        )
        if not state.success or not isinstance(state.data, dict):
            raise HTTPException(502, detail="Backup review state unavailable")
        data = state.data
        permissions = data.get("permissions")
        _require(permissions, "/", "Sys.Audit", "Sys.Modify")
        desired = None
        guests = []
        config = None
        defaults = None
        if settings is not None:
            if before is not None and (
                set(before) - _EDITABLE_KEYS or before.get("type") != "vzdump"
            ):
                raise HTTPException(
                    409,
                    detail="This job uses advanced options outside reviewed editing; manage it natively",
                )
            _require(
                permissions, f"/storage/{settings.storage}", "Datastore.Audit", "Datastore.Allocate"
            )
            _require(permissions, f"/nodes/{settings.node}", "Sys.Audit")
            defaults = data.get("defaults")
            if not isinstance(defaults, dict):
                raise HTTPException(502, detail="Node backup defaults unavailable")
            if defaults.get("script") or defaults.get("fleecing"):
                raise HTTPException(
                    409, detail="Node backup hooks/fleecing require native management"
                )
            config, status, cluster, inventory = (
                data.get(k) for k in ("storage", "status", "cluster", "guests")
            )
            if (
                not isinstance(config, dict)
                or config.get("storage") != settings.storage
                or not isinstance(config.get("type"), str)
                or not isinstance(config.get("content"), str)
                or "backup" not in config["content"].split(",")
                or not isinstance(status, dict)
                or _flag(status.get("active", 0)) != 1
                or _flag(status.get("enabled", 0)) != 1
                or not isinstance(cluster, list)
                or not isinstance(inventory, list)
            ):
                raise HTTPException(409, detail="Backup storage or selected node is unavailable")
            nodes = [
                n
                for n in cluster
                if isinstance(n, dict)
                and n.get("type") == "node"
                and n.get("name") == settings.node
            ]
            if len(nodes) != 1 or _flag(nodes[0].get("online", 0)) != 1:
                raise HTTPException(409, detail="Backup node is not a unique online cluster member")
            if any(not isinstance(g, dict) or type(g.get("vmid")) is not int for g in inventory):
                raise HTTPException(502, detail="Backup guest inventory is malformed")
            if len({g["vmid"] for g in inventory}) != len(inventory):
                raise HTTPException(502, detail="Backup guest inventory has duplicate identities")
            for vmid in ids:
                found = next((g for g in inventory if g["vmid"] == vmid), None)
                if (
                    found is None
                    or found.get("node") != settings.node
                    or found.get("type") not in ("qemu", "lxc")
                    or _flag(found.get("template", 0))
                ):
                    raise HTTPException(
                        409, detail="Select visible non-template guests on the reviewed node"
                    )
                _require(permissions, f"/vms/{vmid}", "VM.Audit", "VM.Backup")
                guests.append({k: found.get(k, "") for k in ("vmid", "node", "type", "name")})
            desired = _job(
                {
                    **(before or {"id": request.job_id, "prune-backups": {"keep-all": 1}}),
                    **settings.model_dump(),
                }
            )
        # Only selected display fields leave the provider read. A delete can
        # review an advanced job without exposing a hook script or secret flags.
        snapshot = {
            "action": request.action,
            "job_id": request.job_id,
            "before": {k: v for k, v in (before or {}).items() if k in _DISPLAY_KEYS}
            if before
            else None,
            "before_digest": _digest(before),
            "desired": desired,
            "guests": guests,
            "storage_digest": _digest(config),
            "storage_retention": {
                k: config[k] for k in ("prune-backups", "maxfiles") if k in config
            }
            if config
            else {},
            "permissions_digest": _digest(permissions),
            "node_defaults_digest": _digest(defaults),
            "node_defaults": {k: v for k, v in (defaults or {}).items() if k in _DISPLAY_KEYS},
        }
        return {
            "expected_digest": _digest(snapshot),
            "snapshot": snapshot,
            "warnings": [
                "Configuration verification does not prove a backup ran or can be restored.",
                "Native edits can race this review. Scheduling uses the node's local time; already running backups are not cancelled.",
                "New jobs keep all backups. Existing retention and notification settings are preserved; monitor capacity and qualify restore independently.",
                "Stop/suspend mode can interrupt guests; an enabled schedule may run before configuration readback finishes.",
            ],
        }


async def apply_backup_job(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Backup job changes require explicit confirmation")
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
        intent = BackupJobReviewRequest(**{k: plan[k] for k in ("action", "job_id", "settings")})
        current = await review_state(adapter, intent)
        if current["expected_digest"] != plan["expected_digest"]:
            raise HTTPException(409, detail="Backup job impact changed since review; review again")
        result = await adapter.apply_reviewed_backup_job(
            plan["action"], plan["job_id"], plan["settings"] or {}, force=True
        )
        if not result.success or result.data is not None:
            raise AdapterOutcomeUnknownError(
                "Backup configuration acknowledgement not verified", adapter_id="proxmox"
            )
        return AdapterResult.ok(
            {
                "backup_job": plan["action"],
                "job_id": plan["job_id"],
                "expected": current["snapshot"]["desired"],
            }
        )
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any) -> dict[str, str]:
    plan = validated_plan(change)
    response = change.applied_response or {}
    ack = response.get("data", {})
    if (
        not isinstance(ack, dict)
        or ack.get("backup_job") != plan["action"]
        or ack.get("job_id") != plan["job_id"]
        or "expected" not in ack
    ):
        return {"status": "unknown", "detail": "backup_job_acknowledgement_unavailable"}
    values = await _jobs(adapter)
    actual = next((row for row in values if row["id"] == plan["job_id"]), None)
    matched = (
        actual is None
        if plan["action"] == "delete"
        else actual is not None and _job(actual) == ack["expected"]
    )
    return {
        "status": "succeeded" if matched else "unknown",
        "detail": "backup_job_configuration_verified"
        if matched
        else "backup_job_configuration_not_verified",
    }


class HypervisorBackupJobService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    async def review(self, controller_id: UUID, body: BackupJobReviewRequest) -> dict[str, Any]:
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(adapter, body)
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self, controller_id: UUID, body: BackupJobOperationRequest
    ) -> BackupJobOperationResponse:
        from app.services.adapter_proxmox_backup import GatewayProxmoxBackupService

        if body.force is not True or self.ops.staging.is_read_only():
            raise HTTPException(
                403, detail="Backup job changes require ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True:
            raise HTTPException(409, detail="Backup job changes require explicit confirmation")
        change = await self.ops._record(
            controller_id,
            body.request_id,
            FEATURE,
            body.action,
            body.job_id,
            {
                "backup_job_version": 1,
                **body.model_dump(exclude={"request_id", "force", "confirmed"}),
            },
        )
        change_id = change.id
        if change.status == "pending":
            domain = GatewayProxmoxBackupService(self.ops.db)
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
        return BackupJobOperationResponse(
            action=body.action,
            job_id=body.job_id,
            request_id=body.request_id,
            change_id=change_id,
            status=change.status,
            provider_task=ProviderTaskResponse.model_validate(task) if task else None,
            message="Request recorded. Check Pending Changes; saving a schedule does not verify a backup.",
        )
