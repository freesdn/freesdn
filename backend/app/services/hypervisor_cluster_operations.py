# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed node power and HA configuration changes with durable write claims.

The provider exposes no task IDs or atomic review-digest preconditions for these
commands. Node power completion requires operator verification. HA readback
proves configuration only, never failover, quorum preservation or guest health.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.proxmox.permissions import has_privileges
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor.schemas import (
    ClusterOperationRequest,
    ClusterOperationResponse,
    HAGroupCreateRequest,
    HAResourceCreateRequest,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import HypervisorOperationService

ACTIONS = {
    "node.reboot": ("proxmox.node.reboot", "create"),
    "node.shutdown": ("proxmox.node.shutdown", "create"),
    "ha.resource.create": ("proxmox.ha.resource", "create"),
    "ha.resource.delete": ("proxmox.ha.resource", "delete"),
    "ha.group.create": ("proxmox.ha.group", "create"),
    "ha.group.delete": ("proxmox.ha.group", "delete"),
}
FEATURES = {feature for feature, _ in ACTIONS.values()}
_CONTROL = {"request_id", "force", "confirmed", "expected_digest"}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
_NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")
_SID = re.compile(r"(?:vm|ct):[1-9][0-9]{2,8}")


def validate_target(action: str, target: str) -> None:
    pattern = (
        _SID
        if action.startswith("ha.resource.")
        else (_NODE if action.startswith("node.") else _NAME)
    )
    if action not in ACTIONS or not isinstance(target, str) or not pattern.fullmatch(target):
        raise HTTPException(400, detail="Invalid cluster operation target")


def is_reviewed_cluster_operation(change: Any) -> bool:
    version = (change.payload or {}).get("cluster_operation_version")
    return change.feature in FEATURES and type(version) is int and version == 1


def validated_plan(change: Any) -> dict[str, Any]:
    raw = change.payload or {}
    try:
        if not is_reviewed_cluster_operation(change):
            raise ValueError("version")
        action, target = raw["action"], raw["target"]
        validate_target(action, target)
        body_type: type[ClusterOperationRequest] = ClusterOperationRequest
        if action == "ha.resource.create":
            body_type = HAResourceCreateRequest
        elif action == "ha.group.create":
            body_type = HAGroupCreateRequest
        options = raw["options"]
        if not isinstance(options, dict) or _CONTROL.intersection(options):
            raise ValueError("options")
        body = body_type(request_id=UUID(int=0), expected_digest=raw["expected_digest"], **options)
        clean = body.model_dump(exclude=_CONTROL)
        if action == "ha.resource.create" and clean["sid"] != target:
            raise ValueError("sid")
        if action == "ha.group.create" and clean["group"] != target:
            raise ValueError("group")
        plan = {
            "cluster_operation_version": 1,
            "action": action,
            "target": target,
            "expected_digest": body.expected_digest,
            "options": clean,
        }
        if (
            (change.feature, change.operation) != ACTIONS[action]
            or change.target_id != target
            or {k: v for k, v in raw.items() if k != "confirmed"} != plan
        ):
            raise ValueError("contract")
        return plan
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(
            400, detail="A reviewed cluster operation plan is required; review legacy intents again"
        ) from None


def _rows(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(row, dict) or not isinstance(row.get(key), str) or not row[key]
        for row in value
    ):
        raise HTTPException(502, detail="Cluster review returned malformed inventory")
    if len({row[key] for row in value}) != len(value):
        raise HTTPException(502, detail="Cluster review returned duplicate identities")
    return sorted(value, key=lambda row: row[key])


def _ha_rows(value: Any, kind: str) -> list[dict[str, Any]]:
    key = "sid" if kind == "resources" else "group"
    rows = _rows(value, key)
    pattern = _SID if kind == "resources" else _NAME
    if any(not pattern.fullmatch(row[key]) for row in rows):
        raise HTTPException(502, detail="HA configuration returned invalid identities")
    return rows


async def review_state(adapter: Any, action: str, target: str, group: str = "") -> dict[str, Any]:
    validate_target(action, target)
    if group and (action != "ha.resource.create" or not _NAME.fullmatch(group)):
        raise HTTPException(400, detail="Invalid selected HA group")
    result = await adapter.get_cluster_operation_state(
        include_groups=action.startswith("ha.group.") or bool(group)
    )
    if not result.success or not isinstance(result.data, dict):
        raise HTTPException(502, detail="Cluster impact could not be read; no write was sent")
    raw = result.data
    # /cluster/resources filters guests by VM.Audit. Require inherited visibility
    # as a minimum, but do not claim this detects every ACL/pool override.
    permissions = raw.get("permissions")
    if not isinstance(permissions, dict) or not has_privileges(
        permissions.get("/vms"), "VM.Audit", propagate=True
    ):
        raise HTTPException(403, detail="Cluster review requires propagating VM.Audit on /vms")
    status = _rows(raw.get("status"), "id")
    nodes = []
    clusters = []
    for row in status:
        if row.get("type") == "node":
            name = row.get("name")
            if (
                not isinstance(name, str)
                or not _NODE.fullmatch(name)
                or row.get("online") not in (0, 1)
            ):
                raise HTTPException(502, detail="Node membership could not be verified")
            nodes.append({"name": name, "online": row["online"]})
        elif row.get("type") == "cluster":
            if not isinstance(row.get("name"), str) or row.get("quorate") not in (0, 1):
                raise HTTPException(502, detail="Cluster quorum could not be read")
            clusters.append({"name": row["name"], "quorate": row["quorate"]})
        else:
            raise HTTPException(502, detail="Unexpected cluster membership entry")
    if not nodes or len({n["name"] for n in nodes}) != len(nodes) or len(clusters) > 1:
        raise HTTPException(502, detail="Cluster membership is incomplete")
    if (not clusters and len(nodes) != 1) or (clusters and clusters[0]["quorate"] != 1):
        raise HTTPException(409, detail="Cluster is not demonstrably quorate; operation refused")
    if action.startswith("node.") and not any(
        n["name"] == target and n["online"] == 1 for n in nodes
    ):
        raise HTTPException(409, detail="The reviewed node is not online")
    guests = []
    if not isinstance(raw.get("guests"), list):
        raise HTTPException(502, detail="Guest inventory could not be read")
    for guest in raw["guests"]:
        if (
            not isinstance(guest, dict)
            or type(guest.get("vmid")) is not int
            or not 100 <= guest["vmid"] <= 999999999
            or guest.get("type") not in ("qemu", "lxc")
            or guest.get("node") not in {n["name"] for n in nodes}
            or guest.get("status") not in ("running", "stopped", "paused")
            or not isinstance(guest.get("name", ""), str)
        ):
            raise HTTPException(502, detail="Guest impact inventory is malformed")
        guests.append(
            {
                k: guest.get(k, "" if k == "name" else 0)
                for k in ("vmid", "type", "node", "status", "name", "template")
            }
        )
    if len({g["vmid"] for g in guests}) != len(guests):
        raise HTTPException(502, detail="Guest impact contains duplicate identities")
    resources = _ha_rows(raw.get("resources"), "resources")
    groups = _ha_rows(raw["groups"], "groups") if "groups" in raw else []
    snapshot = {
        "action": action,
        "target": target,
        "selected_group": group,
        "cluster": clusters[0] if clusters else {"name": "standalone", "quorate": None},
        "nodes": sorted(nodes, key=lambda n: n["name"]),
        "guests": sorted(guests, key=lambda g: g["vmid"]),
        "resources": resources,
        "groups": groups,
    }
    digest = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {"expected_digest": digest, "snapshot": snapshot}


def _check_options(plan: dict[str, Any], snapshot: dict[str, Any]) -> None:
    action, target, options = plan["action"], plan["target"], plan["options"]
    resources, groups = snapshot["resources"], snapshot["groups"]
    if action.startswith("ha."):
        exists = (
            any(row["sid"] == target for row in resources)
            if action.startswith("ha.resource.")
            else any(row["group"] == target for row in groups)
        )
        if exists == action.endswith("create"):
            raise HTTPException(409, detail="HA target already exists or was removed; review again")
    if action == "ha.resource.create":
        kind, vmid = target.split(":")
        if not any(
            g["vmid"] == int(vmid)
            and g["type"] == ("qemu" if kind == "vm" else "lxc")
            and not g["template"]
            for g in snapshot["guests"]
        ):
            raise HTTPException(
                409, detail="An existing non-template guest of the selected type is required"
            )
        if options["group"] and not any(g["group"] == options["group"] for g in groups):
            raise HTTPException(409, detail="The selected HA group is unavailable")
    if action == "ha.group.delete" and any(r.get("group") == target for r in resources):
        raise HTTPException(409, detail="HA group is still referenced by resources")
    if action == "ha.group.create":
        names = []
        for entry in options["nodes"].split(","):
            parts = entry.split(":")
            if (
                len(parts) > 2
                or not _NODE.fullmatch(parts[0])
                or (len(parts) == 2 and (not parts[1].isdigit() or int(parts[1]) > 1000000))
            ):
                raise HTTPException(400, detail="Invalid HA group node priority list")
            names.append(parts[0])
        if len(set(names)) != len(names) or not set(names) <= {
            n["name"] for n in snapshot["nodes"]
        }:
            raise HTTPException(409, detail="HA group nodes must be distinct cluster members")


async def apply_cluster_operation(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Cluster operations require explicit confirmation")
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
    ctrl = target.Controller
    adapter = None
    try:
        adapter = await build_proxmox_adapter(ctrl)
        group = plan["options"].get("group", "") if plan["action"] == "ha.resource.create" else ""
        current = await review_state(adapter, plan["action"], plan["target"], group)
        if current["expected_digest"] != plan["expected_digest"]:
            raise HTTPException(409, detail="Cluster impact changed since review; review again")
        _check_options(plan, current["snapshot"])
        action, target, options = plan["action"], plan["target"], plan["options"]
        if action.startswith("node."):
            method = adapter.reboot_node if action == "node.reboot" else adapter.shutdown_node
            result = await method(target, confirmed=True, force=True)
        elif action == "ha.resource.create":
            result = await adapter.create_ha_resource(**options, force=True)
        elif action == "ha.resource.delete":
            result = await adapter.delete_ha_resource(target, force=True)
        elif action == "ha.group.create":
            result = await adapter.create_ha_group(**options, force=True)
        else:
            result = await adapter.delete_ha_group(target, force=True)
        if not result.success:
            return AdapterResult.fail("Provider rejected cluster operation")
        if result.data is not None:
            raise AdapterOutcomeUnknownError(
                "Unexpected cluster acknowledgement", adapter_id="proxmox"
            )
        # All six native methods return null, never an observable task ID.
        return AdapterResult.ok({"cluster_operation": plan["action"]})
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any) -> dict[str, str]:
    plan = validated_plan(change)
    if plan["action"].startswith("node."):
        return {"status": "unknown", "detail": "node_power_requires_manual_verification"}
    kind = "resources" if plan["action"].startswith("ha.resource.") else "groups"
    result = await adapter.get_ha_configuration(kind)
    if not result.success:
        return {"status": "unknown", "detail": "ha_configuration_unavailable"}
    rows = _ha_rows(result.data, kind)
    key = "sid" if kind == "resources" else "group"
    actual = next((row for row in rows if row[key] == plan["target"]), None)
    matched = actual is None
    if plan["action"].endswith("create"):
        from app.services.hypervisor_guest_changes import _matches

        # Provider omits these documented defaults from the raw HA file.
        defaults: dict[str, Any] = (
            {"max_relocate": 1, "max_restart": 1, "state": "started"} if kind == "resources" else {}
        )
        matched = actual is not None and _matches({**defaults, **actual}, plan["options"])
    return {
        "status": "succeeded" if matched else "unknown",
        "detail": ("ha_configuration_verified" if matched else "ha_configuration_not_verified"),
    }


async def guard_cluster_conflicts(db: AsyncSession, change: AdapterPendingChange) -> None:
    """Arbitrate all staged Proxmox claims against disruptive cluster operations.

    A brief controller lock covers the conflict check and durable claim commit.
    Independent registrations and external/native operators are outside this lock.
    """
    if not change.feature.startswith("proxmox.") or change.controller_id is None:
        return
    key = f"cluster-operation:{change.organization_id}:{change.controller_id}"
    lock = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big", signed=True)
    await db.execute(select(func.pg_advisory_xact_lock(lock)))
    query = select(AdapterPendingChange.id).where(
        AdapterPendingChange.organization_id == change.organization_id,
        AdapterPendingChange.controller_id == change.controller_id,
        AdapterPendingChange.id != change.id,
        AdapterPendingChange.feature.startswith("proxmox."),
        or_(
            AdapterPendingChange.status.in_(["applying", "reconciliation_required"]),
            (AdapterPendingChange.status == "applied")
            & AdapterPendingChange.provider_task["status"].astext.in_(
                ["pending", "running", "unknown"]
            ),
        ),
    )
    from app.services.hypervisor_backup_jobs import FEATURE as BACKUP_JOB_FEATURE
    from app.services.hypervisor_certificates import FEATURES as CERTIFICATE_FEATURES
    from app.services.hypervisor_firewall_operations import FEATURE as FIREWALL_FEATURE
    from app.services.hypervisor_storage_operations import FEATURES as STORAGE_FEATURES
    from app.services.hypervisor_task_control import FEATURE as TASK_STOP_FEATURE
    from app.services.hypervisor_task_control import validated_plan as task_stop_plan

    disruptive = (
        FEATURES
        | CERTIFICATE_FEATURES
        | STORAGE_FEATURES
        | {BACKUP_JOB_FEATURE, TASK_STOP_FEATURE, FIREWALL_FEATURE}
    )
    if change.feature == TASK_STOP_FEATURE:
        plan = task_stop_plan(change)
        # Let an operator stop the exact accepted worker that caused the
        # conflict. Do not bypass unrelated claims, or another stop request.
        original_worker = (
            (AdapterPendingChange.status == "applied")
            & (AdapterPendingChange.feature != TASK_STOP_FEATURE)
            & (AdapterPendingChange.provider_task["id"].astext == plan["upid"])
            & (AdapterPendingChange.provider_task["node"].astext == plan["node"])
        )
        query = query.where(~func.coalesce(original_worker, False))
    if change.feature not in disruptive:
        query = query.where(AdapterPendingChange.feature.in_(disruptive))
    if await db.scalar(query.limit(1)) is not None:
        raise HTTPException(
            409,
            detail="A cluster or guest operation is active or unresolved; inspect Pending Changes",
        )


class HypervisorClusterOperationService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    async def review(
        self, controller_id: UUID, action: str, target: str, group: str = ""
    ) -> dict[str, Any]:
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        validate_target(action, target)
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(adapter, action, target, group)
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self, controller_id: UUID, action: str, target: str, body: ClusterOperationRequest
    ) -> ClusterOperationResponse:
        from app.services.adapter_proxmox_ha import GatewayProxmoxHaService

        validate_target(action, target)
        if body.force is not True or self.ops.staging.is_read_only():
            raise HTTPException(
                403, detail="Cluster operations require ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True:
            raise HTTPException(409, detail="Cluster operations require explicit confirmation")
        feature, operation = ACTIONS[action]
        change = await self.ops._record(
            controller_id,
            body.request_id,
            feature,
            operation,
            target,
            {
                "cluster_operation_version": 1,
                "action": action,
                "target": target,
                "expected_digest": body.expected_digest,
                "options": body.model_dump(exclude=_CONTROL),
            },
        )
        change_id = change.id
        if change.status == "pending":
            domain = GatewayProxmoxHaService(self.ops.db)

            async def apply(c: Any) -> AdapterResult:
                return await apply_cluster_operation(domain, c)

            try:
                change = await self.ops.staging.apply_change(
                    change_id,
                    force=True,
                    confirmed=True,
                    actor_id=self.ops.user.id,
                    applier=self.ops.guard_applier(change, apply),
                )
            except HTTPException:
                saved = await self.ops._existing(change_id)
                if saved is None or saved.status == "pending":
                    raise
                change = saved
        task = change.provider_task
        return ClusterOperationResponse(
            action=action,
            target=target,
            request_id=body.request_id,
            change_id=change_id,
            status=change.status,
            provider_task=ProviderTaskResponse.model_validate(task) if task else None,
            message="Request recorded. Check Pending Changes; acceptance does not prove completion.",
        )
