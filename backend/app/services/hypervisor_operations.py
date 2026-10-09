# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Immediate guest lifecycle requests, durably claimed through the staging chokepoint.

A request ID identifies one operator's intent, not a provider task. Its stable
primary key prevents replay after an HTTP response is lost or a process exits.
Only a pending intent may dispatch; an uncertain outcome is never retried.
"""

from __future__ import annotations

import re
from typing import Any, Protocol
from uuid import UUID, uuid5

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser
from app.core.tenancy import tenant_filter
from app.models.core import Controller, Site
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor.schemas import (
    BackupRestoreIntentPayload,
    BackupRunRequest,
    CloneRequest,
    MigrateRequest,
    VMActionResponse,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_backup import GatewayProxmoxBackupService, _validate_archive
from app.services.adapter_proxmox_container import GatewayProxmoxContainerService
from app.services.adapter_proxmox_snapshot import GatewayProxmoxSnapshotService
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService

# Stable across processes and releases. Changing this would permit old requests
# to dispatch again. No database migration or separate idempotency cache needed.
_REQUEST_NAMESPACE = UUID("ac717b3b-05c1-4ea9-976a-b72137b44266")
_ACTIONS = {
    "qemu": {"start", "stop", "shutdown", "reboot", "suspend", "resume"},
    "lxc": {"start", "stop", "shutdown", "reboot"},
}


class _OperationDomain(Protocol):
    def build_applier(self, change: Any) -> Any: ...


class HypervisorOperationService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.db = db
        self.user = user
        self.staging = AdapterStagingService(db)

    async def _target(self, controller_id: UUID) -> tuple[Controller, Site]:
        # Re-evaluated inside the applier, with ownership held stable until the
        # write outcome is committed. Never use a cached/detached controller.
        row = (
            await self.db.execute(
                select(Controller, Site)
                .join(Site, Site.id == Controller.site_id)
                .where(
                    Controller.id == controller_id,
                    tenant_filter(Controller, self.user),
                    Controller.controller_type.in_(("proxmox", "pve")),
                    Controller.deleted_at.is_(None),
                    Controller.is_active.is_(True),
                    Controller.sync_enabled.is_(True),
                    Site.deleted_at.is_(None),
                    Site.is_active.is_(True),
                )
                .with_for_update(read=True, of=(Controller, Site))
                .execution_options(populate_existing=True)
            )
        ).one_or_none()
        if row is None:
            raise HTTPException(404, detail="Active Proxmox controller not found")
        return row.Controller, row.Site

    async def _existing(self, change_id: UUID) -> AdapterPendingChange | None:
        return (
            await self.db.execute(
                select(AdapterPendingChange)
                .where(
                    AdapterPendingChange.id == change_id,
                    AdapterPendingChange.created_by == self.user.id,
                    tenant_filter(AdapterPendingChange, self.user),
                )
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()

    async def execute(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        action: str,
        vm_type: str,
        *,
        request_id: UUID,
        force: bool,
    ) -> VMActionResponse:
        if action not in _ACTIONS.get(vm_type, set()):
            raise HTTPException(400, detail="Unsupported power action for guest type")
        return await self._submit(
            controller_id,
            node,
            vmid,
            action,
            vm_type,
            request_id=request_id,
            force=force,
            options={},
        )

    async def clone(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        body: CloneRequest,
    ) -> VMActionResponse:
        if body.newid == vmid:
            raise HTTPException(400, detail="Clone ID must differ from the source guest")
        if body.target:
            validate_id(body.target, label="target")
        if body.storage:
            validate_id(body.storage, label="storage")
        options = body.model_dump(exclude={"request_id", "force", "name"})
        options["hostname" if vm_type == "lxc" else "name"] = body.name
        return await self._submit(
            controller_id,
            node,
            vmid,
            "clone",
            vm_type,
            request_id=body.request_id,
            force=body.force,
            options=options,
        )

    async def migrate(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        body: MigrateRequest,
    ) -> VMActionResponse:
        validate_id(body.target, label="target")
        if body.target == node:
            raise HTTPException(400, detail="Migration target must differ from the source node")
        if vm_type == "lxc" and body.online:
            raise HTTPException(
                400,
                detail="LXC live migration is unsupported; choose offline or explicit restart migration",
            )
        if vm_type == "qemu" and body.restart:
            raise HTTPException(400, detail="Restart migration is only supported for containers")
        return await self._submit(
            controller_id,
            node,
            vmid,
            "migrate",
            vm_type,
            request_id=body.request_id,
            force=body.force,
            options=body.model_dump(exclude={"request_id", "force"}),
        )

    async def delete(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        body: Any,
    ) -> VMActionResponse:
        from app.adapters.exceptions import AdapterConfirmationRequiredError

        if body.confirmed is not True:
            raise AdapterConfirmationRequiredError(
                "Deletion requires confirmed=true", adapter_id="proxmox"
            )
        return await self._submit(
            controller_id,
            node,
            vmid,
            "destroy",
            vm_type,
            request_id=body.request_id,
            force=body.force,
            operation="delete",
            confirmed=True,
            options={
                "deletion_version": 1,
                "vm_type": vm_type,
                "expected_digest": body.expected_digest,
            },
        )

    async def guest_change(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        action: str,
        body: Any,
    ) -> VMActionResponse:
        from app.services.hypervisor_guest_changes import build_plan

        options = build_plan(action, vm_type, body)
        return await self._submit(
            controller_id,
            node,
            vmid,
            action,
            vm_type,
            request_id=body.request_id,
            force=body.force,
            options=options,
            feature=(
                "proxmox.vm.convert_to_template"
                if action == "template"
                else f"proxmox.{'vm' if vm_type == 'qemu' else 'container'}.{'resize_disk' if action == 'resize' else 'config'}"
            ),
            operation="create" if action == "template" else "update",
            domain=GatewayProxmoxVmService(self.db)
            if action == "template" or vm_type == "qemu"
            else GatewayProxmoxContainerService(self.db),
            confirmed=payload_confirmed({"confirmed": getattr(body, "confirmed", False)}),
        )

    async def snapshot(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        action: str,
        snapname: str,
        *,
        request_id: UUID,
        force: bool,
        confirmed: bool = False,
        description: str = "",
        vmstate: bool = False,
    ) -> VMActionResponse:
        if action not in {"create", "delete", "rollback"}:
            raise HTTPException(400, detail="Unsupported snapshot action")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", snapname) or snapname == "current":
            raise HTTPException(400, detail="Invalid or reserved snapshot name")
        if action in {"delete", "rollback"} and not confirmed:
            from app.adapters.exceptions import AdapterConfirmationRequiredError

            raise AdapterConfirmationRequiredError(
                "Snapshot deletion/rollback requires confirmed=true",
                adapter_id="proxmox",
            )
        options: dict[str, Any] = {"snapname": snapname, "vm_type": vm_type}
        if action == "create":
            if vm_type == "lxc" and vmstate:
                raise HTTPException(
                    400, detail="Container snapshots cannot include VM memory state"
                )
            options.update(description=description, vmstate=vmstate)
        return await self._submit(
            controller_id,
            node,
            vmid,
            "snapshot." + action,
            vm_type,
            request_id=request_id,
            force=force,
            options=options,
            feature="proxmox.snapshot." + action,
            operation="delete" if action == "delete" else "create",
            target_id=snapname,
            domain=GatewayProxmoxSnapshotService(self.db),
            confirmed=confirmed,
        )

    async def backup(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
        body: BackupRunRequest,
    ) -> VMActionResponse:
        validate_id(body.storage, label="storage")
        return await self._submit(
            controller_id,
            node,
            vmid,
            "backup.run",
            vm_type,
            request_id=body.request_id,
            force=body.force,
            options={**body.model_dump(exclude={"request_id", "force"}), "vm_type": vm_type},
            feature="proxmox.backup.run",
            domain=GatewayProxmoxBackupService(self.db),
        )

    async def create(self, controller_id: UUID, vm_type: str, body: Any) -> VMActionResponse:
        from app.services.hypervisor_creation import build_plan

        if self.user.is_scoped or not self.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        if self.staging.is_read_only() or not body.force:
            raise HTTPException(
                403, detail="Creation requires ADAPTER_READ_ONLY=false and force=true"
            )
        _, site = await self._target(controller_id)
        change_id = uuid5(
            _REQUEST_NAMESPACE, f"{site.organization_id}:{self.user.id}:{body.request_id}"
        )
        plan = build_plan(vm_type, body, change_id)
        return await self._submit(
            controller_id,
            body.node,
            body.vmid,
            "create",
            vm_type,
            request_id=body.request_id,
            force=body.force,
            options=plan,
        )

    async def stage_restore(
        self,
        controller_id: UUID,
        request_id: UUID,
        body: BackupRestoreIntentPayload,
        *,
        notes: str | None = None,
    ) -> AdapterPendingChange:
        # Stage only: read-only mode does not prevent review. There is no force
        # or confirmation here; the shared apply endpoint requires both later.
        _validate_archive(body.archive)
        return await self._record(
            controller_id,
            request_id,
            "proxmox.backup.restore",
            "create",
            str(body.vmid),
            body.model_dump(exclude_none=True),
            notes=notes,
        )

    def guard_applier(self, change: AdapterPendingChange, applier: Any) -> Any:
        """Recheck ownership/activity after the durable claim, before credentials are used."""
        controller_id, site_id, org_id = (
            change.controller_id,
            change.site_id,
            change.organization_id,
        )

        async def apply(c: AdapterPendingChange) -> Any:
            if controller_id is None:
                raise HTTPException(404, detail="Active Proxmox controller not found")
            _, site = await self._target(controller_id)
            if site.organization_id != org_id or (site_id is not None and site.id != site_id):
                raise HTTPException(409, detail="Controller ownership changed before dispatch")
            return await applier(c)

        return apply

    async def _record(
        self,
        controller_id: UUID,
        request_id: UUID,
        feature: str,
        operation: str,
        target_id: str,
        payload: dict[str, Any],
        *,
        notes: str | None = None,
    ) -> AdapterPendingChange:
        if self.user.is_scoped or not self.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        ctrl, site = await self._target(controller_id)
        org_id, site_id, actor_id = site.organization_id, site.id, self.user.id
        # Exclude the action/target: reusing a key for a different payload must
        # conflict, rather than silently derive another valid write ID.
        change_id = uuid5(_REQUEST_NAMESPACE, f"{org_id}:{actor_id}:{request_id}")
        change = await self._existing(change_id)
        if change is None:
            try:
                change = await self.staging.stage_change(
                    change_id=change_id,
                    organization_id=org_id,
                    controller_id=ctrl.id,
                    site_id=site_id,
                    feature=feature,
                    operation=operation,
                    target_id=target_id,
                    payload=payload,
                    actor_id=actor_id,
                    notes=notes or "Hypervisor operation; request_id=" + str(request_id),
                )
            except IntegrityError:
                # PostgreSQL's unique primary key arbitrates concurrent first
                # submissions. Never mistake some other integrity error for a
                # successful insert, or retry a write after a failed commit.
                change = await self._existing(change_id)
                if change is None:
                    raise

        from app.services.hypervisor_creation import same_payload

        if (
            change.controller_id != controller_id
            or change.site_id != site_id
            or change.feature != feature
            or change.operation != operation
            or change.target_id != target_id
            or not same_payload(change, payload)
        ):
            raise HTTPException(
                409, detail="request_id already belongs to a different guest operation"
            )

        return change

    async def _submit(
        self,
        controller_id: UUID,
        node: str,
        vmid: int,
        action: str,
        vm_type: str,
        *,
        request_id: UUID,
        force: bool,
        options: dict[str, Any],
        feature: str | None = None,
        operation: str = "create",
        target_id: str | None = None,
        domain: _OperationDomain | None = None,
        confirmed: bool = False,
    ) -> VMActionResponse:
        if self.user.is_scoped or not self.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        if self.staging.is_read_only() or not force:
            raise HTTPException(
                403, detail="Guest operations require ADAPTER_READ_ONLY=false and force=true"
            )
        if vm_type not in _ACTIONS:
            raise HTTPException(400, detail="Unsupported guest type")
        validate_id(node, label="node")
        if len(node) > 63 or not 100 <= vmid <= 999999999:
            raise HTTPException(400, detail="Invalid guest target")

        feature = feature or f"proxmox.{'vm' if vm_type == 'qemu' else 'container'}.{action}"
        target_id = target_id if target_id is not None else str(vmid)
        change = await self._record(
            controller_id,
            request_id,
            feature,
            operation,
            target_id,
            {"node": node, "vmid": vmid, **options},
        )
        change_id, actor_id = change.id, self.user.id

        if change.status == "pending":
            domain = domain or (
                GatewayProxmoxVmService(self.db)
                if vm_type == "qemu"
                else GatewayProxmoxContainerService(self.db)
            )

            apply = self.guard_applier(change, domain.build_applier(change))

            try:
                change = await self.staging.apply_change(
                    change_id, force=force, confirmed=confirmed, actor_id=actor_id, applier=apply
                )
            except HTTPException:
                # A concurrent caller may already hold the claim; a failed or
                # ambiguous attempt has its own durable receipt. Returning it
                # does not authorize another dispatch.
                saved = await self._existing(change_id)
                if saved is None or saved.status == "pending":
                    raise
                change = saved

        task = change.provider_task
        return VMActionResponse(
            action=action,
            vmid=vmid,
            request_id=request_id,
            change_id=change_id,
            status=change.status,
            upid=task.get("id") if task else None,
            provider_task=ProviderTaskResponse.model_validate(task) if task else None,
            message=(
                "Request accepted; completion is tracked in Pending Changes."
                if change.status == "applied"
                else "Check this operation in Pending Changes before issuing another request."
            ),
        )
