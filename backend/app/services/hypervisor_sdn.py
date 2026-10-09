# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tenant-bound SDN inspection. This service deliberately has no apply path."""

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.proxmox.sdn import validate_node
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.modules.hypervisor.sdn_schemas import (
    SdnAttachmentInspection,
    SdnDependencyInspection,
    SdnDryRunObservation,
    SdnInspection,
)
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import HypervisorOperationService


class HypervisorSdnService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    async def inspect(self, controller_id: UUID) -> SdnInspection:
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = await build_proxmox_adapter(ctrl)
        try:
            return await adapter.inspect_sdn(controller_id)
        finally:
            await close_proxmox_adapter(adapter)

    async def attachments(self, controller_id: UUID) -> SdnAttachmentInspection:
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = await build_proxmox_adapter(ctrl)
        try:
            return await adapter.inspect_sdn_attachments(controller_id)
        finally:
            await close_proxmox_adapter(adapter)

    async def dependencies(self, controller_id: UUID) -> SdnDependencyInspection:
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = await build_proxmox_adapter(ctrl)
        try:
            return await adapter.inspect_sdn_dependencies(controller_id)
        finally:
            await close_proxmox_adapter(adapter)

    async def dry_run(self, controller_id: UUID, node: str) -> SdnDryRunObservation:
        try:
            validate_node(node)
        except ValueError:
            raise HTTPException(400, detail="Invalid Proxmox node") from None
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = await build_proxmox_adapter(ctrl)
        try:
            return await adapter.get_sdn_dry_run(controller_id, node)
        finally:
            await close_proxmox_adapter(adapter)
