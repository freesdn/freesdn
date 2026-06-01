# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Ceph service
========================================

READS ONLY for Proxmox VE Ceph integration: cluster status,
monitors, OSDs, MDS, pools, filesystems, and CRUSH rules. Ceph
writes (pool creation, OSD lifecycle, MGR/MON management) are not
exposed by the Proxmox adapter yet — when they are, add them to
``_APPLY`` and ``build_applier`` below.

Production-safety contract:

- Reads run live against the cluster.
- No writes: ``_APPLY`` is empty, applier 400s on every call.

Every Ceph endpoint takes a ``node`` query/path param because Proxmox
routes Ceph queries through one of the cluster nodes (any quorate
node works).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.validation import validate_id
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list, redact_secrets

logger = logging.getLogger(__name__)

_APPLY: dict[tuple[str, str], str] = {}


class GatewayProxmoxCephService(GatewayServiceBase):
    """Live reads for Proxmox Ceph (writes not yet wired)."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    async def _get_proxmox_adapter(
        self, controller_id: UUID, organization_id: UUID
    ) -> ProxmoxAdapter:
        ctrl = await self._get_controller(controller_id, organization_id)
        return await self._build_adapter(ctrl)

    @staticmethod
    async def _build_adapter(ctrl: Controller) -> ProxmoxAdapter:
        """Item 9: forwards to the shared ``build_proxmox_adapter`` helper."""
        return await build_proxmox_adapter(ctrl)

    async def _read(
        self,
        controller_id: UUID,
        organization_id: UUID,
        method_name: str,
        node: str,
        list_response: bool = True,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            method = getattr(adapter, method_name)
            result = await method(node=node)
        finally:
            await adapter.disconnect()
        body: dict[str, Any] = {
            "controller_id": controller_id,
            "node": node,
            "ok": result.success,
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }
        if list_response:
            body["items"] = redact_list(result.data) if result.success else []
        else:
            body["data"] = redact_secrets(result.data) if result.success else {}
        return body

    # ── Live reads ──────────────────────────────────────────────────

    async def get_status(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_status",
            node,
            list_response=False,
        )

    async def list_mons(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_mon",
            node,
        )

    async def list_osds(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_osd",
            node,
        )

    async def list_pools(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_pools",
            node,
        )

    async def list_fs(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_fs",
            node,
        )

    async def list_mds(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_mds",
            node,
        )

    async def list_crush_rules(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(
            controller_id,
            organization_id,
            "get_ceph_crush_rules",
            node,
        )

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(
                        f"no applier for feature={c.feature!r} "
                        f"operation={c.operation!r} — Proxmox Ceph writes "
                        "are not implemented"
                    ),
                )
            raise HTTPException(  # pragma: no cover
                501,
                detail=f"Ceph applier {method_name!r} not wired",
            )

        return _apply
