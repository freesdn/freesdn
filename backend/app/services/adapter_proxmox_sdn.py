# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Live SDN reads. Legacy writes are retained only for explicit rejection.

Native apply commits all pending SDN state before forking reload workers. The
old unbound write plans cannot safely be replayed; new staging is also blocked
until a reviewed, durable native-lock lifecycle and node observation exist.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.sdn import WRITE_BLOCKED
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list

logger = logging.getLogger(__name__)

# Intentionally read only until native lock ownership and reload observation are
# qualified. The applier below rejects historical payloads before credentials.
_APPLY: dict[tuple[str, str], str] = {}


class GatewayProxmoxSdnService(GatewayServiceBase):
    """Live reads and rejection of legacy SDN write plans."""

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

    # ── Live reads ──────────────────────────────────────────────────

    async def list_zones(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_sdn_zones()
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def list_vnets(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_sdn_vnets()
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            # Reject before resolving credentials, even for old persisted rows.
            raise HTTPException(409, detail=WRITE_BLOCKED)

        return _apply
