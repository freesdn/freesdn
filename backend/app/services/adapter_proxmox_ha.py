# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox HA service
======================================

Read-and-stage for Proxmox VE HA (High Availability): groups,
resources, and overall HA status. Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX works
for Proxmox HA.

Production-safety contract:

- Reads run live against the cluster.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    proxmox.ha.group       create | delete  (target_id = group name)
    proxmox.ha.resource    create | delete  (target_id = sid like vm:100)
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

_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.ha.group", "create"): "create_ha_group",
    ("proxmox.ha.group", "delete"): "delete_ha_group",
    ("proxmox.ha.resource", "create"): "create_ha_resource",
    ("proxmox.ha.resource", "delete"): "delete_ha_resource",
}


def _validate_sid(sid: str) -> str:
    """Validate an HA service ID like ``vm:100`` or ``ct:200``.

    Proxmox allows ``vm:<vmid>`` and ``ct:<vmid>``; we accept those
    plus generic alphanumeric IDs to stay future-proof. Rejects path
    traversal sequences just like ``validate_id``.
    """
    if not isinstance(sid, str) or not sid:
        raise HTTPException(400, detail="invalid sid format")
    # Allow exactly one ``:`` between prefix and numeric suffix.
    parts = sid.split(":")
    if len(parts) == 2:
        prefix, suffix = parts
        validate_id(prefix, label="sid_prefix")
        validate_id(suffix, label="sid_suffix")
        return sid
    # Otherwise enforce the standard opaque-ID pattern.
    return validate_id(sid, label="sid")


class GatewayProxmoxHaService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox HA config."""

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

    async def list_groups(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_ha_groups()
        finally:
            await adapter.disconnect()
        items: list[Any] = []
        if result.success and isinstance(result.data, list):
            for g in result.data:
                if hasattr(g, "__dict__"):
                    items.append(dict(g.__dict__))
                else:
                    items.append(g)
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(items),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def list_resources(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_ha_resources()
        finally:
            await adapter.disconnect()
        items: list[Any] = []
        if result.success and isinstance(result.data, list):
            for r in result.data:
                if hasattr(r, "__dict__"):
                    items.append(dict(r.__dict__))
                else:
                    items.append(r)
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(items),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_status(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_ha_status()
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "data": redact_secrets(result.data),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            from app.services.hypervisor_cluster_operations import apply_cluster_operation

            return await apply_cluster_operation(self, c)

        return _apply
