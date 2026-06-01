# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox SDN service
=======================================

Read-and-stage for Proxmox VE Software Defined Network: zones,
VNets, and the apply pipeline that commits pending SDN config to
the running cluster.

Production-safety contract:

- Reads run live against the cluster.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    proxmox.sdn.zone   create | delete  (target_id = zone name)
    proxmox.sdn.vnet   create | delete  (target_id = vnet name)
    proxmox.sdn.apply  create           (commit staged SDN config)

The apply feature is exposed because zone/vnet writes sit in the
"pending" SDN state on the controller until ``apply_sdn`` is called
— the operator decides when the running config switches.
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
from app.services.adapter_redaction import redact_list

logger = logging.getLogger(__name__)

_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.sdn.zone", "create"): "create_sdn_zone",
    ("proxmox.sdn.zone", "delete"): "delete_sdn_zone",
    ("proxmox.sdn.vnet", "create"): "create_sdn_vnet",
    ("proxmox.sdn.vnet", "delete"): "delete_sdn_vnet",
    ("proxmox.sdn.apply", "create"): "apply_sdn",
}


class GatewayProxmoxSdnService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox SDN config."""

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
            adapter: ProxmoxAdapter | None = None
            try:
                ctrl = await self._get_controller(c.controller_id, c.organization_id)
                adapter = await self._build_adapter(ctrl)
                payload = c.payload or {}
                target_id = c.target_id

                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                    )
                method = getattr(adapter, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"Proxmox adapter has no method {method_name!r}; missing implementation"
                        ),
                    )

                if c.feature == "proxmox.sdn.zone":
                    if c.operation == "create":
                        zone = payload.get("zone") or target_id
                        if not zone or not isinstance(zone, str):
                            raise HTTPException(400, detail="zone create requires zone name")
                        zone = validate_id(zone, label="zone")
                        zone_type = payload.get("type") or payload.get("zone_type")
                        if not zone_type or not isinstance(zone_type, str):
                            raise HTTPException(400, detail="zone create requires zone type")
                        # zone_type is a controlled vocabulary (simple, vlan,
                        # qinq, vxlan, evpn) — let validate_id reject path
                        # traversal.
                        zone_type = validate_id(zone_type, label="zone_type")
                        # Strip ``force`` so a malicious payload can't
                        # collide with the staging applier's force=True. The
                        # adapter signature is keyword-only for ``force`` so
                        # any kwargs collision would raise TypeError; we
                        # filter defensively.
                        extras = {
                            k: v
                            for k, v in payload.items()
                            if k not in ("zone", "type", "zone_type", "force")
                        }
                        return await method(zone, zone_type, force=True, **extras)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(400, detail="zone delete requires target_id")
                        zone = validate_id(target_id, label="zone")
                        # Pre-flight safety: an SDN zone delete is an
                        # unclassified delete -> CATASTROPHIC by default, so it
                        # is refused unless the staged payload carries
                        # confirmed=true (mirrors the snapshot applier).
                        from app.services.adapter_proxmox_preflight import preflight_gate

                        await preflight_gate(
                            adapter,
                            c.feature,
                            c.operation,
                            {**payload, "zone": zone},
                        )
                        return await method(zone, force=True)

                if c.feature == "proxmox.sdn.vnet":
                    if c.operation == "create":
                        vnet = payload.get("vnet") or target_id
                        if not vnet or not isinstance(vnet, str):
                            raise HTTPException(400, detail="vnet create requires vnet name")
                        vnet = validate_id(vnet, label="vnet")
                        zone = payload.get("zone")
                        if not zone or not isinstance(zone, str):
                            raise HTTPException(400, detail="vnet create requires zone")
                        zone = validate_id(zone, label="zone")
                        extras = {
                            k: v for k, v in payload.items() if k not in ("vnet", "zone", "force")
                        }
                        return await method(vnet, zone, force=True, **extras)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(400, detail="vnet delete requires target_id")
                        vnet = validate_id(target_id, label="vnet")
                        # Pre-flight safety: an SDN vnet delete is an
                        # unclassified delete -> CATASTROPHIC by default, so it
                        # is refused unless the staged payload carries
                        # confirmed=true (mirrors the snapshot applier).
                        from app.services.adapter_proxmox_preflight import preflight_gate

                        await preflight_gate(
                            adapter,
                            c.feature,
                            c.operation,
                            {**payload, "vnet": vnet},
                        )
                        return await method(vnet, force=True)

                if c.feature == "proxmox.sdn.apply":
                    # No target, no payload — just commit pending SDN.
                    return await method(force=True)

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
