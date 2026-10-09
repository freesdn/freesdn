# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Firewall service
============================================

Read-and-stage for Proxmox VE firewall config: cluster-level rules,
per-VM/CT (guest) rules, and guest firewall options.

Production-safety contract:

- Reads run live against the cluster.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Reviewed writes use ``proxmox.firewall.operation`` through the hypervisor
review/submit endpoints, including cluster, node and guest scopes. Legacy
cluster_rule, guest_rule and guest_options entries remain recognizable for
compatibility but are refused before credentials; review those intents again.
Node-level legacy reads remain exposed by the node service.
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
    ("proxmox.firewall.operation", "create"): "apply_firewall_operation",
    ("proxmox.firewall.cluster_rule", "create"): "create_firewall_rule",
    ("proxmox.firewall.cluster_rule", "delete"): "delete_firewall_rule",
    ("proxmox.firewall.guest_rule", "create"): "create_guest_firewall_rule",
    ("proxmox.firewall.guest_rule", "delete"): "delete_guest_firewall_rule",
    ("proxmox.firewall.guest_options", "update"): "update_guest_firewall_options",
}

_VM_TYPES = ("qemu", "lxc")

# Allow-listed Proxmox firewall rule fields (Item 16). Anything else
# is a hostile or accidentally-typed value and gets rejected so the
# adapter never sees an unexpected verb / type / proto.
_FIREWALL_ACTIONS: frozenset[str] = frozenset({"ACCEPT", "REJECT", "DROP"})
_FIREWALL_RULE_TYPES: frozenset[str] = frozenset({"in", "out", "group"})
# Proxmox supports the standard L4 protocol names plus ICMP variants
# and a handful of other IP protocols. Anything outside this set is
# refused — easier to expand later than to rescue from a misuse now.
_FIREWALL_PROTOCOLS: frozenset[str] = frozenset(
    {
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "igmp",
        "ipv6-icmp",
        "esp",
        "ah",
        "gre",
        "ipv4",
        "ipv6",
        "sctp",
        "udplite",
    }
)


def _validate_vm_type(vm_type: Any) -> str:
    """Restrict to ``qemu`` / ``lxc`` — the only two Proxmox guest
    types. Reject anything else so a malformed payload can't reach the
    URL-interpolation layer."""
    if vm_type not in _VM_TYPES:
        raise HTTPException(
            400,
            detail=f"vm_type must be one of {_VM_TYPES}",
        )
    return vm_type


def _validate_pos(value: Any) -> int:
    """Firewall rule positions are integers (Proxmox returns them as
    ``pos`` field). Coerce safely."""
    try:
        pos = int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            400,
            detail="invalid firewall rule position (expected int)",
        ) from exc
    if pos < 0:
        raise HTTPException(400, detail="firewall rule position must be >= 0")
    return pos


def _validate_vmid(value: Any) -> int:
    try:
        vmid = int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, detail="invalid vmid (expected int)") from exc
    if vmid < 100 or vmid > 999_999_999:
        # Proxmox VMIDs start at 100 by convention; cap at a sane upper
        # bound so a hostile caller can't send arbitrary integers.
        raise HTTPException(400, detail="vmid out of range (100..999999999)")
    return vmid


class GatewayProxmoxFirewallService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox firewall (cluster + guest)."""

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

    async def list_cluster_rules(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_firewall_rules()
        finally:
            await adapter.disconnect()
        items: list[Any] = []
        if result.success and isinstance(result.data, list):
            for rule in result.data:
                if hasattr(rule, "__dict__"):
                    items.append(dict(rule.__dict__))
                else:
                    items.append(rule)
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(items),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def list_guest_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        vm_type: str,
        vmid: int,
        node: str,
    ) -> dict[str, Any]:
        vm_type = _validate_vm_type(vm_type)
        vmid = _validate_vmid(vmid)
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_guest_firewall_rules(
                node=node,
                vm_type=vm_type,
                vmid=vmid,
            )
        finally:
            await adapter.disconnect()
        items: list[Any] = []
        if result.success and isinstance(result.data, list):
            for rule in result.data:
                if hasattr(rule, "__dict__"):
                    items.append(dict(rule.__dict__))
                else:
                    items.append(rule)
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "vm_type": vm_type,
            "ok": result.success,
            "items": redact_list(items),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_guest_options(
        self,
        controller_id: UUID,
        organization_id: UUID,
        vm_type: str,
        vmid: int,
        node: str,
    ) -> dict[str, Any]:
        vm_type = _validate_vm_type(vm_type)
        vmid = _validate_vmid(vmid)
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_guest_firewall_options(
                node=node,
                vm_type=vm_type,
                vmid=vmid,
            )
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "vm_type": vm_type,
            "ok": result.success,
            "data": redact_secrets(result.data) if result.success else {},
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            from app.services.hypervisor_firewall_operations import apply_firewall

            return await apply_firewall(self, c)

        return _apply
