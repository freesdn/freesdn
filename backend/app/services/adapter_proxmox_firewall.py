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

Supported features::

    proxmox.firewall.cluster_rule    create | delete  (target_id = pos)
    proxmox.firewall.guest_rule      create | delete  (target_id = pos;
                                                       payload includes
                                                       node + vmid +
                                                       vm_type)
    proxmox.firewall.guest_options   update           (payload includes
                                                       node + vmid +
                                                       vm_type + options)

Node-level firewall reads (``get_node_firewall_rules``) are exposed by
the agent-2 node service — this domain owns cluster-scope and
guest-scope only.
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

                # CATASTROPHIC-by-default gate: any firewall-rule delete is blocked
                # unless the staged payload carries confirmed=true. The other Proxmox
                # appliers (vm/snapshot/storage/node) gate per-op; firewall did not,
                # letting cluster/guest rule deletes apply blind (sweep critical/high).
                from app.services.adapter_proxmox_preflight import preflight_gate

                await preflight_gate(adapter, c.feature, c.operation, payload)

                if c.feature == "proxmox.firewall.cluster_rule":
                    if c.operation == "create":
                        action = payload.get("action")
                        if not action or not isinstance(action, str):
                            raise HTTPException(
                                400,
                                detail="cluster_rule create requires action",
                            )
                        # enforce action / type / proto
                        # allow-lists. The adapter takes these strings
                        # straight to URL params; an unexpected value
                        # would either be silently accepted by Proxmox
                        # or surface a 4xx far from this layer.
                        if action not in _FIREWALL_ACTIONS:
                            raise HTTPException(
                                400,
                                detail=(
                                    "cluster_rule.action must be one of "
                                    f"{sorted(_FIREWALL_ACTIONS)}"
                                ),
                            )
                        rule_type = str(payload.get("type", "in"))
                        if rule_type not in _FIREWALL_RULE_TYPES:
                            raise HTTPException(
                                400,
                                detail=(
                                    "cluster_rule.type must be one of "
                                    f"{sorted(_FIREWALL_RULE_TYPES)}"
                                ),
                            )
                        proto = payload.get("proto")
                        if proto is not None and proto != "":
                            if not isinstance(proto, str) or proto not in _FIREWALL_PROTOCOLS:
                                raise HTTPException(
                                    400,
                                    detail=(
                                        "cluster_rule.proto must be one of "
                                        f"{sorted(_FIREWALL_PROTOCOLS)}"
                                    ),
                                )
                        return await method(
                            action=action,
                            rule_type=rule_type,
                            enable=bool(payload.get("enable", True)),
                            source=payload.get("source"),
                            dest=payload.get("dest"),
                            sport=payload.get("sport"),
                            dport=payload.get("dport"),
                            proto=proto,
                            macro=payload.get("macro"),
                            comment=payload.get("comment"),
                            force=True,
                        )
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail="cluster_rule delete requires target_id (pos)",
                            )
                        pos = _validate_pos(target_id)
                        return await method(pos, force=True)

                if c.feature == "proxmox.firewall.guest_rule":
                    node = payload.get("node")
                    vm_type = payload.get("vm_type")
                    vmid = payload.get("vmid")
                    if not isinstance(node, str) or not node:
                        raise HTTPException(
                            400,
                            detail="guest_rule payload must include node",
                        )
                    if vmid is None:
                        raise HTTPException(
                            400,
                            detail="guest_rule payload must include vmid",
                        )
                    node = validate_id(node, label="node")
                    vm_type = _validate_vm_type(vm_type)
                    vmid = _validate_vmid(vmid)

                    if c.operation == "create":
                        rule = payload.get("rule")
                        if not isinstance(rule, dict) or not rule:
                            raise HTTPException(
                                400,
                                detail="guest_rule create requires rule dict",
                            )
                        # Same allow-list applied to the inner rule
                        # dict; the adapter passes these straight
                        # through to Proxmox.
                        rule_action = rule.get("action")
                        if rule_action and rule_action not in _FIREWALL_ACTIONS:
                            raise HTTPException(
                                400,
                                detail=(
                                    f"guest_rule.action must be one of {sorted(_FIREWALL_ACTIONS)}"
                                ),
                            )
                        rule_type_inner = rule.get("type")
                        if rule_type_inner and rule_type_inner not in _FIREWALL_RULE_TYPES:
                            raise HTTPException(
                                400,
                                detail=(
                                    f"guest_rule.type must be one of {sorted(_FIREWALL_RULE_TYPES)}"
                                ),
                            )
                        rule_proto = rule.get("proto")
                        if rule_proto and rule_proto not in _FIREWALL_PROTOCOLS:
                            raise HTTPException(
                                400,
                                detail=(
                                    f"guest_rule.proto must be one of {sorted(_FIREWALL_PROTOCOLS)}"
                                ),
                            )
                        return await method(
                            node=node,
                            vm_type=vm_type,
                            vmid=vmid,
                            rule=rule,
                            force=True,
                        )
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail="guest_rule delete requires target_id (pos)",
                            )
                        pos = _validate_pos(target_id)
                        return await method(
                            node=node,
                            vm_type=vm_type,
                            vmid=vmid,
                            pos=pos,
                            force=True,
                        )

                if c.feature == "proxmox.firewall.guest_options":
                    node = payload.get("node")
                    vm_type = payload.get("vm_type")
                    vmid = payload.get("vmid")
                    options = payload.get("options")
                    if not isinstance(node, str) or not node:
                        raise HTTPException(
                            400,
                            detail="guest_options payload must include node",
                        )
                    if vmid is None:
                        raise HTTPException(
                            400,
                            detail="guest_options payload must include vmid",
                        )
                    if not isinstance(options, dict):
                        raise HTTPException(
                            400,
                            detail="guest_options payload must include options dict",
                        )
                    node = validate_id(node, label="node")
                    vm_type = _validate_vm_type(vm_type)
                    vmid = _validate_vmid(vmid)
                    return await method(
                        node=node,
                        vm_type=vm_type,
                        vmid=vmid,
                        options=options,
                        force=True,
                    )

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
