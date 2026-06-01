# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Node service
========================================

Read-and-stage for per-node Proxmox operations: power (reboot /
shutdown), service control (pveproxy / pvedaemon / etc.), APT package
refresh, and TLS certificate management. Mirrors
``adapter_opnsense_firewall.py`` so the same Pending Changes UX works
for Proxmox.

Hard production-safety constraint: Proxmox is in PRODUCTION. Three
operations here are catastrophic / high-risk:

* ``proxmox.node.shutdown`` takes the node offline with no automatic
  recovery (someone has to physically / IPMI-power-on the box).
* ``proxmox.node.reboot`` cycles the node — every VM/CT on it goes
  down for the duration.
* ``proxmox.node.certificate_upload`` replaces the node's TLS cert; a
  bad cert / key mismatch can lock the operator out of pveproxy.

Every write is STAGED first; the dual-gate (``ADAPTER_READ_ONLY=false``
AND ``force=true`` in the apply call) is the last guardrail.

Supported features::

    proxmox.node.reboot               create  (target_id = node) — CATASTROPHIC
    proxmox.node.shutdown             create  (target_id = node) — CATASTROPHIC
    proxmox.node.service_action       create  (target_id = service;
                                                payload = {node, action})
    proxmox.node.apt_refresh          create  (payload = {node})
    proxmox.node.certificate_upload   create  — HIGH-RISK
                                                (payload = {node,
                                                            certificates,
                                                            key,
                                                            overwrite?,
                                                            restart?})
    proxmox.node.certificate_delete   delete  (target_id = node)
    proxmox.node.acme_renew           create  (target_id = node)

The applier passes ``force=True`` to the Proxmox adapter so the write
actually reaches the cluster — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
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
from app.services.adapter_redaction import redact_secrets

logger = logging.getLogger(__name__)

# (feature, operation) → bound adapter method name. The applier
# uses this to dispatch — same pattern Omada / OPNsense services use.
_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.node.reboot", "create"): "reboot_node",
    ("proxmox.node.shutdown", "create"): "shutdown_node",
    ("proxmox.node.service_action", "create"): "node_service_action",
    ("proxmox.node.apt_refresh", "create"): "refresh_node_apt",
    ("proxmox.node.certificate_upload", "create"): "upload_custom_certificate",
    ("proxmox.node.certificate_delete", "delete"): "delete_custom_certificate",
    ("proxmox.node.acme_renew", "create"): "renew_node_acme_certificate",
}

# Allowed Proxmox node-level service actions (start / stop / restart /
# reload). Locked-down to avoid arbitrary verbs being passed through
# to the cluster — the Proxmox API is permissive about strings.
_ALLOWED_SERVICE_ACTIONS = frozenset({"start", "stop", "restart", "reload"})

# Allow-list of services the applier will touch. Locks the
# ``service_action`` feature to the Proxmox-internal services
# documented in the PVE admin guide so a hostile staging payload
# can't restart unrelated systemd units (e.g. ``ssh``).
_ALLOWED_SERVICES: frozenset[str] = frozenset(
    {
        "pveproxy",
        "pvedaemon",
        "pvestatd",
        "pve-cluster",
        "pve-firewall",
        "pve-ha-crm",
        "pve-ha-lrm",
        "cron",
        "chrony",
        "corosync",
    }
)

# Cluster-critical services: stopping or restarting any of these can break
# quorum (``corosync``), the cluster config filesystem (``pve-cluster`` /
# pmxcfs, which goes read-only and locks out the API), or HA fencing
# (``pve-ha-crm`` / ``pve-ha-lrm`` — a stale LRM can trigger a node fence).
# A disruptive action on one of these is effectively cluster-wide and
# catastrophic, so it is gated behind an explicit ``confirmed=true`` in the
# staged payload — the same second factor the catastrophic-op preflight uses
# for node reboot/shutdown. ``start`` (recovery) and ``reload`` (graceful,
# non-interrupting) stay ungated.
_CLUSTER_CRITICAL_SERVICES: frozenset[str] = frozenset(
    {
        "corosync",
        "pve-cluster",
        "pve-ha-crm",
        "pve-ha-lrm",
    }
)
_DISRUPTIVE_SERVICE_ACTIONS: frozenset[str] = frozenset({"stop", "restart"})


class GatewayProxmoxNodeService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox per-node operations."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter helper ───────────────────────────────────────────────

    @staticmethod
    async def _build_adapter(ctrl: Controller) -> ProxmoxAdapter:
        """Item 9: forwards to the shared ``build_proxmox_adapter`` helper."""
        return await build_proxmox_adapter(ctrl)

    async def _get_proxmox_adapter(
        self, controller_id: UUID, organization_id: UUID
    ) -> ProxmoxAdapter:
        """Resolve the Proxmox controller and return a connected adapter."""
        ctrl = await self._get_controller(controller_id, organization_id)
        if ctrl.controller_type != "proxmox":
            raise HTTPException(
                400,
                detail=(
                    "this gateway feature requires a 'proxmox' "
                    f"controller; got {ctrl.controller_type!r}"
                ),
            )
        return await self._build_adapter(ctrl)

    # ── Live reads ───────────────────────────────────────────────────
    #
    # Each read calls a single adapter method, validates ``node`` (and
    # ``disk`` where applicable), and re-shapes the result into the
    # standard ``{controller_id, node, items|item, fetched_at}`` envelope
    # the frontend already understands.

    async def _read(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        method_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            method = getattr(adapter, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"Proxmox adapter has no method {method_name!r}; missing implementation"
                    ),
                )
            result = await method(node, *args, **kwargs)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        # Adapter returns either a list, a dict, or a dataclass. Pass
        # the raw value through — FastAPI handles serialization for
        # whichever shape the underlying call produced.
        data = result.data
        if hasattr(data, "__dict__"):
            data = dict(data.__dict__)
        return {
            "controller_id": controller_id,
            "node": node,
            "data": redact_secrets(data),
            "fetched_at": datetime.now(UTC),
        }

    async def get_status(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_status")

    async def get_network(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_network")

    async def get_disks(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_disks")

    async def get_dns(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_dns")

    async def get_services(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_services")

    async def get_sensors(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_sensors")

    async def get_rrd(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        timeframe: str = "hour",
    ) -> dict[str, Any]:
        # Proxmox accepts: hour | day | week | month | year. Reject
        # anything else so injection through the timeframe param is
        # impossible.
        if timeframe not in ("hour", "day", "week", "month", "year"):
            raise HTTPException(400, detail="invalid timeframe")
        return await self._read(
            controller_id, organization_id, node, "get_node_rrd", timeframe=timeframe
        )

    async def get_certificates(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_certificates")

    async def get_apt_updates(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_apt_updates")

    async def get_apt_versions(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_apt_versions")

    async def get_firewall_rules(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        return await self._read(controller_id, organization_id, node, "get_node_firewall_rules")

    async def get_disk_smart(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        disk: str,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        disk = validate_id(disk, label="disk")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_disk_smart(node, disk)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "disk": disk,
            "data": redact_secrets(result.data),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the cluster.

        Every call passes ``force=True`` to the Proxmox adapter so it
        satisfies the client-layer read-only check.
        """

        async def _apply(c: Any) -> Any:
            adapter: ProxmoxAdapter | None = None
            try:
                adapter = await self._get_proxmox_adapter(c.controller_id, c.organization_id)
                payload = c.payload or {}
                target_id = c.target_id or ""

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

                # ── Power: reboot / shutdown ──────────────────────────
                if c.feature in ("proxmox.node.reboot", "proxmox.node.shutdown"):
                    node = validate_id(target_id, label="node")
                    # Pre-flight: rebooting/shutting a node interrupts EVERY
                    # running guest on it — CATASTROPHIC, blocked unless the
                    # staged payload carries confirmed=true; the read-only check
                    # counts the affected guests.
                    from app.services.adapter_proxmox_preflight import preflight_gate

                    await preflight_gate(adapter, c.feature, c.operation, {**payload, "node": node})
                    return await method(node, force=True)

                # ── Service action ────────────────────────────────────
                if c.feature == "proxmox.node.service_action":
                    # target_id = service name (pveproxy, pvedaemon, …);
                    # payload = {node, action}.
                    service_raw = validate_id(target_id, label="service")
                    if service_raw not in _ALLOWED_SERVICES:
                        raise HTTPException(
                            400,
                            detail=(
                                "proxmox.node.service_action.service must "
                                f"be one of {sorted(_ALLOWED_SERVICES)}"
                            ),
                        )
                    node = validate_id(str(payload.get("node", "")), label="node")
                    action = str(payload.get("action", ""))
                    if action not in _ALLOWED_SERVICE_ACTIONS:
                        raise HTTPException(
                            400,
                            detail=(
                                "proxmox.node.service_action.action must be "
                                f"one of {sorted(_ALLOWED_SERVICE_ACTIONS)}"
                            ),
                        )
                    # Catastrophic guard: stopping/restarting a cluster-critical
                    # service (corosync / pve-cluster / pve-ha-*) is effectively
                    # cluster-wide — it can drop quorum, freeze pmxcfs, or trip HA
                    # fencing. classify() returns SAFE for this feature (operation
                    # is "create"), so the standard preflight_gate would NOT block
                    # it; gate it here with the same confirmed=true second factor.
                    from app.services.adapter_preflight_common import payload_confirmed

                    if (
                        service_raw in _CLUSTER_CRITICAL_SERVICES
                        and action in _DISRUPTIVE_SERVICE_ACTIONS
                        and not payload_confirmed(payload)
                    ):
                        raise HTTPException(
                            409,
                            detail=(
                                f"{action!r} on cluster-critical service "
                                f"{service_raw!r} is catastrophic (can break quorum, "
                                "freeze the cluster config filesystem, or trip HA "
                                "fencing); re-stage with confirmed=true to proceed"
                            ),
                        )
                    return await method(node, service_raw, action, force=True)

                # ── APT refresh ───────────────────────────────────────
                if c.feature == "proxmox.node.apt_refresh":
                    # Accept node either in target_id or payload — the
                    # frontend may not have a meaningful target_id for
                    # this action.
                    node_raw = target_id or str(payload.get("node", ""))
                    node = validate_id(node_raw, label="node")
                    return await method(node, force=True)

                # ── Certificate: upload (HIGH-RISK) ───────────────────
                if c.feature == "proxmox.node.certificate_upload":
                    # target_id = node; payload = {certificates, key,
                    # overwrite?, restart?}.
                    node = validate_id(target_id, label="node")
                    certificates = str(payload.get("certificates", ""))
                    key = str(payload.get("key", ""))
                    if not (certificates and key):
                        raise HTTPException(
                            400,
                            detail=(
                                "proxmox.node.certificate_upload requires certificates and key"
                            ),
                        )
                    overwrite = bool(payload.get("overwrite", False))
                    restart = bool(payload.get("restart", False))
                    return await method(
                        node,
                        certificates,
                        key,
                        overwrite=overwrite,
                        restart=restart,
                        force=True,
                    )

                # ── Certificate: delete ───────────────────────────────
                if c.feature == "proxmox.node.certificate_delete":
                    node = validate_id(target_id, label="node")
                    restart = bool(payload.get("restart", False))
                    return await method(node, restart=restart, force=True)

                # ── ACME renewal ──────────────────────────────────────
                if c.feature == "proxmox.node.acme_renew":
                    node = validate_id(target_id, label="node")
                    acme_force = bool(payload.get("acme_force", False))
                    return await method(node, acme_force=acme_force, force=True)

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
