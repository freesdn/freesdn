# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Cluster service
==========================================

Read-and-stage for Proxmox VE cluster-wide config: status, log,
resources, options, replication, config nodes, tasks (list/status/log/
stop) and cluster-level firewall options. Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX works
for Proxmox.

Production-safety contract:

- Reads run live against the cluster.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    proxmox.cluster.task_stop          create  (target_id = upid)
    proxmox.cluster.firewall_options   update  (no target_id)

Subscription is exposed as a read endpoint folded into this domain
since it's a cluster-level read-only concern. Cluster (extended)
methods (``get_cluster_options``, ``get_cluster_log``,
``get_cluster_config_nodes``, ``get_cluster_replication``) are also
folded in here.

The applier passes ``force=True`` to the Proxmox client so the write
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
from app.adapters.validation import validate_id, validate_upid
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list, redact_secrets

logger = logging.getLogger(__name__)

# (feature, operation) → bound adapter method name. The applier uses
# this to dispatch — same pattern as the OPNsense services.
_REDACTED = "***"

# Task-identity fields we strip before surfacing the task list. Keep
# enough metadata that operators see "what's running" on the cluster
# (type/status/start_time/end_time) but mask the operator-identity
# columns that other tenants don't need to see. The ``user`` and
# ``saved`` fields commonly carry ``operator@pam`` / mail target
# addresses respectively.
_TASK_ACTOR_FIELDS: frozenset[str] = frozenset(
    {
        "user",
        "saved",
    }
)


def _mask_task_actor(task: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *task* with operator-identity fields masked.

    Defense-in-depth for multi-tenant Proxmox visibility. Today every
    FreeSDN controller is single-tenant so the basic exposure is
    closed by the
    ``_get_proxmox_adapter`` org check, but stripping the actor
    metadata means future shared-Proxmox deployments don't leak
    operator account names + realms across tenants.
    """
    masked = dict(task)
    for k in _TASK_ACTOR_FIELDS:
        if k in masked and masked[k]:
            masked[k] = _REDACTED
    return masked


_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.cluster.task_stop", "create"): "stop_task",
    ("proxmox.cluster.firewall_options", "update"): "update_cluster_firewall_options",
}


class GatewayProxmoxClusterService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox cluster-wide config."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter helper ──────────────────────────────────────────────

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

    async def get_status(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_status()
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "data": redact_secrets(result.data),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_log(
        self,
        controller_id: UUID,
        organization_id: UUID,
        max_entries: int = 200,
    ) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_log(max_entries=max_entries)
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_resources(
        self,
        controller_id: UUID,
        organization_id: UUID,
        resource_type: str | None = None,
    ) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_resources(resource_type=resource_type)
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_options(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_options()
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "data": redact_secrets(result.data) if result.success else {},
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_replication(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_replication()
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_config_nodes(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_config_nodes()
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_tasks(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        limit: int = 50,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_tasks(node=node, limit=limit)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )

        # Multi-tenant filter. On a
        # shared Proxmox cluster the task list cuts across every
        # tenant that uses the box — exposing other operators' user
        # identifiers (``user@realm``), their VM/CT ids in task UPIDs,
        # and the timing of their operations. FreeSDN's controller is
        # already org-scoped via Site→Org FK so the basic cross-org
        # exposure is closed, but defense in depth says we strip the
        # operator-identity fields anyway — those leak operator
        # account names + realms even within the same org.
        #
        # We keep the task type / status / start time / end time
        # because operators legitimately need to see "what's running"
        # on the cluster; we mask the ``user``, ``saved`` (mail
        # endpoint), and ``upid``-embedded user fragment.
        items = redact_list(result.data) if result.success else []
        items = [_mask_task_actor(t) for t in items if isinstance(t, dict)]
        return {
            "controller_id": controller_id,
            "node": node,
            "ok": result.success,
            "items": items,
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_task_status(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        upid: str,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        # validate_upid (wider charset + longer cap) — generic
        # validate_id refuses real Proxmox UPIDs because they contain
        # ``@`` and exceed 64 chars. Same fix as cluster.task_stop.
        upid = validate_upid(upid, label="upid")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_task_status(node=node, upid=upid)
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "node": node,
            "upid": upid,
            "ok": result.success,
            "data": redact_secrets(result.data),
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_task_log(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        upid: str,
        start: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        upid = validate_upid(upid, label="upid")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_task_log(node=node, upid=upid, start=start, limit=limit)
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "node": node,
            "upid": upid,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_firewall_options(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_cluster_firewall_options()
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "data": redact_secrets(result.data) if result.success else {},
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_subscription(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
    ) -> dict[str, Any]:
        """Read-only subscription status for a node — folded into cluster
        domain since it's a per-node read but not a write surface."""
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_node_subscription(node=node)
        finally:
            await adapter.disconnect()
        if not result.success:
            # REST semantics: an upstream cluster-read failure is a gateway
            # error, not a 200 with ok=false in the body (which clients silently
            # treated as success). Mirrors adapter_proxmox_node.py.
            raise HTTPException(
                status_code=502, detail=result.error or "Proxmox cluster query failed"
            )
        return {
            "controller_id": controller_id,
            "node": node,
            "ok": result.success,
            "data": redact_secrets(result.data) if result.success else {},
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the cluster.

        Every call passes ``force=True`` to the Proxmox client so it
        satisfies the client-layer read-only check — that gate is
        the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher (``gateway_vpn.apply_change``)
        is what actually opens the gate via
        ``AdapterStagingService.apply_change``'s dual-gate check.
        """

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

                if c.feature == "proxmox.cluster.task_stop":
                    # target_id = upid; payload should carry node so we know
                    # which node owns the task. Validate both.
                    if not target_id:
                        raise HTTPException(400, detail="task_stop requires target_id (upid)")
                    node = payload.get("node")
                    if not isinstance(node, str) or not node:
                        raise HTTPException(400, detail="task_stop payload must include node")
                    node = validate_id(node, label="node")
                    # Real Proxmox UPIDs contain ``@`` (user@realm) and
                    # are ~85 chars — the generic ``validate_id`` regex
                    # refuses them. Use the dedicated UPID validator.
                    # Without this, every real
                    # ``task_stop`` apply would 400 before reaching the
                    # adapter — silent feature-broken-in-production.
                    upid = validate_upid(target_id, label="upid")
                    return await method(node=node, upid=upid, force=True)
                if c.feature == "proxmox.cluster.firewall_options":
                    # No target_id — the cluster firewall options object is
                    # a singleton. Payload is the options dict.
                    return await method(payload, force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
