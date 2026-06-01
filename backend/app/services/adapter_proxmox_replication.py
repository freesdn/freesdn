# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Replication service
==============================================

READS ONLY for Proxmox VE storage replication jobs. The Proxmox
adapter currently exposes ``get_replication_jobs`` /
``get_replication_log`` but no replication-write surface (job
create/edit/delete is a future build-out). This service is the
read plumbing + a sentinel applier that keeps the URL shape
consistent with the other gateway-* services for the day a write
surface lands.

Production-safety contract:

- Reads run live against the cluster.
- No writes: every staging POST is rejected at the endpoint layer
  (see ``app/api/v1/endpoints/adapter_proxmox_replication.py`` —
  the ``startswith("proxmox.replication.")`` allow-list never
  matches because ``_APPLY`` is empty, so even if a caller ignored
  the URL prefix the applier would 400).

Supported features:: (none — reads only for now)

When the Proxmox adapter grows ``create_replication_job`` /
``delete_replication_job``, add them to ``_APPLY`` and the
``build_applier`` dispatch below.
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

# Empty for now — replication writes aren't implemented in the adapter
# yet. The map exists so the dispatcher contract stays stable.
_APPLY: dict[tuple[str, str], str] = {}


class GatewayProxmoxReplicationService(GatewayServiceBase):
    """Live reads for Proxmox replication jobs (writes not yet wired)."""

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

    async def list_jobs(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_replication_jobs()
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    async def get_job_log(
        self,
        controller_id: UUID,
        organization_id: UUID,
        replication_id: str,
    ) -> dict[str, Any]:
        # Replication ID looks like ``vmid-N`` (e.g. ``100-0``); allow
        # the standard opaque-ID pattern.
        replication_id = validate_id(replication_id, label="replication_id")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_replication_log(replication_id=replication_id)
        finally:
            await adapter.disconnect()
        return {
            "controller_id": controller_id,
            "replication_id": replication_id,
            "ok": result.success,
            "items": redact_list(result.data) if result.success else [],
            "error": result.error,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ──────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that 400s — no replication writes are
        implemented yet. This keeps the dispatcher contract stable so
        when the adapter grows ``create_replication_job`` etc. the
        wiring lands here without an import-time change to
        ``gateway_vpn._service_for_feature``.
        """

        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(
                        f"no applier for feature={c.feature!r} "
                        f"operation={c.operation!r} — Proxmox replication "
                        "writes are not implemented"
                    ),
                )
            # Unreachable until _APPLY is populated. Kept to mirror the
            # other services' shape.
            raise HTTPException(  # pragma: no cover
                501,
                detail=f"replication applier {method_name!r} not wired",
            )

        return _apply
