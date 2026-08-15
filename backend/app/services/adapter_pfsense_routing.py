# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Routing service
===========================================

Read-and-stage for pfSense gateways and static routes.

Status of write surface today:
    - The pfSense client only exposes *read* methods for routing
      (``get_gateways``, ``get_gateway_status``, ``get_static_routes``).
    - No ``add_static_route`` / ``delete_static_route`` / etc. on the
      client today. ``_APPLY`` is empty until the adapter grows the
      write verbs.

The shape still matches ``adapter_opnsense_routing.py``: live reads,
``GatewayServiceBase`` + ``SUPPORTED_CONTROLLER_TYPE = "pfsense"``,
and a ``build_applier`` that 501s every feature for now.

Supported features:: (none yet — reads only)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# Empty until the pfSense adapter grows static-route write methods.
_APPLY: dict[tuple[str, str], str] = {}


class GatewayPfsenseRoutingService(GatewayServiceBase):
    """Live reads (writes deferred until adapter grows route write verbs)."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_gateways(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        gateways = await client.get_gateways()
        return {
            "controller_id": controller_id,
            "items": (
                [redact_secrets(g) for g in gateways] if isinstance(gateways, list) else gateways
            ),
            "fetched_at": datetime.now(UTC),
        }

    async def get_gateway_status(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        status_data = await client.get_gateway_status()
        return {
            "controller_id": controller_id,
            "status": status_data,
            "fetched_at": datetime.now(UTC),
        }

    async def list_static_routes(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        routes = await client.get_static_routes()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in routes] if isinstance(routes, list) else routes),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Routing writes are not yet implemented on the pfSense adapter;
        every feature lands here and 501s until the adapter side ships.
        """

        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense routing write surface is not yet "
                        f"implemented (feature={c.feature!r}, "
                        f"operation={c.operation!r}). The adapter "
                        "exposes reads only — add the corresponding "
                        "``add_*``/``delete_*`` method to "
                        "``app/adapters/pfsense/client.py`` first."
                    ),
                )
            # Unreachable today — kept so the diff to enable a feature
            # is one ``_APPLY`` row + dispatch branch below.
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense adapter has no method {method_name!r}; missing implementation"
                    ),
                )
            payload = c.payload or {}
            target_id = c.target_id
            if c.operation == "create":
                return await method(payload, force=True)
            if c.operation == "update":
                return await method(target_id, payload, force=True)
            if c.operation == "delete":
                return await method(target_id, force=True)
            raise HTTPException(
                400,
                detail=(f"unhandled operation={c.operation!r} for feature={c.feature!r}"),
            )

        return _apply
