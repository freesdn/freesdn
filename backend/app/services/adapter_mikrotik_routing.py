# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Routing service
============================================

Read-and-stage for MikroTik RouterOS routing config: static routes,
OSPF (instance/area/area-range/interface-template + neighbors), and
BGP (connection/template + sessions). Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX
applies. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.routing.static_route             create | update | delete
    mikrotik.routing.ospf_instance            create | update | delete
    mikrotik.routing.ospf_area                create | update | delete
    mikrotik.routing.ospf_area_range          create |        | delete
    mikrotik.routing.ospf_interface_template  create | update | delete
    mikrotik.routing.bgp_connection           create | update | delete
    mikrotik.routing.bgp_template             create | update | delete

Production safety: every write is staged. The applier passes
``force=True`` to the MikroTik client so the read-only gate lets the
sanctioned write through; every write outside the applier is refused
at the bottom of the stack.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# RouterOS routing tables surface ``auth-key``/``md5-auth-key`` for
# OSPF/BGP authentication; these aren't matched by the underscored
# allowlist.
_ROUTEROS_ROUTING_SENSITIVE: frozenset[str] = frozenset(
    {
        "auth-key",
        "md5-auth-key",
        "auth-secret",
        "shared-secret",
        "passphrase",
    }
)


def _mask_routeros(payload: Any, depth: int = 0) -> Any:
    if depth >= 16:
        return payload
    if isinstance(payload, dict):
        return {
            k: (
                "***"
                if isinstance(k, str) and k.lower() in _ROUTEROS_ROUTING_SENSITIVE
                else _mask_routeros(v, depth + 1)
            )
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [_mask_routeros(i, depth + 1) for i in payload]
    return payload


def _redact_items(items: list[Any]) -> list[Any]:
    return [_mask_routeros(redact_secrets(i)) for i in items]


# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    # Static routes
    ("mikrotik.routing.static_route", "create"): "add_route",
    ("mikrotik.routing.static_route", "update"): "update_route",
    ("mikrotik.routing.static_route", "delete"): "delete_route",
    # OSPF — instance
    ("mikrotik.routing.ospf_instance", "create"): "add_ospf_instance",
    ("mikrotik.routing.ospf_instance", "update"): "update_ospf_instance",
    ("mikrotik.routing.ospf_instance", "delete"): "delete_ospf_instance",
    # OSPF — area
    ("mikrotik.routing.ospf_area", "create"): "add_ospf_area",
    ("mikrotik.routing.ospf_area", "update"): "update_ospf_area",
    ("mikrotik.routing.ospf_area", "delete"): "delete_ospf_area",
    # OSPF — area-range (no update verb on the client)
    ("mikrotik.routing.ospf_area_range", "create"): "add_ospf_area_range",
    ("mikrotik.routing.ospf_area_range", "delete"): "delete_ospf_area_range",
    # OSPF — interface-template
    ("mikrotik.routing.ospf_interface_template", "create"): "add_ospf_interface_template",
    ("mikrotik.routing.ospf_interface_template", "update"): "update_ospf_interface_template",
    ("mikrotik.routing.ospf_interface_template", "delete"): "delete_ospf_interface_template",
    # BGP — connection
    ("mikrotik.routing.bgp_connection", "create"): "add_bgp_connection",
    ("mikrotik.routing.bgp_connection", "update"): "update_bgp_connection",
    ("mikrotik.routing.bgp_connection", "delete"): "delete_bgp_connection",
    # BGP — template
    ("mikrotik.routing.bgp_template", "create"): "add_bgp_template",
    ("mikrotik.routing.bgp_template", "update"): "update_bgp_template",
    ("mikrotik.routing.bgp_template", "delete"): "delete_bgp_template",
}


class GatewayMikrotikRoutingService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik routing config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ─ static routes ────────────────────────────────────

    async def list_routes(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_routes()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ OSPF ─────────────────────────────────────────────

    async def list_ospf_instances(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ospf_instances()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ospf_areas(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ospf_areas()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ospf_area_ranges(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ospf_area_ranges()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ospf_interface_templates(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ospf_interface_templates()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ospf_neighbors(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ospf_neighbors()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ BGP ──────────────────────────────────────────────

    async def list_bgp_connections(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_bgp_connections()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_bgp_templates(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_bgp_templates()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_bgp_sessions(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_bgp_sessions()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True``; the dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the gate
        via ``AdapterStagingService.apply_change``'s dual-gate check.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # Every routing feature is row-scoped. Uniform shape:
            #   create(payload), update(id, payload), delete(id).
            if c.operation == "create":
                return await method(payload, force=True)
            if c.operation == "update":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"update on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, payload, force=True)
            if c.operation == "delete":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"delete on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, force=True)
            raise HTTPException(
                400,
                detail=(f"unhandled operation={c.operation!r} for feature={c.feature!r}"),
            )

        return _apply
