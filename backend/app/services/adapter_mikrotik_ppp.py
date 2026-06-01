# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik PPP / PPPoE service
================================================

Read-and-stage for MikroTik RouterOS PPP and PPPoE config:

- PPPoE servers (interface concentrators)
- PPPoE clients (uplinks to ISPs)
- PPP secrets (per-user accounts)
- PPP profiles (rate / DNS / address-pool templates)
- Active sessions (read-only)

Supported features::

    mikrotik.ppp.pppoe_server   create | update | delete
    mikrotik.ppp.pppoe_client   create | update | delete
    mikrotik.ppp.secret         create | update | delete
    mikrotik.ppp.profile        create | update | delete

Production safety: every write is staged. The applier passes
``force=True`` so the read-only gate at the client layer lets the
sanctioned write through.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# the shared ``redact_secrets`` helper now
# normalises hyphens and covers ``private-key``, ``passphrase`` and
# ``radius-secret``. Only ``shared-secret`` and ``auth-secret`` are
# RouterOS-specific and not yet in the shared list, so the per-
# service mask is reduced to those two entries.
_ROUTEROS_PPP_SENSITIVE: frozenset[str] = frozenset(
    {
        "shared-secret",
        "auth-secret",
    }
)


def _mask_routeros(payload: Any, depth: int = 0) -> Any:
    if depth >= 16:
        return payload
    if isinstance(payload, dict):
        return {
            k: (
                "***"
                if isinstance(k, str) and k.lower() in _ROUTEROS_PPP_SENSITIVE
                else _mask_routeros(v, depth + 1)
            )
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [_mask_routeros(i, depth + 1) for i in payload]
    return payload


def _redact_items(items: list[Any]) -> list[Any]:
    return [_mask_routeros(redact_secrets(i)) for i in items]


_APPLY: dict[tuple[str, str], str] = {
    # PPPoE server (interface concentrator)
    ("mikrotik.ppp.pppoe_server", "create"): "add_pppoe_server",
    ("mikrotik.ppp.pppoe_server", "update"): "update_pppoe_server",
    ("mikrotik.ppp.pppoe_server", "delete"): "delete_pppoe_server",
    # PPPoE client (uplink)
    ("mikrotik.ppp.pppoe_client", "create"): "add_pppoe_client",
    ("mikrotik.ppp.pppoe_client", "update"): "update_pppoe_client",
    ("mikrotik.ppp.pppoe_client", "delete"): "delete_pppoe_client",
    # PPP secrets (per-user)
    ("mikrotik.ppp.secret", "create"): "add_ppp_secret",
    ("mikrotik.ppp.secret", "update"): "update_ppp_secret",
    ("mikrotik.ppp.secret", "delete"): "delete_ppp_secret",
    # PPP profile templates
    ("mikrotik.ppp.profile", "create"): "add_ppp_profile",
    ("mikrotik.ppp.profile", "update"): "update_ppp_profile",
    ("mikrotik.ppp.profile", "delete"): "delete_ppp_profile",
}


class GatewayMikrotikPppService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik PPP / PPPoE config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_pppoe_servers(
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
            "items": _redact_items(await client.get_pppoe_servers()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_pppoe_clients(
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
            "items": _redact_items(await client.get_pppoe_clients()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_secrets(
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
            "items": _redact_items(await client.get_ppp_secrets()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_profiles(
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
            "items": _redact_items(await client.get_ppp_profiles()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_active(
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
            "items": _redact_items(await client.get_ppp_active()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
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

            # Every PPP feature is row-scoped with the same shape:
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
