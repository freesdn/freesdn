# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Hotspot service
============================================

Read-and-stage for MikroTik RouterOS Hotspot (captive portal) config:

- Hotspot servers (per-interface)
- Hotspot profiles (login templates, RADIUS bindings)
- Hotspot users (local accounts)
- Hotspot user-profiles (rate / quota templates)
- Walled garden entries
- Active sessions / hosts (read-only)

Supported features::

    mikrotik.hotspot.server          create | update | delete
    mikrotik.hotspot.profile         create | update | delete
    mikrotik.hotspot.user            create | update | delete
    mikrotik.hotspot.user_profile    create | update | delete
    mikrotik.hotspot.walled_garden   create |        | delete

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

# the shared ``redact_secrets`` helper now covers
# ``passphrase`` and ``radius-secret`` (via hyphen-aware
# normalisation). Only ``shared-secret`` is RouterOS-specific and
# not in the shared list, so the per-service mask is reduced to
# that one entry.
_ROUTEROS_HOTSPOT_SENSITIVE: frozenset[str] = frozenset(
    {
        "shared-secret",
    }
)


def _mask_routeros(payload: Any, depth: int = 0) -> Any:
    if depth >= 16:
        return payload
    if isinstance(payload, dict):
        return {
            k: (
                "***"
                if isinstance(k, str) and k.lower() in _ROUTEROS_HOTSPOT_SENSITIVE
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
    # Hotspot server (per-interface)
    ("mikrotik.hotspot.server", "create"): "add_hotspot_server",
    ("mikrotik.hotspot.server", "update"): "update_hotspot_server",
    ("mikrotik.hotspot.server", "delete"): "delete_hotspot_server",
    # Hotspot profile (login templates)
    ("mikrotik.hotspot.profile", "create"): "add_hotspot_profile",
    ("mikrotik.hotspot.profile", "update"): "update_hotspot_profile",
    ("mikrotik.hotspot.profile", "delete"): "delete_hotspot_profile",
    # Hotspot user (local account)
    ("mikrotik.hotspot.user", "create"): "add_hotspot_user",
    ("mikrotik.hotspot.user", "update"): "update_hotspot_user",
    ("mikrotik.hotspot.user", "delete"): "delete_hotspot_user",
    # Hotspot user-profile (rate / quota template)
    ("mikrotik.hotspot.user_profile", "create"): "add_hotspot_user_profile",
    ("mikrotik.hotspot.user_profile", "update"): "update_hotspot_user_profile",
    ("mikrotik.hotspot.user_profile", "delete"): "delete_hotspot_user_profile",
    # Walled garden — no update verb on the client
    ("mikrotik.hotspot.walled_garden", "create"): "add_hotspot_walled_garden_entry",
    ("mikrotik.hotspot.walled_garden", "delete"): "delete_hotspot_walled_garden_entry",
}


class GatewayMikrotikHotspotService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik Hotspot config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_servers(
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
            "items": _redact_items(await client.get_hotspot_servers()),
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
            "items": _redact_items(await client.get_hotspot_profiles()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_users(
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
            "items": _redact_items(await client.get_hotspot_users()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_user_profiles(
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
            "items": _redact_items(await client.get_hotspot_user_profiles()),
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
            "items": _redact_items(await client.get_hotspot_active()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_hosts(
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
            "items": _redact_items(await client.get_hotspot_hosts()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_walled_garden(
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
            "items": _redact_items(await client.get_hotspot_walled_garden()),
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

            # All hotspot features are row-scoped:
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
