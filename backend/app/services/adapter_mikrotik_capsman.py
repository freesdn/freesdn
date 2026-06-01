# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik CAPsMAN service
============================================

Read-and-stage for MikroTik CAPsMAN (centralized AP management):

- Configuration profiles (SSID, channel, security binding, …)
- Datapaths (bridge / interface mapping)
- Security profiles (WPA / WPA2 / WPA3)
- Manager (singleton — enable + cert + ca-cert)
- Access list (per-MAC ACL)
- Interfaces (CAP-side virtual ifaces)
- Registrations (associated APs / clients — read-only)

Supported features::

    mikrotik.capsman.configuration   create | update | delete
    mikrotik.capsman.datapath        create | update | delete
    mikrotik.capsman.security        create | update | delete
    mikrotik.capsman.manager         update         (singleton)
    mikrotik.capsman.access_list     create |        | delete
    mikrotik.capsman.interface       update         (no create — APs auto-register)

Production safety: every write is staged; the applier passes
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
# ``passphrase``, ``private-key`` and ``tls-certificate`` (via
# hyphen-aware normalisation). Only the RouterOS-specific
# ``mschapv2-password`` and ``shared-secret`` aren't in the shared
# list, so the per-service mask is reduced to those.
_ROUTEROS_CAPSMAN_SENSITIVE: frozenset[str] = frozenset(
    {
        "mschapv2-password",  # CAPsMAN EAP-MSCHAPv2 inner password
        "shared-secret",  # IPsec / RADIUS shared secret
    }
)


def _mask_routeros(payload: Any, depth: int = 0) -> Any:
    if depth >= 16:
        return payload
    if isinstance(payload, dict):
        return {
            k: (
                "***"
                if isinstance(k, str) and k.lower() in _ROUTEROS_CAPSMAN_SENSITIVE
                else _mask_routeros(v, depth + 1)
            )
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [_mask_routeros(i, depth + 1) for i in payload]
    return payload


def _redact_items(items: list[Any]) -> list[Any]:
    return [_mask_routeros(redact_secrets(i)) for i in items]


def _redact_item(item: Any) -> Any:
    return _mask_routeros(redact_secrets(item))


_APPLY: dict[tuple[str, str], str] = {
    # Configuration
    ("mikrotik.capsman.configuration", "create"): "add_capsman_configuration",
    ("mikrotik.capsman.configuration", "update"): "update_capsman_configuration",
    ("mikrotik.capsman.configuration", "delete"): "delete_capsman_configuration",
    # Datapath
    ("mikrotik.capsman.datapath", "create"): "add_capsman_datapath",
    ("mikrotik.capsman.datapath", "update"): "update_capsman_datapath",
    ("mikrotik.capsman.datapath", "delete"): "delete_capsman_datapath",
    # Security profile
    ("mikrotik.capsman.security", "create"): "add_capsman_security_profile",
    ("mikrotik.capsman.security", "update"): "update_capsman_security_profile",
    ("mikrotik.capsman.security", "delete"): "delete_capsman_security_profile",
    # Manager (singleton)
    ("mikrotik.capsman.manager", "update"): "update_capsman_manager",
    # Access list
    ("mikrotik.capsman.access_list", "create"): "add_capsman_access_list_entry",
    ("mikrotik.capsman.access_list", "delete"): "delete_capsman_access_list_entry",
    # Interface (per-AP virtual iface — only update; create is auto)
    ("mikrotik.capsman.interface", "update"): "update_capsman_interface",
}

_SINGLETON_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.capsman.manager",
    }
)

# Features that take (target_id, payload) for update — every row-scoped
# update verb in CAPsMAN. Used by the dispatcher below.
_ROW_SCOPED_UPDATE: frozenset[str] = frozenset(
    {
        "mikrotik.capsman.configuration",
        "mikrotik.capsman.datapath",
        "mikrotik.capsman.security",
        "mikrotik.capsman.interface",
    }
)


class GatewayMikrotikCapsmanService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik CAPsMAN config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_configurations(
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
            "items": _redact_items(await client.get_capsman_configurations()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_datapaths(
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
            "items": _redact_items(await client.get_capsman_datapaths()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_security(
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
            "items": _redact_items(await client.get_capsman_security()),
            "fetched_at": datetime.now(UTC),
        }

    async def get_manager(
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
            "item": _redact_item(await client.get_capsman_manager()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_access_list(
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
            "items": _redact_items(await client.get_capsman_access_list()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_registrations(
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
            "items": _redact_items(await client.get_capsman_registrations()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_interfaces(
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
            "items": _redact_items(await client.get_capsman_interfaces()),
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

            # Singleton resources: just PATCH the whole thing.
            if c.feature in _SINGLETON_FEATURES:
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                return await method(payload, force=True)

            # mikrotik.capsman.interface only supports update (id, payload).
            if c.feature == "mikrotik.capsman.interface":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"update on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, payload, force=True)

            # Row-scoped features. Uniform shape:
            #   create(payload), update(id, payload), delete(id).
            if c.operation == "create":
                return await method(payload, force=True)
            if c.operation == "update":
                if c.feature not in _ROW_SCOPED_UPDATE:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} does not support 'update'"),
                    )
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
