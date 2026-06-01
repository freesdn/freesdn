# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense System service
==========================================

Read-and-stage for pfSense system / firmware operations. Mirrors
``adapter_opnsense_system.py``: live reads, staged writes, applier
passes ``force=True`` so the pfSense client's universal
``ADAPTER_READ_ONLY`` gate lets the sanctioned write through.

Supported features::

    pfsense.system.reboot              create
    pfsense.system.halt                create

Reads:
    info (system status)
    version
    firmware info

The pfSense client does not currently expose firmware-update or
config-restore verbs, so those features are omitted. ``halt`` is
exposed deliberately even though it is destructive — the staging
layer keeps it gated behind ``firewall:write`` AND ``force=true`` at
apply-time, and the operator may legitimately need to power down a
unit before physical work.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    ("pfsense.system.reboot", "create"): "reboot",
    ("pfsense.system.halt", "create"): "halt",
}


class GatewayPfsenseSystemService(GatewayServiceBase):
    """Live reads + staged writes for pfSense system / firmware."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_info(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.get_system_status()
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_version(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.get_system_version()
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_firmware_info(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.get_firmware_info()
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            # Fast-fail BEFORE building a network client.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            # reboot / halt are one-shot ops — explicitly gate
            # operation so an accidental ``update`` / ``delete`` does
            # NOT fall through to the no-arg write below.
            if (
                c.feature
                in (
                    "pfsense.system.reboot",
                    "pfsense.system.halt",
                )
                and c.operation != "create"
            ):
                raise HTTPException(
                    400,
                    detail=(f"{c.feature} only supports operation=create (one-shot)"),
                )

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

            # No-arg writes (reboot / halt).
            if c.feature in (
                "pfsense.system.reboot",
                "pfsense.system.halt",
            ):
                return await method(force=True)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply
