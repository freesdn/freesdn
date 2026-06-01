# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense System service
===========================================

Read-and-stage for OPNsense system / firmware / backup operations.
Mirrors the shape of ``adapter_opnsense_firewall.py``: live reads,
staged writes, applier passes ``force=True`` so the OPNsense client's
universal ``ADAPTER_READ_ONLY`` gate lets the sanctioned write through.

Supported features::

    opnsense.system.reboot              create
    opnsense.system.halt                create
    opnsense.system.firmware_check      create
    opnsense.system.firmware_update     create
    opnsense.system.backup_create       create
    opnsense.system.backup_delete       create   (target_id = filename)
    opnsense.system.backup_restore      create   (target_id = filename, or
                                                  payload['filename'])

Reads:
    list_services-style ``info`` (system status)
    firmware status
    list_backups
    download_config (raw XML — handled at the endpoint, not here)

The config-XML download is the special case. ``download_config_xml``
on the client returns a raw text (XML) string, not a JSON dict. The
endpoint streams that out as ``application/octet-stream`` and audit-logs
the access BEFORE the controller fetch, mirroring Omada's
``download_backup`` pattern in ``gateway_system.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name.
#
# ``halt`` is exposed deliberately even though it is destructive — the
# OPNsense API has it, the staging layer keeps it gated behind
# ``firewall:write`` AND ``force=true`` at apply-time, and the operator
# may legitimately need to power down a unit before physical work.
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.system.reboot", "create"): "reboot",
    ("opnsense.system.halt", "create"): "halt",
    ("opnsense.system.firmware_check", "create"): "firmware_check",
    ("opnsense.system.firmware_update", "create"): "firmware_update",
    ("opnsense.system.backup_create", "create"): "create_backup",
    ("opnsense.system.backup_delete", "create"): "delete_backup",
    # OPNsense exposes "revert" as the restore-from-backup op.
    ("opnsense.system.backup_restore", "create"): "revert_backup",
}


class GatewayOpnsenseSystemService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense system / firmware /
    backup."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_info(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            item = await client.get_system_status()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_firmware_status(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            item = await client.get_firmware_status()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def list_backups(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_backup_list()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def download_config_xml(self, controller_id: UUID, organization_id: UUID) -> str:
        """Return the raw OPNsense ``config.xml`` text.

        The endpoint that calls this is responsible for the audit log
        BEFORE invoking us — same shape as Omada's ``download_backup``.
        """
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            return await client.download_config_xml()
        finally:
            await client.close()  # Item 14

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            try:
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
                            f"OPNsense adapter has no method {method_name!r}; "
                            "missing implementation"
                        ),
                    )

                # No-arg writes
                if c.feature in (
                    "opnsense.system.reboot",
                    "opnsense.system.halt",
                    "opnsense.system.firmware_check",
                    "opnsense.system.firmware_update",
                    "opnsense.system.backup_create",
                ):
                    return await method(force=True)

                # Backup ops that need a filename. Prefer ``target_id`` (the
                # canonical staging-layer slot); fall back to
                # ``payload['filename']`` so older callers that put the name
                # in the body still work.
                if c.feature in (
                    "opnsense.system.backup_delete",
                    "opnsense.system.backup_restore",
                ):
                    filename = target_id or payload.get("filename")
                    if not filename:
                        raise HTTPException(
                            400,
                            detail=(
                                f"feature={c.feature!r} requires target_id or payload['filename']"
                            ),
                        )
                    # re-validate the filename at apply-time.
                    # The endpoint validates at stage-time but a row
                    # inserted directly into the staging table could
                    # carry a path-traversal payload otherwise.
                    validate_id(str(filename), label="backup_id")
                    return await method(filename, force=True)

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply
