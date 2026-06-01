# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-firmware service
===================================

Reads firmware status + available versions live from the controller.
Writes (single upgrade, batch upgrade, schedule CRUD) all flow through
:class:`AdapterStagingService` — they never touch the live device unless
an operator opts in to force-apply.

This service is feature-distinct from the existing FreeSDN
``app.services.firmware`` which manages locally-stored firmware images
and per-device records in our own ``firmware_*`` tables. This module
fronts the controller's own firmware lifecycle (vendor-supplied images,
controller-driven upgrade jobs).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.models.core import Site
from app.services.adapter_base import GatewayServiceBase, _decrypt  # noqa: F401
from app.services.adapter_redaction import redact_list, redact_secrets


class GatewayFirmwareService(GatewayServiceBase):
    """Read live firmware state from the controller; stage every upgrade."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    # ``_get_controller``, ``_get_client``, ``_resolve_omada_site_id``
    # all inherit from GatewayServiceBase. The base does a single-query
    # JOIN and applies the SSRF host gate before building the adapter,
    # both of which the local copies skipped.

    # ── Live reads ──────────────────────────────────────────────────────

    async def get_device_firmware_info(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        device_mac: str,
    ) -> dict[str, Any]:
        """Current firmware + available upgrade for one device."""
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        info = await client.get_device_firmware_info(omada_site_id, device_mac)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "device_mac": device_mac,
            "info": redact_secrets(info),
            "fetched_at": datetime.now(UTC),
        }

    async def get_available_firmware(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        model: str | None = None,
    ) -> dict[str, Any]:
        """Firmware images available for adopted devices on this site."""
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.get_available_firmware(omada_site_id, model)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "model": model,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def list_firmware_upgrade_schedules(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_firmware_upgrade_schedules(omada_site_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_upgrade_history(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        limit: int = 100,
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.get_firmware_upgrade_history(omada_site_id, limit=limit)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    # ── Stage writes ────────────────────────────────────────────────────

    async def stage_change(
        self,
        *,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID | None,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> Any:
        ctrl = await self._get_controller(controller_id, organization_id)
        omada_site_id = None
        if site_id is not None:
            site = await self.db.get(Site, site_id)
            if (
                site is None
                or site.organization_id != organization_id
                or site.deleted_at is not None
            ):
                raise HTTPException(404, detail="site not found")
            omada_site_id = self._resolve_omada_site_id(ctrl, site)
        return await self.staging.stage_change(
            organization_id=organization_id,
            controller_id=ctrl.id,
            site_id=site_id,
            omada_site_id=omada_site_id,
            feature=feature,
            operation=operation,
            payload=payload,
            target_id=target_id,
            notes=notes,
            actor_id=actor_id,
        )

    # ── Build applier (used only on force-apply) ────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_map: dict[tuple[str, str], str] = {
                ("firmware.upgrade", "create"): "upgrade_device_firmware",
                ("firmware.upgrade.batch", "create"): "upgrade_devices_firmware_batch",
                ("firmware.schedule", "create"): "create_firmware_upgrade_schedule",
                ("firmware.schedule", "update"): "update_firmware_upgrade_schedule",
                ("firmware.schedule", "delete"): "delete_firmware_upgrade_schedule",
            }
            method_name = method_map.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name)

            # Argument shape varies
            if c.feature == "firmware.upgrade" and c.operation == "create":
                # payload: {"device_mac": "...", "version": "..."}
                return await method(
                    omada_site_id,
                    payload["device_mac"],
                    version=payload.get("version"),
                )
            if c.feature == "firmware.upgrade.batch" and c.operation == "create":
                # payload: {"macs": [...], "version": "..."}
                return await method(
                    omada_site_id,
                    payload["macs"],
                    version=payload.get("version"),
                )
            if c.feature == "firmware.schedule":
                if c.operation == "create":
                    return await method(omada_site_id, payload)
                if c.operation == "update":
                    if target_id is None:
                        raise HTTPException(400, detail="update needs target_id")
                    return await method(omada_site_id, target_id, payload)
                if c.operation == "delete":
                    if target_id is None:
                        raise HTTPException(400, detail="delete needs target_id")
                    return await method(omada_site_id, target_id)
            raise HTTPException(400, detail="unhandled change shape")

        return _apply
