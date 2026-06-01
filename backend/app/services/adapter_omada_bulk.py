# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway bulk-ops + cloning + templates service.

All operations here are mutations against the controller, so every
single request goes through the staging service. There is no live-
write codepath in this service even when callers pass force=true —
the apply step still runs through AdapterStagingService.apply_change.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.core.site_access import assert_site_access_for_request
from app.models.core import Site
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → client method name
_APPLY: dict[tuple[str, str], str] = {
    # Bulk device ops
    ("bulk.device.adopt", "create"): "bulk_adopt_devices",
    ("bulk.device.forget", "create"): "bulk_forget_devices",
    ("bulk.device.reboot", "create"): "bulk_reboot_devices",
    ("bulk.device.factory_reset", "create"): "bulk_factory_reset_devices",
    ("bulk.device.locate", "create"): "bulk_locate_devices",
    ("bulk.device.move_site", "create"): "bulk_move_devices_to_site",
    # Bulk SSID + clients
    ("bulk.ssid.set_state", "create"): "bulk_set_ssid_state",
    ("bulk.client.block", "create"): "bulk_block_clients",
    ("bulk.client.unblock", "create"): "bulk_unblock_clients",
    ("bulk.client.kick", "create"): "bulk_kick_clients",
    # Site cloning + templates
    ("site.clone", "create"): "clone_site",
    ("site.template.export", "create"): "export_site_template",
    ("site.template.apply", "create"): "apply_site_template",
    ("site.template.delete", "delete"): "delete_site_template",
}


class GatewayBulkService(GatewayServiceBase):
    """Stages every bulk operation. Reads (template list) run live."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def list_site_templates(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.list_site_templates()
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            # A change staged outside the Omada REST endpoints — e.g. by the
            # Fabric executor, which threads only the FreeSDN site_id — carries no
            # omada_site_id. Resolve it from the controller's site_mappings so the
            # bulk write targets the correct Omada site instead of "".
            if not omada_site_id and c.site_id:
                site = await self.db.get(Site, c.site_id)
                omada_site_id = self._resolve_omada_site_id(ctrl, site) or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name)

            # Bulk device ops (the macs are in payload["macs"])
            if (
                c.feature.startswith("bulk.device.")
                and c.feature != ("bulk.device.locate")
                and c.feature != "bulk.device.move_site"
            ):
                return await method(omada_site_id, payload["macs"])

            if c.feature == "bulk.device.locate":
                return await method(
                    omada_site_id,
                    payload["macs"],
                    duration_seconds=payload.get("duration_seconds", 60),
                )

            if c.feature == "bulk.device.move_site":
                # Tenancy guard (two parts): the move target is an Omada-side
                # site id interpolated straight into the controller request.
                #   (1) It must be one of the controller's mapped Omada sites —
                #       otherwise a caller could move devices into an arbitrary
                #       Omada site id (no FreeSDN site / another tenant's site).
                #   (2) The FreeSDN site that Omada site maps to must be one the
                #       CALLER IS GRANTED. site_mappings is
                #       {omada_site_id: freesdn_site_uuid}, so a known KEY can
                #       still map to a non-granted sibling FreeSDN site B that
                #       merely shares this physical controller — the key-only
                #       check (1) does not cover that. Mirror controllers.py
                #       (_assert_mapping_targets_accessible), which
                #       grant-checks every mapping VALUE.
                target_site_id = payload["target_site_id"]
                mapped_freesdn_sid = (ctrl.site_mappings or {}).get(str(target_site_id))
                if mapped_freesdn_sid is None:
                    raise HTTPException(
                        400,
                        detail=(
                            "target_site_id is not a known site on this "
                            "controller (must be one of the controller's "
                            "mapped Omada sites)"
                        ),
                    )
                # Per-user site grant on the RESOLVED FreeSDN target site. Reads
                # the request's current_user_var (set during apply); no-op for
                # super_admin / org_admin / grant-less callers. Raises 404 so a
                # site-limited operator gets no existence oracle on sibling sites.
                assert_site_access_for_request(
                    UUID(str(mapped_freesdn_sid)),
                    detail="target site not found",
                )
                return await method(
                    omada_site_id,
                    payload["macs"],
                    target_site_id=target_site_id,
                )

            if c.feature == "bulk.ssid.set_state":
                return await method(
                    omada_site_id,
                    payload["ssid_ids"],
                    enabled=payload.get("enabled", True),
                )

            if c.feature in (
                "bulk.client.block",
                "bulk.client.unblock",
                "bulk.client.kick",
            ):
                return await method(omada_site_id, payload["macs"])

            # Site clone + templates
            if c.feature == "site.clone":
                return await method(
                    omada_site_id,
                    new_name=payload["new_name"],
                    copy_devices=payload.get("copy_devices", False),
                )

            if c.feature == "site.template.export":
                return await method(omada_site_id, name=payload["name"])

            if c.feature == "site.template.apply":
                return await method(omada_site_id, template_id=payload["template_id"])

            if c.feature == "site.template.delete":
                if target_id is None:
                    raise HTTPException(400, detail="template delete needs target_id")
                return await method(target_id)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply
