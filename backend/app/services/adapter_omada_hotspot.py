# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway hotspot deeper service: operator accounts, SMS gateway,
form-auth fields, free-auth policies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

_APPLY: dict[tuple[str, str], str] = {
    ("hotspot.operator", "create"): "create_hotspot_operator",
    ("hotspot.operator", "update"): "update_hotspot_operator",
    ("hotspot.operator", "delete"): "delete_hotspot_operator",
    ("hotspot.sms_gateway", "update"): "update_sms_gateway_config",
    ("hotspot.sms_gateway.test", "create"): "test_sms_gateway",
    ("hotspot.form_auth_fields", "update"): "update_form_auth_fields",
    ("hotspot.free_auth_policy", "create"): "create_free_auth_policy",
    ("hotspot.free_auth_policy", "update"): "update_free_auth_policy",
    ("hotspot.free_auth_policy", "delete"): "delete_free_auth_policy",
}


class GatewayHotspotService(GatewayServiceBase):
    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def list_operators(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_hotspot_operators(omada_site_id)
        return self._envelope(controller_id, site_id, items)

    async def get_sms_gateway(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        # SMS gateway config carries apiSecret/apiKey — redact.
        item = redact_secrets(await client.get_sms_gateway_config(omada_site_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_form_auth_fields(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        portal_id: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = redact_list(await client.get_form_auth_fields(omada_site_id, portal_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "portal_id": portal_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_free_auth_policies(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_free_auth_policies(omada_site_id)
        return self._envelope(controller_id, site_id, items)

    @staticmethod
    def _envelope(controller_id: UUID, site_id: UUID, items: Any) -> dict[str, Any]:
        # operator rows can carry per-operator passwords; redact.
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(400, detail=f"no applier for {c.feature!r}/{c.operation!r}")
            method = getattr(client, method_name)

            if c.feature == "hotspot.operator":
                if c.operation == "create":
                    return await method(omada_site_id, payload)
                if c.operation == "update":
                    return await method(omada_site_id, target_id, payload)
                if c.operation == "delete":
                    return await method(omada_site_id, target_id)

            if c.feature == "hotspot.sms_gateway.test":
                return await method(
                    omada_site_id,
                    recipient=payload["recipient"],
                    message=payload["message"],
                )

            if c.feature == "hotspot.form_auth_fields":
                return await method(omada_site_id, payload["portal_id"], payload["fields"])

            if c.feature == "hotspot.free_auth_policy":
                if c.operation == "create":
                    return await method(omada_site_id, payload)
                if c.operation == "update":
                    return await method(omada_site_id, target_id, payload)
                if c.operation == "delete":
                    return await method(omada_site_id, target_id)

            # SMS gateway update
            return await method(omada_site_id, payload)

        return _apply
