# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway firewall depth service
========================================================

Read URL filter / app control / port-forward / DMZ / 1:1 NAT / UPnP /
attack defense / ALG / IDS-IPS state. Writes are staged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

# Read-list mapping: feature group → client method name
_READ_LISTS: dict[str, str] = {
    "url_filter": "list_url_filter_rules",
    "app_filter": "list_app_filter_rules",
    "app_categories": "get_app_categories",
    "port_forward": "list_port_forwards",
    "one_to_one_nat": "list_one_to_one_nat",
    "upnp_mappings": "list_upnp_mappings",
    "ids_ips_events": "get_ids_ips_events",
}

# Read-config mapping: feature group → client method name (single dict response)
_READ_CONFIGS: dict[str, str] = {
    "dmz": "get_dmz_config",
    "upnp": "get_upnp_config",
    "attack_defense": "get_attack_defense_config",
    "alg": "get_alg_config",
    "ids_ips": "get_ids_ips_config",
}

# Apply mapping for staged writes: (feature, operation) → client method name
_APPLY: dict[tuple[str, str], str] = {
    # URL filter
    ("firewall.urlfilter.rule", "create"): "create_url_filter_rule",
    ("firewall.urlfilter.rule", "update"): "update_url_filter_rule",
    ("firewall.urlfilter.rule", "delete"): "delete_url_filter_rule",
    # App filter
    ("firewall.appfilter.rule", "create"): "create_app_filter_rule",
    ("firewall.appfilter.rule", "update"): "update_app_filter_rule",
    ("firewall.appfilter.rule", "delete"): "delete_app_filter_rule",
    # Port forwarding
    ("firewall.port_forward", "create"): "create_port_forward",
    ("firewall.port_forward", "update"): "update_port_forward",
    ("firewall.port_forward", "delete"): "delete_port_forward",
    # DMZ (single-item config)
    ("firewall.dmz", "update"): "update_dmz_config",
    # 1:1 NAT
    ("firewall.one_to_one_nat", "create"): "create_one_to_one_nat",
    ("firewall.one_to_one_nat", "update"): "update_one_to_one_nat",
    ("firewall.one_to_one_nat", "delete"): "delete_one_to_one_nat",
    # UPnP
    ("firewall.upnp", "update"): "update_upnp_config",
    ("firewall.upnp.mapping", "delete"): "delete_upnp_mapping",
    # Attack defense
    ("firewall.attack_defense", "update"): "update_attack_defense_config",
    # ALG
    ("firewall.alg", "update"): "update_alg_config",
    # IDS/IPS
    ("firewall.ids_ips", "update"): "update_ids_ips_config",
    ("firewall.ids_ips.signatures", "create"): "update_ids_ips_signatures",
}


class GatewayFirewallService(GatewayServiceBase):
    """Read live firewall depth state; stage every write."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def list_collection(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        collection: str,
    ) -> dict[str, Any]:
        method_name = _READ_LISTS.get(collection)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(
                    f"unknown collection={collection!r}; expected one of {sorted(_READ_LISTS)}"
                ),
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await getattr(client, method_name)(omada_site_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "collection": collection,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_config(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        config_name: str,
    ) -> dict[str, Any]:
        method_name = _READ_CONFIGS.get(config_name)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(f"unknown config={config_name!r}; expected one of {sorted(_READ_CONFIGS)}"),
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = await getattr(client, method_name)(omada_site_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "config_name": config_name,
            "item": redact_secrets(item),
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
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name)

            if c.operation == "create":
                return await method(omada_site_id, payload)
            if c.operation == "update":
                if target_id is None:
                    return await method(omada_site_id, payload)
                return await method(omada_site_id, target_id, payload)
            if c.operation == "delete":
                if target_id is None:
                    raise HTTPException(400, detail="delete needs target_id")
                return await method(omada_site_id, target_id)
            raise HTTPException(400, detail=f"bad operation={c.operation!r}")

        return _apply
