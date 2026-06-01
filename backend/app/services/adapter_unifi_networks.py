# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Networks service
=========================================

Live reads + staged writes for UniFi networks (VLANs / subnets).

Supported features::

    unifi.networks.create_vlan   create   payload {vlan_id, name, subnet?,
                                                   dhcp_enabled?, dhcp_start?,
                                                   dhcp_stop?}
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets
from app.services.adapter_unifi_common import enforce_unifi_site_grant

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.networks.create_vlan", "create"): "create_vlan",
    ("unifi.networks.update", "update"): "update_network",
    ("unifi.networks.delete", "delete"): "delete_network",
}


class GatewayUniFiNetworksService(GatewayServiceBase):
    """Live reads + staged writes for UniFi networks."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"

    async def list_networks(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        items = await client.list_networks(site)
        # Networks can carry inline DHCP option strings + RADIUS
        # secrets when an LAN doubles as a managed RADIUS realm.
        return {
            "controller_id": controller_id,
            "site": site,
            "items": ([redact_secrets(n) for n in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_one(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        network_id: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any] | None:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        result = await client.get_network(site, network_id)
        return redact_secrets(result) if isinstance(result, dict) else result

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            payload = c.payload or {}

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
                    detail=(f"UniFi adapter has no method {method_name!r}"),
                )

            # create_vlan(vlan_id, name, **kwargs) — BaseAdapter contract
            # Site comes from the default_site of the
            # adapter; UniFi's networks are controller-wide on a per-
            # site basis.
            if c.feature == "unifi.networks.create_vlan":
                # create_vlan writes the controller's DEFAULT upstream site (it sets
                # self._api.site = self._default_site), NOT payload.site. The generic
                # apply-time grant check saw payload.site, so re-check the per-user
                # grant against the ACTUAL write target here — otherwise a site-limited
                # user could pass the check with a granted slug while the VLAN lands on
                # a mapped-but-ungranted default site.
                enforce_unifi_site_grant(ctrl, getattr(client, "_default_site", None))
                vlan_id = payload.get("vlan_id")
                name = payload.get("name")
                if vlan_id is None or not name:
                    raise HTTPException(
                        400,
                        detail=(
                            "unifi.networks.create_vlan requires payload.vlan_id + payload.name"
                        ),
                    )
                kwargs = {k: v for k, v in payload.items() if k not in {"vlan_id", "name", "site"}}
                # Staged apply already cleared the ADAPTER_READ_ONLY + force
                # dual-gate; opt in to the live write like every other UniFi
                # applier (devices/clients/wlans all pass force=True).
                return await method(int(vlan_id), str(name), force=True, **kwargs)

            site = payload.get("site") or getattr(client, "_default_site", "default")
            if c.feature == "unifi.networks.update":
                if not c.target_id:
                    raise HTTPException(400, detail="unifi.networks.update requires target_id")
                body = {k: v for k, v in payload.items() if k != "site"}
                return await client.update_network(site, c.target_id, body, force=True)
            if c.feature == "unifi.networks.delete":
                if not c.target_id:
                    raise HTTPException(400, detail="unifi.networks.delete requires target_id")
                return await client.delete_network(site, c.target_id, force=True)

            raise HTTPException(
                400,
                detail=f"unhandled feature={c.feature!r}",
            )

        return _apply
