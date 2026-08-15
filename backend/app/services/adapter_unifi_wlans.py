# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi WLANs service
======================================

Live reads + staged writes for UniFi wireless networks (SSIDs).

Supported features::

    unifi.wlans.create_ssid  create  payload.data = full wlanconf object
    unifi.wlans.update       update  target_id=wlan_id  payload.data
    unifi.wlans.delete_ssid  delete  target_id=wlan_id
    unifi.wlans.password     update  target_id=wlan_id  payload.new_psk
    unifi.wlans.enable       update  target_id=wlan_id  payload.enabled
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
    ("unifi.wlans.create_ssid", "create"): "create_wlan",
    ("unifi.wlans.update", "update"): "update_wlan",
    ("unifi.wlans.delete_ssid", "delete"): "delete_ssid",
    ("unifi.wlans.password", "update"): "update_wlan_password",
    ("unifi.wlans.enable", "update"): "enable_wlan",
}


class GatewayUniFiWlansService(GatewayServiceBase):
    """Live reads + staged writes for UniFi WLANs."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"

    async def list_wlans(
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
        items = await client.list_wlans(site)
        # Strip PSKs (``x_passphrase``) and IAPP keys (``x_iapp_key``)
        # before the WLAN list reaches the operator — UniFi returns
        # them inline on every read.
        return {
            "controller_id": controller_id,
            "site": site,
            "items": ([redact_secrets(w) for w in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_one(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        wlan_id: str,
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
        result = await client.get_wlan(site, wlan_id)
        return redact_secrets(result) if isinstance(result, dict) else result

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site")
            wlan_id = c.target_id

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
            if not site:
                raise HTTPException(
                    400,
                    detail=f"feature {c.feature!r} requires payload.site",
                )

            def _body() -> dict[str, Any]:
                raw = payload.get("data") if isinstance(payload.get("data"), dict) else payload
                return {k: v for k, v in raw.items() if k != "site"}

            # create_wlan(site, payload, *, force=True) — a create has no target_id
            if c.feature == "unifi.wlans.create_ssid":
                return await method(site, _body(), force=True)

            # everything below acts on an existing SSID
            if not wlan_id:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires target_id (wlan_id)"),
                )

            # delete_ssid(site, wlan_id, *, force=True)
            if c.feature == "unifi.wlans.delete_ssid":
                return await method(site, wlan_id, force=True)

            # update_wlan(site, wlan_id, payload, *, force=True) — full update
            if c.feature == "unifi.wlans.update":
                return await method(site, wlan_id, _body(), force=True)

            # update_wlan_password(site, wlan_id, new_psk, *, force=True)
            if c.feature == "unifi.wlans.password":
                new_psk = payload.get("new_psk")
                if not new_psk:
                    raise HTTPException(
                        400,
                        detail=("unifi.wlans.password requires payload.new_psk"),
                    )
                return await method(site, wlan_id, new_psk, force=True)

            # enable_wlan(site, wlan_id, enabled: bool, *, force=True)
            if c.feature == "unifi.wlans.enable":
                enabled = payload.get("enabled")
                if enabled is None:
                    raise HTTPException(
                        400,
                        detail=("unifi.wlans.enable requires payload.enabled (bool)"),
                    )
                return await method(
                    site,
                    wlan_id,
                    bool(enabled),
                    force=True,
                )

            raise HTTPException(
                400,
                detail=f"unhandled feature={c.feature!r}",
            )

        return _apply
