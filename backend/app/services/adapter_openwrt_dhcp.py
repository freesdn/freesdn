# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt DHCP service
=======================================

Read-and-stage for OpenWrt DHCP static host writes (reservations) and
DNS overrides. Mirrors the per-domain pattern used for OPNsense/pfSense.

Supported features::

    openwrt.dhcp.static_host   create | update | delete
    openwrt.dns.override       create | update | delete

The adapter commits ``dhcp`` and reloads ``dnsmasq`` after each write
so each staged change is self-applying — no separate apply feature.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("openwrt.dhcp.static_host", "create"): "create_dhcp_static_mapping",
    ("openwrt.dhcp.static_host", "update"): "update_dhcp_static_mapping",
    ("openwrt.dhcp.static_host", "delete"): "delete_dhcp_static_mapping",
    ("openwrt.dns.override", "create"): "create_dns_override",
    ("openwrt.dns.override", "update"): "update_dns_override",
    ("openwrt.dns.override", "delete"): "delete_dns_override",
}

# Verify-list mapping for the IDOR guard — see
# ``adapter_openwrt_firewall._verify_target_owned`` for the full
# explanation. The applier fetches the live list and confirms the
# staged ``target_id`` (UCI section name or stable UUID) actually
# lives on this controller before letting an update/delete through.
_LIST_FOR_VERIFY: dict[str, tuple[str, str]] = {
    "openwrt.dhcp.static_host": ("get_dhcp_static_mappings", "static_mappings"),
    "openwrt.dns.override": ("get_dns_overrides", "overrides"),
}


async def _verify_target_owned(
    client: Any,
    feature: str,
    target_id: str,
) -> str:
    """Verify ``target_id`` lives on this controller AND return the
    matched UCI section name so the adapter can skip its own lookup.
    Same shape as the firewall-service helper — see that one for the
    full IDOR + perf rationale.
    """
    pair = _LIST_FOR_VERIFY.get(feature)
    if pair is None:
        raise HTTPException(
            501,
            detail=(
                f"no verify-list mapping for feature={feature!r}; "
                "refuse write until target ownership can be checked"
            ),
        )
    list_method_name, items_key = pair
    list_method = getattr(client, list_method_name, None)
    if list_method is None:
        raise HTTPException(
            501,
            detail=(
                f"OpenWrt adapter missing {list_method_name!r} — cannot verify target ownership"
            ),
        )
    result = await list_method()
    if getattr(result, "success", True) is False:
        raise HTTPException(
            502,
            detail=(
                f"could not fetch live {feature} list to verify "
                f"target_id={target_id!r}: "
                f"{getattr(result, 'error', 'unknown error')}"
            ),
        )
    data = getattr(result, "data", None) or {}
    items = data.get(items_key, []) if isinstance(data, dict) else []
    target_str = str(target_id)
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get("id")) == target_str or str(item.get("uci_name")) == target_str:
            uci_name = item.get("uci_name")
            if not isinstance(uci_name, str) or not uci_name:
                raise HTTPException(
                    500,
                    detail=(f"target {target_id!r} matched but is missing a uci_name field"),
                )
            return uci_name
    raise HTTPException(
        404,
        detail=(f"target_id={target_id!r} not found on this controller for feature={feature!r}"),
    )


def _unwrap(result: Any) -> dict[str, Any]:
    if result is None:
        raise HTTPException(502, detail="adapter returned no result")
    if getattr(result, "success", True) is False:
        raise HTTPException(
            502,
            detail=getattr(result, "error", None) or "adapter call failed",
        )
    return {
        "success": True,
        "message": getattr(result, "message", None),
        "data": getattr(result, "data", None),
    }


class GatewayOpenWrtDhcpService(GatewayServiceBase):
    """Staged-write surface for OpenWrt DHCP/DNS UCI sections."""

    SUPPORTED_CONTROLLER_TYPE = "openwrt"

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            if c.operation in ("update", "delete") and not c.target_id:
                raise HTTPException(
                    400,
                    detail=(
                        f"{c.operation} on {c.feature} requires target_id "
                        "(UCI section name or stable UUID)"
                    ),
                )

            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"OpenWrt adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            payload = c.payload or {}
            if c.operation == "create":
                result = await method(payload)
            elif c.operation == "update":
                uci_name = await _verify_target_owned(
                    client,
                    c.feature,
                    c.target_id,
                )
                result = await method(
                    c.target_id,
                    payload,
                    uci_name=uci_name,
                )
            else:
                uci_name = await _verify_target_owned(
                    client,
                    c.feature,
                    c.target_id,
                )
                result = await method(c.target_id, uci_name=uci_name)
            return _unwrap(result)

        return _apply
