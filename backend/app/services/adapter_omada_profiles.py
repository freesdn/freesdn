# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway profile/group service
=======================================================

Reads live MAC/Domain/OUI groups, time ranges, rate-limit profiles,
PPSK / RADIUS / LDAP profiles. Writes stage through AdapterStagingService.

These are the foundational object-catalog primitives that URL filter,
app control, bandwidth control, captive portal, RADIUS-backed SSIDs,
and 802.1X all reference by ID.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

# Profile types this service exposes. Each maps to a client-method
# triple (list/create/update/delete) and a feature dotted-string.
_PROFILE_TYPES: dict[str, dict[str, str]] = {
    "mac_groups": {
        "list": "list_mac_groups",
        "get": "get_mac_group",
        "create": "create_mac_group",
        "update": "update_mac_group",
        "delete": "delete_mac_group",
        "feature": "profile.mac_group",
    },
    "domain_groups": {
        "list": "list_domain_groups",
        "get": "get_domain_group",
        "create": "create_domain_group",
        "update": "update_domain_group",
        "delete": "delete_domain_group",
        "feature": "profile.domain_group",
    },
    "oui_profiles": {
        "list": "list_oui_profiles",
        "create": "create_oui_profile",
        "update": "update_oui_profile",
        "delete": "delete_oui_profile",
        "feature": "profile.oui",
    },
    "time_ranges": {
        "list": "list_time_ranges",
        "get": "get_time_range",
        "create": "create_time_range",
        "update": "update_time_range",
        "delete": "delete_time_range",
        "feature": "profile.time_range",
    },
    "rate_limit_profiles": {
        "list": "list_rate_limit_profiles",
        "create": "create_rate_limit_profile",
        "update": "update_rate_limit_profile",
        "delete": "delete_rate_limit_profile",
        "feature": "profile.rate_limit",
    },
    "ppsk_profiles": {
        "list": "list_ppsk_profiles",
        "create": "create_ppsk_profile",
        "update": "update_ppsk_profile",
        "delete": "delete_ppsk_profile",
        "feature": "profile.ppsk",
    },
    "radius_profiles": {
        "list": "list_radius_profiles",
        "get": "get_radius_profile",
        "create": "create_radius_profile",
        "update": "update_radius_profile",
        "delete": "delete_radius_profile",
        "feature": "profile.radius",
    },
    "ldap_profiles": {
        "list": "list_ldap_profiles",
        "create": "create_ldap_profile",
        "update": "update_ldap_profile",
        "delete": "delete_ldap_profile",
        "feature": "profile.ldap",
    },
}


def _profile_meta(profile_type: str) -> dict[str, str]:
    meta = _PROFILE_TYPES.get(profile_type)
    if meta is None:
        raise HTTPException(
            400,
            detail=(
                f"unknown profile_type={profile_type!r}; expected one of {sorted(_PROFILE_TYPES)}"
            ),
        )
    return meta


class GatewayProfilesService(GatewayServiceBase):
    """Live reads + staged writes for the Omada profile catalog."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def list_profiles(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        profile_type: str,
    ) -> dict[str, Any]:
        meta = _profile_meta(profile_type)
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await getattr(client, meta["list"])(omada_site_id)
        # radius/ppsk/ldap profiles carry RADIUS shared secrets,
        # per-user PSKs and LDAP bind passwords — redact before returning to a
        # network:read (viewer/operator) caller, mirroring the VPN sibling.
        items = redact_list(items) if isinstance(items, list) else redact_secrets(items)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "profile_type": profile_type,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_profile(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        profile_type: str,
        profile_id: str,
    ) -> dict[str, Any]:
        meta = _profile_meta(profile_type)
        if "get" not in meta:
            raise HTTPException(
                400,
                detail=(
                    f"profile_type={profile_type!r} has no single-item "
                    "GET endpoint; use list and filter client-side"
                ),
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = await getattr(client, meta["get"])(omada_site_id, profile_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "profile_type": profile_type,
            "item": redact_secrets(item),
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        """Apply a staged profile change. Refused unless the staging
        service's dual-gate is satisfied."""

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            # Feature looks like "profile.mac_group" — find which type.
            for ptype, meta in _PROFILE_TYPES.items():
                if c.feature == meta["feature"]:
                    method_key = c.operation
                    method_name = meta.get(method_key)
                    if method_name is None:
                        raise HTTPException(
                            400,
                            detail=(
                                f"operation={c.operation!r} not supported for profile_type={ptype}"
                            ),
                        )
                    method = getattr(client, method_name)
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
            raise HTTPException(
                400,
                detail=f"feature={c.feature!r} not handled by profiles applier",
            )

        return _apply
