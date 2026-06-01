# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Shared base for UniFi domain gateway services
========================================================

The expanded UniFi surface (firewall / wifi / traffic / dns / …) is wide but
mechanically uniform: every gated adapter write shares the
``(site, [target_id], [payload], *, force)`` shape. This base collapses that
into:

  * ``_read_collection`` — a redacted live read of any adapter list method;
  * a generic ``build_applier`` that dispatches create / update / delete
    through a per-service ``APPLY_MAP`` (``(feature, operation) -> method``).

A concrete service therefore only declares ``FEATURE_PREFIX`` + ``APPLY_MAP``
and adds thin read wrappers. The staged applier opts in with ``force=True``
*after* the staging dual-gate has cleared (mirrors the networks/clients
services); destructive deletes are registered in
``adapter_staging._CATASTROPHIC_EVENT_PREFIXES``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.core.site_access import assert_site_access_for_request, site_ids_for_request
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets


def enforce_unifi_site_grant(ctrl: Any, site_slug: str | None) -> None:
    """Enforce the per-user FreeSDN site grant for a requested UniFi site slug.

    A single UniFi controller can front multiple upstream sites; the operator maps
    each upstream slug → a FreeSDN site via ``controller.site_mappings``
    (``{slug: freesdn_site_id}``). ``_get_controller`` / ``_resolve_controller_or_gateway``
    only bind the request to the *controller's* FreeSDN site — so a site-limited
    user who can reach the controller could otherwise name a SIBLING upstream slug
    the stored credential happens to see (a cross-site read/write). This closes
    that gap.

    Enforced through the request-scoped current-user contextvar
    (``assert_site_access_for_request`` / ``site_ids_for_request``), so it needs no
    ``current_user`` threading and is a no-op for super/org admins, grant-less
    users, and system/background context.

    Policy:
      * No mappings configured → the controller-row grant already governs; allow.
      * No slug supplied → the applier/read falls back to the controller's DEFAULT
        upstream site, which is NOT verifiable here. A site-limited caller must name
        an explicit slug that maps to a granted site (else it could silently hit a
        mapped-but-ungranted sibling via the default); unrestricted callers pass.
      * Slug maps to a FreeSDN site_id → a site-limited user must hold that grant
        (404 otherwise, matching the existence-oracle-safe convention).
      * Mappings ARE configured but the slug is unmapped → a site-limited user
        can't be shown to hold a grant for it → 404; unrestricted users pass.
    """
    mappings = getattr(ctrl, "site_mappings", None) or {}
    if not mappings:
        return
    if not site_slug:
        # No explicit slug → default-site fallback the grant check can't verify. A
        # site-limited caller must name an explicit granted slug; the earlier
        # grant-check/applier slug MISMATCH (check saw no slug, applier wrote the
        # default) is closed by denying here.
        if site_ids_for_request() is not None:  # caller is site-limited
            raise HTTPException(status_code=404, detail="site not found")
        return
    raw = mappings.get(site_slug)
    if raw is None:
        # Operator configured slug→FreeSDN mappings but this one isn't among them.
        if site_ids_for_request() is not None:  # caller is site-limited
            raise HTTPException(status_code=404, detail="site not found")
        return
    try:
        site_id = UUID(str(raw))
    except (ValueError, TypeError):
        # Malformed mapping value — don't 500; org + controller scoping still apply.
        return
    assert_site_access_for_request(site_id, detail="site not found")


class GatewayUniFiServiceBase(GatewayServiceBase):
    """Generic reads + uniform create/update/delete applier for UniFi domains."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"
    FEATURE_PREFIX: str = "unifi."
    APPLY_MAP: dict[tuple[str, str], str] = {}

    async def _read_collection(
        self,
        adapter_method: str,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        enforce_unifi_site_grant(ctrl, site)
        adapter = await self._get_adapter(ctrl)
        items = await getattr(adapter, adapter_method)(site)
        if isinstance(items, list):
            items = [redact_secrets(i) for i in items]
        else:
            items = redact_secrets(items)
        return {
            "controller_id": controller_id,
            "site": site,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    @staticmethod
    def _body(payload: dict[str, Any]) -> dict[str, Any]:
        """The object body to send — payload.data if present, else payload itself,
        minus the routing-only ``site`` key."""
        raw = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        return {k: v for k, v in raw.items() if k != "site"}

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            adapter = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site") or getattr(adapter, "_default_site", "default")

            method_name = self.APPLY_MAP.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=f"no applier for feature={c.feature!r} operation={c.operation!r}",
                )
            method = getattr(adapter, method_name, None)
            if method is None:
                raise HTTPException(501, detail=f"UniFi adapter has no method {method_name!r}")

            # Staged apply has already cleared the dual-gate; opt in to the live
            # write with force=True like every UniFi applier.
            if c.operation == "create":
                return await method(site, self._body(payload), force=True)
            if c.operation == "update":
                if not c.target_id:
                    raise HTTPException(400, detail="update requires target_id")
                return await method(site, c.target_id, self._body(payload), force=True)
            if c.operation == "delete":
                if not c.target_id:
                    raise HTTPException(400, detail="delete requires target_id")
                return await method(site, c.target_id, force=True)
            raise HTTPException(400, detail=f"unhandled operation={c.operation!r}")

        return _apply
