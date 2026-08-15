# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX inbound-routes (DIDs) staging service
=========================================================

Live reads + staged CRUD for inbound routes / DIDs on a FreePBX PBX.
Twin of :mod:`app.services.adapter_freepbx_extensions` — same shape,
different feature prefix.

Backed by FreePBX 16+'s GraphQL surface:
    Read:  ``allInboundRoutes { inboundRoutes { ... } }``
    Write: ``addInboundRoute`` / ``updateInboundRoute`` / ``removeInboundRoute``

The REST client's :meth:`list_dids` was migrated to GraphQL in this
same PR; the adapter's read path therefore returns the canonical
shape (``id`` / ``extension`` / ``cidnum`` / ``description`` /
``destinationConnection``) under OAuth2 and falls back to the
AJAX grid for legacy installs.

The taxonomy:

    pbx.inbound_route.create     stage → apply → adapter.create_did
    pbx.inbound_route.update     stage → apply → adapter.update_did
    pbx.inbound_route.delete     stage → apply → adapter.delete_did

The adapter implements ``create_did`` / ``update_did`` / ``delete_did``
over the GraphQL ``addInboundRoute`` / ``updateInboundRoute`` /
``removeInboundRoute`` mutations (force-gated like every other config
write). The apply path drives them with ``force=True`` post env-lock;
if a given install's adapter is older and lacks a method, the applier
still falls back to a 501 with the staged intent preserved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXInboundRoutesService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX DID/inbound-route CRUD.

    PBX resolution + controllers auto-pair + adapter construction are
    inherited from :class:`FreePBXServiceBase`.
    """

    @staticmethod
    def _envelope(
        controller_id: UUID,
        items: list[dict[str, Any]] | dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "controller_id": controller_id,
            "items": items if isinstance(items, list) else [items],
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ──────────────────────────────────────────────────────

    async def list_inbound_routes(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        """List inbound routes (DIDs) from the PBX."""
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.list_dids()
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_dids failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    # ── Stage writes ────────────────────────────────────────────────────

    async def stage_change(
        self,
        *,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        controller_id: UUID,
        organization_id: UUID,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> Any:
        """Record an inbound-route-CRUD intent. Never touches the PBX."""
        _ALLOWED_FEATURES = {
            "pbx.inbound_route.create",
            "pbx.inbound_route.update",
            "pbx.inbound_route.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX inbound-routes "
                    f"service; expected one of {sorted(_ALLOWED_FEATURES)}"
                ),
            )

        return await self._stage(
            feature=feature,
            operation=operation,
            payload=payload,
            controller_id=controller_id,
            organization_id=organization_id,
            target_id=target_id,
            notes=notes,
            actor_id=actor_id,
        )

    # ── Apply path ──────────────────────────────────────────────────────

    @staticmethod
    def _route_id(target_id: str, cidnum: str | None) -> str:
        """Reconstruct FreePBX's composite inbound-route id.

        FreePBX keys an inbound route by ``(extension, cidnum)`` and exposes
        it as the single id ``"{extension}/{cidnum}"`` (e.g. ``"15551234/"``
        when the CID is unconstrained). That id contains a ``/``, which the
        shared :func:`app.adapters.validation.validate_id` chokepoint rejects
        — slashes are banned there because some vendors interpolate
        ``target_id`` straight into a URL path segment.

        So the UI / API stage the slash-free ``extension`` as ``target_id``
        and carry ``cidnum`` in the payload; the apply path rebuilds the
        composite here, just before it reaches the adapter (which feeds it to
        a parameterised GraphQL variable, never a URL path). If a caller ever
        does stage the full ``"ext/cid"`` form, we pass it through unchanged.
        """
        if "/" in target_id:
            return target_id
        return f"{target_id}/{cidnum or ''}"

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            method_map = {
                "pbx.inbound_route.create": "create_did",
                "pbx.inbound_route.update": "update_did",
                "pbx.inbound_route.delete": "delete_did",
            }
            method_name = method_map.get(c.feature)
            if method_name is None:
                raise HTTPException(400, detail=f"no applier for feature={c.feature!r}")

            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"FreePBX adapter does not yet implement "
                        f"{method_name!r}; staged intent preserved, "
                        "retry after the adapter is updated"
                    ),
                )

            payload = c.payload or {}
            target_id = c.target_id

            # force=True: runs only inside apply_change, post env-lock gate.
            if c.feature == "pbx.inbound_route.create":
                result = await method(payload, force=True)
            elif c.feature == "pbx.inbound_route.update":
                if not target_id:
                    raise HTTPException(400, detail="inbound_route update requires target_id")
                # ``old_cidnum`` identifies the existing row; ``cidnum`` (if
                # present in the payload) is the new value the adapter applies.
                did_id = self._route_id(target_id, payload.get("old_cidnum"))
                result = await method(did_id, payload, force=True)
            else:  # delete
                if not target_id:
                    raise HTTPException(400, detail="inbound_route delete requires target_id")
                did_id = self._route_id(target_id, payload.get("cidnum"))
                result = await method(did_id, force=True)

            if isinstance(result, AdapterResult):
                if not result.success:
                    raise HTTPException(502, detail=result.error or "freepbx rejected the change")
                return (
                    result.data
                    if result.data is not None
                    else {"ok": True, "message": result.message}
                )
            return result

        return _apply
