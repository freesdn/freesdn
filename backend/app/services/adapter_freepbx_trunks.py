# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX trunks staging service
==========================================

Live reads + staged CRUD for SIP trunks on a FreePBX PBX. Twin of
:mod:`app.services.adapter_freepbx_extensions` — same shape, different
feature prefix and adapter methods.

The taxonomy:

    pbx.trunk.create     stage_change → apply → adapter.create_trunk
    pbx.trunk.update     stage_change → apply → adapter.update_trunk
    pbx.trunk.delete     stage_change → apply → adapter.delete_trunk

Reads use ``list_trunks`` / ``list_trunks_with_details`` / ``get_trunk``
directly against the FreePBX REST API. They bypass staging because
they don't change device state. Writes always stage first; the live
PBX is only touched when an operator explicitly applies a change with
``ADAPTER_READ_ONLY=false`` + ``force=true``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXTrunksService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX SIP-trunk CRUD.

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

    @staticmethod
    def _detail_envelope(
        controller_id: UUID,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ──────────────────────────────────────────────────────

    async def list_trunks(
        self,
        controller_id: UUID,
        organization_id: UUID,
        with_details: bool = False,
    ) -> dict[str, Any]:
        """List SIP trunks on the PBX.

        When ``with_details=True``, returns the full PJSIP config
        (scraped from config pages — slower but richer). Default is
        the lightweight list endpoint.
        """
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = (
            await client.list_trunks_with_details() if with_details else await client.list_trunks()
        )
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_trunks failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    async def get_trunk(
        self,
        controller_id: UUID,
        organization_id: UUID,
        trunk_id: str,
    ) -> dict[str, Any]:
        """Read one trunk's config."""
        from app.adapters.validation import validate_id

        validate_id(trunk_id, label="trunk_id")

        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.get_trunk(trunk_id)
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(404, detail=result.error or "trunk not found")
            data = result.data or {}
        else:
            data = result
        return self._detail_envelope(controller_id, redact_secrets(data))

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
        """Record a trunk-CRUD intent. Never touches the PBX."""
        _ALLOWED_FEATURES = {
            "pbx.trunk.create",
            "pbx.trunk.update",
            "pbx.trunk.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX trunks "
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

    def build_applier(self, change: Any) -> Any:
        """Return the awaitable that pushes ``change`` to the live PBX."""

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)

            feature = c.feature
            payload = c.payload or {}
            target_id = c.target_id

            # force=True: this runs only inside apply_change, after the
            # env-lock half of the dual-gate has already passed.
            if feature == "pbx.trunk.create":
                result = await client.create_trunk(payload, force=True)
            elif feature == "pbx.trunk.update":
                if not target_id:
                    raise HTTPException(400, detail="trunk update requires target_id")
                result = await client.update_trunk(target_id, payload, force=True)
            elif feature == "pbx.trunk.delete":
                if not target_id:
                    raise HTTPException(400, detail="trunk delete requires target_id")
                result = await client.delete_trunk(target_id, force=True)
            else:
                raise HTTPException(400, detail=f"no applier for feature={feature!r}")

            if isinstance(result, AdapterResult):
                if not result.success:
                    raise HTTPException(
                        502,
                        detail=result.error or "freepbx rejected the change",
                    )
                return (
                    result.data
                    if result.data is not None
                    else {"ok": True, "message": result.message}
                )
            return result

        return _apply
