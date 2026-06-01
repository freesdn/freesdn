# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX ring-groups staging service
===============================================

Live reads + staged CRUD for ring groups on a FreePBX PBX. Twin of
:mod:`app.services.adapter_freepbx_extensions` — same shape, different
feature prefix.

Unlike queues / IVR, ring-group CRUD IS exposed by the FreePBX adapter
(``adapter.list_ring_groups`` / ``create_ring_group``). The GraphQL
backing for these methods is ``fetchAllRingGroups`` (read) and the
``addRingGroup`` / ``updateRingGroup`` / ``deleteRingGroup`` mutations.
The REST client's :meth:`list_ring_groups` was migrated to GraphQL
in this same PR; the adapter's read path therefore returns rich data
under OAuth2 and falls back to the AJAX grid for legacy installs.

The taxonomy:

    pbx.ring_group.create     stage → apply → adapter.create_ring_group
    pbx.ring_group.update     stage → apply → adapter.update_ring_group (TODO at adapter)
    pbx.ring_group.delete     stage → apply → adapter.delete_ring_group (TODO at adapter)

Reads are live, idempotent, and bypass staging.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXRingGroupsService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX ring-group CRUD.

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

    async def list_ring_groups(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        """List ring groups from the PBX."""
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.list_ring_groups()
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_ring_groups failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    async def get_ring_group(
        self,
        controller_id: UUID,
        organization_id: UUID,
        grpnum: str,
    ) -> dict[str, Any]:
        """Read one ring group's config."""
        from app.adapters.validation import validate_id

        validate_id(grpnum, label="grpnum")

        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.get_ring_group(grpnum)
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(404, detail=result.error or "ring group not found")
            data = result.data or {}
        elif result is None:
            raise HTTPException(404, detail=f"ring group {grpnum!r} not found")
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
        """Record a ring-group-CRUD intent. Never touches the PBX."""
        _ALLOWED_FEATURES = {
            "pbx.ring_group.create",
            "pbx.ring_group.update",
            "pbx.ring_group.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX ring-groups "
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
        async def _apply(c: Any) -> Any:
            method_map = {
                "pbx.ring_group.create": "create_ring_group",
                "pbx.ring_group.update": "update_ring_group",
                "pbx.ring_group.delete": "delete_ring_group",
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
                        f"{method_name!r}; staged intent preserved"
                    ),
                )

            payload = c.payload or {}
            target_id = c.target_id

            # force=True: runs only inside apply_change, post env-lock gate.
            if c.feature == "pbx.ring_group.create":
                result = await method(payload, force=True)
            elif c.feature == "pbx.ring_group.update":
                if not target_id:
                    raise HTTPException(400, detail="ring_group update requires target_id")
                result = await method(target_id, payload, force=True)
            else:  # delete
                if not target_id:
                    raise HTTPException(400, detail="ring_group delete requires target_id")
                result = await method(target_id, force=True)

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
