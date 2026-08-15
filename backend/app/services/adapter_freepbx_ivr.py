# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX IVR staging service
=======================================

Live reads + staged CRUD intents for IVR menus on a FreePBX PBX.

The FreePBX adapter currently exposes only ``list_ivrs`` — there are
no create/update/delete methods on the adapter yet. This staging
service still records the operator's INTENT for those operations
(stage rows land in ``adapter_pending_changes`` with feature
``pbx.ivr.create`` / ``update`` / ``delete``), so operators can build
out their IVR config in the FreeSDN UI and review it in the Pending
Changes drawer. The apply path raises a clear 501 until the adapter
catches up.

This is the intended pattern: STAGING SERVICE FIRST, ADAPTER
METHOD SECOND. Decoupling them lets operator intent be captured even
while the adapter is still being built out. Once the FreePBX adapter
grows ``create_ivr`` / ``update_ivr`` / ``delete_ivr``, the apply
path in this service will start working without changes to the
endpoint, UI, or staging table contents.

The taxonomy:

    pbx.ivr.create     stage → apply → adapter.create_ivr (TODO)
    pbx.ivr.update     stage → apply → adapter.update_ivr (TODO)
    pbx.ivr.delete     stage → apply → adapter.delete_ivr (TODO)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXIVRService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX IVR CRUD.

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

    async def list_ivrs(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        """List IVR menus configured on the PBX."""
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.list_ivrs()
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_ivrs failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    # ── Stage writes (records intent even though adapter doesn't apply yet) ─

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
        """Record an IVR-CRUD intent. Never touches the PBX.

        Note: until the FreePBX adapter grows ``create_ivr`` /
        ``update_ivr`` / ``delete_ivr``, the apply path will fail with
        a clear 501. Operators can still build their IVR config in the
        UI and review it in Pending Changes — apply will succeed
        automatically once the adapter catches up.
        """
        _ALLOWED_FEATURES = {
            "pbx.ivr.create",
            "pbx.ivr.update",
            "pbx.ivr.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX IVR "
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

    # ── Apply path (currently raises 501 until adapter methods exist) ───

    def build_applier(self, change: Any) -> Any:
        """Apply IVR CRUD to the live PBX.

        Currently raises 501 for every feature — the FreePBX adapter
        doesn't expose IVR CRUD methods yet. The staging row stays in
        the queue (``status='failed'`` with the 501 reason) so the
        operator can re-try once the adapter catches up. Reads in the
        meantime continue to work.
        """

        async def _apply(c: Any) -> Any:
            feature = c.feature
            method_map = {
                "pbx.ivr.create": "create_ivr",
                "pbx.ivr.update": "update_ivr",
                "pbx.ivr.delete": "delete_ivr",
            }
            method_name = method_map.get(feature)
            if method_name is None:
                raise HTTPException(400, detail=f"no applier for feature={feature!r}")

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
            if feature == "pbx.ivr.create":
                result = await method(payload, force=True)
            elif feature == "pbx.ivr.update":
                if not target_id:
                    raise HTTPException(400, detail="ivr update requires target_id")
                result = await method(target_id, payload, force=True)
            else:  # delete
                if not target_id:
                    raise HTTPException(400, detail="ivr delete requires target_id")
                result = await method(target_id, force=True)

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
