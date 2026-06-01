# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX extensions staging service
==============================================

Reads run live against the FreePBX REST API. Writes (extension CRUD)
flow through :class:`AdapterStagingService` and never touch the live
PBX until an operator explicitly applies them.

This service applies the staging pattern to VoIP config: writes
(extension CRUD, trunk CRUD, IVR)
get the same stage→apply gate that VLAN/firewall writes already have,
while operator-realtime actions (originate call, hangup, reboot phone)
stay on the direct-call + event-emit path.

The taxonomy:

    pbx.extension.create     stage_change → apply → adapter.create_extension
    pbx.extension.update     stage_change → apply → adapter.update_extension
    pbx.extension.delete     stage_change → apply → adapter.delete_extension

Reads call the adapter live (``list_extensions``, ``get_extension``)
and DO NOT go through staging — they're idempotent and don't change
device state. The CONTRACT §1 invariants (read live, write staged,
dual-gate apply) inherit from :class:`GatewayServiceBase` via the
``self.staging`` attribute.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXExtensionsService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX extension CRUD.

    Resolution of the PBX (``voip.pbx``), the controllers-FK auto-pair,
    and adapter construction are inherited from :class:`FreePBXServiceBase`.
    """

    # ── Envelope helpers ────────────────────────────────────────────────

    @staticmethod
    def _envelope(
        controller_id: UUID,
        items: list[dict[str, Any]] | dict[str, Any],
    ) -> dict[str, Any]:
        """Wrap a list/detail result in the standard staging envelope."""
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

    async def list_extensions(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        """Pull the current extension list from the PBX (live read).

        Bypasses staging entirely — reads are idempotent and don't
        change device state. The PBX REST API is hit directly.
        """
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.list_extensions()
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_extensions failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    async def get_extension(
        self,
        controller_id: UUID,
        organization_id: UUID,
        ext_number: str,
    ) -> dict[str, Any]:
        """Read one extension's full config from the PBX."""
        from app.adapters.validation import validate_id

        validate_id(ext_number, label="ext_number")

        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.get_extension(ext_number)
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(404, detail=result.error or "extension not found")
            data = result.data or {}
        else:
            data = result
        return self._detail_envelope(controller_id, redact_secrets(data))

    # ── Stage writes (always safe — never touches the PBX) ──────────────

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
        """Record an extension-CRUD intent. Never touches the PBX.

        ``feature`` must be one of:
            - ``pbx.extension.create``  (operation=``create``)
            - ``pbx.extension.update``  (operation=``update``, target_id=ext_number)
            - ``pbx.extension.delete``  (operation=``delete``, target_id=ext_number)
        """
        _ALLOWED_FEATURES = {
            "pbx.extension.create",
            "pbx.extension.update",
            "pbx.extension.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX extensions "
                    f"service; expected one of {sorted(_ALLOWED_FEATURES)}"
                ),
            )

        # ``_stage`` (FreePBXServiceBase) resolves + tenant-checks the PBX,
        # lazily auto-pairs the controllers row for the staging FK, then
        # records the pending change. It never touches the live PBX.
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

    # ── Apply path (only fires under ADAPTER_READ_ONLY=false + force=true) ─

    def build_applier(self, change: Any) -> Any:
        """Return the awaitable that pushes ``change`` to the live PBX.

        Used only by :meth:`AdapterStagingService.apply_change` after
        the dual-gate check passes. Maps ``(feature, operation)`` to
        the right :class:`FreePBXAdapter` method.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)

            feature = c.feature
            payload = c.payload or {}
            target_id = c.target_id

            # ``force=True`` is correct here: this closure runs ONLY inside
            # AdapterStagingService.apply_change, which already enforced the
            # env half of the dual-gate (ADAPTER_READ_ONLY → 403 before any
            # applier runs). The adapter's own _check_write_allowed is the
            # defence-in-depth backstop.
            if feature == "pbx.extension.create":
                ext_number = target_id or payload.get("extension") or payload.get("ext_number")
                if not ext_number:
                    raise HTTPException(
                        400,
                        detail=("extension create needs target_id or payload.extension"),
                    )
                result = await client.create_extension(ext_number, payload, force=True)
            elif feature == "pbx.extension.update":
                if not target_id:
                    raise HTTPException(400, detail="extension update requires target_id")
                result = await client.update_extension(target_id, payload, force=True)
            elif feature == "pbx.extension.delete":
                if not target_id:
                    raise HTTPException(400, detail="extension delete requires target_id")
                result = await client.delete_extension(target_id, force=True)
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
