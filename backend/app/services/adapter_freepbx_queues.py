# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX queues staging service
==========================================

Live reads + staged CRUD intents for call queues on a FreePBX PBX.

The FreePBX adapter currently exposes ``list_queues`` + ``get_queue``
(REST/AJAX path) but no create/update/delete operations — queue CRUD
is an admin UI workflow that doesn't have a sanctioned REST endpoint
in stock FreePBX 16. This staging service still records CRUD intents
(``pbx.queue.create`` / ``update`` / ``delete``) so operators can
build out queue config in the FreeSDN UI and review it in the
Pending Changes drawer; the apply path raises 501 until the adapter
catches up, mirroring the IVR pattern from
:mod:`app.services.adapter_freepbx_ivr`.

The taxonomy:

    pbx.queue.create     stage → apply → adapter.create_queue (TODO)
    pbx.queue.update     stage → apply → adapter.update_queue (TODO)
    pbx.queue.delete     stage → apply → adapter.delete_queue (TODO)

Reads (``list_queues`` / ``get_queue``) are live + idempotent and
bypass staging.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_freepbx_base import FreePBXServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets


class FreePBXQueuesService(FreePBXServiceBase):
    """Live reads + staged writes for FreePBX call-queue CRUD.

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

    async def list_queues(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        """List call queues from the PBX."""
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.list_queues()
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(502, detail=result.error or "list_queues failed")
            data = result.data or []
        else:
            data = result
        return self._envelope(
            controller_id,
            redact_list(data) if isinstance(data, list) else redact_secrets(data),
        )

    async def get_queue(
        self,
        controller_id: UUID,
        organization_id: UUID,
        queue_ext: str,
    ) -> dict[str, Any]:
        """Read one queue's config."""
        from app.adapters.validation import validate_id

        validate_id(queue_ext, label="queue_ext")

        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        result = await client.get_queue(queue_ext)
        if isinstance(result, AdapterResult):
            if not result.success:
                raise HTTPException(404, detail=result.error or "queue not found")
            data = result.data or {}
        elif result is None:
            raise HTTPException(404, detail=f"queue {queue_ext!r} not found")
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
        """Record a queue-CRUD intent. Never touches the PBX."""
        _ALLOWED_FEATURES = {
            "pbx.queue.create",
            "pbx.queue.update",
            "pbx.queue.delete",
        }
        if feature not in _ALLOWED_FEATURES:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} not handled by FreePBX queues "
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
        """Return the awaitable that pushes ``change`` to the live PBX.

        Currently raises 501 — queue CRUD methods aren't exposed by
        the FreePBX adapter yet. Once they land, this applier starts
        working with no other changes.
        """

        async def _apply(c: Any) -> Any:
            method_map = {
                "pbx.queue.create": "create_queue",
                "pbx.queue.update": "update_queue",
                "pbx.queue.delete": "delete_queue",
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
            if c.feature == "pbx.queue.create":
                result = await method(payload, force=True)
            elif c.feature == "pbx.queue.update":
                if not target_id:
                    raise HTTPException(400, detail="queue update requires target_id")
                result = await method(target_id, payload, force=True)
            else:  # delete
                if not target_id:
                    raise HTTPException(400, detail="queue delete requires target_id")
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
