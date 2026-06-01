# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Camera device-config write envelope — audit + best-effort rollback.

Camera/NVR config writes can't ride the controller-bound ``AdapterStagingService``
(NVRs aren't ``core.controllers`` rows), so this is the camera-native equivalent
of "stage → auto-apply + audit": for every config write it

  1. CAPTURES the device's current state (``capture``),
  2. APPLIES the write (``apply`` — the adapter ``set_*`` still enforces the
     ``ADAPTER_READ_ONLY``/``force`` dual-gate, so the apply-now UX is unchanged),
  3. writes a structured AUDIT record with the before/after + outcome, and
  4. on failure, best-effort ROLLS BACK to the captured pre-state.

The apply-now UX is preserved; the gains are a per-change audit trail with
before/after and automatic restore if the device write fails mid-way.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

from app.services.audit import AuditAction, AuditService, ResourceType

logger = logging.getLogger(__name__)

# Bound the before/after blobs stamped into the audit row — some configs carry
# long values (motion grid_map hex, privacy/line/field coordinate lists).
_AUDIT_BLOB_CAP = 2000


def _summarize(state: Any) -> Any:
    """Return ``state`` for the audit record, truncated if it serializes large."""
    try:
        s = json.dumps(state, default=str)
    except (TypeError, ValueError):
        return {"_unserializable": True}
    if len(s) > _AUDIT_BLOB_CAP:
        return {"_truncated": True, "len": len(s), "head": s[:_AUDIT_BLOB_CAP]}
    return state


async def staged_camera_write(
    *,
    db: Any,
    actor_id: UUID | None,
    organization_id: UUID | None,
    camera: Any,
    feature: str,
    capture: Callable[[], Awaitable[Any]],
    apply: Callable[[], Awaitable[Any]],
    rollback: Callable[[Any], Awaitable[Any]] | None = None,
) -> Any:
    """Run a camera config write inside the audit + rollback envelope.

    ``capture`` reads device pre-state. ``apply`` performs the write and MUST
    raise on a device-reported failure (so a ``{"success": false}`` result is
    surfaced as an exception by the caller). ``rollback(old)`` best-effort
    restores the pre-state if ``apply`` raises. Returns ``apply``'s result;
    re-raises ``apply`` errors after the rollback + failure audit.
    """
    before: Any = None
    try:
        before = await capture()
    except Exception:  # noqa: BLE001 — a read failure must not block the write
        logger.warning("camera config %s: pre-state capture failed (continuing)", feature)
        before = None
    # Only a clean dict pre-state is safe to roll back to (skip error payloads).
    restorable = isinstance(before, dict) and "error" not in before

    try:
        result = await apply()
    except Exception as exc:
        rolled_back = False
        if rollback is not None and restorable:
            try:
                await rollback(before)
                rolled_back = True
            except Exception:  # noqa: BLE001 — rollback is best-effort
                logger.exception("camera config %s: rollback failed", feature)
        await _audit(
            db,
            actor_id,
            organization_id,
            camera,
            feature,
            "failure",
            before,
            None,
            error=str(exc),
            rolled_back=rolled_back,
        )
        raise

    await _audit(db, actor_id, organization_id, camera, feature, "success", before, result)
    return result


async def _audit(
    db: Any,
    actor_id: UUID | None,
    organization_id: UUID | None,
    camera: Any,
    feature: str,
    outcome: str,
    before: Any,
    after: Any,
    *,
    error: str | None = None,
    rolled_back: bool | None = None,
) -> None:
    """Write the before/after config-change audit record (never raises)."""
    extra: dict[str, Any] = {
        "config": feature,
        "outcome": outcome,
        "before": _summarize(before),
        "after": _summarize(after),
    }
    if error is not None:
        extra["error"] = str(error)[:500]
    if rolled_back is not None:
        extra["rolled_back"] = rolled_back
    try:
        await AuditService(db=db).log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=getattr(camera, "id", None),
            resource_name=getattr(camera, "name", None),
            organization_id=organization_id,
            actor_id=actor_id,
            extra_metadata=extra,
        )
    except Exception:  # noqa: BLE001 — audit must never break the write path
        logger.exception("camera config %s: audit log failed", feature)
