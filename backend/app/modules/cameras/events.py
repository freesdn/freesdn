# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Cameras module event publishing helper.

Thin wrapper around :func:`app.core.events.publish_adapter_event` that
the cameras module's write endpoints call to fan a state change out
to the platform event bus. Mirror of what the staging service already
does for network/firewall adapters — closes the platform-citizen gap
for camera writes that bypass AdapterStagingService.

Every camera write (PTZ command, motion-detection toggle, recording-
schedule update, NVR reboot, recording lock) should call one of the
helpers below AFTER the underlying adapter call succeeds (and again
on failure, with ``outcome="failed"``). The publish is best-effort —
failures are swallowed so the actual API response is never affected.

Naming convention::

    camera.<action>.<outcome>
    nvr.<action>.<outcome>

with ``outcome`` in ``{ok, failed}``. Automation rules can match by
``payload.adapter_id`` to fire vendor-specific actions (e.g. "reboot
all UniFi Protect cameras in site X on this trigger").
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from app.core.events import (
    EventCategory,
    EventPriority,
    publish_adapter_event,
)

logger = logging.getLogger(__name__)


async def record_camera_action(
    action: str,
    *,
    camera_id: UUID,
    adapter_id: str,
    organization_id: UUID | str | None,
    outcome: str = "ok",
    priority: EventPriority = EventPriority.NORMAL,
    **extra: Any,
) -> None:
    """Emit ``camera.<action>.<outcome>`` on the event bus.

    Catastrophic actions (PTZ goto + factory reset on the camera) lift
    to HIGH priority automatically via the priority argument. For
    routine operations leave the default NORMAL.
    """
    try:
        await publish_adapter_event(
            f"camera.{action}.{outcome}",
            adapter_id=adapter_id,
            organization_id=(str(organization_id) if organization_id else None),
            category=EventCategory.DEVICE,
            priority=priority,
            camera_id=str(camera_id),
            **extra,
        )
    except Exception:
        # Best-effort — never block the API response on event publish.
        logger.debug(
            "camera event publish skipped for action=%s camera=%s",
            action,
            camera_id,
            exc_info=True,
        )


async def record_nvr_action(
    action: str,
    *,
    nvr_id: UUID,
    adapter_id: str,
    organization_id: UUID | str | None,
    outcome: str = "ok",
    priority: EventPriority = EventPriority.HIGH,
    **extra: Any,
) -> None:
    """Emit ``nvr.<action>.<outcome>`` on the event bus.

    NVR-level operations (reboot, firmware push, config restore) are
    HIGH priority by default — they affect every camera attached to
    the NVR, so automation rules typically want to react fast.
    """
    try:
        await publish_adapter_event(
            f"nvr.{action}.{outcome}",
            adapter_id=adapter_id,
            organization_id=(str(organization_id) if organization_id else None),
            category=EventCategory.DEVICE,
            priority=priority,
            nvr_id=str(nvr_id),
            **extra,
        )
    except Exception:
        logger.debug(
            "nvr event publish skipped for action=%s nvr=%s",
            action,
            nvr_id,
            exc_info=True,
        )
