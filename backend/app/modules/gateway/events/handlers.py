# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Event Handlers
========================================

Handlers that subscribe to cross-module events so the gateway
module can react to changes published by other modules.

Returned via ``GatewayModule.get_event_handlers()`` and registered
on the EventBus at startup.

Important:
    Event handlers run inside the EventBus dispatch loop and have
    **no DB session** injected.  For any database work they must
    open their own session (``async_session_factory``).  Heavy work
    is delegated to Celery tasks to keep the event loop responsive.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any
from uuid import UUID

from sqlalchemy import select

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────


async def _get_session():
    """Obtain a fresh async DB session for event-handler use."""
    from app.db.session import async_session_factory

    return async_session_factory()


# ── Handlers ─────────────────────────────────────────────────────────────


async def _on_network_vlan_created(event: Any) -> None:
    """A VLAN was created in the network module.

    If the site has a brain assigned, auto-create a **MONITORED**
    canonical VLAN so it appears in the gateway dashboard.  The user
    must explicitly switch it to MANAGED to trigger distribution.
    """
    payload = getattr(event, "payload", {})
    site_id = payload.get("site_id")
    vlan_id = payload.get("vlan_id")
    org_id = payload.get("organization_id")

    logger.info(
        "gateway: received network.vlan.created  vlan_id=%s site=%s",
        vlan_id,
        site_id,
    )

    if not all([site_id, vlan_id, org_id]):
        return

    # Validate payload types before DB operations
    try:
        site_uuid = UUID(str(site_id))
        org_uuid = UUID(str(org_id))
        vlan_num = int(vlan_id)
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid vlan.created payload: %s", exc)
        return

    if not 1 <= vlan_num <= 4094:
        logger.warning("Invalid VLAN ID in event: %s", vlan_id)
        return

    from app.modules.gateway.models import (
        CanonicalVLAN,
        ManagementState,
        SiteRoleMap,
    )

    session = await _get_session()
    try:
        async with session:
            # Only act if site has a role map (gateway orchestration active)
            rm_result = await session.execute(
                select(SiteRoleMap).where(SiteRoleMap.site_id == site_uuid)
            )
            if not rm_result.scalar_one_or_none():
                return

            # Skip if canonical VLAN already exists
            existing = await session.execute(
                select(CanonicalVLAN).where(
                    CanonicalVLAN.site_id == site_uuid,
                    CanonicalVLAN.vlan_id == vlan_num,
                    CanonicalVLAN.deleted_at.is_(None),
                )
            )
            if existing.scalar_one_or_none():
                return

            # Require valid subnet and gateway_ip — skip if missing
            subnet = payload.get("subnet") or ""
            gateway_ip = payload.get("gateway_ip") or ""
            if not subnet or not gateway_ip:
                logger.info(
                    "Skipping auto-create of canonical VLAN %s for site %s — "
                    "missing subnet or gateway_ip",
                    vlan_num,
                    site_uuid,
                )
                return

            logger.info(
                "Auto-creating MONITORED canonical VLAN %s for site %s",
                vlan_num,
                site_uuid,
            )
            vlan = CanonicalVLAN(
                organization_id=org_uuid,
                site_id=site_uuid,
                vlan_id=vlan_num,
                name=payload.get("name", f"VLAN {vlan_num}"),
                subnet=subnet,
                gateway_ip=gateway_ip,
                management_state=ManagementState.MONITORED,
            )
            session.add(vlan)
            await session.commit()
    except Exception:
        logger.exception(
            "Failed to auto-create canonical VLAN %s for site %s",
            vlan_id,
            site_id,
        )


async def _on_network_vlan_updated(event: Any) -> None:
    """A VLAN was updated — log for observability."""
    payload = getattr(event, "payload", {})
    logger.info(
        "gateway: received network.vlan.updated  vlan_id=%s fields=%s",
        payload.get("vlan_id"),
        payload.get("updated_fields"),
    )


async def _on_network_vlan_deleted(event: Any) -> None:
    """A VLAN was deleted from the network module.

    Creates a drift event so the user can decide whether to retract
    the VLAN from the brain device.  We do NOT auto-retract because
    the brain-side config may still be needed.
    """
    payload = getattr(event, "payload", {})
    site_id = payload.get("site_id")
    vlan_id = payload.get("vlan_id")

    logger.info(
        "gateway: received network.vlan.deleted  vlan_id=%s site=%s",
        vlan_id,
        site_id,
    )

    if not site_id or not vlan_id:
        return

    # Validate payload types
    try:
        site_uuid = UUID(str(site_id))
        vlan_num = int(vlan_id)
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid vlan.deleted payload: %s", exc)
        return

    from app.modules.gateway.models import (
        CanonicalVLAN,
        DriftEvent,
        DriftSeverity,
        DriftType,
    )

    session = await _get_session()
    try:
        async with session:
            # Find the matching canonical VLAN
            cv_result = await session.execute(
                select(CanonicalVLAN).where(
                    CanonicalVLAN.site_id == site_uuid,
                    CanonicalVLAN.vlan_id == vlan_num,
                    CanonicalVLAN.deleted_at.is_(None),
                )
            )
            cv = cv_result.scalar_one_or_none()
            if cv is None:
                return

            # Find brain device for this site (needed for device_id FK)
            from app.modules.gateway.models import NetworkRole, SiteRoleMap

            rm_result = await session.execute(
                select(SiteRoleMap).where(SiteRoleMap.site_id == site_uuid)
            )
            role_map = rm_result.scalar_one_or_none()
            brain_device_id = None
            if role_map:
                from sqlalchemy.orm import selectinload

                rm_full = await session.execute(
                    select(SiteRoleMap)
                    .options(selectinload(SiteRoleMap.assignments))
                    .where(SiteRoleMap.id == role_map.id)
                )
                rm_full_obj = rm_full.scalar_one_or_none()
                if rm_full_obj:
                    brain = next(
                        (a for a in rm_full_obj.assignments if a.role == NetworkRole.BRAIN),
                        None,
                    )
                    if brain:
                        brain_device_id = brain.gateway_id

            if brain_device_id is None:
                logger.warning(
                    "No brain device for site %s — cannot create drift event",
                    site_uuid,
                )
                return

            # Create a drift event for user attention
            drift = DriftEvent(
                organization_id=cv.organization_id,
                site_id=cv.site_id,
                device_id=brain_device_id,
                drift_type=DriftType.TAG_REMOVED,
                resource_type="vlan",
                resource_id=cv.id,
                expected_value={
                    "vlan_id": cv.vlan_id,
                    "name": cv.name,
                },
                actual_value=None,
                severity=DriftSeverity.WARNING,
                message=(
                    f"VLAN {cv.vlan_id} ({cv.name}) deleted from network "
                    f"module — brain-side config may need retraction"
                ),
            )
            session.add(drift)
            await session.commit()
    except Exception:
        logger.exception(
            "Failed to create drift event for deleted VLAN %s at site %s",
            vlan_id,
            site_id,
        )


async def _on_network_wifi_changed(event: Any) -> None:
    """A WiFi network was created/updated/deleted — log for observability."""
    payload = getattr(event, "payload", {})
    logger.info(
        "gateway: received %s  ssid=%s site=%s",
        getattr(event, "event_type", "network.wifi.*"),
        payload.get("ssid"),
        payload.get("site_id"),
    )


async def _on_device_status_changed(event: Any) -> None:
    """A gateway device changed status (online/offline).

    Publishes an alert event when a brain device goes offline so
    operators see it in the dashboard.  Distribution locks have a
    5-minute TTL that handles stale-lock cleanup automatically.
    """
    payload = getattr(event, "payload", {})
    device_id = payload.get("device_id")
    status = payload.get("status")

    logger.info(
        "gateway: received device.status.changed  device=%s status=%s",
        device_id,
        status,
    )

    if not device_id or status != "offline":
        return

    # Validate device_id
    try:
        device_uuid = UUID(str(device_id))
    except (ValueError, TypeError):
        logger.warning("Invalid device_id in status event: %s", device_id)
        return

    # Check if this device is assigned as a brain anywhere
    from sqlalchemy.orm import selectinload

    from app.modules.gateway.models import NetworkRole, SiteRoleAssignment

    session = await _get_session()
    try:
        async with session:
            brain_result = await session.execute(
                select(SiteRoleAssignment)
                .options(selectinload(SiteRoleAssignment.role_map))
                .where(
                    SiteRoleAssignment.gateway_id == device_uuid,
                    SiteRoleAssignment.role == NetworkRole.BRAIN,
                )
            )
            assignment = brain_result.scalar_one_or_none()
            if assignment is None:
                return

            site_id_value = (
                assignment.role_map.site_id if assignment.role_map else assignment.role_map_id
            )

            logger.warning(
                "Brain device %s (site %s) went offline",
                device_id,
                site_id_value,
            )

            # Publish alert via event bus
            try:
                from app.core.events import (
                    Event,
                    EventCategory,
                    EventPriority,
                    get_event_bus,
                )

                bus = get_event_bus()
                await bus.publish(
                    Event(
                        event_type="gateway.brain.offline",
                        category=EventCategory.SECURITY,
                        priority=EventPriority.HIGH,
                        source="gateway.event_handlers",
                        payload={
                            "device_id": str(device_id),
                            "site_id": str(site_id_value),
                        },
                    )
                )
            except Exception:
                logger.debug("Failed to emit brain-offline alert", exc_info=True)
    except Exception:
        logger.exception(
            "Failed to check brain status for device %s",
            device_id,
        )


async def _on_gateway_sync_completed(event: Any) -> None:
    """A gateway sync finished — schedule a drift check via Celery.

    Delegated to a Celery task to keep the event bus responsive.
    """
    payload = getattr(event, "payload", {})
    site_id = payload.get("site_id")

    logger.info(
        "gateway: received gateway.sync.completed  gateway=%s site=%s",
        payload.get("gateway_id"),
        site_id,
    )

    if not site_id:
        return

    try:
        from app.modules.gateway.tasks.drift_tasks import check_site_drift

        check_site_drift.delay(str(site_id))
    except Exception:
        logger.warning("Failed to schedule drift check for site %s", site_id, exc_info=True)


def get_handlers() -> dict[str, Callable[..., Coroutine[Any, Any, None]]]:
    """Return mapping of event-type patterns → handler coroutines.

    These are registered on the EventBus by the module loader.
    """
    return {
        "network.vlan.created": _on_network_vlan_created,
        "network.vlan.updated": _on_network_vlan_updated,
        "network.vlan.deleted": _on_network_vlan_deleted,
        "network.wifi.#": _on_network_wifi_changed,
        "device.status.changed": _on_device_status_changed,
        "gateway.sync.completed": _on_gateway_sync_completed,
    }
