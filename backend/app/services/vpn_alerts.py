# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Alert Service
======================================

Publishes VPN events to the event bus and triggers notifications.
Integrates VPN state changes with the enterprise notification pipeline.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventCategory, EventPriority, get_event_bus
from app.models.vpn import VPNConnectionRecord, VPNEvent, VPNEventSeverity

logger = logging.getLogger(__name__)

# Latency threshold for "degraded" alerts (ms)
DEFAULT_LATENCY_THRESHOLD_MS = 200.0


class VPNAlertService:
    """
    Integrates VPN state changes with the enterprise notification pipeline.
    Records VPNEvent audit rows, publishes to event bus (→ WebSocket),
    and optionally fires notifications via dispatch_notifications().
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── helpers ──────────────────────────────────────────────────────────

    async def _record_event(
        self,
        *,
        organization_id: UUID,
        event_type: str,
        severity: str,
        title: str,
        details: dict[str, Any] | None = None,
        site_id: UUID | None = None,
        connection_id: UUID | None = None,
        tunnel_id: UUID | None = None,
        source: str | None = None,
        actor_id: UUID | None = None,
    ) -> VPNEvent:
        event = VPNEvent(
            organization_id=organization_id,
            site_id=site_id,
            connection_id=connection_id,
            tunnel_id=tunnel_id,
            event_type=event_type,
            severity=severity,
            title=title,
            details=details or {},
            source=source,
            actor_id=actor_id,
            created_at=datetime.now(UTC),
        )
        self._session.add(event)
        await self._session.flush()
        return event

    async def _publish(
        self,
        event_type: str,
        payload: dict[str, Any],
        priority: str = "normal",
    ) -> None:
        try:
            bus = get_event_bus()
            await bus.publish(
                Event(
                    event_type=event_type,
                    category=EventCategory.VPN,
                    priority=EventPriority(priority)
                    if priority != "normal"
                    else EventPriority.NORMAL,
                    payload=payload,
                )
            )
        except Exception:
            logger.debug("Failed to publish VPN event %s", event_type, exc_info=True)

    async def _try_notify(
        self,
        organization_id: UUID,
        title: str,
        body: str,
    ) -> None:
        """Best-effort notification dispatch. Never fails the caller."""
        try:
            from app.services.notification_helpers import dispatch_notifications

            # Use default channels for the org (in-app is always available)
            await dispatch_notifications(
                db=self._session,
                channels_config={"in_app": {}},
                title=title,
                body=body,
                organization_id=organization_id,
            )
        except Exception:
            logger.debug("VPN notification dispatch failed", exc_info=True)

    @staticmethod
    def _conn_payload(conn: VPNConnectionRecord, **extra: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "connection_id": str(conn.id),
            "name": conn.name,
            "vpn_type": conn.vpn_type,
            "organization_id": str(conn.organization_id) if conn.organization_id else None,
        }
        payload.update(extra)
        return payload

    # ── public methods ───────────────────────────────────────────────────

    async def on_connection_down(
        self,
        connection: VPNConnectionRecord,
        error: str,
        *,
        source: str = "health_check",
    ) -> None:
        """VPN connection lost — record event, publish, notify."""
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.disconnected",
            severity=VPNEventSeverity.WARNING,
            title=f'VPN connection "{connection.name}" lost',
            details={"error": error[:500], "vpn_type": connection.vpn_type},
            connection_id=connection.id,
            source=source,
        )

        payload = self._conn_payload(connection, error=error[:500], ws_type="vpn_connection_down")
        await self._publish("vpn.connection.down", payload, priority="high")
        await self._try_notify(org_id, f"VPN Down: {connection.name}", error[:200])

    async def on_connection_restored(
        self,
        connection: VPNConnectionRecord,
        latency_ms: float | None = None,
        *,
        source: str = "health_check",
    ) -> None:
        """VPN connection restored — record event, publish."""
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.connected",
            severity=VPNEventSeverity.INFO,
            title=f'VPN connection "{connection.name}" restored',
            details={"latency_ms": latency_ms, "vpn_type": connection.vpn_type},
            connection_id=connection.id,
            source=source,
        )

        payload = self._conn_payload(
            connection,
            latency_ms=latency_ms,
            ws_type="vpn_connection_restored",
        )
        await self._publish("vpn.connection.restored", payload)

    async def on_health_degraded(
        self,
        connection: VPNConnectionRecord,
        latency_ms: float,
        threshold_ms: float = DEFAULT_LATENCY_THRESHOLD_MS,
        *,
        source: str = "health_check",
    ) -> None:
        """Latency spike above threshold."""
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.health_degraded",
            severity=VPNEventSeverity.WARNING,
            title=f'VPN "{connection.name}" degraded ({latency_ms:.0f}ms > {threshold_ms:.0f}ms)',
            details={"latency_ms": latency_ms, "threshold_ms": threshold_ms},
            connection_id=connection.id,
            source=source,
        )

        payload = self._conn_payload(
            connection,
            latency_ms=latency_ms,
            threshold_ms=threshold_ms,
            ws_type="vpn_health_degraded",
        )
        await self._publish("vpn.connection.degraded", payload)

    async def on_reconnect_started(
        self,
        connection: VPNConnectionRecord,
        attempt: int,
        max_attempts: int,
    ) -> None:
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.reconnect_started",
            severity=VPNEventSeverity.INFO,
            title=f'Reconnecting "{connection.name}" (attempt {attempt}/{max_attempts})',
            details={"attempt": attempt, "max_attempts": max_attempts},
            connection_id=connection.id,
            source="auto_reconnect",
        )

        payload = self._conn_payload(
            connection,
            attempt=attempt,
            max_attempts=max_attempts,
            ws_type="vpn_reconnect_started",
        )
        await self._publish("vpn.connection.reconnect_started", payload)

    async def on_reconnect_success(
        self,
        connection: VPNConnectionRecord,
        attempt: int,
    ) -> None:
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.reconnect_success",
            severity=VPNEventSeverity.INFO,
            title=f'VPN "{connection.name}" reconnected on attempt {attempt}',
            details={"attempt": attempt},
            connection_id=connection.id,
            source="auto_reconnect",
        )

        payload = self._conn_payload(connection, attempt=attempt, ws_type="vpn_connection_restored")
        await self._publish("vpn.connection.restored", payload)

    async def on_reconnect_exhausted(
        self,
        connection: VPNConnectionRecord,
        total_attempts: int,
    ) -> None:
        """All retry attempts failed — CRITICAL alert."""
        org_id = connection.organization_id
        if not org_id:
            return

        await self._record_event(
            organization_id=org_id,
            event_type="vpn.reconnect_exhausted",
            severity=VPNEventSeverity.CRITICAL,
            title=f'VPN "{connection.name}" reconnect exhausted after {total_attempts} attempts',
            details={"total_attempts": total_attempts},
            connection_id=connection.id,
            source="auto_reconnect",
        )

        payload = self._conn_payload(
            connection,
            total_attempts=total_attempts,
            ws_type="vpn_reconnect_exhausted",
        )
        await self._publish("vpn.connection.reconnect_exhausted", payload, priority="critical")
        await self._try_notify(
            org_id,
            f'CRITICAL: VPN "{connection.name}" unreachable',
            f"Auto-reconnect exhausted after {total_attempts} attempts. Manual intervention required.",
        )

    async def on_tunnel_status_change(
        self,
        tunnel_id: UUID,
        organization_id: UUID,
        old_status: str,
        new_status: str,
        *,
        site_a_name: str = "",
        site_b_name: str = "",
        error_message: str | None = None,
    ) -> None:
        severity = VPNEventSeverity.INFO
        if new_status == "error":
            severity = VPNEventSeverity.ERROR
        elif new_status == "disabled":
            severity = VPNEventSeverity.WARNING

        label = f"{site_a_name} ↔ {site_b_name}" if site_a_name else str(tunnel_id)[:8]
        await self._record_event(
            organization_id=organization_id,
            event_type=f"vpn.tunnel_{new_status}",
            severity=severity,
            title=f"S2S tunnel {label}: {old_status} → {new_status}",
            details={
                "old_status": old_status,
                "new_status": new_status,
                "error_message": error_message[:500] if error_message else None,
            },
            tunnel_id=tunnel_id,
            source="tunnel_health",
        )

        await self._publish(
            f"vpn.tunnel.{new_status}",
            {
                "tunnel_id": str(tunnel_id),
                "organization_id": str(organization_id),
                "old_status": old_status,
                "new_status": new_status,
                "ws_type": "vpn_tunnel_status_changed",
            },
        )

    async def record_config_event(
        self,
        *,
        organization_id: UUID,
        event_type: str,
        title: str,
        details: dict[str, Any] | None = None,
        site_id: UUID | None = None,
        connection_id: UUID | None = None,
        actor_id: UUID | None = None,
    ) -> None:
        """Record a VPN config CRUD event (create/update/delete/import)."""
        await self._record_event(
            organization_id=organization_id,
            event_type=event_type,
            severity=VPNEventSeverity.INFO,
            title=title,
            details=details or {},
            site_id=site_id,
            connection_id=connection_id,
            source="user_action",
            actor_id=actor_id,
        )
