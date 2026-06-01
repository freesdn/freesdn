# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - WebSocket Service (DEPRECATED)
========================================

.. warning::

    This module previously contained an alternate ``ConnectionManager`` and a
    ``setup_websocket_event_handlers()`` helper that subscribed to
    ``device.*``, ``discovery.*``, ``controller.*``, ``alert.*``, ``sla.#``
    and ``vpn.#`` on the event bus and forwarded every matching event to
    **every** connected WebSocket client via an unfiltered ``broadcast()``
    — i.e. across organizations.

    That helper was never wired up in production (``main.py`` uses the
    org-scoped manager in :mod:`app.api.v1.endpoints.websocket` instead),
    but it remained importable as :mod:`app.services.websocket` and was
    re-exported from :mod:`app.services`. A future caller (a plugin, a
    bootstrap hook, or a well-meaning refactor) could have enabled a
    cross-tenant event firehose in one line.

    It has therefore been removed.

    - The dangerous module-global ``websocket_manager`` singleton is gone.
    - ``setup_websocket_event_handlers()`` is gone.
    - The :class:`ConnectionManager` class itself is preserved because the
      unit tests in ``tests/services/test_websocket.py`` exercise it as a
      self-contained data structure. The class is **not** wired to the
      event bus, is **not** instantiated at import time, and should not be
      used for new code. Any production broadcasting must go through
      :mod:`app.api.v1.endpoints.websocket`, which filters every event by
      the recipient's ``organization_id`` (and optional site filter).

All new WebSocket integrations must publish an :class:`app.core.events.Event`
with a populated ``organization_id`` onto the event bus and rely on the
org-scoped manager in :mod:`app.api.v1.endpoints.websocket` to deliver it.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# SECURITY: keys stripped from event payloads before WebSocket broadcast.
# Retained because the ConnectionManager below is still exercised by tests
# and future callers might want to reuse this helper defensively.
_SENSITIVE_PAYLOAD_KEYS = frozenset(
    {
        "password",
        "hashed_password",
        "secret",
        "api_key",
        "api_secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "ssh_key",
        "mfa_secret",
        "mfa_backup_codes",
        "credentials",
        "cookie",
        "session_token",
        "encryption_key",
    }
)


def _sanitize_payload(payload: dict[str, Any] | Any) -> dict[str, Any] | Any:
    """Strip sensitive keys from event payloads before broadcasting to clients."""
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            return [_sanitize_payload(item) for item in payload]
        return payload
    return {
        k: _sanitize_payload(v) if isinstance(v, (dict, list)) else v
        for k, v in payload.items()
        if k.lower() not in _SENSITIVE_PAYLOAD_KEYS
    }


# =============================================================================
# WebSocket Event Types (legacy constants, kept for any external reference)
# =============================================================================


class WSEventType:
    """Standard WebSocket event types for frontend (legacy constants)."""

    # Device events
    DEVICE_DISCOVERED = "device_discovered"
    DEVICE_UPDATED = "device_updated"
    DEVICE_STATUS_CHANGE = "device_status_change"
    DEVICE_DELETED = "device_deleted"
    DEVICE_ACTION = "device_action"

    # Controller events
    CONTROLLER_ONLINE = "controller_online"
    CONTROLLER_OFFLINE = "controller_offline"
    CONTROLLER_ERROR = "controller_error"

    # Discovery events
    DISCOVERY_STARTED = "discovery_started"
    DISCOVERY_PROGRESS = "discovery_progress"
    DISCOVERY_COMPLETED = "discovery_completed"
    DISCOVERY_FAILED = "discovery_failed"

    # System events
    SYNC_STARTED = "sync_started"
    SYNC_COMPLETED = "sync_completed"
    ALERT = "alert"
    NOTIFICATION = "notification"
    ERROR = "error"

    # Task events
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"

    # Alert events
    ALERT_FIRED = "alert_fired"
    ALERT_RESOLVED = "alert_resolved"

    # SLA events
    SLA_BREACH_CREATED = "sla_breach_created"
    SLA_BREACH_RESOLVED = "sla_breach_resolved"

    # Camera events
    CAMERA_EVENT = "camera_event"
    CAMERA_ALERT = "camera_alert"
    CAMERA_HEALTH_UPDATE = "camera_health_update"

    # VPN events
    VPN_CONNECTION_DOWN = "vpn_connection_down"
    VPN_CONNECTION_RESTORED = "vpn_connection_restored"
    VPN_HEALTH_DEGRADED = "vpn_health_degraded"
    VPN_RECONNECT_STARTED = "vpn_reconnect_started"
    VPN_RECONNECT_EXHAUSTED = "vpn_reconnect_exhausted"
    VPN_TUNNEL_STATUS_CHANGED = "vpn_tunnel_status_changed"


# =============================================================================
# Connection Manager (preserved for existing unit tests only)
# =============================================================================


class ConnectionManager:
    """
        WebSocket connection manager (legacy, for tests).

        .. deprecated::
            Do not use this class for new production code. The event-bus
            handlers that previously instantiated a module-global singleton
            and broadcast across all organizations have been removed
    . Use :mod:`app.api.v1.endpoints.websocket` which
            enforces per-connection organization scoping.

        Features still exposed for tests:

        - Connection tracking by user / organization / room
        - Broadcast helpers (``broadcast``, ``broadcast_to_user``,
          ``broadcast_to_organization``, ``broadcast_to_room``)

        NOTE: ``broadcast()`` sends to **every** currently-tracked connection
        with no filtering. Callers are responsible for choosing a scoped
        variant. This is the reason the previous global wiring was unsafe —
        it called the unscoped variant from event-bus handlers.
    """

    def __init__(self):
        # Active connections: websocket -> metadata
        self._connections: dict[WebSocket, dict[str, Any]] = {}

        # User connections: user_id -> set of websockets
        self._user_connections: dict[str, set[WebSocket]] = {}

        # Organization connections: org_id -> set of websockets
        self._org_connections: dict[str, set[WebSocket]] = {}

        # Room subscriptions: room_name -> set of websockets
        self._rooms: dict[str, set[WebSocket]] = {}

    @property
    def connection_count(self) -> int:
        """Get total number of active connections."""
        return len(self._connections)

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()

        # Store connection metadata
        self._connections[websocket] = {
            "user_id": user_id,
            "organization_id": organization_id,
            "connected_at": datetime.now(UTC),
            "rooms": set(),
        }

        # Track by user
        if user_id:
            if user_id not in self._user_connections:
                self._user_connections[user_id] = set()
            self._user_connections[user_id].add(websocket)

        # Track by organization
        if organization_id:
            if organization_id not in self._org_connections:
                self._org_connections[organization_id] = set()
            self._org_connections[organization_id].add(websocket)

        logger.info(
            f"WebSocket connected: user={user_id}, org={organization_id} "
            f"(total: {self.connection_count})"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        metadata = self._connections.pop(websocket, None)
        if not metadata:
            return

        user_id = metadata.get("user_id")
        org_id = metadata.get("organization_id")
        rooms = metadata.get("rooms", set())

        # Remove from user tracking
        if user_id and user_id in self._user_connections:
            self._user_connections[user_id].discard(websocket)
            if not self._user_connections[user_id]:
                del self._user_connections[user_id]

        # Remove from org tracking
        if org_id and org_id in self._org_connections:
            self._org_connections[org_id].discard(websocket)
            if not self._org_connections[org_id]:
                del self._org_connections[org_id]

        # Remove from rooms
        for room in rooms:
            if room in self._rooms:
                self._rooms[room].discard(websocket)

        logger.info(f"WebSocket disconnected: user={user_id} (remaining: {self.connection_count})")

    # =========================================================================
    # Room Management
    # =========================================================================

    def join_room(self, websocket: WebSocket, room: str) -> None:
        """Add a connection to a room."""
        if websocket not in self._connections:
            return

        if room not in self._rooms:
            self._rooms[room] = set()
        self._rooms[room].add(websocket)
        self._connections[websocket]["rooms"].add(room)

        logger.debug("WebSocket joined room: %s", room)

    def leave_room(self, websocket: WebSocket, room: str) -> None:
        """Remove a connection from a room."""
        if room in self._rooms:
            self._rooms[room].discard(websocket)
        if websocket in self._connections:
            self._connections[websocket]["rooms"].discard(room)

    # =========================================================================
    # Message Sending
    # =========================================================================

    async def send_message(
        self,
        websocket: WebSocket,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> bool:
        """Send a message to a specific connection."""
        message = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }

        try:
            await websocket.send_json(message)
            return True
        except Exception as e:
            logger.warning("Failed to send message: %s", e)
            self.disconnect(websocket)
            return False

    async def broadcast(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """
        Broadcast a message to all connected clients concurrently.

        .. warning::
            This method has no organization filtering. Never call it from
            an event-bus handler that may receive cross-tenant events.
            Use :meth:`broadcast_to_organization` instead.
        """
        message = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return await self._send_to_many(list(self._connections.keys()), message)

    async def _send_to_many(
        self,
        websockets: list[WebSocket],
        message: dict[str, Any],
    ) -> int:
        """Send a message to multiple WebSockets concurrently with backpressure."""
        if not websockets:
            return 0

        async def _safe_send(ws: WebSocket) -> bool:
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=5.0)
                return True
            except Exception:
                return False

        results = await asyncio.gather(
            *(_safe_send(ws) for ws in websockets),
            return_exceptions=True,
        )

        failed = [
            ws
            for ws, ok in zip(websockets, results, strict=False)
            if not ok or isinstance(ok, BaseException)
        ]
        for ws in failed:
            self.disconnect(ws)

        return sum(1 for ok in results if ok is True)

    async def broadcast_to_user(
        self,
        user_id: str,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """Broadcast to all connections for a specific user."""
        connections = self._user_connections.get(user_id, set())
        message = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }
        return await self._send_to_many(list(connections), message)

    async def broadcast_to_organization(
        self,
        organization_id: str,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """Broadcast to all connections in an organization."""
        connections = self._org_connections.get(organization_id, set())
        message = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }
        return await self._send_to_many(list(connections), message)

    async def broadcast_to_room(
        self,
        room: str,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """Broadcast to all connections in a room."""
        connections = self._rooms.get(room, set())
        message = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }
        return await self._send_to_many(list(connections), message)

    # =========================================================================
    # Status
    # =========================================================================

    def get_connected_users(self) -> list[str]:
        """Get list of connected user IDs."""
        return list(self._user_connections.keys())

    def get_user_connection_count(self, user_id: str) -> int:
        """Get number of connections for a user."""
        return len(self._user_connections.get(user_id, set()))

    def is_user_connected(self, user_id: str) -> bool:
        """Check if a user has any active connections."""
        return user_id in self._user_connections


# =============================================================================
# Deprecated module-level singletons
# =============================================================================
#
# The following symbols previously existed at module scope:
#
#     websocket_manager = ConnectionManager()
#
#     async def setup_websocket_event_handlers() -> None: ...
#
# They have been removed. The singleton would have been a tempting
# import target for new code, and ``setup_websocket_event_handlers()``
# was a one-line switch that would have attached unfiltered, cross-tenant
# event-bus handlers. If future code accidentally tries to import either
# name, the import will raise ``ImportError`` — which is intentional.
#
# Do NOT reintroduce a module-global ``ConnectionManager`` here. All
# real-time delivery must go through the org-scoped manager in
# :mod:`app.api.v1.endpoints.websocket`.


def create_ws_message(
    event_type: str,
    data: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a properly formatted WebSocket message (pure helper)."""
    message = {
        "type": event_type,
        "data": data or {},
        "timestamp": datetime.now(UTC).isoformat(),
    }
    message["data"].update(extra)
    return message
