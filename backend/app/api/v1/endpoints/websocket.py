# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - WebSocket Endpoint
================================

Real-time WebSocket communication for live updates.
"""

import asyncio
import contextlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel

from app.api.v1.deps import get_current_active_user
from app.core.events import Event, EventType
from app.core.security import verify_token

# subscription RBAC + inbound message rate limiter live in a
# dependency-free module so they can be unit-tested without pulling FastAPI /
# SQLAlchemy / Celery through this file.
from app.core.ws_rbac import (
    SUBSCRIPTION_PERMISSIONS,
    ConnectionRateLimiter,
)
from app.core.ws_rbac import (
    user_can_subscribe as _user_can_subscribe,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# Re-export so callers that imported these from this module keep working.
__all__ = [
    "SUBSCRIPTION_PERMISSIONS",
    "ConnectionRateLimiter",
    "_user_can_subscribe",
]

# SECURITY: re-validate WebSocket sessions every 5 minutes
_WS_REVALIDATION_INTERVAL_SECONDS = 300


# ===========================================
# Origin Validation (CSWSH Protection)
# ===========================================


def _is_origin_allowed(origin: str, allowed_origins: list[str]) -> bool:
    """Check if the WebSocket Origin header matches an allowed origin.

    Compares scheme + host + port exactly. Rejects missing origins.
    Does NOT allow wildcard matches.
    """
    if not origin:
        return False

    try:
        req = urlparse(origin)
    except Exception:
        return False

    if not req.scheme or not req.netloc:
        return False

    for allowed in allowed_origins:
        try:
            a = urlparse(allowed)
        except Exception:
            continue
        if req.scheme == a.scheme and req.netloc == a.netloc:
            return True

    return False


def _is_same_origin(origin: str, host_header: str) -> bool:
    """True if the Origin's host[:port] equals the request's own Host header.

    A same-origin WebSocket handshake — our SPA, served by our own edge, opening
    a socket back to the same host — is NOT a CSWSH vector: a browser sets Origin
    to the page's origin and Host to the server it is connecting to, so a
    cross-site attacker's page can never make Origin-host equal our Host. Treating
    same-origin as always-allowed means realtime works on every deployment host
    out of the box without the operator also having to enumerate that host in
    CORS_ORIGINS (which only governs cross-origin REST). Compares netloc only —
    behind a TLS edge the browser Origin is ``https://host`` while the forwarded
    Host header carries no scheme.
    """
    if not origin or not host_header:
        return False
    try:
        o = urlparse(origin)
    except Exception:
        return False
    return bool(o.netloc) and o.netloc.lower() == host_header.strip().lower()


async def _validate_ws_origin(websocket: WebSocket) -> bool:
    """Validate the Origin header. Closes the socket if invalid.

    Returns True if the origin is allowed, False if rejected (and socket closed).
    Used for browser-facing WebSocket endpoints to prevent Cross-Site
    WebSocket Hijacking (CSWSH).
    """
    from app.core.config import settings

    origin = websocket.headers.get("origin", "")
    # Same-origin (our SPA → our own edge) is always allowed and is not CSWSH —
    # see _is_same_origin. This is what lets realtime work on any deploy host
    # without the operator also listing it in CORS_ORIGINS.
    if _is_same_origin(origin, websocket.headers.get("host", "")):
        return True
    if not _is_origin_allowed(origin, settings.CORS_ORIGINS):
        logger.warning(
            "WebSocket rejected: origin %r not in allowed origins",
            origin or "<missing>",
        )
        # Socket is not yet accepted — close with policy violation
        with contextlib.suppress(Exception):
            await websocket.close(code=1008, reason="Origin not allowed")
        return False
    return True


async def _validate_ws_origin_optional(websocket: WebSocket) -> bool:
    """Validate Origin if present. Non-browser clients may omit Origin — allow those.

    This is used for agent WebSocket endpoints where the client is not a
    browser. Browser-based CSWSH attacks always set an Origin header, so
    endpoints that reject unknown origins when present remain protected
    while still allowing direct non-browser (agent) connections.
    """
    origin = websocket.headers.get("origin", "")
    if not origin:
        # No Origin header — non-browser client, allow
        return True

    from app.core.config import settings

    if not _is_origin_allowed(origin, settings.CORS_ORIGINS):
        logger.warning(
            "Agent WebSocket rejected: origin %r not in allowed origins",
            origin,
        )
        with contextlib.suppress(Exception):
            await websocket.close(code=1008, reason="Origin not allowed")
        return False
    return True


# ===========================================
# WebSocket Connection Manager
# ===========================================


class ConnectionInfo(BaseModel):
    """Information about a WebSocket connection."""

    websocket: Any  # WebSocket type
    user_id: str
    organization_id: str | None = None
    site_ids: list[str] = []
    # server-enforced per-user site scope. Unlike
    # the opt-in client ``site_ids`` filter, these are loaded from UserSiteAccess
    # at connect (and on revalidation) and are NOT client-controllable. When
    # ``is_site_limited`` is True, the broadcast path drops any site-tagged event
    # whose site isn't in ``accessible_site_ids``.
    is_site_limited: bool = False
    accessible_site_ids: list[str] = []
    subscriptions: set[str] = set()
    connected_at: datetime = datetime.now(UTC)
    token_version: int = 0  # SECURITY: track for mid-session revocation
    access_jti: str | None = None  # SECURITY: per-device session revocation (W03/WS)
    last_revalidated: datetime = datetime.now(UTC)

    class Config:
        arbitrary_types_allowed = True


class ConnectionManager:
    """Manages WebSocket connections and message broadcasting."""

    # Caps: without these, one authenticated user can open
    # unbounded connections (FD/RAM exhaustion + broadcast slowdown for the whole
    # pod) and inflate one connection's subscription set without bound (RAM +
    # per-event O(N) scan amplification).
    MAX_WS_PER_USER = 25
    MAX_WS_GLOBAL = 5000
    MAX_SUBSCRIPTIONS_PER_CONN = 200

    def __init__(self) -> None:
        self._connections: dict[str, ConnectionInfo] = {}
        self._user_connections: dict[str, set[str]] = {}

    def can_accept(self, user_id: str) -> bool:
        """Whether a new connection for ``user_id`` is within the caps."""
        if len(self._connections) >= self.MAX_WS_GLOBAL:
            return False
        return len(self._user_connections.get(user_id, set())) < self.MAX_WS_PER_USER

    async def connect(
        self,
        websocket: WebSocket,
        connection_id: str,
        user_id: str,
        organization_id: str | None = None,
    ) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()

        self._connections[connection_id] = ConnectionInfo(
            websocket=websocket,
            user_id=user_id,
            organization_id=organization_id,
        )

        if user_id not in self._user_connections:
            self._user_connections[user_id] = set()
        self._user_connections[user_id].add(connection_id)

        logger.info("WebSocket connected: %s (user: %s)", connection_id, user_id)

    async def disconnect(self, connection_id: str) -> None:
        """Remove a WebSocket connection."""
        if connection_id in self._connections:
            info = self._connections[connection_id]

            # Remove from user connections
            if info.user_id in self._user_connections:
                self._user_connections[info.user_id].discard(connection_id)
                if not self._user_connections[info.user_id]:
                    del self._user_connections[info.user_id]

            del self._connections[connection_id]
            logger.info("WebSocket disconnected: %s", connection_id)

    async def subscribe(
        self,
        connection_id: str,
        subscriptions: list[str],
    ) -> None:
        """Subscribe a connection to event types (capped per connection)."""
        info = self._connections.get(connection_id)
        if info is None:
            return
        room = self.MAX_SUBSCRIPTIONS_PER_CONN - len(info.subscriptions)
        if room <= 0:
            logger.warning(
                "Connection %s hit subscription cap (%d); ignoring extra",
                connection_id,
                self.MAX_SUBSCRIPTIONS_PER_CONN,
            )
            return
        info.subscriptions.update(list(subscriptions)[:room])
        logger.debug("Connection %s subscribed to: %s", connection_id, subscriptions)

    async def unsubscribe(
        self,
        connection_id: str,
        subscriptions: list[str],
    ) -> None:
        """Unsubscribe a connection from event types."""
        if connection_id in self._connections:
            self._connections[connection_id].subscriptions.difference_update(subscriptions)

    def set_site_filter(
        self,
        connection_id: str,
        site_ids: list[str],
    ) -> None:
        """Set site filter for a connection."""
        if connection_id in self._connections:
            self._connections[connection_id].site_ids = site_ids

    async def send_personal(
        self,
        connection_id: str,
        message: dict[str, Any],
    ) -> None:
        """Send a message to a specific connection."""
        if connection_id in self._connections:
            try:
                await self._connections[connection_id].websocket.send_json(message)
            except Exception as e:
                logger.error("Error sending to %s: %s", connection_id, e)
                await self.disconnect(connection_id)

    async def send_to_user(
        self,
        user_id: str,
        message: dict[str, Any],
    ) -> None:
        """Send a message to all of ``user_id``'s connections — local AND
        on every other pod.

        Targeted sends were previously single-pod: a user with tabs open
        on pods A and B would only see the message on whichever pod
        called ``send_to_user``. The local fan-out below stays first
        (no extra latency for single-pod deployments); the cross-pod
        publish is best-effort and is a no-op when ``REDIS_URL`` is
        unset. The receiving pods invoke :meth:`_deliver_remote_to_user`
        which delivers only to their own ``_user_connections`` for the
        target user — the originating pod is skipped via ``pod_id``
        in the envelope so we never double-deliver locally.
        """
        await self._send_to_user_local(user_id, message)
        try:
            from app.services.websocket_pubsub import get_ws_pubsub

            await get_ws_pubsub().publish_to_user(user_id, message)
        except Exception:
            logger.exception("send_to_user: cross-pod publish failed for %s", user_id)

    async def _send_to_user_local(
        self,
        user_id: str,
        message: dict[str, Any],
    ) -> None:
        """Local-only delivery — does not cross pods. Used by both the
        public ``send_to_user`` and the cross-instance delivery hook
        so the remote path can't recursively re-publish."""
        if user_id in self._user_connections:
            for connection_id in list(self._user_connections[user_id]):
                await self.send_personal(connection_id, message)

    async def _deliver_remote_to_user(
        self,
        user_id: str,
        message: dict[str, Any],
    ) -> None:
        """Callback handed to :class:`WSCrossInstanceBus`. Invoked when
        another pod targeted this user — deliver to this pod's locally
        held connections (if any) without re-publishing."""
        await self._send_to_user_local(user_id, message)

    # Per-send budget for ``broadcast_event``. A wedged client must not
    # be allowed to block other clients (or the publisher) for longer
    # than this. Tuned to be larger than the worst-case healthy WAN RTT
    # but small enough that a frozen tab won't visibly stall the bus.
    _BROADCAST_SEND_TIMEOUT_SECONDS = 5.0

    async def broadcast_event(self, event: Event) -> None:
        """Broadcast an event to all subscribed connections.

        Sanitization: the outbound payload is passed through
        ``_sanitize_payload`` so sensitive keys (password / api_key /
        token / secret / refresh_token / encryption_key / etc.) are
        stripped before the message reaches any connected client.
        Previously only VoIPEvent.to_dict() sanitized; generic Event
        broadcasts (device discovery, controller events, alerts)
        forwarded the raw payload to every subscribed intra-org
        client — so a device-sync event whose payload included a
        controller credential or webhook secret leaked to every
        viewer with a websocket open.

        Fan-out concurrency: previously this
        method ``await``-ed each ``send_json`` sequentially with no
        per-send timeout. One slow/frozen socket would block every
        other client AND the publisher — and because this is invoked
        from ``EventBus._dispatch_local`` (also sequential), any
        adapter write / sync task / discovery scan stalls behind the
        slowest WS client. We now fan out concurrently with a per-send
        ``asyncio.wait_for`` budget so a single wedged connection only
        loses its own slot, not the broadcast.
        """
        from app.services.websocket import _sanitize_payload

        raw = event.to_dict()
        # ``raw["payload"]`` is the operator/adapter-supplied dict
        # that may contain device creds. Sanitize it in place.
        if isinstance(raw, dict) and isinstance(raw.get("payload"), dict):
            raw["payload"] = _sanitize_payload(raw["payload"])
        message = {
            "type": "event",
            "event": raw,
        }

        # Snapshot subscribed targets before launching tasks so disconnect()
        # mutating ``self._connections`` mid-fan-out can't trip "dict changed
        # size" on the iterator.
        targets = [
            (cid, info)
            for cid, info in list(self._connections.items())
            if self._should_receive(info, event)
        ]
        if not targets:
            return

        async def _safe_send(cid: str, info: ConnectionInfo) -> None:
            try:
                await asyncio.wait_for(
                    info.websocket.send_json(message),
                    timeout=self._BROADCAST_SEND_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                logger.warning(
                    "WS send timed out for %s after %.1fs; disconnecting",
                    cid,
                    self._BROADCAST_SEND_TIMEOUT_SECONDS,
                )
                await self.disconnect(cid)
            except Exception as e:
                logger.error("Error broadcasting to %s: %s", cid, e)
                await self.disconnect(cid)

        # ``return_exceptions=True`` so a bug in one ``_safe_send`` can't
        # cancel siblings (gather propagates the first exception otherwise).
        await asyncio.gather(
            *(_safe_send(cid, info) for cid, info in targets),
            return_exceptions=True,
        )

    def _should_receive(self, info: ConnectionInfo, event: Event) -> bool:
        """Check if a connection should receive an event."""
        # NOTE: Event uses ``event_type`` (not ``.type``) and stores
        # ``site_id`` inside ``.payload`` (not as a top-level attribute).
        # The previous code referenced ``.type`` / ``.site_id`` which raised
        # AttributeError on every check — the exception was swallowed by
        # the outer try/except in :meth:`broadcast_event` so no events ever
        # reached the frontend.
        event_type = event.event_type
        event_site_id = (
            (event.payload or {}).get("site_id") if isinstance(event.payload, dict) else None
        )

        # Check subscription
        subscribed = False
        for sub in info.subscriptions:
            if sub == "*" or sub == event_type:
                subscribed = True
                break
            if sub.endswith("*") and event_type.startswith(sub[:-1]):
                subscribed = True
                break

        if not subscribed:
            return False

        # SECURITY (cross-tenant WS leak): the org
        # filter must fail CLOSED in both directions:
        #   - if the receiver has no org_id, drop.
        #   - if the EVENT has no org_id (e.g. a helper that forgot to
        #     thread it), drop. The prior code guarded the comparison
        #     with ``if event.organization_id and ...``, which let any
        #     event without org_id reach every subscribed client across
        #     tenants — exactly the leak the audit flagged. Cross-tenant
        #     SYSTEM broadcasts (e.g. ``system.shutdown`` for admin
        #     dashboards) must be modelled as an explicit allowlist
        #     plus a super_admin subscription check, not as the absence
        #     of an organization_id.
        if not info.organization_id:
            return False
        if not event.organization_id:
            return False
        # Compare as strings — Event.organization_id may be UUID or str
        # depending on the construction path; ConnectionInfo stores str.
        if info.organization_id != str(event.organization_id):
            return False

        # SECURITY: server-enforced per-user site scope. A
        # site-limited user (>=1 UserSiteAccess grant; never super/org admin)
        # may only receive events for sites they're granted — independent of
        # the opt-in client ``site_ids`` filter below. Fail CLOSED: a site-
        # tagged event outside the grant is dropped, and an event with NO
        # site_id is dropped UNLESS it's explicitly targeted at this user
        # (payload user_id == this user) — mirrors can_access_site at REST.
        if info.is_site_limited:
            if event_site_id is not None:
                if str(event_site_id) not in info.accessible_site_ids:
                    return False
            else:
                target_user = (
                    (event.payload or {}).get("user_id")
                    if isinstance(event.payload, dict)
                    else None
                )
                if target_user is None or str(target_user) != info.user_id:
                    return False

        # Check optional client-set site filter
        return not (info.site_ids and event_site_id and event_site_id not in info.site_ids)

    @property
    def active_connections(self) -> int:
        return len(self._connections)


# Global connection manager
manager = ConnectionManager()


async def _revalidate_ws_session(info: ConnectionInfo) -> bool:
    """Check if the user is still active and their token_version hasn't changed.

    Returns True if the session is still valid, False if it should be closed.
    """
    from sqlalchemy import select

    from app.db import async_session_factory
    from app.models import User

    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(User.is_active, User.token_version, User.deleted_at).where(
                    User.id == UUID(info.user_id)
                )
            )
            row = result.one_or_none()
            if row is None:
                return False
            is_active, tv, deleted_at = row
            if not is_active or deleted_at is not None:
                return False
            if (tv or 0) != info.token_version:
                return False  # session revoked (logout, password change, etc.)
            # Per-device revocation: a targeted DELETE /auth/sessions/{id} flips
            # UserSession.revoked_at WITHOUT bumping token_version, so the tv check
            # above misses it. Mirror the REST chokepoint (get_current_user_optional).
            if info.access_jti:
                from app.core.session_revocation import is_session_revoked_for_access_jti

                if await is_session_revoked_for_access_jti(session, info.access_jti):
                    return False
        return True
    except Exception:
        logger.warning("WebSocket revalidation failed for %s", info.user_id, exc_info=True)
        return True  # fail-open on transient DB errors to avoid mass disconnects


# ===========================================
# WebSocket Authentication
# ===========================================


async def authenticate_websocket(
    token: str,
) -> dict[str, Any] | None:
    """Authenticate a WebSocket connection token using the standard verify_token pipeline."""
    try:
        payload = await verify_token(token, token_type="access")
        if payload is None:
            logger.warning("WebSocket auth: invalid or expired token")
            return None

        user_id = payload.get("sub")
        if not user_id:
            logger.warning("WebSocket auth: No 'sub' claim in token")
            return None

        # A NARROWED token must not open the org-wide realtime socket.
        #
        # /cameras/{id}/stream-token mints a deliberately tiny credential: it
        # lives ~60 seconds and carries scope="stream" plus the single camera_id
        # it was issued for, precisely so it can be put in a URL query string
        # where it will be logged by proxies and land in browser history. The
        # camera endpoints honour that (cameras/api.py: a query token must be
        # scope="stream", and its camera_id must equal the camera being
        # requested).
        #
        # This endpoint read the claim -- the line below used to be the only
        # mention of "scope" in the file -- and then never compared it to
        # anything. So that one-camera, one-minute token also opened the general
        # realtime WebSocket and subscribed to the caller's whole organization:
        # device status, alerts, VPN, discovery, every event family the socket
        # carries. A credential designed to be the narrowest in the product was
        # silently the widest.
        #
        # Refuse ANY token carrying a narrowing scope, not just "stream": a
        # future scope would otherwise inherit the same hole by default.
        token_scope = payload.get("scope")
        if token_scope:
            logger.warning(
                "WebSocket auth: refusing scope=%r token for user %s — the realtime "
                "socket requires a full access token",
                token_scope,
                user_id,
            )
            return None

        return {
            "user_id": user_id,
            "organization_id": payload.get("org_id"),
            "role": payload.get("role"),
            "permissions": payload.get("permissions", []),
            "token_version": payload.get("tv", 0),
            "access_jti": payload.get("jti"),  # per-device revocation check
            # Always None past the guard above; kept so callers can log it.
            "scope": token_scope,
        }

    except Exception as e:
        logger.warning("WebSocket auth failed: %s", e)
        return None


async def _load_ws_site_scope(user_id: str, role: str | None) -> tuple[bool, list[str]]:
    """Resolve the per-user site scope for a WebSocket connection.

    The JWT carries no site grants, so we load UserSiteAccess from the DB at
    connect (and on revalidation). Mirrors CurrentUser.is_site_limited:
    super_admin / org_admin are never site-limited; any other role with >=1
    grant becomes site-limited and is constrained to its granted site IDs.
    Returns ``(is_site_limited, accessible_site_ids)``. Fails CLOSED on error
    (treat as limited-with-no-sites) so a DB hiccup can't widen exposure.
    """
    if role in ("super_admin", "org_admin"):
        return False, []
    try:
        from sqlalchemy import select

        from app.db import async_session_factory
        from app.models.core import UserSiteAccess

        async with async_session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(UserSiteAccess.site_id).where(UserSiteAccess.user_id == user_id)
                    )
                )
                .scalars()
                .all()
            )
        site_ids = [str(s) for s in rows]
        # No grants → not site-limited (backwards-compatible role-based access).
        return bool(site_ids), site_ids
    except Exception:
        logger.exception("WS site-scope load failed for user %s — failing closed", user_id)
        return True, []


class _WSAuthPrincipal:
    """Minimal user-like principal used for subscription RBAC checks.

    Built from the JWT claims attached to the connection so we don't have
    to re-query the DB on every subscribe message.
    """

    def __init__(
        self,
        role: str | None,
        permissions: list[str],
    ) -> None:
        self.role = role or "viewer"
        self.permissions = permissions or []
        self.is_superuser = self.role == "super_admin"

    def has_permission(self, permission: str) -> bool:
        if self.is_superuser:
            return True
        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True

        # Colon wildcard (e.g. "device:*" matches "device:read")
        if ":" in permission:
            resource = permission.split(":", 1)[0]
            if f"{resource}:*" in self.permissions:
                return True

        # Dot wildcard (e.g. "cameras.*" matches "cameras.view")
        if "." in permission:
            module = permission.split(".", 1)[0]
            if f"{module}.*" in self.permissions:
                return True

        # Fall back to role defaults so callers don't have to mint full
        # permission lists into JWT claims.
        from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS

        role_perms = DEFAULT_ROLE_PERMISSIONS.get(self.role, [])
        if permission in role_perms or "*" in role_perms:
            return True
        if ":" in permission:
            resource = permission.split(":", 1)[0]
            if f"{resource}:*" in role_perms:
                return True
        if "." in permission:
            module = permission.split(".", 1)[0]
            if f"{module}.*" in role_perms:
                return True
        return False


# ===========================================
# WebSocket Message Handlers
# ===========================================


class WSMessageType:
    AUTH = "auth"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    SET_FILTERS = "set_filters"
    PING = "ping"


async def handle_message(
    connection_id: str,
    message: dict[str, Any],
    user: Any | None = None,
) -> None:
    """Handle incoming WebSocket message."""
    msg_type = message.get("type")

    if msg_type == WSMessageType.SUBSCRIBE:
        raw_subscriptions = message.get("subscriptions", [])
        if not isinstance(raw_subscriptions, list):
            return

        # SECURITY: filter subscriptions by user permission.
        allowed: list[str] = []
        denied: list[str] = []
        for sub in raw_subscriptions:
            if not isinstance(sub, str):
                continue
            if len(sub) > 200:  # reject absurdly long patterns
                denied.append(sub)
                continue
            if user is not None and _user_can_subscribe(user, sub):
                allowed.append(sub)
            else:
                denied.append(sub)

        await manager.subscribe(connection_id, allowed)
        await manager.send_personal(
            connection_id,
            {
                "type": "subscribed",
                "subscriptions": allowed,
            },
        )
        if denied:
            await manager.send_personal(
                connection_id,
                {
                    "type": "subscription_denied",
                    "patterns": denied,
                    "reason": "insufficient_permissions",
                },
            )

    elif msg_type == WSMessageType.UNSUBSCRIBE:
        subscriptions = message.get("subscriptions", [])
        await manager.unsubscribe(connection_id, subscriptions)
        await manager.send_personal(
            connection_id,
            {
                "type": "unsubscribed",
                "subscriptions": subscriptions,
            },
        )

    elif msg_type == WSMessageType.SET_FILTERS:
        site_ids = message.get("site_ids", [])
        # Validate site_ids: only allow sites belonging to the user's organization
        if site_ids:
            info = manager._connections.get(connection_id)
            if info and info.organization_id:
                from sqlalchemy import select

                from app.db import async_session_factory
                from app.models import Site

                async with async_session_factory() as session:
                    result = await session.execute(
                        select(Site.id).where(
                            Site.organization_id == info.organization_id,
                            Site.id.in_(site_ids),
                            Site.deleted_at.is_(None),
                        )
                    )
                    valid_ids = {str(row[0]) for row in result.fetchall()}
                site_ids = [sid for sid in site_ids if sid in valid_ids]
                # a site-limited user can never filter to (or away
                # from) a site outside their grant — intersect with the grant so
                # a forbidden site can't be set even as a filter target.
                if info.is_site_limited:
                    site_ids = [sid for sid in site_ids if sid in info.accessible_site_ids]
            else:
                # No organization_id means we cannot validate — deny all site filters
                site_ids = []
        manager.set_site_filter(connection_id, site_ids)
        await manager.send_personal(
            connection_id,
            {
                "type": "filters_set",
                "site_ids": site_ids,
            },
        )

    elif msg_type == WSMessageType.PING:
        await manager.send_personal(
            connection_id,
            {
                "type": "pong",
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )


# ===========================================
# Event Bus Integration
# ===========================================


async def forward_to_websockets(event: Event) -> None:
    """Forward all events to WebSocket connections."""
    await manager.broadcast_event(event)


# NOTE: Previously this module ran ``@event_bus.subscribe("*")`` at
# import time against the ``_LazyEventBus`` shim. That registered the
# handler on the *shim*, not the real singleton — by the time the
# lifespan called ``get_event_bus()`` and connected it, no subscriber
# existed for ``*``. Result: WebSocket clients never received any event.
# We now bind during the FastAPI startup hook against the real bus.
_ws_subscription_id: str | None = None


def register_event_bus_forwarder() -> None:
    """Bind the WebSocket forwarder to the real EventBus singleton.

    Must be called from FastAPI startup (after :mod:`app.main` has
    imported :func:`app.core.events.get_event_bus`). Safe to call more
    than once — subsequent calls are no-ops.
    """
    global _ws_subscription_id
    if _ws_subscription_id is not None:
        return
    from app.core.events import get_event_bus

    bus = get_event_bus()
    sub_id = bus.subscribe("*", forward_to_websockets)
    if isinstance(sub_id, str):
        _ws_subscription_id = sub_id
        logger.info("WebSocket event forwarder registered on event bus (sub_id=%s)", sub_id)
    else:
        logger.info("WebSocket event forwarder registered on event bus")


# ===========================================
# WebSocket Endpoints
# ===========================================


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str | None = Query(
        None, description="JWT authentication token (deprecated — prefer auth message)"
    ),
) -> None:
    """
    WebSocket endpoint for real-time updates.

    ## Authentication

    **Preferred (secure):** Connect without query params and send an auth
    message as the first frame after the connection opens:

    ```json
    {"type": "auth", "token": "<jwt_token>"}
    ```

    **Deprecated (backwards-compatible):** Pass JWT token as query parameter
    ``/ws?token=<jwt_token>``.  This method will be removed in a future
    release because tokens in URLs leak via server logs, proxy logs, and
    browser history.

    ## Message Types (Client -> Server)

    ### Subscribe to events
    ```json
    {
        "type": "subscribe",
        "subscriptions": ["device.*", "controller.*"]
    }
    ```

    ### Unsubscribe from events
    ```json
    {
        "type": "unsubscribe",
        "subscriptions": ["device.*"]
    }
    ```

    ### Set site filters
    ```json
    {
        "type": "set_filters",
        "site_ids": ["site-uuid-1", "site-uuid-2"]
    }
    ```

    ### Ping
    ```json
    {"type": "ping"}
    ```

    ## Message Types (Server -> Client)

    ### Event notification
    ```json
    {
        "type": "event",
        "event": {
            "id": "...",
            "type": "device.status_changed",
            "timestamp": "...",
            "data": {...}
        }
    }
    ```

    ### Subscription confirmation
    ```json
    {"type": "subscribed", "subscriptions": [...]}
    ```

    ### Pong response
    ```json
    {"type": "pong", "timestamp": "..."}
    ```
    """
    # ── Phase 0: Origin validation (CSWSH protection) ─────────────
    # Browsers send cookies on WebSocket handshakes regardless of CORS
    # policy, so we must explicitly validate the Origin header against
    # the CORS allowlist before accepting the connection.
    if not await _validate_ws_origin(websocket):
        return

    # Idempotently bind the event-bus forwarder. We do this on first
    # connection (rather than module-import time) so we resolve the real
    # ``get_event_bus()`` singleton — not the lazy shim that the legacy
    # module-import decorator would have hit. See note on
    # :func:`register_event_bus_forwarder`.
    register_event_bus_forwarder()

    # ── Phase 1: Authenticate ─────────────────────────────────────
    auth: dict[str, Any] | None = None

    if token:
        # Backwards-compatible: token was provided in query string (deprecated)
        logger.warning(
            "WebSocket auth via query param is deprecated — client should "
            'send {"type": "auth", "token": "..."} as first message'
        )
        auth = await authenticate_websocket(token)

    # Try httpOnly cookie (browser sends cookies during WebSocket handshake)
    if not auth:
        from app.core.cookies import ACCESS_COOKIE

        cookie_token = websocket.cookies.get(ACCESS_COOKIE)
        if cookie_token:
            auth = await authenticate_websocket(cookie_token)

    if not auth:
        # Accept the connection first, then wait for an auth message.
        # The WebSocket handshake must complete before we can receive frames.
        await websocket.accept()

        try:
            # Wait up to 10 seconds for the auth message
            first_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        except (TimeoutError, WebSocketDisconnect, json.JSONDecodeError):
            with contextlib.suppress(Exception):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        if first_msg.get("type") != WSMessageType.AUTH or not first_msg.get("token"):
            try:
                await websocket.send_json(
                    {
                        "type": "error",
                        "message": 'First message must be {"type": "auth", "token": "..."}',
                    }
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            except Exception:
                pass
            return

        auth = await authenticate_websocket(first_msg["token"])
        if not auth:
            try:
                await websocket.send_json(
                    {
                        "type": "error",
                        "message": "Authentication failed",
                    }
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            except Exception:
                pass
            return

        # Per-user / global connection cap — reject before
        # registering so one account can't exhaust FDs/RAM. Socket is already
        # accepted on this path, so close it.
        if not manager.can_accept(auth["user_id"]):
            with contextlib.suppress(Exception):
                await websocket.close(code=1013)  # Try Again Later
            return

        # Connection already accepted above — register with manager
        # (skip the manager.connect accept step)
        # NOTE: ``datetime.now().timestamp()`` is millisecond-resolution at
        # best on Windows and two near-simultaneous WebSocket handshakes
        # (e.g. a tab reload firing both old + new connections) would
        # collide on the same connection_id. We add a uuid4 suffix.
        connection_id = f"{auth['user_id']}_{datetime.now(UTC).timestamp()}_{uuid.uuid4().hex}"
        # Manually register without re-accepting
        manager._connections[connection_id] = ConnectionInfo(
            websocket=websocket,
            user_id=auth["user_id"],
            organization_id=auth.get("organization_id"),
            token_version=auth.get("token_version", 0),
        )
        if auth["user_id"] not in manager._user_connections:
            manager._user_connections[auth["user_id"]] = set()
        manager._user_connections[auth["user_id"]].add(connection_id)
        logger.info("WebSocket connected: %s (user: %s)", connection_id, auth["user_id"])
    else:
        # Token was in query param — use the normal connect flow (which calls accept)
        # NOTE: see comment above about uuid4 suffix to avoid collisions
        # between near-simultaneous handshakes.
        # Cap check BEFORE accept so we reject without upgrading.
        if not manager.can_accept(auth["user_id"]):
            with contextlib.suppress(Exception):
                await websocket.close(code=1013)
            return
        connection_id = f"{auth['user_id']}_{datetime.now(UTC).timestamp()}_{uuid.uuid4().hex}"
        await manager.connect(
            websocket,
            connection_id,
            auth["user_id"],
            auth.get("organization_id"),
        )

    # load the server-enforced per-user site scope (UserSiteAccess)
    # and stamp it on the connection — applies to BOTH registration paths.
    _limited, _sites = await _load_ws_site_scope(auth["user_id"], auth.get("role"))
    _ci = manager._connections.get(connection_id)
    if _ci is not None:
        _ci.is_site_limited = _limited
        _ci.accessible_site_ids = _sites
        # SECURITY (WS session revocation): enforce token_version + per-device
        # access-jti revocation at CONNECT. The REST path checks every request;
        # the WS path otherwise deferred this to the ~5-min periodic
        # revalidation, leaving a window where a just-revoked token could open a
        # fresh socket. Stamp both fields uniformly (covers the query-param path,
        # whose manager.connect() does not set them) then fail closed on revoke.
        _ci.token_version = auth.get("token_version", 0)
        _ci.access_jti = auth.get("access_jti")
        if not await _revalidate_ws_session(_ci):
            with contextlib.suppress(Exception):
                await websocket.send_json(
                    {"type": "session_revoked", "message": "Your session has been revoked."}
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            await manager.disconnect(connection_id)
            return

    # ── Phase 2: Message loop ─────────────────────────────────────
    # Build a lightweight principal for per-subscription RBAC checks.
    principal = _WSAuthPrincipal(
        role=auth.get("role"),
        permissions=list(auth.get("permissions", []) or []),
    )
    # Per-connection inbound message rate limiter to stop clients from
    # spamming subscribe/unsubscribe/set_filters frames.
    rate_limiter = ConnectionRateLimiter(max_per_second=5, window=1.0)

    try:
        # Send welcome message
        await manager.send_personal(
            connection_id,
            {
                "type": "connected",
                "connection_id": connection_id,
                "user_id": auth["user_id"],
                "available_events": [e.value for e in EventType],
            },
        )

        # Message loop with periodic session re-validation
        while True:
            try:
                # Use timeout so we can periodically re-validate the session
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=float(_WS_REVALIDATION_INTERVAL_SECONDS),
                )
                # SECURITY: rate-limit inbound messages.
                if not rate_limiter.check():
                    logger.warning(
                        "WebSocket %s exceeded message rate limit — closing",
                        connection_id,
                    )
                    with contextlib.suppress(Exception):
                        await websocket.send_json(
                            {
                                "type": "error",
                                "message": "Message rate limit exceeded",
                            }
                        )
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return
                # Ignore duplicate auth messages after initial authentication
                if data.get("type") == WSMessageType.AUTH:
                    continue
                # a client that keeps sending messages never
                # reaches the TimeoutError branch below, so it would otherwise
                # never re-validate — keeping a revoked session/site-grant alive
                # for the life of a chatty connection. Re-validate on a wall-clock
                # schedule here too (token_version + site-scope refresh).
                _ci = manager._connections.get(connection_id)
                if (
                    _ci
                    and (datetime.now(UTC) - _ci.last_revalidated).total_seconds()
                    >= _WS_REVALIDATION_INTERVAL_SECONDS
                ):
                    if not await _revalidate_ws_session(_ci):
                        await manager.send_personal(
                            connection_id,
                            {
                                "type": "session_revoked",
                                "message": "Your session has been revoked. Please re-authenticate.",
                            },
                        )
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                        return
                    _ci.last_revalidated = datetime.now(UTC)
                    _limited, _sites = await _load_ws_site_scope(_ci.user_id, auth.get("role"))
                    _ci.is_site_limited = _limited
                    _ci.accessible_site_ids = _sites
                await handle_message(connection_id, data, user=principal)
            except TimeoutError:
                # No message received within the interval — re-validate session
                conn_info = manager._connections.get(connection_id)
                if conn_info and not await _revalidate_ws_session(conn_info):
                    logger.info(
                        "WebSocket session revoked for %s (token_version mismatch or user inactive)",
                        connection_id,
                    )
                    await manager.send_personal(
                        connection_id,
                        {
                            "type": "session_revoked",
                            "message": "Your session has been revoked. Please re-authenticate.",
                        },
                    )
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return
                # Update last revalidated timestamp
                if conn_info:
                    conn_info.last_revalidated = datetime.now(UTC)
                    # refresh the site scope too, so a grant
                    # revoked mid-session tightens the live socket within one
                    # revalidation interval (parity with token_version checks).
                    _limited, _sites = await _load_ws_site_scope(
                        conn_info.user_id, auth.get("role")
                    )
                    conn_info.is_site_limited = _limited
                    conn_info.accessible_site_ids = _sites
            except json.JSONDecodeError:
                await manager.send_personal(
                    connection_id,
                    {
                        "type": "error",
                        "message": "Invalid JSON",
                    },
                )

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(connection_id)


@router.get("/ws/stats")
async def websocket_stats(
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Get WebSocket connection statistics (requires authentication)."""
    return {
        "active_connections": manager.active_connections,
    }
