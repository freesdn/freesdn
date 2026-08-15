# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Asterisk REST Interface (ARI) Client
====================================================

Async HTTP + WebSocket client for the Asterisk REST Interface.

ARI provides:
  - REST API (HTTP on port 8088) for channel/bridge/endpoint control
  - WebSocket for real-time Stasis events

Authentication: HTTP Basic Auth (same user configured in ari.conf)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

import aiohttp

from app.core.http_client import build_aiohttp_session

from .constants import (
    ARI_DEFAULT_PORT,
    ARI_ENDPOINTS,
    ARI_REQUEST_TIMEOUT,
    ARI_WS_PING_INTERVAL,
    ARI_WS_RECONNECT_DELAY,
    FREESDN_ARI_APP,
)
from .exceptions import (
    ARIAuthError,
    ARIConnectionError,
    ARIWebSocketError,
)

logger = logging.getLogger("freesdn.adapters.freepbx.ari")

# WebSocket reconnect limits
_WS_RECONNECT_MAX_DELAY = 60.0
_WS_RECONNECT_MAX_ATTEMPTS = 20

# Type alias for WS event handlers
ARIEventHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class ARIClient:
    """
    Asynchronous ARI HTTP + WebSocket client.

    Usage::

        ari = ARIClient(host="198.51.100.10", username="freesdn", password="<PASSWORD>")
        await ari.connect()
        channels = await ari.list_channels()
        await ari.disconnect()
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = ARI_DEFAULT_PORT,
        use_ssl: bool = False,
        # ``verify_ssl`` defaults to True. Brownfield deployments with
        # a self-signed ARI cert must explicitly opt out — and the
        # service layer separately enforces an acknowledgement gate on
        # the PBX row before allowing the opt-out.
        verify_ssl: bool = True,
        app_name: str = FREESDN_ARI_APP,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.app_name = app_name

        self._scheme = "https" if use_ssl else "http"
        self._ws_scheme = "wss" if use_ssl else "ws"
        self._base_url = f"{self._scheme}://{self.host}:{self.port}"

        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._ws_task: asyncio.Task[None] | None = None
        self._connected = False
        self._closing = False

        # Event handlers
        self._event_handlers: dict[str, list[ARIEventHandler]] = {}
        self._global_handlers: list[ARIEventHandler] = []

    # ── properties ─────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected

    # ── lifecycle ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create HTTP session and verify connectivity."""
        if self._connected:
            return
        self._closing = False

        auth = aiohttp.BasicAuth(self.username, self.password)
        # sock_connect caps the TCP-connect phase so an unreachable PBX fails
        # fast (~8s) instead of hanging up to the (long) total request timeout.
        timeout = aiohttp.ClientTimeout(total=ARI_REQUEST_TIMEOUT, sock_connect=8.0)
        ssl_ctx: bool | None = None
        if self.use_ssl:
            ssl_ctx = self.verify_ssl  # False = skip verification
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        self._session = build_aiohttp_session(
            auth=auth,
            timeout=timeout,
            connector=connector,
        )

        # Verify connection by hitting the asterisk info endpoint
        try:
            async with self._session.get(
                f"{self._base_url}{ARI_ENDPOINTS['asterisk']}/info"
            ) as resp:
                if resp.status == 401:
                    await self._cleanup_session()
                    raise ARIAuthError("ARI authentication failed (401)")
                if resp.status != 200:
                    await self._cleanup_session()
                    raise ARIConnectionError(f"ARI connection test failed: HTTP {resp.status}")
                self._connected = True
                logger.info("ARI connected to %s:%s", self.host, self.port)
        except (TimeoutError, aiohttp.ClientError, OSError) as exc:
            await self._cleanup_session()
            raise ARIConnectionError(
                f"ARI connection to {self.host}:{self.port} failed: {exc}"
            ) from exc

    async def disconnect(self) -> None:
        """Close WebSocket and HTTP session."""
        self._closing = True
        self._connected = False

        if self._ws_task and not self._ws_task.done():
            self._ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._ws_task
        self._ws_task = None

        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._ws = None

        await self._cleanup_session()
        logger.info("ARI disconnected from %s:%s", self.host, self.port)

    async def close(self) -> None:
        """Alias for disconnect."""
        await self.disconnect()

    async def __aenter__(self) -> ARIClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    async def _cleanup_session(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._connected = False

    # ── WebSocket ──────────────────────────────────────────────────────

    async def connect_websocket(self) -> None:
        """
        Open the ARI WebSocket for Stasis events.

        Events arrive as JSON objects with a ``type`` field.
        """
        if not self._connected or not self._session:
            raise ARIConnectionError("Must connect() before connect_websocket()")

        ws_url = (
            f"{self._ws_scheme}://{self.host}:{self.port}"
            f"{ARI_ENDPOINTS['events']}"
            f"?app={self.app_name}"
        )

        try:
            self._ws = await self._session.ws_connect(
                ws_url,
                heartbeat=ARI_WS_PING_INTERVAL,
            )
        except aiohttp.ClientError as exc:
            raise ARIWebSocketError(f"ARI WebSocket connection failed: {exc}") from exc

        self._ws_task = asyncio.create_task(self._ws_event_loop(), name="ari-ws-loop")
        logger.info("ARI WebSocket connected for app '%s'", self.app_name)

    async def _ws_event_loop(self) -> None:
        """Read events from ARI WebSocket and dispatch."""
        while self._ws and not self._ws.closed and not self._closing:
            try:
                msg = await self._ws.receive(timeout=60.0)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    event = json.loads(msg.data)
                    await self._dispatch_event(event)
                except json.JSONDecodeError:
                    logger.warning("ARI WS: invalid JSON: %s", msg.data[:200])
            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error("ARI WS error: %s", self._ws.exception())
                break
            elif msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.CLOSED,
            ):
                break

        if not self._closing:
            logger.warning("ARI WebSocket disconnected, will reconnect...")
            await self._ws_reconnect()

    async def _ws_reconnect(self) -> None:
        """Attempt to reconnect the WebSocket with exponential backoff."""
        delay = ARI_WS_RECONNECT_DELAY
        attempts = 0
        while not self._closing and attempts < _WS_RECONNECT_MAX_ATTEMPTS:
            attempts += 1
            await asyncio.sleep(delay)
            try:
                await self.connect_websocket()
                logger.info("ARI WebSocket reconnected after %d attempts", attempts)
                return
            except (ARIWebSocketError, ARIConnectionError) as exc:
                logger.warning(
                    "ARI WS reconnect attempt %d/%d failed: %s",
                    attempts,
                    _WS_RECONNECT_MAX_ATTEMPTS,
                    exc,
                )
                delay = min(delay * 2, _WS_RECONNECT_MAX_DELAY)

        if not self._closing:
            logger.error(
                "ARI WebSocket reconnect gave up after %d attempts",
                _WS_RECONNECT_MAX_ATTEMPTS,
            )

    async def _dispatch_event(self, event: dict[str, Any]) -> None:
        """Route an ARI event to handlers."""
        event_type = event.get("type", "")

        handlers = self._event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception("Error in ARI handler for '%s'", event_type)

        for handler in self._global_handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception("Error in global ARI event handler")

    # ── event handler registration ─────────────────────────────────────

    def on_event(self, event_type: str, handler: ARIEventHandler) -> None:
        """Register a handler for a specific ARI event type."""
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler)

    def on_any_event(self, handler: ARIEventHandler) -> None:
        """Register a handler for all ARI events."""
        self._global_handlers.append(handler)

    # ── HTTP helpers ───────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Send an ARI HTTP request."""
        if not self._session or not self._connected:
            raise ARIConnectionError("ARI not connected")

        url = f"{self._base_url}{path}"
        try:
            resp = await self._session.request(method, url, params=params, json=json_body)
            if resp.status == 401:
                raise ARIAuthError("ARI authentication failed")
            if resp.status == 404:
                return None
            if resp.status == 204:
                return None

            body = await resp.json()
            if resp.status >= 400:
                error_msg = body.get("message", "") if isinstance(body, dict) else str(body)
                raise ARIConnectionError(
                    f"ARI request {method} {path} failed ({resp.status}): {error_msg}"
                )
            return body
        except aiohttp.ClientError as exc:
            raise ARIConnectionError(f"ARI request {method} {path} failed: {exc}") from exc

    async def _get(self, path: str, **params: Any) -> Any:
        return await self._request("GET", path, params=params or None)

    async def _post(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        return await self._request("POST", path, params=params, json_body=json_body)

    async def _delete(self, path: str, **params: Any) -> Any:
        return await self._request("DELETE", path, params=params or None)

    # ═══════════════════════════════════════════════════════════════════
    # Channel operations
    # ═══════════════════════════════════════════════════════════════════

    async def list_channels(self) -> list[dict[str, Any]]:
        """List all active channels."""
        result = await self._get(ARI_ENDPOINTS["channels"])
        return result if isinstance(result, list) else []

    async def get_channel(self, channel_id: str) -> dict[str, Any] | None:
        """Get details of a specific channel."""
        return await self._get(f"{ARI_ENDPOINTS['channels']}/{channel_id}")

    async def originate(
        self,
        endpoint: str,
        *,
        extension: str | None = None,
        context: str = "from-internal",
        priority: int = 1,
        caller_id: str = "",
        timeout: int = 30,
        app: str | None = None,
        app_args: str = "",
        variables: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Originate a new channel."""
        params: dict[str, Any] = {
            "endpoint": endpoint,
            "timeout": timeout,
        }
        if extension:
            params["extension"] = extension
            params["context"] = context
            params["priority"] = priority
        if app or not extension:
            params["app"] = app or self.app_name
        if app_args:
            params["appArgs"] = app_args
        if caller_id:
            params["callerId"] = caller_id

        json_body: dict[str, Any] | None = None
        if variables:
            json_body = {"variables": variables}

        return await self._post(
            ARI_ENDPOINTS["channels"],
            params=params,
            json_body=json_body,
        )

    async def hangup_channel(self, channel_id: str, reason: str = "normal") -> None:
        """Hang up a channel."""
        await self._delete(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}",
            reason_code=reason,
        )

    async def hold_channel(self, channel_id: str) -> None:
        """Place a channel on hold."""
        await self._post(f"{ARI_ENDPOINTS['channels']}/{channel_id}/hold")

    async def unhold_channel(self, channel_id: str) -> None:
        """Remove a channel from hold."""
        await self._delete(f"{ARI_ENDPOINTS['channels']}/{channel_id}/hold")

    async def mute_channel(self, channel_id: str, direction: str = "both") -> None:
        """Mute a channel. Direction: both, in, out."""
        await self._post(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/mute",
            params={"direction": direction},
        )

    async def unmute_channel(self, channel_id: str, direction: str = "both") -> None:
        """Unmute a channel."""
        await self._delete(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/mute",
            direction=direction,
        )

    async def send_dtmf(self, channel_id: str, dtmf: str, *, duration: int = 100) -> None:
        """Send DTMF tones to a channel."""
        await self._post(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/dtmf",
            params={"dtmf": dtmf, "duration": duration},
        )

    async def start_recording(
        self,
        channel_id: str,
        name: str,
        *,
        format: str = "wav",
        max_duration_seconds: int = 0,
        max_silence_seconds: int = 0,
        beep: bool = False,
        terminate_on: str = "none",
    ) -> dict[str, Any] | None:
        """Start recording a channel."""
        return await self._post(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/record",
            params={
                "name": name,
                "format": format,
                "maxDurationSeconds": max_duration_seconds,
                "maxSilenceSeconds": max_silence_seconds,
                "beep": beep,
                "terminateOn": terminate_on,
            },
        )

    async def play_media(
        self,
        channel_id: str,
        media: str,
        *,
        lang: str = "en",
    ) -> dict[str, Any] | None:
        """Play media on a channel (e.g., 'sound:hello-world')."""
        return await self._post(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/play",
            params={"media": media, "lang": lang},
        )

    async def get_rtp_statistics(self, channel_id: str) -> dict[str, Any] | None:
        """Get RTP statistics for a channel."""
        return await self._get(f"{ARI_ENDPOINTS['channels']}/{channel_id}/rtp_statistics")

    async def snoop_channel(
        self,
        channel_id: str,
        *,
        spy: str = "both",
        whisper: str = "none",
        app: str | None = None,
    ) -> dict[str, Any] | None:
        """Create a snoop (spy/whisper) channel."""
        return await self._post(
            f"{ARI_ENDPOINTS['channels']}/{channel_id}/snoop",
            params={
                "spy": spy,
                "whisper": whisper,
                "app": app or self.app_name,
            },
        )

    # ═══════════════════════════════════════════════════════════════════
    # Bridge operations
    # ═══════════════════════════════════════════════════════════════════

    async def list_bridges(self) -> list[dict[str, Any]]:
        """List all active bridges."""
        result = await self._get(ARI_ENDPOINTS["bridges"])
        return result if isinstance(result, list) else []

    async def create_bridge(
        self, bridge_type: str = "mixing", name: str = ""
    ) -> dict[str, Any] | None:
        """Create a new bridge."""
        params: dict[str, Any] = {"type": bridge_type}
        if name:
            params["name"] = name
        return await self._post(ARI_ENDPOINTS["bridges"], params=params)

    async def add_channel_to_bridge(self, bridge_id: str, channel_id: str) -> None:
        """Add a channel to a bridge."""
        await self._post(
            f"{ARI_ENDPOINTS['bridges']}/{bridge_id}/addChannel",
            params={"channel": channel_id},
        )

    async def remove_channel_from_bridge(self, bridge_id: str, channel_id: str) -> None:
        """Remove a channel from a bridge."""
        await self._post(
            f"{ARI_ENDPOINTS['bridges']}/{bridge_id}/removeChannel",
            params={"channel": channel_id},
        )

    async def destroy_bridge(self, bridge_id: str) -> None:
        """Destroy a bridge."""
        await self._delete(f"{ARI_ENDPOINTS['bridges']}/{bridge_id}")

    # ═══════════════════════════════════════════════════════════════════
    # Endpoint operations
    # ═══════════════════════════════════════════════════════════════════

    async def list_endpoints(self) -> list[dict[str, Any]]:
        """List all endpoints."""
        result = await self._get(ARI_ENDPOINTS["endpoints"])
        return result if isinstance(result, list) else []

    async def get_endpoint(self, tech: str, resource: str) -> dict[str, Any] | None:
        """Get a specific endpoint."""
        return await self._get(f"{ARI_ENDPOINTS['endpoints']}/{tech}/{resource}")

    # ═══════════════════════════════════════════════════════════════════
    # Asterisk system info
    # ═══════════════════════════════════════════════════════════════════

    async def get_asterisk_info(self, only: str | None = None) -> dict[str, Any] | None:
        """
        Get Asterisk system info.

        ``only`` can be: build, system, config, status
        """
        params: dict[str, Any] = {}
        if only:
            params["only"] = only
        return await self._get(f"{ARI_ENDPOINTS['asterisk']}/info", **params)

    async def get_global_variable(self, variable: str) -> str | None:
        """Get a global Asterisk variable."""
        result = await self._get(
            f"{ARI_ENDPOINTS['asterisk']}/variable",
            variable=variable,
        )
        if isinstance(result, dict):
            return result.get("value")
        return None

    async def set_global_variable(self, variable: str, value: str) -> None:
        """Set a global Asterisk variable."""
        await self._post(
            f"{ARI_ENDPOINTS['asterisk']}/variable",
            params={"variable": variable, "value": value},
        )
