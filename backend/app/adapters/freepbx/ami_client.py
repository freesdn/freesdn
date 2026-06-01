# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Asterisk Manager Interface (AMI) Client
======================================================

Async TCP client for the Asterisk Manager Interface.

Protocol overview:
  - Text-based, line-delimited (\\r\\n) messages on TCP port 5038
  - Login with Username / Secret
  - Actions: client → Asterisk  (ActionID correlation)
  - Events: Asterisk → client   (pushed asynchronously)
  - Responses: Asterisk → client (response to an Action)

This client supports:
  - Persistent connection with auto-reconnect
  - Action/response correlation via ActionID + asyncio.Future
  - Background event dispatch to registered handlers
  - Keepalive via periodic Ping actions
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    AMI_ACTION_TIMEOUT,
    AMI_DEFAULT_PORT,
    AMI_KEEPALIVE_INTERVAL,
    AMI_LOGIN_TIMEOUT,
    AMI_READ_TIMEOUT,
    AMI_RECONNECT_DELAY_BASE,
    AMI_RECONNECT_DELAY_MAX,
)
from .exceptions import (
    AMIAuthError,
    AMIConnectionError,
    AMIProtocolError,
    AMITimeoutError,
)

logger = logging.getLogger("freesdn.adapters.freepbx.ami")

# Maximum AMI read buffer size (16 MB) — prevents unbounded memory growth
_MAX_BUFFER_SIZE = 16 * 1024 * 1024

# AMI Originate ``Application`` field allowlist. Defence-in-depth — the
# high-level adapter also checks this, but the low-level client checks
# again so direct callers (tests, future code paths) can't sneak past.
# ``System``/``Exec``/``AGI``/``MixMonitor`` are RCE / arbitrary-file-write
# primitives via Asterisk dialplan applications.
_AMI_ORIGINATE_APP_ALLOWLIST: frozenset[str] = frozenset(
    {
        "Dial",
        "Playback",
        "Queue",
        "ConfBridge",
    }
)

# Type alias for event handler callbacks
EventHandler = Callable[["AMIMessage"], Coroutine[Any, Any, None]]


# ═══════════════════════════════════════════════════════════════════════════════
# AMI message
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class AMIMessage:
    """
    Represents a single AMI message (Action, Response, or Event).

    AMI messages are key-value pairs separated by ``\\r\\n`` with a blank
    line terminator.  Multi-line values (e.g., ``Output:``) are accumulated
    into the ``raw`` field.
    """

    headers: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    # ── convenience accessors ──────────────────────────────────────────

    @property
    def response(self) -> str:
        return self.headers.get("Response", "")

    @property
    def event(self) -> str:
        return self.headers.get("Event", "")

    @property
    def action_id(self) -> str:
        return self.headers.get("ActionID", "")

    @property
    def message(self) -> str:
        return self.headers.get("Message", "")

    @property
    def is_event(self) -> bool:
        return "Event" in self.headers

    @property
    def is_response(self) -> bool:
        return "Response" in self.headers

    @property
    def is_success(self) -> bool:
        return self.response.lower() == "success"

    @property
    def is_error(self) -> bool:
        return self.response.lower() == "error"

    def get(self, key: str, default: str = "") -> str:
        return self.headers.get(key, default)

    def __repr__(self) -> str:
        if self.is_event:
            return f"<AMIMessage Event={self.event}>"
        if self.is_response:
            return f"<AMIMessage Response={self.response} ActionID={self.action_id}>"
        return f"<AMIMessage headers={list(self.headers.keys())}>"


# ═══════════════════════════════════════════════════════════════════════════════
# AMI Client
# ═══════════════════════════════════════════════════════════════════════════════


class AMIClient:
    """
    Asynchronous AMI TCP client with auto-reconnect and event dispatch.

    **Security note**: AMI is a plaintext TCP protocol.  Credentials and
    commands are sent unencrypted.  Deploy behind a firewall or VPN, and
    restrict ``manager.conf`` to trusted source IPs only.

    Usage::

        ami = AMIClient(host="198.51.100.10", username="admin", secret="<SECRET>")
        await ami.connect()
        peers = await ami.get_sip_peers()
        await ami.disconnect()
    """

    def __init__(
        self,
        host: str,
        username: str,
        secret: str,
        *,
        port: int = AMI_DEFAULT_PORT,
        auto_reconnect: bool = True,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.secret = secret
        self.auto_reconnect = auto_reconnect

        # Connection state
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._authenticated = False
        self._closing = False

        # Action/response correlation
        self._pending: dict[str, asyncio.Future[AMIMessage]] = {}

        # Multi-response collection (for list commands)
        self._collectors: dict[str, _ListCollector] = {}

        # Event handlers: event_name → [handlers]
        self._event_handlers: dict[str, list[EventHandler]] = {}
        self._global_handlers: list[EventHandler] = []

        # Background tasks
        self._read_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None

    # ── properties ─────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected and self._authenticated

    # ── lifecycle ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open TCP connection and authenticate."""
        if self._connected:
            return
        self._closing = False

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=AMI_LOGIN_TIMEOUT,
            )
        except TimeoutError as exc:
            raise AMIConnectionError(
                f"AMI connection to {self.host}:{self.port} timed out"
            ) from exc
        except OSError as exc:
            raise AMIConnectionError(
                f"AMI connection to {self.host}:{self.port} failed: {exc}"
            ) from exc

        self._connected = True

        # Read greeting line  (e.g. "Asterisk Call Manager/6.0.1")
        try:
            greeting = await asyncio.wait_for(self._reader.readline(), timeout=AMI_LOGIN_TIMEOUT)
            greeting_str = greeting.decode("utf-8", errors="replace").strip()
            logger.debug("AMI greeting: %s", greeting_str)
            if "Asterisk Call Manager" not in greeting_str:
                raise AMIProtocolError(f"Unexpected AMI greeting: {greeting_str}")
        except TimeoutError as exc:
            await self._close_transport()
            raise AMIConnectionError("Timed out waiting for AMI greeting") from exc

        # Authenticate
        await self._login()

        # Start background tasks
        self._read_task = asyncio.create_task(self._read_loop(), name="ami-read-loop")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="ami-keepalive")
        logger.info("AMI connected and authenticated to %s:%s", self.host, self.port)

    async def disconnect(self) -> None:
        """Gracefully disconnect from AMI."""
        self._closing = True
        self._authenticated = False

        # Cancel background tasks
        for task in (self._read_task, self._keepalive_task):
            if task and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        self._read_task = None
        self._keepalive_task = None

        # Try to send Logoff action
        if self._connected and self._writer:
            with contextlib.suppress(Exception):
                await self._send_raw("Action: Logoff\r\nActionID: logoff\r\n\r\n")

        await self._close_transport()

        # Cancel pending futures
        for _action_id, future in self._pending.items():
            if not future.done():
                future.cancel()
        self._pending.clear()
        self._collectors.clear()

        logger.info("AMI disconnected from %s:%s", self.host, self.port)

    async def _close_transport(self) -> None:
        self._connected = False
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
        self._reader = None

    # ── authentication ─────────────────────────────────────────────────

    async def _login(self) -> None:
        """Send Login action and wait for response."""
        action_id = self._next_action_id()
        login_action = (
            f"Action: Login\r\n"
            f"ActionID: {action_id}\r\n"
            f"Username: {self.username}\r\n"
            f"Secret: {self.secret}\r\n"
            f"\r\n"
        )

        # Create future before sending
        future: asyncio.Future[AMIMessage] = asyncio.get_running_loop().create_future()
        self._pending[action_id] = future

        await self._send_raw(login_action)

        try:
            resp = await asyncio.wait_for(future, timeout=AMI_LOGIN_TIMEOUT)
        except TimeoutError as exc:
            self._pending.pop(action_id, None)
            await self._close_transport()
            raise AMIConnectionError("AMI login timed out") from exc

        if resp.is_error:
            await self._close_transport()
            raise AMIAuthError(f"AMI authentication failed: {resp.message}")

        self._authenticated = True
        logger.debug("AMI login successful")

    # ── sending actions ────────────────────────────────────────────────

    async def send_action(
        self,
        action: str,
        headers: dict[str, str] | None = None,
        *,
        timeout: float = AMI_ACTION_TIMEOUT,
    ) -> AMIMessage:
        """
        Send an AMI action and wait for the response.

        Args:
            action: AMI action name (e.g., "SIPpeers", "Originate").
            headers: Additional key-value headers for the action.
            timeout: Maximum time to wait for a response.

        Returns:
            The AMI response message.

        Raises:
            AMIConnectionError: If not connected.
            AMITimeoutError: If response not received in time.
        """
        if not self.connected:
            raise AMIConnectionError("Not connected to AMI")

        action_id = self._next_action_id()
        lines = [
            f"Action: {_sanitize_ami_value(action)}",
            f"ActionID: {action_id}",
        ]
        if headers:
            for key, value in headers.items():
                lines.append(f"{_sanitize_ami_value(key)}: {_sanitize_ami_value(value)}")
        lines.append("")
        lines.append("")  # blank line = end of message
        raw = "\r\n".join(lines)

        future: asyncio.Future[AMIMessage] = asyncio.get_running_loop().create_future()
        self._pending[action_id] = future

        await self._send_raw(raw)

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as exc:
            self._pending.pop(action_id, None)
            raise AMITimeoutError(f"AMI action '{action}' timed out after {timeout}s") from exc

    async def send_action_collect(
        self,
        action: str,
        headers: dict[str, str] | None = None,
        *,
        event_name: str,
        complete_event: str,
        timeout: float = AMI_ACTION_TIMEOUT,
    ) -> list[AMIMessage]:
        """
        Send an AMI action that returns multiple events and collect them.

        Many AMI commands (SIPpeers, QueueStatus, CoreShowChannels) respond
        with one event per item and a "Complete" event at the end.

        Args:
            action: AMI action name.
            headers: Additional headers.
            event_name: The event name for each item (e.g., "PeerEntry").
            complete_event: The event that signals completion (e.g., "PeerlistComplete").
            timeout: Maximum time to wait.

        Returns:
            List of collected event messages.
        """
        if not self.connected:
            raise AMIConnectionError("Not connected to AMI")

        action_id = self._next_action_id()
        collector = _ListCollector(
            event_name=event_name,
            complete_event=complete_event,
        )
        self._collectors[action_id] = collector

        lines = [
            f"Action: {_sanitize_ami_value(action)}",
            f"ActionID: {action_id}",
        ]
        if headers:
            for key, value in headers.items():
                lines.append(f"{_sanitize_ami_value(key)}: {_sanitize_ami_value(value)}")
        lines.append("")
        lines.append("")
        raw = "\r\n".join(lines)

        # Also register the initial response future
        future: asyncio.Future[AMIMessage] = asyncio.get_running_loop().create_future()
        self._pending[action_id] = future

        await self._send_raw(raw)

        # Wait for initial response
        try:
            resp = await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as exc:
            self._pending.pop(action_id, None)
            self._collectors.pop(action_id, None)
            raise AMITimeoutError(f"AMI action '{action}' response timed out") from exc

        if resp.is_error:
            self._collectors.pop(action_id, None)
            return []

        # Wait for the complete event
        try:
            return await asyncio.wait_for(collector.future, timeout=timeout)
        except TimeoutError:
            self._collectors.pop(action_id, None)
            # Return what we have so far
            logger.warning(
                "AMI list action '%s' timed out, returning %d partial events",
                action,
                len(collector.events),
            )
            return collector.events

    # ── event handlers ─────────────────────────────────────────────────

    def on_event(self, event_name: str, handler: EventHandler) -> None:
        """Register a handler for a specific AMI event type."""
        if event_name not in self._event_handlers:
            self._event_handlers[event_name] = []
        self._event_handlers[event_name].append(handler)

    def on_any_event(self, handler: EventHandler) -> None:
        """Register a handler that receives all AMI events."""
        self._global_handlers.append(handler)

    def remove_event_handler(self, event_name: str, handler: EventHandler) -> None:
        """Remove a specific event handler."""
        handlers = self._event_handlers.get(event_name, [])
        if handler in handlers:
            handlers.remove(handler)

    # ── high-level AMI commands ────────────────────────────────────────

    async def ping(self) -> bool:
        """Send a Ping action, return True if Pong received."""
        try:
            resp = await self.send_action("Ping", timeout=5.0)
            return resp.is_success
        except (AMITimeoutError, AMIConnectionError):
            return False

    async def get_sip_peers(self) -> list[AMIMessage]:
        """List all SIP/PJSIP peers."""
        # Try PJSIP first (modern Asterisk 13+)
        try:
            events = await self.send_action_collect(
                "PJSIPShowEndpoints",
                event_name="EndpointList",
                complete_event="EndpointListComplete",
                timeout=15.0,
            )
            if events:
                return events
        except (AMITimeoutError, AMIConnectionError):
            pass

        # Fallback to SIP
        return await self.send_action_collect(
            "SIPpeers",
            event_name="PeerEntry",
            complete_event="PeerlistComplete",
            timeout=15.0,
        )

    async def get_active_channels(self) -> list[AMIMessage]:
        """List all active channels."""
        return await self.send_action_collect(
            "CoreShowChannels",
            event_name="CoreShowChannel",
            complete_event="CoreShowChannelsComplete",
            timeout=15.0,
        )

    async def get_extension_states(
        self, extensions: list[str] | None = None, context: str = "default"
    ) -> list[AMIMessage]:
        """
        Get extension state(s).

        If ``extensions`` is None, queries all hints via ``ExtensionStateList``.
        Otherwise queries each extension individually.
        """
        if extensions is None:
            return await self.send_action_collect(
                "ExtensionStateList",
                event_name="ExtensionStatus",
                complete_event="ExtensionStateListComplete",
                timeout=15.0,
            )

        results: list[AMIMessage] = []
        for ext in extensions:
            resp = await self.send_action(
                "ExtensionState",
                {"Exten": ext, "Context": context},
            )
            results.append(resp)
        return results

    async def get_queue_status(self, queue: str | None = None) -> list[AMIMessage]:
        """Get queue status (members + callers)."""
        headers = {}
        if queue:
            headers["Queue"] = queue
        return await self.send_action_collect(
            "QueueStatus",
            headers=headers or None,
            event_name="QueueMember",
            complete_event="QueueStatusComplete",
            timeout=15.0,
        )

    async def get_queue_summary(self, queue: str | None = None) -> list[AMIMessage]:
        """Get queue summary statistics."""
        headers = {}
        if queue:
            headers["Queue"] = queue
        return await self.send_action_collect(
            "QueueSummary",
            headers=headers or None,
            event_name="QueueSummary",
            complete_event="QueueSummaryComplete",
            timeout=15.0,
        )

    async def originate(
        self,
        channel: str,
        *,
        exten: str | None = None,
        context: str = "from-internal",
        priority: str = "1",
        application: str | None = None,
        data: str | None = None,
        caller_id: str = "",
        timeout_ms: int = 30000,
        variables: dict[str, str] | None = None,
        async_originate: bool = True,
    ) -> AMIMessage:
        """
        Originate a new call.

        Either (exten + context) or (application + data) must be provided.
        """
        # Defence-in-depth: reject dangerous Originate applications even
        # if a future caller forgot to gate them at a higher layer.
        if application and application not in _AMI_ORIGINATE_APP_ALLOWLIST:
            raise AMIProtocolError(
                f"AMI Originate Application {application!r} is not in the "
                f"safe allowlist {sorted(_AMI_ORIGINATE_APP_ALLOWLIST)}; refusing"
            )

        headers: dict[str, str] = {
            "Channel": channel,
            "Timeout": str(timeout_ms),
        }
        if exten:
            headers["Exten"] = exten
            headers["Context"] = context
            headers["Priority"] = priority
        if application:
            headers["Application"] = application
        if data:
            headers["Data"] = data
        if caller_id:
            headers["CallerID"] = caller_id
        if async_originate:
            headers["Async"] = "true"
        if variables:
            var_str = ",".join(f"{k}={v}" for k, v in variables.items())
            headers["Variable"] = var_str

        return await self.send_action("Originate", headers)

    async def hangup(self, channel: str, cause: int = 16) -> AMIMessage:
        """Hang up a channel. Cause 16 = Normal Clearing."""
        return await self.send_action("Hangup", {"Channel": channel, "Cause": str(cause)})

    async def redirect(
        self,
        channel: str,
        exten: str,
        context: str = "from-internal",
        priority: str = "1",
    ) -> AMIMessage:
        """Redirect (transfer) a channel to another extension."""
        return await self.send_action(
            "Redirect",
            {
                "Channel": channel,
                "Exten": exten,
                "Context": context,
                "Priority": priority,
            },
        )

    async def queue_add(
        self,
        queue: str,
        interface: str,
        *,
        member_name: str = "",
        penalty: int = 0,
        paused: bool = False,
    ) -> AMIMessage:
        """Add a member to a queue."""
        headers: dict[str, str] = {
            "Queue": queue,
            "Interface": interface,
        }
        if member_name:
            headers["MemberName"] = member_name
        if penalty:
            headers["Penalty"] = str(penalty)
        if paused:
            headers["Paused"] = "true"
        return await self.send_action("QueueAdd", headers)

    async def queue_remove(self, queue: str, interface: str) -> AMIMessage:
        """Remove a member from a queue."""
        return await self.send_action("QueueRemove", {"Queue": queue, "Interface": interface})

    async def queue_pause(
        self, queue: str, interface: str, paused: bool = True, reason: str = ""
    ) -> AMIMessage:
        """Pause/unpause a queue member."""
        headers: dict[str, str] = {
            "Queue": queue,
            "Interface": interface,
            "Paused": "true" if paused else "false",
        }
        if reason:
            headers["Reason"] = reason
        return await self.send_action("QueuePause", headers)

    async def get_voicemail_users(self) -> list[AMIMessage]:
        """List voicemail users."""
        return await self.send_action_collect(
            "VoicemailUsersList",
            event_name="VoicemailUserEntry",
            complete_event="VoicemailUserEntryComplete",
            timeout=15.0,
        )

    async def reload_module(self, module: str = "") -> AMIMessage:
        """Reload an Asterisk module or all modules."""
        headers = {}
        if module:
            headers["Module"] = module
        return await self.send_action("Reload", headers or None)

    async def get_system_info(self) -> AMIMessage:
        """Get Asterisk core system info."""
        return await self.send_action("CoreSettings")

    async def get_version(self) -> str:
        """Return the Asterisk version string."""
        resp = await self.send_action("CoreSettings")
        return resp.get("AsteriskVersion", "unknown")

    # ── internal: read loop ────────────────────────────────────────────

    async def _read_loop(self) -> None:
        """
        Background task that reads AMI messages and dispatches them.

        Each message is ``\\r\\n`` delimited, terminated by a blank line.
        """
        buffer = ""
        while self._connected and not self._closing:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(8192),  # type: ignore[union-attr]
                    timeout=AMI_READ_TIMEOUT,
                )
            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                if not self._closing:
                    logger.warning("AMI connection lost: %s", exc)
                    await self._handle_disconnect()
                return
            except asyncio.CancelledError:
                return

            if not data:
                if not self._closing:
                    logger.warning("AMI connection closed by server")
                    await self._handle_disconnect()
                return

            buffer += data.decode("utf-8", errors="replace")

            # Guard against unbounded buffer growth (DoS protection)
            if len(buffer) > _MAX_BUFFER_SIZE:
                logger.error(
                    "AMI read buffer exceeded %d bytes, dropping connection",
                    _MAX_BUFFER_SIZE,
                )
                await self._handle_disconnect()
                return

            # Split on double CRLF (message separator)
            while "\r\n\r\n" in buffer:
                raw_msg, buffer = buffer.split("\r\n\r\n", 1)
                msg = self._parse_message(raw_msg)
                if msg:
                    await self._dispatch(msg)

    async def _dispatch(self, msg: AMIMessage) -> None:
        """Route a parsed message to the appropriate handler."""
        action_id = msg.action_id

        # Check if this is a response to a pending action
        if msg.is_response and action_id in self._pending:
            future = self._pending.pop(action_id)
            if not future.done():
                future.set_result(msg)
            return

        # Check if this is part of a list collection
        if msg.is_event and action_id:
            collector = self._collectors.get(action_id)
            if collector:
                collector.receive(msg)
                if collector.complete:
                    self._collectors.pop(action_id, None)
                return

        # It's an async event — dispatch to handlers
        if msg.is_event:
            event_name = msg.event
            handlers = self._event_handlers.get(event_name, [])
            for handler in handlers:
                try:
                    await handler(msg)
                except Exception:
                    logger.exception("Error in AMI event handler for '%s'", event_name)
            for handler in self._global_handlers:
                try:
                    await handler(msg)
                except Exception:
                    logger.exception("Error in global AMI event handler")

    # ── internal: keepalive ────────────────────────────────────────────

    async def _keepalive_loop(self) -> None:
        """Periodic Ping to keep the connection alive."""
        while self._connected and not self._closing:
            try:
                await asyncio.sleep(AMI_KEEPALIVE_INTERVAL)
                if self._connected and not self._closing:
                    ok = await self.ping()
                    if not ok:
                        logger.warning("AMI keepalive ping failed")
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("AMI keepalive error")

    # ── internal: reconnect ────────────────────────────────────────────

    async def _handle_disconnect(self) -> None:
        """Handle unexpected disconnect with optional auto-reconnect."""
        await self._close_transport()

        if not self.auto_reconnect or self._closing:
            return

        delay = AMI_RECONNECT_DELAY_BASE
        while not self._closing:
            logger.info("AMI reconnecting in %.1fs...", delay)
            await asyncio.sleep(delay)
            try:
                await self.connect()
                logger.info("AMI reconnected successfully")
                return
            except (AMIConnectionError, AMIAuthError) as exc:
                logger.warning("AMI reconnect failed: %s", exc)
                delay = min(delay * 2, AMI_RECONNECT_DELAY_MAX)

    # ── internal: transport ────────────────────────────────────────────

    async def _send_raw(self, data: str) -> None:
        """Send raw string over the TCP connection."""
        if not self._writer:
            raise AMIConnectionError("AMI transport not available")
        try:
            self._writer.write(data.encode("utf-8"))
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            raise AMIConnectionError(f"AMI write failed: {exc}") from exc

    @staticmethod
    def _parse_message(raw: str) -> AMIMessage | None:
        """Parse raw AMI text block into an AMIMessage."""
        if not raw.strip():
            return None

        headers: dict[str, str] = {}
        for line in raw.split("\r\n"):
            if not line:
                continue
            # Handle "Key: Value" format
            colon_idx = line.find(":")
            if colon_idx > 0:
                key = line[:colon_idx].strip()
                value = line[colon_idx + 1 :].strip()
                headers[key] = value
        if not headers:
            return None
        return AMIMessage(headers=headers, raw=raw)

    @staticmethod
    def _next_action_id() -> str:
        """Generate a unique ActionID."""
        return f"freesdn-{uuid.uuid4().hex[:12]}"


# ═══════════════════════════════════════════════════════════════════════════════
# Security helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _sanitize_ami_value(value: str) -> str:
    """
    Strip CR/LF from AMI header values to prevent CRLF injection.

    The AMI protocol uses ``\\r\\n`` as line delimiters.  If an attacker
    injects ``\\r\\n`` into a header value, they can inject arbitrary AMI
    actions into the TCP stream.
    """
    return value.replace("\r", "").replace("\n", "")


# ═══════════════════════════════════════════════════════════════════════════════
# List collector helper
# ═══════════════════════════════════════════════════════════════════════════════


class _ListCollector:
    """
    Accumulates AMI list events until the completion event arrives.

    Many AMI commands (SIPpeers, CoreShowChannels, QueueStatus, …) respond
    with one event per item followed by a "…Complete" event.
    """

    def __init__(self, event_name: str, complete_event: str):
        self.event_name = event_name
        self.complete_event = complete_event
        self.events: list[AMIMessage] = []
        self.complete = False
        self.future: asyncio.Future[list[AMIMessage]] = asyncio.get_running_loop().create_future()

    def receive(self, msg: AMIMessage) -> None:
        if msg.event == self.complete_event:
            self.complete = True
            if not self.future.done():
                self.future.set_result(self.events)
        elif msg.event == self.event_name:
            self.events.append(msg)
