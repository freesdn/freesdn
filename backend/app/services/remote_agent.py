# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Remote Agent Service
====================================

Server-side infrastructure for managing remote site agents.
Remote agents enable network management at sites not directly accessible
from the FreeSDN server.

Features:
- WebSocket-based agent communication
- Network scanning at remote sites
- Device control proxying
- Health monitoring and heartbeat
- Credential caching at agent level
- Command queue with prioritization

Architecture:
    FreeSDN Server <--WebSocket--> Remote Agent <---> Local Devices

Ported from FreeSDN v1 with async/await improvements for v2.
"""

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from app.models.agents import AgentHeartbeat, AgentTask, RemoteAgent

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class AgentStatus(StrEnum):
    """Agent connection status."""

    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class AgentCommandType(StrEnum):
    """Commands that can be sent to agents."""

    # Discovery
    SCAN_NETWORK = "scan_network"
    FINGERPRINT_DEVICE = "fingerprint_device"
    PROBE_API = "probe_api"

    # Device Control
    EXECUTE_ACTION = "execute_action"
    PUSH_CONFIG = "push_config"
    BACKUP_CONFIG = "backup_config"
    PROXY_HTTP = "proxy_http"  # edge bridge: agent proxies an HTTP request to a LAN device

    # Agent Management
    UPDATE_CREDENTIALS = "update_credentials"
    UPDATE_SCHEDULE = "update_schedule"  # backend pushes new scan schedule set
    REPORT_STATUS = "report_status"
    GET_HEALTH = "get_health"
    RESTART = "restart"
    UPDATE_AGENT = "update_agent"

    # Monitoring
    COLLECT_METRICS = "collect_metrics"
    GET_DEVICE_STATUS = "get_device_status"


class AgentReportType(StrEnum):
    """Reports sent from agent to server."""

    HEARTBEAT = "heartbeat"
    SCAN_RESULT = "scan_result"
    SCAN_PROGRESS = "scan_progress"
    ACTION_RESULT = "action_result"
    DEVICE_EVENT = "device_event"
    TOPOLOGY_UPDATE = "topology_update"
    METRICS = "metrics"
    ERROR = "error"
    LOG = "log"


# =============================================================================
# Wire-value coercion
# =============================================================================
#
# Everything arriving over the agent WebSocket is untrusted JSON. The metrics
# below land in typed DB columns, so a string or null from an older/foreign
# agent build would otherwise surface as a DBAPI error inside a handler whose
# only recovery is to drop the report -- or, on the heartbeat path, to tear the
# connection down. Coerce once, at the edge, and clamp to the range the column
# and the UI both assume.


def _as_float(value: Any, *, default: float = 0.0, lo: float = 0.0, hi: float = 100.0) -> float:
    """A percentage from the wire, or ``default``. Never raises."""
    try:
        if isinstance(value, bool) or value is None:
            return default
        number = float(value)
    except (TypeError, ValueError):
        return default
    # NaN and infinities survive min/max: ``min(100.0, nan)`` is 100.0 because
    # every comparison against NaN is False. Clamping them would report a fake
    # 100% CPU rather than "unknown", so reject them before the clamp.
    if number != number or number in (float("inf"), float("-inf")):
        return default
    return max(lo, min(hi, number))


def _as_int(value: Any, *, default: int = 0, lo: int = 0, hi: int = 2**31 - 1) -> int:
    """A counter from the wire, or ``default``. Never raises."""
    try:
        if isinstance(value, bool) or value is None:
            return default
        number = float(value)
        if number != number:  # NaN: int(nan) raises, and it means nothing here
            return default
        return max(lo, min(hi, int(number)))
    except (TypeError, ValueError, OverflowError):
        return default


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class AgentCommand:
    """Command to be sent to remote agent."""

    id: str = field(default_factory=lambda: str(uuid4()))
    type: AgentCommandType = AgentCommandType.REPORT_STATUS
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str | None = None
    priority: int = 5  # 1-10, lower is higher priority
    timeout_seconds: float = 30.0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "payload": self.payload,
            "correlation_id": self.correlation_id,
            "priority": self.priority,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AgentReport:
    """Report received from remote agent.

    ``agent_id`` is stamped by :py:meth:`AgentConnection._handle_report`
    just before handlers run, so report handlers can attribute the
    payload to its source connection without re-scanning the registry.
    Wire format from the agent does not include this field.
    """

    type: AgentReportType
    payload: dict[str, Any]
    command_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    agent_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentReport":
        # ``payload`` is untrusted wire data. It is DECLARED dict and every
        # consumer in the codebase calls ``.get`` on it, but nothing enforced
        # the shape -- an agent (or anything holding an agent key) sending
        # ``"payload": []`` produced an AttributeError inside _handle_report,
        # which _receiver_loop catches with ``break``. One malformed frame
        # therefore tore the WebSocket down, and a persistently malformed one
        # became a reconnect loop. Coerce here, at the single boundary every
        # report crosses, rather than defending in each handler.
        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            logger.warning(
                "Agent report payload is %s, not an object — discarding it",
                type(payload).__name__,
            )
            payload = {}
        return cls(
            type=AgentReportType(data.get("type", "heartbeat")),
            payload=payload,
            command_id=data.get("command_id"),
            correlation_id=data.get("correlation_id"),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(UTC),
        )


@dataclass
class AgentInfo:
    """Information about a connected agent."""

    agent_id: str
    site_id: UUID
    site_name: str

    # Connection info
    status: AgentStatus = AgentStatus.OFFLINE
    connected_at: datetime | None = None
    last_heartbeat: datetime | None = None

    # Agent details
    version: str = "unknown"
    hostname: str = "unknown"
    platform: str = "unknown"

    # Network info
    local_ip: str | None = None
    public_ip: str | None = None
    subnets: list[str] = field(default_factory=list)

    # Statistics
    uptime_seconds: float = 0.0
    commands_processed: int = 0
    errors_count: int = 0

    # Health
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "site_id": str(self.site_id),
            "site_name": self.site_name,
            "status": self.status.value,
            "connected_at": self.connected_at.isoformat() if self.connected_at else None,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "version": self.version,
            "hostname": self.hostname,
            "platform": self.platform,
            "local_ip": self.local_ip,
            "public_ip": self.public_ip,
            "subnets": self.subnets,
            "uptime_seconds": self.uptime_seconds,
            "commands_processed": self.commands_processed,
            "errors_count": self.errors_count,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "disk_percent": self.disk_percent,
        }


@dataclass
class CommandResult:
    """Result of a command execution."""

    command_id: str
    success: bool
    result: Any = None
    error: str | None = None
    duration_ms: float = 0.0


# =============================================================================
# Exceptions
# =============================================================================


class AgentError(Exception):
    """Base agent error."""

    pass


class AgentNotFoundError(AgentError):
    """Agent not found for site."""

    pass


class AgentConnectionError(AgentError):
    """Agent connection error."""

    pass


class CommandTimeoutError(AgentError):
    """Command timed out."""

    pass


# =============================================================================
# Agent Connection Handler
# =============================================================================


class AgentConnection:
    """
    Manages WebSocket connection to a single remote agent.
    Handles message queuing, heartbeat, and reconnection.
    """

    HEARTBEAT_INTERVAL = 30  # seconds
    HEARTBEAT_TIMEOUT = 90  # seconds - disconnect if no heartbeat

    def __init__(
        self,
        agent_info: AgentInfo,
        websocket: Any,  # WebSocket from FastAPI/Starlette
    ):
        self.info = agent_info
        self.websocket = websocket

        # Inbound throttle: the browser WS path is rate-limited but
        # the agent path was not — a compromised/buggy agent could flood frames or
        # send a huge payload. 10/s allows heartbeats + bursts.
        from app.core.ws_rbac import ConnectionRateLimiter

        self._rate_limiter = ConnectionRateLimiter(max_per_second=10)
        # Hard per-frame size cap (bytes). Big enough for a full 5000-host scan
        # batch, small enough to refuse a memory-bomb frame.
        self._max_frame_bytes = 16 * 1024 * 1024

        # Command queue
        self._command_queue: asyncio.Queue[AgentCommand] = asyncio.Queue()
        self._pending_commands: dict[str, asyncio.Future[CommandResult]] = {}

        # Message handlers
        self._report_handlers: dict[AgentReportType, list[Callable[..., Any]]] = {}

        # State
        self._running = False
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._sender_task: asyncio.Task[None] | None = None
        self._receiver_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start connection handlers."""
        self._running = True
        self.info.status = AgentStatus.ONLINE
        self.info.connected_at = datetime.now(UTC)

        # Start tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._sender_task = asyncio.create_task(self._sender_loop())
        self._receiver_task = asyncio.create_task(self._receiver_loop())

        logger.info("Agent connection started for site %s", self.info.site_name)

    async def stop(self) -> None:
        """Stop connection handlers."""
        self._running = False
        self.info.status = AgentStatus.OFFLINE

        # Cancel tasks
        for task in [self._heartbeat_task, self._sender_task, self._receiver_task]:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        # Cancel pending commands
        for future in self._pending_commands.values():
            if not future.done():
                future.set_exception(AgentConnectionError("Agent disconnected"))

        logger.info("Agent connection stopped for site %s", self.info.site_name)

    async def send_command(
        self,
        command: AgentCommand,
        wait_result: bool = True,
    ) -> CommandResult | None:
        """Send command to agent and optionally wait for result."""
        await self._command_queue.put(command)

        if wait_result:
            future: asyncio.Future[CommandResult] = asyncio.get_running_loop().create_future()
            self._pending_commands[command.id] = future

            try:
                result: CommandResult = await asyncio.wait_for(
                    future, timeout=command.timeout_seconds
                )
                return result
            except TimeoutError:
                self._pending_commands.pop(command.id, None)
                return CommandResult(
                    command_id=command.id,
                    success=False,
                    error="Command timed out",
                )

        return None

    def add_report_handler(
        self,
        report_type: AgentReportType,
        handler: Callable[[AgentReport], None],
    ) -> None:
        """Register handler for specific report type."""
        if report_type not in self._report_handlers:
            self._report_handlers[report_type] = []
        self._report_handlers[report_type].append(handler)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat requests."""
        while self._running:
            try:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)

                # Check for heartbeat timeout
                if self.info.last_heartbeat:
                    elapsed = (datetime.now(UTC) - self.info.last_heartbeat).total_seconds()
                    if elapsed > self.HEARTBEAT_TIMEOUT:
                        logger.warning("Agent %s heartbeat timeout", self.info.site_name)
                        self.info.status = AgentStatus.ERROR
                        break

                # Request heartbeat
                cmd = AgentCommand(
                    type=AgentCommandType.GET_HEALTH,
                    priority=1,  # High priority
                    timeout_seconds=10.0,
                )
                await self._command_queue.put(cmd)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Heartbeat error: %s", e)

    async def _sender_loop(self) -> None:
        """Send queued commands to agent."""
        while self._running:
            try:
                command = await self._command_queue.get()

                if self.websocket:
                    await self.websocket.send_json(command.to_dict())
                    logger.debug("Sent command %s to %s", command.type.value, self.info.site_name)
                else:
                    logger.error("Cannot send command, WebSocket closed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Sender error: %s", e)

    async def _receiver_loop(self) -> None:
        """Receive and process messages from agent.

        Exiting this loop means the peer is gone -- the socket closed, the
        agent tripped the rate limit, or a frame could not be handled. Whatever
        the reason, ``_running`` MUST be cleared on the way out.

        It was not, and the WebSocket endpoint parks on
        ``while connection._running: await asyncio.sleep(1)``. So when an agent
        disconnected, this loop broke and that one spun forever: the endpoint
        coroutine never returned, its ``finally`` never ran, and the registry
        kept a connection whose socket was closed.

        Which matters because the registry is deliberately treated as ground
        truth over the DB status column -- ``run_interactive_scan`` says so in
        as many words and dispatches on ``get_connection_for_site``. So an
        operator hitting Scan got their command written into a dead socket.
        Meanwhile the row never flipped to offline, ``disconnected_at`` stayed
        null, and every disconnect leaked one coroutine and one registry entry
        for the life of the process.
        """
        try:
            await self._receive_forever()
        finally:
            self._running = False

    async def _receive_forever(self) -> None:
        while self._running:
            try:
                # Read as text first so we can enforce a size cap + rate limit
                # before parsing/dispatching.
                raw = await self.websocket.receive_text()
                if len(raw) > self._max_frame_bytes:
                    logger.warning(
                        "Agent %s sent oversized frame (%d bytes) — dropping",
                        getattr(self.info, "agent_id", "?"),
                        len(raw),
                    )
                    continue
                if not self._rate_limiter.check():
                    logger.warning(
                        "Agent %s exceeded inbound rate limit — closing",
                        getattr(self.info, "agent_id", "?"),
                    )
                    break
                data = json.loads(raw)
                report = AgentReport.from_dict(data)
                await self._handle_report(report)

            except asyncio.CancelledError:
                break
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON from agent: %s", e)
            except Exception as e:
                logger.error("Receiver error: %s", e)
                break

    async def _handle_report(self, report: AgentReport) -> None:
        """Process incoming report from agent."""
        # Stamp the connection's agent_id onto the report so handlers
        # (which only see the dataclass) can attribute the payload.
        report.agent_id = self.info.agent_id

        # Update heartbeat time
        if report.type == AgentReportType.HEARTBEAT:
            self.info.last_heartbeat = datetime.now(UTC)
            self.info.status = AgentStatus.ONLINE

            # Update agent stats from heartbeat
            payload = report.payload
            self.info.uptime_seconds = _as_int(payload.get("uptime_seconds"))
            self.info.cpu_percent = _as_float(payload.get("cpu_percent"))
            self.info.memory_percent = _as_float(payload.get("memory_percent"))
            self.info.disk_percent = _as_float(payload.get("disk_percent"))
            self.info.version = payload.get("version") or self.info.version

            # Persist heartbeat freshness + telemetry back to the DB.
            #
            # Without this, ``cleanup_stale_agents`` (which compares
            # remote_agents.last_heartbeat to a cutoff) would mark every live
            # agent offline once a minute, because the in-memory
            # ``AgentInfo.last_heartbeat`` update above never reaches the row.
            #
            # The metrics half was missing entirely. The shipped agent sends
            # cpu/memory/disk/uptime/version/platform/hostname every 30s over
            # this socket, and all of it stopped at AgentInfo -- an in-memory
            # object no API reads. So ``GET /agents`` reported
            # ``uptime_seconds: 0`` forever, and ``version`` kept showing
            # whatever the agent registered with, even after it self-updated.
            # WS is the only transport the shipped agent uses; the HTTP
            # ``POST /{id}/heartbeat`` endpoint that does persist all this is
            # dead code by comparison.
            #
            # Done in a fresh session because ``self.db`` is bound at
            # registry-construct time and goes stale on long-lived WS
            # connections.
            try:
                from sqlalchemy import update as _upd

                from app.db import async_session_factory
                from app.models.agents import RemoteAgent as _RA

                values: dict[str, Any] = {
                    "last_heartbeat": self.info.last_heartbeat,
                    "last_seen": self.info.last_heartbeat,
                    "status": AgentStatus.ONLINE.value,
                    "uptime_seconds": self.info.uptime_seconds,
                }
                # ``capabilities`` gates which scan_types the operator may
                # schedule, and it is read back as ``caps.get("scan_types")``.
                # A non-object here (an agent sending a bare list) used to be
                # stored verbatim and then 500'd every later read.
                caps = payload.get("capabilities")
                if isinstance(caps, dict) and caps:
                    values["capabilities"] = caps
                elif caps:
                    logger.warning(
                        "Agent %s reported capabilities as %s, not an object — ignoring",
                        self.info.agent_id,
                        type(caps).__name__,
                    )
                version = payload.get("version")
                if isinstance(version, str) and version:
                    values["version"] = version[:50]
                platform = payload.get("platform")
                if isinstance(platform, str) and platform:
                    values["platform"] = platform[:100]
                hostname = payload.get("hostname")
                if isinstance(hostname, str) and hostname:
                    values["last_hostname"] = hostname[:255]

                async with async_session_factory() as _s:
                    await _s.execute(
                        _upd(_RA).where(_RA.id == UUID(self.info.agent_id)).values(**values)
                    )
                    await _s.commit()
            except Exception:
                logger.debug(
                    "Failed to persist heartbeat freshness for %s",
                    self.info.agent_id,
                    exc_info=True,
                )

            # Time-series row, so the health history the UI and
            # ``GET /agents/{id}/heartbeats`` read is not permanently empty
            # for every agent that connects over the socket. Separate try so
            # a LogDB outage cannot cost us the freshness write above --
            # losing history is cosmetic, losing freshness marks a live agent
            # offline.
            await self._record_heartbeat_sample(payload)

        # Resolve pending command
        if report.command_id and report.command_id in self._pending_commands:
            future = self._pending_commands.pop(report.command_id)
            if not future.done():
                result = CommandResult(
                    command_id=report.command_id,
                    success=report.type != AgentReportType.ERROR,
                    result=report.payload,
                    error=report.payload.get("error")
                    if report.type == AgentReportType.ERROR
                    else None,
                )
                future.set_result(result)

        # Call registered handlers
        handlers = self._report_handlers.get(report.type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(report)
                else:
                    handler(report)
            except Exception as e:
                logger.error("Report handler error: %s", e)

    async def _record_heartbeat_sample(self, payload: dict[str, Any]) -> None:
        """Append one ``agent_heartbeats`` row from a WS heartbeat.

        The same row ``POST /agents/{id}/heartbeat`` writes. That HTTP endpoint
        exists, has a read endpoint (``GET /agents/{id}/heartbeats``) and a
        retention endpoint (``DELETE /agents/heartbeats/old``) behind it -- but
        the shipped agent has always used this WebSocket instead, so nothing
        ever wrote a row and the whole health-history feature returned an empty
        list on every deployment.

        Best-effort and fully swallowed: heartbeat HISTORY is a nice-to-have,
        while heartbeat FRESHNESS (persisted by the caller) is what keeps a
        live agent from being marked offline.
        """
        try:
            from app.db.session import get_logdb_factory
            from app.models.agents import AgentHeartbeat as _HB

            factory = get_logdb_factory()
            async with factory() as _log:
                _log.add(
                    _HB(
                        agent_id=UUID(self.info.agent_id),
                        timestamp=self.info.last_heartbeat or datetime.now(UTC),
                        cpu_percent=_as_float(payload.get("cpu_percent")),
                        memory_percent=_as_float(payload.get("memory_percent")),
                        disk_percent=_as_float(payload.get("disk_percent")),
                        status=AgentStatus.ONLINE.value,
                        latency_ms=None,
                        managed_devices=_as_int(payload.get("managed_devices")),
                        active_tasks=_as_int(payload.get("active_tasks")),
                    )
                )
                await _log.commit()
        except Exception:
            logger.debug(
                "Failed to record heartbeat sample for %s",
                self.info.agent_id,
                exc_info=True,
            )


# =============================================================================
# Schedule-run notification dispatch
# =============================================================================


async def _maybe_notify_schedule_run(
    db,
    *,
    schedule,
    run_status: str,
    new_host_count: int,
    total_device_count: int,
    duration_seconds: float | None,
    error_message: str | None,
) -> None:
    """Dispatch schedule-run notifications via the shared helper.

    Triggers:
    - ``notify_on_failure=True`` + ``run_status="failed"`` → always notify.
    - ``notify_on_new_devices>0`` + run created at least that many
      previously-unseen hosts → notify.

    No-op if ``notification_channels`` is empty or the trigger
    conditions aren't met. Failure to deliver is logged but does NOT
    re-raise — the run record stays persisted regardless.
    """
    channels = schedule.notification_channels or {}
    if not channels:
        return

    should_notify = False
    title = ""
    body_lines: list[str] = []

    if schedule.notify_on_failure and run_status == "failed":
        should_notify = True
        title = f"[FreeSDN] Scheduled scan FAILED: {schedule.name}"
        body_lines.append(f"Schedule: {schedule.name}")
        body_lines.append(f"Cron: {schedule.cron}")
        body_lines.append("Status: failed")
        if error_message:
            body_lines.append(f"Error: {error_message}")
        if duration_seconds is not None:
            body_lines.append(f"Duration: {duration_seconds:.1f}s")

    elif (
        schedule.notify_on_new_devices > 0
        and run_status == "completed"
        and new_host_count >= schedule.notify_on_new_devices
    ):
        should_notify = True
        title = f"[FreeSDN] Scan found {new_host_count} new device(s): {schedule.name}"
        body_lines.append(f"Schedule: {schedule.name}")
        body_lines.append(f"New hosts: {new_host_count}")
        body_lines.append(f"Total observed this run: {total_device_count}")
        if duration_seconds is not None:
            body_lines.append(f"Duration: {duration_seconds:.1f}s")

    if not should_notify:
        return

    body_lines.append("")
    body_lines.append(f"Site ID: {schedule.site_id}")
    body_lines.append(f"Schedule ID: {schedule.id}")

    from app.services.notification_helpers import dispatch_notifications

    try:
        await dispatch_notifications(
            db,
            channels_config=channels,
            title=title,
            body="\n".join(body_lines),
            organization_id=schedule.organization_id,
        )
        logger.info(
            "Dispatched notifications for schedule %s (status=%s, new=%d)",
            schedule.name,
            run_status,
            new_host_count,
        )
    except Exception:
        logger.exception(
            "dispatch_notifications failed for schedule %s",
            schedule.name,
        )


# =============================================================================
# Agent Registry Service
# =============================================================================


class AgentRegistryService:
    """
    Service for managing all remote agents.
    Handles registration, authentication, and connection management.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self._connections: dict[str, AgentConnection] = {}
        self._api_keys: dict[str, str] = {}  # agent_id -> hashed_key
        # Interactive scan task IDs currently awaiting WS reports. The
        # scan-progress/result handler skips DB updates when the
        # command_id isn't in this set, so scheduled-scan progress (which
        # uses a random UUID) doesn't pay the per-tick DB cost.
        self._interactive_tasks: set[str] = set()

    def register_interactive_task(self, task_id: str) -> None:
        """Mark an AgentTask as interactive — scan_progress/result reports
        with this command_id will mirror state into the agent_tasks row."""
        self._interactive_tasks.add(task_id)

    def unregister_interactive_task(self, task_id: str) -> None:
        """Drop an interactive task ID once it's terminal (or cancelled)."""
        self._interactive_tasks.discard(task_id)

    def generate_agent_token(self, site_id: UUID, site_name: str) -> tuple[str, str]:
        """
        Generate a new agent registration token.

        Returns:
            Tuple of (agent_id, api_key)
        """
        agent_id = f"agent_{site_id.hex[:8]}_{secrets.token_hex(4)}"
        api_key = secrets.token_urlsafe(32)

        # Store hashed key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        self._api_keys[agent_id] = key_hash

        return agent_id, api_key

    def verify_agent_token(self, agent_id: str, api_key: str) -> bool:
        """Verify agent API key."""
        stored_hash = self._api_keys.get(agent_id)
        if not stored_hash:
            return False

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return hmac.compare_digest(stored_hash, key_hash)

    async def register_connection(
        self,
        agent_id: str,
        site_id: UUID,
        site_name: str,
        websocket: Any,
    ) -> AgentConnection:
        """Register a new agent connection."""

        # Create agent info
        info = AgentInfo(
            agent_id=agent_id,
            site_id=site_id,
            site_name=site_name,
        )

        # Create connection handler
        connection = AgentConnection(info, websocket)

        # Register the SCAN_RESULT persistence handler. The audit found
        # that scan_result reports from daemon-scheduled scans were
        # silently dropped because no handler was registered for them.
        # This handler upserts the findings into devices.discovered_hosts
        # via the same service the REST /discovery/results endpoint uses.
        connection.add_report_handler(
            AgentReportType.SCAN_RESULT,
            self._persist_scan_result,
        )
        # Same drop-on-floor problem as SCAN_RESULT — the agent's LLDP
        # / CDP listeners emit ``topology_update`` reports but nothing
        # was subscribed. Persist into devices.topology_edges so the
        # observed L2 graph is queryable from the topology UI.
        connection.add_report_handler(
            AgentReportType.TOPOLOGY_UPDATE,
            self._persist_topology_update,
        )
        # Interactive-scan progress / completion mirror. Updates the
        # agent_tasks row so the web UI can poll for live state instead
        # of waiting for the agent to finish + push results.
        connection.add_report_handler(
            AgentReportType.SCAN_PROGRESS,
            self._update_interactive_task,
        )
        connection.add_report_handler(
            AgentReportType.SCAN_RESULT,
            self._update_interactive_task,
        )
        connection.add_report_handler(
            AgentReportType.ACTION_RESULT,
            self._update_interactive_task,
        )
        connection.add_report_handler(
            AgentReportType.ERROR,
            self._update_interactive_task,
        )

        # Store connection
        self._connections[agent_id] = connection

        # Start connection handlers
        await connection.start()

        logger.info("Agent registered: %s for site %s", agent_id, site_name)

        return connection

    async def _persist_scan_result(self, report: AgentReport) -> None:
        """Persist a scan_result WS report into devices.discovered_hosts.

        Called by AgentConnection._handle_report whenever the agent emits
        a ``scan_result`` message. The payload shape mirrors the HTTP
        ``POST /discovery/results`` schema — ``payload["devices"]`` is a
        list of host dicts from the agent's ``ScanResult.to_dict()``.

        If ``payload["schedule_name"]`` is present (set by
        SchedulerService for scheduled runs), this also inserts an
        ``agent_schedule_runs`` row and bumps the schedule's
        ``last_fired_at`` so the operator can see when scheduled scans
        actually ran. Manual / GUI scans don't set schedule_name and
        skip that path.

        Uses a fresh DB session because the registry's ``self.db`` may
        be stale (it was bound at registry-construct time and the WS
        connection is long-lived).
        """
        try:
            payload = report.payload or {}
            raw_hosts = payload.get("devices") or payload.get("results") or []
            # Bound the batch to the SAME cap the HTTP ingestion enforces
            # (DiscoveryResultsRequest max_length=5000) so the WS path can't be a
            # cap bypass for per-host DB-write amplification.
            _MAX_HOSTS = 5000
            #
            # The cap used to be guarded by ``isinstance(hosts, list)``, which
            # meant a non-list slipped past it AND straight into upsert_batch,
            # whose loop does ``h.get("ip_address")``. Iterating a dict yields
            # its keys, so the first element was a str and the whole scan died
            # on AttributeError -- swallowed by the except at the bottom of this
            # method. The operator saw a scan that "completed" with zero hosts
            # and no error anywhere. A dict payload also bypassed the cap
            # entirely, which was the exact amplification the cap exists for.
            #
            # NOTE the log arguments below: this method hangs off
            # AgentRegistryService, which has NO ``self.info`` -- that lives on
            # AgentConnection. The original truncation warning read
            # ``getattr(self.info, "agent_id", "?")``, and getattr evaluates
            # ``self.info`` before it can supply the default, so the warning
            # itself raised AttributeError. The except at the bottom of this
            # method caught it, which meant the 5000-host CAP -- whose entire
            # job is to truncate an oversized scan down to something safe --
            # instead discarded the scan whole, and logged nothing an operator
            # would ever see. Use ``report.agent_id``, which is stamped on
            # every report by _handle_report.
            if not isinstance(raw_hosts, list):
                logger.warning(
                    "Agent %s scan_result 'devices' is %s, not a list — dropping",
                    report.agent_id,
                    type(raw_hosts).__name__,
                )
                raw_hosts = []
            if len(raw_hosts) > _MAX_HOSTS:
                logger.warning(
                    "Agent %s scan_result has %d hosts > cap %d — truncating",
                    report.agent_id,
                    len(raw_hosts),
                    _MAX_HOSTS,
                )
                raw_hosts = raw_hosts[:_MAX_HOSTS]
            # Drop non-object entries rather than letting one poison the batch:
            # upsert_batch runs in a single transaction, so one bad element used
            # to cost every good host beside it.
            hosts = [h for h in raw_hosts if isinstance(h, dict)]
            if len(hosts) != len(raw_hosts):
                logger.warning(
                    "Agent %s scan_result had %d non-object host entries — skipped",
                    report.agent_id,
                    len(raw_hosts) - len(hosts),
                )

            schedule_name = payload.get("schedule_name")
            if schedule_name is not None and not isinstance(schedule_name, str):
                schedule_name = None
            # These land in typed columns on agent_schedule_runs, and the INSERT
            # is what records that a scheduled scan ran at all. A wire value of
            # the wrong type or length fails it, and the failure is swallowed by
            # the except at the bottom of this method -- so the run silently
            # never happened as far as the operator can tell.
            #
            # ``status`` is String(16), not the 50 these columns usually get.
            run_status = str(payload.get("status") or "completed")[:16]
            raw_duration = payload.get("duration_seconds")
            # Nullable Float: None means "the agent did not say", which is a
            # different fact from "it took no time".
            duration = (
                None
                if raw_duration is None
                else _as_float(raw_duration, default=0.0, hi=float(2**31))
            )
            error_message = payload.get("error")
            if error_message is not None:
                # Text column, so no hard limit — bound it anyway so one agent
                # cannot write an unbounded blob per scheduled run.
                error_message = str(error_message)[:4000]

            # Need the agent's site_id + organization_id. Look up the
            # connection that owns this report.
            connection = self._connections.get(report.agent_id)
            if connection is None:
                logger.warning(
                    "SCAN_RESULT from agent %s but no connection registered",
                    report.agent_id,
                )
                return
            site_id = connection.info.site_id

            from datetime import UTC as _UTC
            from datetime import datetime as _dt

            from sqlalchemy import select as _sel

            from app.db import async_session_factory
            from app.models.agents import AgentSchedule, AgentScheduleRun
            from app.models.core import Site
            from app.services.discovered_hosts import upsert_batch

            async with async_session_factory() as bg_session:
                site_q = await bg_session.execute(
                    _sel(Site).where(Site.id == site_id, Site.deleted_at.is_(None))
                )
                site = site_q.scalar_one_or_none()
                if not site:
                    logger.warning(
                        "SCAN_RESULT for site %s but site not found",
                        site_id,
                    )
                    return

                # Persist devices (skipped if list is empty — still
                # records the schedule run for empty-but-completed scans).
                summary: dict[str, Any] = {"created": 0, "updated": 0, "skipped": 0, "routed": {}}
                if hosts:
                    summary = await upsert_batch(
                        bg_session,
                        site_id=site_id,
                        organization_id=site.organization_id,
                        discovered_by_agent_id=UUID(report.agent_id),
                        hosts=hosts,
                    )
                    logger.info(
                        "Persisted scan_result from agent %s: %s",
                        report.agent_id,
                        summary,
                    )

                # Record schedule run + bump last_fired_at when this was
                # a scheduled scan.
                schedule_to_notify: AgentSchedule | None = None
                new_host_count = 0
                if schedule_name:
                    sched_q = await bg_session.execute(
                        _sel(AgentSchedule).where(
                            AgentSchedule.site_id == site_id,
                            AgentSchedule.name == schedule_name,
                            AgentSchedule.deleted_at.is_(None),
                        )
                    )
                    schedule = sched_q.scalar_one_or_none()
                    if schedule:
                        now = _dt.now(_UTC)
                        run = AgentScheduleRun(
                            schedule_id=schedule.id,
                            agent_id=UUID(report.agent_id),
                            status=run_status,
                            device_count=len(hosts),
                            duration_seconds=duration,
                            error_message=error_message,
                            started_at=now,
                            completed_at=now,
                        )
                        bg_session.add(run)
                        schedule.last_fired_at = now
                        # Capture for after-commit notification dispatch
                        schedule_to_notify = schedule
                        # `summary["created"]` is brand-new discovered_hosts
                        # for this run; `updated` is re-observed. The
                        # operator cares about NEW because that's what
                        # represents new exposure on the network.
                        new_host_count = summary.get("created", 0)
                        logger.info(
                            "Recorded schedule run: %s (status=%s, devices=%d, new=%d)",
                            schedule_name,
                            run_status,
                            len(hosts),
                            new_host_count,
                        )
                    else:
                        logger.warning(
                            "scan_result tagged schedule %r but no matching schedule at site %s",
                            schedule_name,
                            site_id,
                        )

                await bg_session.commit()

                # Dispatch notifications AFTER commit so a delivery
                # failure can't roll back the run record. Same site
                # (multi-tenant scope) inherits its org from the schedule.
                if schedule_to_notify is not None:
                    try:
                        await _maybe_notify_schedule_run(
                            bg_session,
                            schedule=schedule_to_notify,
                            run_status=run_status,
                            new_host_count=new_host_count,
                            total_device_count=len(hosts),
                            duration_seconds=duration,
                            error_message=error_message,
                        )
                    except Exception:
                        logger.exception(
                            "Failed to dispatch notifications for schedule %s",
                            schedule_to_notify.name,
                        )
        except Exception:
            logger.exception(
                "Failed to persist scan_result from agent %s",
                report.agent_id,
            )

    async def _persist_topology_update(self, report: AgentReport) -> None:
        """Persist a topology_update WS report into devices.topology_edges.

        Called when the agent's LLDP or CDP listener parses a neighbor
        announcement frame. Uses the same fresh-session pattern as the
        scan_result persister.
        """
        try:
            payload = report.payload or {}
            connection = self._connections.get(report.agent_id)
            if connection is None:
                logger.warning(
                    "TOPOLOGY_UPDATE from agent %s but no connection registered",
                    report.agent_id,
                )
                return
            site_id = connection.info.site_id

            from sqlalchemy import select as _sel

            from app.db import async_session_factory
            from app.models.core import Site
            from app.services.agent_topology import (
                normalize_lldp_payload,
                upsert_topology_edge,
            )

            kwargs = normalize_lldp_payload(payload)
            if kwargs is None:
                # No chassis/port — nothing actionable to persist
                logger.debug(
                    "topology_update from %s skipped — missing chassis/port",
                    report.agent_id,
                )
                return

            async with async_session_factory() as bg_session:
                site_q = await bg_session.execute(
                    _sel(Site).where(Site.id == site_id, Site.deleted_at.is_(None))
                )
                site = site_q.scalar_one_or_none()
                if not site:
                    logger.warning(
                        "topology_update for site %s but site not found",
                        site_id,
                    )
                    return

                await upsert_topology_edge(
                    bg_session,
                    site_id=site_id,
                    organization_id=site.organization_id,
                    discovered_by_agent_id=UUID(report.agent_id),
                    **kwargs,
                )
                await bg_session.commit()
                logger.info(
                    "Persisted topology edge from agent %s: %s/%s → %s/%s",
                    report.agent_id,
                    kwargs.get("local_interface"),
                    site_id,
                    kwargs.get("neighbor_chassis_id"),
                    kwargs.get("neighbor_port_id"),
                )
        except Exception:
            logger.exception(
                "Failed to persist topology_update from agent %s",
                report.agent_id,
            )

    async def _update_interactive_task(self, report: AgentReport) -> None:
        """Mirror scan_progress/result/error reports into the agent_tasks row.

        Only acts when ``report.command_id`` is in the interactive-task
        registry — scheduled scan reports (which carry a random UUID
        command_id) short-circuit out so we don't pay a DB round-trip
        for every per-scanner progress tick.

        Wraps :py:meth:`_apply_interactive_report` in a fresh DB session
        (registry's ``self.db`` may be stale on long-lived WS connections).
        The split keeps the SQL-mutation logic testable independently of
        the session-management plumbing.
        """
        cmd_id = report.command_id
        if not cmd_id or cmd_id not in self._interactive_tasks:
            return

        try:
            task_uuid = UUID(cmd_id)
        except (ValueError, TypeError):
            return

        from app.db import async_session_factory

        try:
            async with async_session_factory() as bg_session:
                await self._apply_interactive_report(
                    bg_session,
                    task_uuid,
                    report,
                )
                await bg_session.commit()
        except Exception:
            logger.exception(
                "Failed to update interactive task %s from %s report",
                cmd_id,
                report.type,
            )

    async def _apply_interactive_report(
        self,
        session: AsyncSession,
        task_uuid: UUID,
        report: AgentReport,
    ) -> None:
        """Apply a single scan_progress/result/error report to the task row.

        Pure DB logic — no commit. Caller owns the transaction so this
        can be unit-tested against a test session and run for real
        against a fresh background session.

        Progress reports bump ``progress`` (and capture the current
        scanner + devices_found into ``result`` so the UI can show
        them live). ``scan_result`` writes the device list and marks
        the task completed. ``error`` reports mark it failed.
        ``action_result`` is treated as a redundant terminal signal
        (``scan_result`` already wrote the data) but kept as a fallback
        in case the agent emits action_result without a prior scan_result.
        """
        from app.models.agents import AgentTask

        cmd_id = report.command_id
        payload = report.payload or {}
        report_type = report.type

        row_q = await session.execute(select(AgentTask).where(AgentTask.id == task_uuid))
        task = row_q.scalar_one_or_none()
        if task is None:
            if cmd_id:
                self._interactive_tasks.discard(cmd_id)
            return

        terminal_already = task.status in (
            "completed",
            "failed",
            "cancelled",
        )

        if report_type == AgentReportType.SCAN_PROGRESS:
            if terminal_already:
                return
            pct = int(payload.get("progress", task.progress or 0))
            task.progress = max(0, min(100, pct))
            if task.status == "pending":
                task.status = "running"
                task.started_at = task.started_at or datetime.now(UTC)
            live = dict(task.result or {})
            live["scanner"] = payload.get("scanner")
            live["devices_found"] = payload.get(
                "devices_found",
                live.get("devices_found", 0),
            )
            live["status"] = payload.get(
                "status",
                live.get("status", "running"),
            )
            task.result = live

        elif report_type == AgentReportType.SCAN_RESULT:
            # If the operator cancelled the task while it was running,
            # don't resurrect it as "completed" when the agent's late
            # scan_result eventually lands. Discard from the interactive
            # set so any further reports are ignored too.
            if task.status == "cancelled":
                if cmd_id:
                    self._interactive_tasks.discard(cmd_id)
                return
            devices = payload.get("devices") or []
            task.status = "completed"
            task.progress = 100
            task.completed_at = datetime.now(UTC)
            task.result = {
                "devices": devices,
                "total": payload.get("total", len(devices)),
            }
            if cmd_id:
                self._interactive_tasks.discard(cmd_id)

        elif report_type == AgentReportType.ACTION_RESULT:
            if not terminal_already:
                task.status = "completed"
                task.progress = 100
                task.completed_at = datetime.now(UTC)
                inner = payload.get("result")
                if inner is not None and not task.result:
                    task.result = inner if isinstance(inner, dict) else {"data": inner}
            if cmd_id:
                self._interactive_tasks.discard(cmd_id)

        elif report_type == AgentReportType.ERROR:
            task.status = "failed"
            task.completed_at = datetime.now(UTC)
            task.error_message = str(payload.get("message", "Agent reported error"))
            if cmd_id:
                self._interactive_tasks.discard(cmd_id)

    async def unregister_connection(self, agent_id: str) -> None:
        """Unregister agent connection."""
        connection = self._connections.pop(agent_id, None)
        if connection:
            await connection.stop()
            logger.info("Agent unregistered: %s", agent_id)

    def get_connection(self, agent_id: str) -> AgentConnection | None:
        """Get agent connection by ID."""
        return self._connections.get(agent_id)

    def get_connection_for_site(self, site_id: UUID) -> AgentConnection | None:
        """Get agent connection for a site."""
        # Snapshot via list() so concurrent register/unregister don't
        # raise RuntimeError: dictionary changed size during iteration.
        for conn in list(self._connections.values()):
            if conn.info.site_id == site_id:
                return conn
        return None

    def connections_for_site(self, site_id: UUID) -> list[tuple[str, AgentConnection]]:
        """Snapshot list of (agent_id, connection) for the given site.

        external callers were reaching into the
        private ``_connections`` dict to iterate connections at a site,
        which races with the WS handler's register_connection /
        unregister_connection mutating that dict from a different
        coroutine. Calling list() takes a thread-safe snapshot of the
        ``dict_items`` view.
        """
        return [
            (aid, conn)
            for aid, conn in list(self._connections.items())
            if conn and conn.info and conn.info.site_id == site_id
        ]

    def list_agents(self) -> list[AgentInfo]:
        """List all connected agents."""
        return [conn.info for conn in list(self._connections.values())]

    async def send_command_to_site(
        self,
        site_id: UUID,
        command: AgentCommand,
        wait_result: bool = True,
    ) -> CommandResult | None:
        """Send command to agent for a specific site."""
        connection = self.get_connection_for_site(site_id)
        if not connection:
            raise AgentNotFoundError(f"No agent connected for site {site_id}")

        return await connection.send_command(command, wait_result)

    async def proxy_http_via_site(
        self,
        site_id: UUID,
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = False,
        timeout: float = 15.0,
    ) -> CommandResult | None:
        """Edge bridge: have the site's agent proxy an HTTP request to a LAN device.

        For appliance sites the controller can't reach directly (the device — a
        camera/PBX — can't join the overlay), the agent on that LAN executes the
        request and returns the response. Pairs with the agent-side ``proxy_http``
        handler. Raises ``AgentNotFoundError`` if no agent is connected for the
        site. See docs.freesdn.org.
        """
        command = AgentCommand(
            type=AgentCommandType.PROXY_HTTP,
            payload={
                "url": url,
                "method": method,
                "headers": headers or {},
                "body": body,
                "username": username,
                "password": password,
                "verify_ssl": verify_ssl,
                "timeout": timeout,
            },
            timeout_seconds=timeout + 10,
        )
        return await self.send_command_to_site(site_id, command, wait_result=True)

    async def broadcast_command(
        self,
        command: AgentCommand,
        site_ids: list[UUID] | None = None,
    ) -> dict[str, CommandResult]:
        """
        Broadcast command to multiple agents.

        Args:
            command: Command to send
            site_ids: Optional list of site IDs to target (all if None)

        Returns:
            Dict mapping agent_id to result
        """
        results = {}

        for agent_id, connection in self._connections.items():
            if site_ids is None or connection.info.site_id in site_ids:
                try:
                    result = await connection.send_command(command, wait_result=True)
                    if result:
                        results[agent_id] = result
                except Exception as e:
                    results[agent_id] = CommandResult(
                        command_id=command.id,
                        success=False,
                        error=str(e),
                    )

        return results


# =============================================================================
# Remote Discovery Service
# =============================================================================


class RemoteDiscoveryService:
    """
    Service for coordinating device discovery on remote sites via agents.
    """

    def __init__(self, agent_registry: AgentRegistryService):
        self.registry = agent_registry

    async def start_remote_scan(
        self,
        site_id: UUID,
        targets: list[str],
        methods: list[str] | None = None,
        ports: list[int] | None = None,
    ) -> str:
        """
        Start network scan on remote site.

        Returns:
            Scan ID for tracking progress
        """
        command = AgentCommand(
            type=AgentCommandType.SCAN_NETWORK,
            payload={
                "targets": targets,
                "methods": methods or ["tcp_connect", "mdns", "ssdp"],
                "ports": ports,
            },
            timeout_seconds=300.0,  # 5 minute timeout for scans
        )

        await self.registry.send_command_to_site(site_id, command, wait_result=False)

        # Return scan ID (command ID serves as scan ID)
        return command.id

    async def get_scan_progress(
        self,
        site_id: UUID,
        scan_id: str,
    ) -> dict[str, Any] | None:
        """Get progress of remote scan."""
        command = AgentCommand(
            type=AgentCommandType.REPORT_STATUS,
            payload={"scan_id": scan_id},
            timeout_seconds=10.0,
        )

        result = await self.registry.send_command_to_site(site_id, command)
        if result and result.success:
            return result.result  # type: ignore[no-any-return]
        return None

    async def fingerprint_remote_device(
        self,
        site_id: UUID,
        ip_address: str,
    ) -> dict[str, Any] | None:
        """Fingerprint a device on remote site."""
        command = AgentCommand(
            type=AgentCommandType.FINGERPRINT_DEVICE,
            payload={"ip_address": ip_address},
            timeout_seconds=60.0,
        )

        result = await self.registry.send_command_to_site(site_id, command)
        if result and result.success:
            return result.result  # type: ignore[no-any-return]
        return None


# =============================================================================
# Remote Control Service
# =============================================================================


class RemoteControlService:
    """
    Service for executing device control actions on remote sites via agents.
    """

    def __init__(self, agent_registry: AgentRegistryService):
        self.registry = agent_registry

    async def execute_action(
        self,
        site_id: UUID,
        device_id: str,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> CommandResult:
        """Execute device action on remote site."""
        command = AgentCommand(
            type=AgentCommandType.EXECUTE_ACTION,
            payload={
                "device_id": device_id,
                "action": action,
                "params": params or {},
            },
            timeout_seconds=60.0,
        )

        result = await self.registry.send_command_to_site(site_id, command)
        return result or CommandResult(
            command_id=command.id,
            success=False,
            error="No response from agent",
        )

    async def push_config(
        self,
        site_id: UUID,
        device_id: str,
        config: dict[str, Any],
    ) -> CommandResult | None:
        """Push configuration to device on remote site."""
        command = AgentCommand(
            type=AgentCommandType.PUSH_CONFIG,
            payload={
                "device_id": device_id,
                "config": config,
            },
            timeout_seconds=120.0,
        )

        return await self.registry.send_command_to_site(site_id, command)

    async def backup_config(
        self,
        site_id: UUID,
        device_id: str,
    ) -> dict[str, Any] | None:
        """Backup configuration from device on remote site."""
        command = AgentCommand(
            type=AgentCommandType.BACKUP_CONFIG,
            payload={"device_id": device_id},
            timeout_seconds=60.0,
        )

        result = await self.registry.send_command_to_site(site_id, command)
        if result and result.success:
            return result.result  # type: ignore[no-any-return]
        return None


# =============================================================================
# Persistent Agent Service (DB-backed)
# =============================================================================


class PersistentAgentService:
    """
    Database-backed agent management service.

    Bridges in-memory WebSocket connections (AgentRegistryService) with
    PostgreSQL persistence for agent registration, heartbeats, tasks,
    and approval workflows.

    Usage pattern:
        - REST API endpoints use this service for CRUD operations
        - WebSocket handler uses AgentRegistryService for real-time comms
        - This service syncs state between the two layers
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # -------------------------------------------------------------------------
    # Agent Registration & CRUD
    # -------------------------------------------------------------------------

    async def register_agent(
        self,
        name: str,
        site_id: UUID,
        organization_id: UUID,
        description: str | None = None,
        agent_type: str = "site",
    ) -> tuple["RemoteAgent", str]:
        """
        Register a new agent and return the model + one-time API key.

        Returns:
            Tuple of (RemoteAgent, plaintext_api_key)
        """
        from app.models.agents import RemoteAgent

        # Generate credentials
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        agent = RemoteAgent(
            agent_key=key_hash,
            name=name,
            description=description,
            agent_type=agent_type,
            site_id=site_id,
            organization_id=organization_id,
            status="offline",
        )

        self.db.add(agent)
        await self.db.flush()
        await self.db.refresh(agent)

        return agent, api_key

    async def verify_credentials(
        self,
        agent_id: UUID,
        api_key: str,
    ) -> "RemoteAgent | None":
        """Verify agent credentials. Returns agent if valid."""
        from app.models.agents import RemoteAgent

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        result = await self.db.execute(
            select(RemoteAgent).where(
                RemoteAgent.id == agent_id,
                RemoteAgent.agent_key == key_hash,
                RemoteAgent.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def get_agent(self, agent_id: UUID) -> "RemoteAgent | None":
        """Get agent by ID."""
        from app.models.agents import RemoteAgent

        result = await self.db.execute(
            select(RemoteAgent).where(
                RemoteAgent.id == agent_id,
                RemoteAgent.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def list_agents(
        self,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        status: str | None = None,
        agent_type: str | None = None,
        is_approved: bool | None = None,
        is_enabled: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        accessible_site_ids: set[UUID] | None = None,
    ) -> tuple[list["RemoteAgent"], int]:
        """
        List agents with filtering.

        Returns:
            Tuple of (agents, total_count)
        """
        from sqlalchemy import func as sa_func

        from app.models.agents import RemoteAgent

        query = select(RemoteAgent).where(RemoteAgent.deleted_at.is_(None))
        count_query = select(sa_func.count(RemoteAgent.id)).where(RemoteAgent.deleted_at.is_(None))

        if organization_id:
            query = query.where(RemoteAgent.organization_id == organization_id)
            count_query = count_query.where(RemoteAgent.organization_id == organization_id)
        if site_id:
            query = query.where(RemoteAgent.site_id == site_id)
            count_query = count_query.where(RemoteAgent.site_id == site_id)
        # site-limited callers only see agents in granted sites.
        if accessible_site_ids is not None:
            query = query.where(RemoteAgent.site_id.in_(accessible_site_ids))
            count_query = count_query.where(RemoteAgent.site_id.in_(accessible_site_ids))
        if status:
            query = query.where(RemoteAgent.status == status)
            count_query = count_query.where(RemoteAgent.status == status)
        if agent_type:
            query = query.where(RemoteAgent.agent_type == agent_type)
            count_query = count_query.where(RemoteAgent.agent_type == agent_type)
        if is_approved is not None:
            query = query.where(RemoteAgent.is_approved == is_approved)
            count_query = count_query.where(RemoteAgent.is_approved == is_approved)
        if is_enabled is not None:
            query = query.where(RemoteAgent.is_enabled == is_enabled)
            count_query = count_query.where(RemoteAgent.is_enabled == is_enabled)

        total = (await self.db.execute(count_query)).scalar() or 0

        query = query.order_by(RemoteAgent.created_at.desc())
        query = query.limit(limit).offset(offset)
        result = await self.db.execute(query)
        agents = list(result.scalars().all())

        return agents, total

    async def update_agent(
        self,
        agent_id: UUID,
        **kwargs: Any,
    ) -> "RemoteAgent | None":
        """Update agent fields."""
        agent = await self.get_agent(agent_id)
        if not agent:
            return None

        for key, value in kwargs.items():
            if hasattr(agent, key) and value is not None:
                setattr(agent, key, value)

        await self.db.flush()
        await self.db.refresh(agent)
        return agent

    async def approve_agent(
        self,
        agent_id: UUID,
        approved_by_id: UUID,
    ) -> "RemoteAgent | None":
        """Approve an agent for task execution."""
        agent = await self.get_agent(agent_id)
        if not agent:
            return None

        agent.is_approved = True
        agent.approved_at = datetime.now(UTC)
        agent.approved_by_id = approved_by_id

        await self.db.flush()
        await self.db.refresh(agent)
        return agent

    async def soft_delete_agent(
        self,
        agent_id: UUID,
        logdb_session: "AsyncSession | None" = None,
    ) -> bool:
        """Soft-delete an agent, purge heartbeats, AND revoke any WireGuard
        peer config bound to the agent's site.

        NOTE: the previous implementation only tombstoned the row
        and deleted heartbeats — the agent's WireGuard peer remained active
        on the brain gateway, so a leaked agent key + private key could
        still authenticate and reach the site network. We now look up any
        WireGuard-backed ``SiteVPNConfiguration`` for the agent's site and
        try to revoke it. If the brain-gateway integration isn't reachable
        from this code path (it lives in ``app.services.adapter_omada_vpn`` /
        ``app.services.brain_vpn`` and requires a controller connection),
        we still:

          1. Clear ``wireguard_peer_public_key`` / ``wireguard_endpoint`` /
             ``wireguard_allowed_ips`` on the DB row so the peer cannot be
             re-provisioned by an automation,
          2. Mark the VPN config status as ``revoked``,
          3. Emit a WARN log instructing operators to manually run
             ``wg set <iface> peer <key> remove`` on the brain.

        This is fail-open by design: a transient gateway outage must NOT
        block agent deletion — the audit trail records that the delete
        happened, and the DB-side revocation prevents key reuse.
        """
        agent = await self.get_agent(agent_id)
        if not agent:
            return False

        # Purge heartbeats from LogDB (prevents orphaned time-series data)
        if logdb_session is None:
            raise RuntimeError(
                "logdb_session is required for soft_delete_agent. Ensure LOGDB_URL is configured."
            )
        from app.models.agents import AgentHeartbeat

        await logdb_session.execute(
            delete(AgentHeartbeat).where(AgentHeartbeat.agent_id == agent_id)
        )

        # NOTE: WireGuard peer revocation. Find any WireGuard VPN
        # config bound to this agent's site and tombstone the peer fields.
        # Production deployments should also push ``wg set <iface> peer
        # <pubkey> remove`` to the brain gateway — that path lives in
        # ``gateway_vpn``/``brain_vpn`` and is gated on a controller
        # connection, so we only attempt best-effort here and log a WARN
        # if the actual gateway push isn't possible from this context.
        if agent.site_id is not None:
            try:
                from app.models.vpn import SiteVPNConfiguration, VPNType

                vpn_result = await self.db.execute(
                    select(SiteVPNConfiguration).where(
                        SiteVPNConfiguration.site_id == agent.site_id,
                        SiteVPNConfiguration.vpn_type == VPNType.WIREGUARD,
                    )
                )
                wg_configs = list(vpn_result.scalars().all())
                for wg in wg_configs:
                    revoked_pubkey = wg.wireguard_peer_public_key
                    # Tombstone the peer: clear key/endpoint/allowed-ips so
                    # the agent cannot reauthenticate even if its private
                    # key leaks AND no automation can silently re-publish
                    # the same peer config.
                    wg.wireguard_peer_public_key = None
                    wg.wireguard_endpoint = None
                    wg.wireguard_allowed_ips = []
                    wg.status = "revoked"
                    wg.enabled = False
                    logger.warning(
                        "Agent %s soft-deleted: revoked WireGuard peer "
                        "(pubkey=%s) on site %s vpn_config=%s. "
                        "Operator MUST manually run `wg set <iface> peer "
                        "%s remove` on the brain gateway to complete the "
                        "revocation. The DB-side fields are cleared so the "
                        "peer cannot be re-provisioned by automation.",
                        agent_id,
                        revoked_pubkey[:16] + "..." if revoked_pubkey else "<none>",
                        agent.site_id,
                        wg.id,
                        revoked_pubkey or "<unknown>",
                    )
            except Exception:
                # WG revocation failure must never block agent delete —
                # the agent_key is already invalidated by deleted_at below,
                # so the agent cannot reauthenticate via the WS path. Log
                # loudly so operators can clean up manually.
                logger.exception(
                    "Agent %s soft-delete: WireGuard peer revocation failed "
                    "(non-fatal). Operator must manually remove peer from "
                    "brain gateway for site %s.",
                    agent_id,
                    agent.site_id,
                )

        agent.deleted_at = datetime.now(UTC)
        agent.status = "offline"
        await self.db.flush()
        return True

    async def get_agent_stats(
        self,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get aggregate agent statistics."""
        from sqlalchemy import case
        from sqlalchemy import func as sa_func

        from app.models.agents import RemoteAgent

        query = select(
            sa_func.count(RemoteAgent.id).label("total"),
            sa_func.count(case((RemoteAgent.status == "online", 1))).label("online"),
            sa_func.count(case((RemoteAgent.status == "offline", 1))).label("offline"),
            sa_func.count(case((RemoteAgent.status == "error", 1))).label("error"),
            sa_func.count(case((RemoteAgent.is_approved == False, 1))).label("pending_approval"),  # noqa: E712
        ).where(RemoteAgent.deleted_at.is_(None))

        if organization_id:
            query = query.where(RemoteAgent.organization_id == organization_id)

        row = (await self.db.execute(query)).one()

        return {
            "total": row.total,
            "online": row.online,
            "offline": row.offline,
            "error": row.error,
            "pending_approval": row.pending_approval,
        }

    # -------------------------------------------------------------------------
    # Heartbeats
    # -------------------------------------------------------------------------

    async def record_heartbeat(
        self,
        agent_id: UUID,
        cpu_percent: float,
        memory_percent: float,
        disk_percent: float,
        status: str = "online",
        latency_ms: float | None = None,
        managed_devices: int = 0,
        active_tasks: int = 0,
        logdb_session: "AsyncSession | None" = None,
    ) -> "AgentHeartbeat":
        """Record a heartbeat from an agent and update agent status.

        Args:
            logdb_session: Optional separate session for time-series writes.
                           If provided, heartbeat is written to logdb; agent
                           status is always updated via self.db (primary).
        """
        from app.models.agents import AgentHeartbeat, RemoteAgent

        now = datetime.now(UTC)
        if logdb_session is None:
            raise RuntimeError(
                "logdb_session is required for record_heartbeat. "
                "LogDB is mandatory for time-series data."
            )
        ts_session = logdb_session

        # Create heartbeat record (written to logdb when available)
        heartbeat = AgentHeartbeat(
            agent_id=agent_id,
            timestamp=now,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_percent=disk_percent,
            status=status,
            latency_ms=latency_ms,
            managed_devices=managed_devices,
            active_tasks=active_tasks,
        )
        ts_session.add(heartbeat)

        # Update agent last_heartbeat and status (always primary DB)
        await self.db.execute(
            update(RemoteAgent)
            .where(RemoteAgent.id == agent_id)
            .values(
                last_heartbeat=now,
                last_seen=now,
                status=status,
            )
        )

        await ts_session.flush()
        await self.db.flush()
        return heartbeat

    async def get_heartbeats(
        self,
        agent_id: UUID,
        limit: int = 100,
        since: datetime | None = None,
        logdb_session: "AsyncSession | None" = None,
    ) -> list["AgentHeartbeat"]:
        """Get heartbeat history for an agent."""
        from app.models.agents import AgentHeartbeat

        if logdb_session is None:
            raise RuntimeError(
                "logdb_session is required for get_heartbeats. "
                "LogDB is mandatory for time-series data."
            )
        ts_session = logdb_session
        query = (
            select(AgentHeartbeat)
            .where(AgentHeartbeat.agent_id == agent_id)
            .order_by(AgentHeartbeat.timestamp.desc())
            .limit(limit)
        )
        if since:
            query = query.where(AgentHeartbeat.timestamp >= since)

        result = await ts_session.execute(query)
        return list(result.scalars().all())

    async def purge_old_heartbeats(
        self, days: int = 7, logdb_session: "AsyncSession | None" = None
    ) -> int:
        """Delete heartbeat records older than N days."""
        from datetime import timedelta

        from sqlalchemy import delete

        from app.models.agents import AgentHeartbeat

        if logdb_session is None:
            raise RuntimeError(
                "logdb_session is required for purge_old_heartbeats. "
                "LogDB is mandatory for time-series data."
            )
        ts_session = logdb_session
        cutoff = datetime.now(UTC) - timedelta(days=days)

        result = await ts_session.execute(
            delete(AgentHeartbeat).where(AgentHeartbeat.timestamp < cutoff)
        )
        await ts_session.flush()
        return result.rowcount or 0  # type: ignore[attr-defined]

    # -------------------------------------------------------------------------
    # Tasks
    # -------------------------------------------------------------------------

    async def create_task(
        self,
        agent_id: UUID,
        task_type: str,
        task_data: dict[str, Any] | None = None,
        priority: int = 5,
        scheduled_at: datetime | None = None,
        max_retries: int = 3,
    ) -> "AgentTask":
        """Create a task for an agent."""
        from app.models.agents import AgentTask

        task = AgentTask(
            agent_id=agent_id,
            task_type=task_type,
            task_data=task_data or {},
            priority=priority,
            scheduled_at=scheduled_at,
            max_retries=max_retries,
            status="pending",
        )
        self.db.add(task)
        await self.db.flush()
        await self.db.refresh(task)
        return task

    async def get_pending_tasks(
        self,
        agent_id: UUID,
    ) -> list["AgentTask"]:
        """Get pending tasks for an agent, ordered by priority."""
        from app.models.agents import AgentTask

        now = datetime.now(UTC)
        query = (
            select(AgentTask)
            .where(
                AgentTask.agent_id == agent_id,
                AgentTask.status == "pending",
            )
            .where((AgentTask.scheduled_at.is_(None)) | (AgentTask.scheduled_at <= now))
            .order_by(AgentTask.priority.asc(), AgentTask.created_at.asc())
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_task(
        self,
        task_id: UUID,
        **kwargs: Any,
    ) -> "AgentTask | None":
        """Update a task's status/progress/result."""
        from app.models.agents import AgentTask

        result = await self.db.execute(select(AgentTask).where(AgentTask.id == task_id))
        task = result.scalar_one_or_none()
        if not task:
            return None

        now = datetime.now(UTC)

        # refuse to mutate a task that has already reached a
        # terminal state. Without this guard, a key-holding agent could PATCH a
        # cancelled task back to running/completed (defeating an operator
        # cancel) or repeatedly PATCH status=failed to inflate
        # total_tasks_executed/failed_tasks. Mirrors the terminal_already guard
        # in _handle_report. A cancel of an already-terminal task becomes a
        # no-op, which is correct.
        if task.status in ("completed", "failed", "cancelled"):
            return task

        for key, value in kwargs.items():
            if hasattr(task, key) and value is not None:
                setattr(task, key, value)

        # Auto-set timestamps based on status transitions
        new_status = kwargs.get("status")
        if new_status == "running" and not task.started_at:
            task.started_at = now
        elif new_status in ("completed", "failed", "cancelled"):
            task.completed_at = now
            # Update agent stats
            agent = await self.get_agent(task.agent_id)
            if agent:
                agent.total_tasks_executed += 1
                if new_status == "failed":
                    agent.failed_tasks += 1

        await self.db.flush()
        await self.db.refresh(task)
        return task

    async def cancel_task(self, task_id: UUID) -> bool:
        """Cancel a pending/running task."""
        task = await self.update_task(task_id, status="cancelled")
        return task is not None

    async def get_agent_tasks(
        self,
        agent_id: UUID,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list["AgentTask"]:
        """Get tasks for an agent."""
        from app.models.agents import AgentTask

        query = (
            select(AgentTask)
            .where(AgentTask.agent_id == agent_id)
            .order_by(AgentTask.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status:
            query = query.where(AgentTask.status == status)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # -------------------------------------------------------------------------
    # Stale Agent Cleanup
    # -------------------------------------------------------------------------

    async def mark_stale_agents_offline(
        self,
        timeout_seconds: int = 120,
    ) -> int:
        """Mark agents as offline if no heartbeat within timeout."""
        from datetime import timedelta

        from app.models.agents import RemoteAgent

        cutoff = datetime.now(UTC) - timedelta(seconds=timeout_seconds)

        result = await self.db.execute(
            update(RemoteAgent)
            .where(
                RemoteAgent.status == "online",
                RemoteAgent.last_heartbeat < cutoff,
                RemoteAgent.deleted_at.is_(None),
            )
            .values(
                status="offline",
                disconnected_at=datetime.now(UTC),
            )
        )
        await self.db.flush()
        return result.rowcount or 0  # type: ignore[attr-defined]

    async def get_agents_for_site(
        self,
        site_id: UUID,
    ) -> list["RemoteAgent"]:
        """Get all agents assigned to a site."""
        from app.models.agents import RemoteAgent

        result = await self.db.execute(
            select(RemoteAgent).where(
                RemoteAgent.site_id == site_id,
                RemoteAgent.deleted_at.is_(None),
            )
        )
        return list(result.scalars().all())
