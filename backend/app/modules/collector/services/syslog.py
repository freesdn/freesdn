# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Syslog Receiver
================================

asyncio UDP server for syslog (RFC 3164 + RFC 5424).
Parses incoming messages, correlates to devices, and persists to DB.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _task_error_handler(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Background task failed: %s", exc, exc_info=exc)


# Syslog facility/severity tables
FACILITY_NAMES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}
SEVERITY_NAMES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

# RFC 3164 pattern
_RFC3164 = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)?\s*"
    r"(?P<hostname>\S+)?\s+"
    r"(?P<tag>[^:]+):\s*"
    r"(?P<message>.*)$"
)

# RFC 5424 pattern
_RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[.*?\])\s*"
    r"(?P<message>.*)$",
    re.DOTALL,
)


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        try:
            line = data.decode("utf-8", errors="replace").strip()
            asyncio.create_task(self._receiver._process(line, source_ip)).add_done_callback(
                _task_error_handler
            )
        except Exception as exc:
            logger.debug("Syslog datagram error from %s: %s", source_ip, exc)

    def error_received(self, exc: Exception) -> None:
        logger.warning("Syslog UDP error: %s", exc)


class SyslogReceiver:
    """asyncio UDP server for syslog (RFC 3164 + RFC 5424)."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 514,
        session_factory: Callable[[], AsyncSession] | None = None,
        resolver: Any = None,
        allowlist: list[ipaddress._BaseNetwork] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._session_factory = session_factory
        self._resolver = resolver
        self._allowlist = allowlist or []
        self._transport: asyncio.DatagramTransport | None = None
        # NOTE(C3): packets dropped by source-IP allowlist.
        self._rejected_packets: int = 0
        # NOTE(C2): rows dropped because source IP could not be mapped
        # to a known device → org.
        self._dropped_unknown_source: int = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self),
            local_addr=(self.host, self.port),
            # SO_REUSEPORT lets a config reload rebind the same port while the
            # previous socket is still closing (asyncio defers the close one loop
            # tick), avoiding an EADDRINUSE race. No-op where unsupported (Windows).
            reuse_port=hasattr(socket, "SO_REUSEPORT"),
        )
        self._transport = transport  # type: ignore[assignment]
        logger.info("Syslog receiver listening on %s:%s/udp", self.host, self.port)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    def _parse_rfc3164(self, line: str) -> dict | None:
        m = _RFC3164.match(line)
        if not m:
            return None
        pri = int(m.group("pri"))
        facility = pri >> 3
        severity = pri & 0x07
        return {
            "source_type": "syslog",
            "facility": FACILITY_NAMES.get(facility, str(facility)),
            "severity": SEVERITY_NAMES.get(severity, str(severity)),
            "hostname": m.group("hostname") or "",
            "app_name": (m.group("tag") or "").strip(),
            "message": m.group("message"),
        }

    def _parse_rfc5424(self, line: str) -> dict | None:
        m = _RFC5424.match(line)
        if not m:
            return None
        pri = int(m.group("pri"))
        facility = pri >> 3
        severity = pri & 0x07
        return {
            "source_type": "syslog",
            "facility": FACILITY_NAMES.get(facility, str(facility)),
            "severity": SEVERITY_NAMES.get(severity, str(severity)),
            "hostname": m.group("hostname") if m.group("hostname") != "-" else "",
            "app_name": m.group("appname") if m.group("appname") != "-" else "",
            "message": m.group("message"),
        }

    async def _process(self, line: str, source_ip: str) -> None:
        # NOTE(C3): allowlist enforced BEFORE regex parsing.
        from app.modules.collector.services.manager import ip_allowed

        if not ip_allowed(source_ip, self._allowlist):
            self._rejected_packets += 1
            logger.info(
                "collector.syslog.rejected source_ip=%s reason=allowlist",
                source_ip,
            )
            return

        parsed = self._parse_rfc5424(line) or self._parse_rfc3164(line)
        if not parsed:
            parsed = {
                "source_type": "syslog",
                "facility": None,
                "severity": None,
                "hostname": None,
                "app_name": None,
                "message": line,
            }

        parsed["source_ip"] = source_ip
        parsed["timestamp"] = datetime.now(UTC)
        parsed["raw_data"] = line[:2000] if len(line) > 2000 else line

        # NOTE(C2): tag with organization_id + device_id from the
        # source-IP resolver; drop if unknown to avoid a global bucket
        # of un-tenanted rows.
        if self._resolver is not None:
            resolved = await self._resolver.resolve(source_ip)
            if resolved is None:
                self._dropped_unknown_source += 1
                logger.info(
                    "collector.syslog.dropped source_ip=%s reason=unknown_source",
                    source_ip,
                )
                return
            parsed["organization_id"], parsed["device_id"] = resolved

        # NOTE(C1): session_factory was historically None on the
        # singleton, making this branch dead code.
        if self._session_factory is not None:
            try:
                from app.modules.collector.models import CollectorLog

                async with self._session_factory() as db:
                    db.add(CollectorLog(**parsed))
                    await db.commit()
            except Exception as exc:
                logger.warning("Failed to persist syslog: %s", exc)
