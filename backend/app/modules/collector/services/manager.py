# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Collector Manager
================================

Starts, stops, and reloads the SNMP/Syslog/NetFlow collector services
based on per-org configuration. Provides graceful degradation when a
port is already in use.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Source-IP → (organization_id, device_id) resolver
# ─────────────────────────────────────────────────────────────────────────────
# NOTE(C2): Per-packet DB lookups would tank ingest. Cache resolution
# with a 60s TTL. Misses are cached too (as None) so a flood of unknown
# sources can't hammer the DB.

_RESOLVER_TTL_SECONDS = 60.0


class SourceResolver:
    """Resolve a source IP to (organization_id, device_id) via Device.ip_address.

    Lookup chain: Device.ip_address == source_ip → Device.site → Site.organization_id.
    Caches both hits and misses for ``_RESOLVER_TTL_SECONDS``.
    """

    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory
        self._cache: dict[str, tuple[float, tuple[UUID, UUID] | None]] = {}

    async def resolve(self, source_ip: str) -> tuple[UUID, UUID] | None:
        now = time.monotonic()
        entry = self._cache.get(source_ip)
        if entry is not None:
            ts, value = entry
            if now - ts < _RESOLVER_TTL_SECONDS:
                return value
        value = await self._lookup(source_ip)
        self._cache[source_ip] = (now, value)
        # Cheap LRU-ish bound — drop oldest if cache balloons
        if len(self._cache) > 4096:
            for k in list(self._cache)[:1024]:
                self._cache.pop(k, None)
        return value

    async def _lookup(self, source_ip: str) -> tuple[UUID, UUID] | None:
        try:
            from app.models.devices import Device  # local import — avoid cycles
        except Exception:  # pragma: no cover — model import failure is fatal
            logger.warning("SourceResolver: Device model import failed", exc_info=True)
            return None
        try:
            async with self._session_factory() as db:
                result = await db.execute(
                    select(Device)
                    .where(
                        Device.ip_address == source_ip,
                        Device.deleted_at.is_(None),
                    )
                    .options(selectinload(Device.site))
                    .limit(1)
                )
                device = result.scalar_one_or_none()
                if device is None or device.site is None:
                    return None
                org_id = device.site.organization_id
                if org_id is None:
                    return None
                return (org_id, device.id)
        except Exception as exc:
            logger.debug("SourceResolver DB lookup failed for %s: %s", source_ip, exc)
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Allowlist helper
# ─────────────────────────────────────────────────────────────────────────────


def build_allowlist(cidrs: list[str] | None) -> list[ipaddress._BaseNetwork]:
    """Compile a list of CIDR strings into ``ip_network`` objects.

    Invalid entries are skipped with a warning. ``None`` and empty list
    both yield an empty allowlist (which means "block all" — secure
    default per C3).
    """
    nets: list[ipaddress._BaseNetwork] = []
    if not cidrs:
        return nets
    for raw in cidrs:
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except (ValueError, TypeError):
            logger.warning("Collector allowlist: ignoring invalid CIDR %r", raw)
    return nets


def ip_allowed(source_ip: str, allowlist: list[ipaddress._BaseNetwork]) -> bool:
    """Return True if ``source_ip`` falls inside any of the CIDRs."""
    if not allowlist:
        return False
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(ip in net for net in allowlist)


class CollectorManager:
    """
    Manages all collector UDP services (SNMP trap, Syslog, NetFlow).

    Services are started according to the CollectorConfig stored in the
    database.  The manager keeps track of running service instances so
    they can be stopped or reconfigured at runtime without a full restart.
    """

    # NOTE(C1): ``session_factory`` is now REQUIRED. Without it the
    # receivers cannot persist anything (this was the historical bug —
    # the module-level singleton was instantiated with None).
    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        if session_factory is None:
            raise ValueError("CollectorManager requires a session_factory")
        self._session_factory = session_factory
        self._resolver = SourceResolver(session_factory)
        self._snmp_receiver: Any | None = None
        self._syslog_receiver: Any | None = None
        self._netflow_receiver: Any | None = None
        self._running = False

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    async def start(self, config: Any) -> None:
        """
        Start enabled collector services according to *config*.

        If a service fails to bind (e.g. port already in use), a warning is
        logged and the remaining services continue to start.
        """
        self._running = True
        # NOTE(C3): compile the per-org CIDR allowlist once at start.
        # Empty list = block all (secure default).
        allowlist = build_allowlist(getattr(config, "allowed_source_ips", None))

        if config.snmp_enabled:
            await self._start_snmp(config.snmp_port, config.snmp_community, allowlist)

        if config.syslog_enabled:
            await self._start_syslog(config.syslog_port, allowlist)

        if config.netflow_enabled:
            await self._start_netflow(config.netflow_port, allowlist)

    async def stop(self) -> None:
        """Stop all running collector services."""
        self._running = False

        if self._snmp_receiver:
            try:
                await self._snmp_receiver.stop()
            except Exception as exc:
                logger.warning("Error stopping SNMP receiver: %s", exc)
            self._snmp_receiver = None

        if self._syslog_receiver:
            try:
                await self._syslog_receiver.stop()
            except Exception as exc:
                logger.warning("Error stopping syslog receiver: %s", exc)
            self._syslog_receiver = None

        if self._netflow_receiver:
            try:
                await self._netflow_receiver.stop()
            except Exception as exc:
                logger.warning("Error stopping NetFlow receiver: %s", exc)
            self._netflow_receiver = None

        logger.info("CollectorManager: all services stopped")

    async def reload_config(self, config: Any) -> None:
        """
        Apply new configuration without a full restart.

        Services that change port or enabled status are restarted;
        services whose config is unchanged are left running.
        """
        # Stop everything, then re-start with new config for simplicity.
        await self.stop()
        await self.start(config)

    def status(self) -> dict[str, Any]:
        """Return the running status of each collector service."""
        return {
            "snmp_trap": {
                "running": self._snmp_receiver is not None,
                "port": getattr(self._snmp_receiver, "port", None),
                "rejected": getattr(self._snmp_receiver, "_rejected_packets", 0),
            },
            "syslog": {
                "running": self._syslog_receiver is not None,
                "port": getattr(self._syslog_receiver, "port", None),
                "rejected": getattr(self._syslog_receiver, "_rejected_packets", 0),
            },
            "netflow": {
                "running": self._netflow_receiver is not None,
                "port": getattr(self._netflow_receiver, "port", None),
                "rejected": getattr(self._netflow_receiver, "_rejected_packets", 0),
                "dropped": getattr(self._netflow_receiver, "_dropped_packets", 0),
            },
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _start_snmp(
        self,
        port: int,
        community: str,
        allowlist: list[ipaddress._BaseNetwork],
    ) -> None:
        from app.modules.collector.services.snmp_trap import SNMPTrapReceiver

        receiver = SNMPTrapReceiver(
            port=port,
            session_factory=self._session_factory,
            resolver=self._resolver,
            allowlist=allowlist,
        )
        try:
            await receiver.start()
            self._snmp_receiver = receiver
            logger.info("SNMP trap receiver started on port %s/udp", port)
        except OSError as exc:
            logger.warning(
                f"Could not bind SNMP trap receiver on port {port}: {exc}. "
                "Service disabled — check port availability or run as root."
            )

    async def _start_syslog(
        self,
        port: int,
        allowlist: list[ipaddress._BaseNetwork],
    ) -> None:
        from app.modules.collector.services.syslog import SyslogReceiver

        receiver = SyslogReceiver(
            port=port,
            session_factory=self._session_factory,
            resolver=self._resolver,
            allowlist=allowlist,
        )
        try:
            await receiver.start()
            self._syslog_receiver = receiver
            logger.info("Syslog receiver started on port %s/udp", port)
        except OSError as exc:
            logger.warning(
                f"Could not bind syslog receiver on port {port}: {exc}. "
                "Service disabled — check port availability."
            )

    async def _start_netflow(
        self,
        port: int,
        allowlist: list[ipaddress._BaseNetwork],
    ) -> None:
        from app.modules.collector.services.netflow import NetFlowReceiver

        receiver = NetFlowReceiver(
            port=port,
            session_factory=self._session_factory,
            resolver=self._resolver,
            allowlist=allowlist,
        )
        try:
            await receiver.start()
            self._netflow_receiver = receiver
            logger.info("NetFlow receiver started on port %s/udp", port)
        except OSError as exc:
            logger.warning(
                f"Could not bind NetFlow receiver on port {port}: {exc}. "
                "Service disabled — check port availability."
            )


# NOTE(C1): The historical module-level singleton was constructed with
# session_factory=None which made every receiver's persistence path a
# no-op (``if self._session_factory:`` was always False). The singleton
# is now lazy: ``get_collector_manager()`` instantiates it on first use
# with the real ``AsyncSessionLocal`` factory.

_collector_manager: CollectorManager | None = None


def get_collector_manager() -> CollectorManager:
    """Return the process-wide collector manager, creating it if needed."""
    global _collector_manager
    if _collector_manager is None:
        from app.db.session import AsyncSessionLocal

        _collector_manager = CollectorManager(session_factory=AsyncSessionLocal)
    return _collector_manager


class _CollectorManagerProxy:
    """Thin proxy preserving the legacy ``collector_manager`` import path.

    Existing callers used ``from ... import collector_manager`` and then
    awaited ``collector_manager.start(config)`` etc.  Keeping that import
    site stable avoids touching the rest of the codebase while still
    enforcing the session_factory contract under the hood.
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(get_collector_manager(), name)


collector_manager = _CollectorManagerProxy()
