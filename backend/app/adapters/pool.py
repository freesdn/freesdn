# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter Connection Pool
=====================================

Connection pool for adapter instances with:
- Reuse of authenticated connections
- Automatic cleanup of idle connections
- Connection health checking
- Per-controller connection limits
"""

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.adapters.base import BaseAdapter
from app.adapters.registry import adapter_registry

logger = logging.getLogger(__name__)


@dataclass
class PooledConnection:
    """
    A pooled adapter connection.

    Tracks usage statistics and health for pool management.
    """

    adapter: BaseAdapter
    adapter_id: str
    controller_id: str
    host: str

    # Connection state
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    use_count: int = 0
    is_healthy: bool = True

    # Acquire state
    is_acquired: bool = False
    acquired_at: datetime | None = None

    @property
    def idle_time_seconds(self) -> float:
        """Time since last use in seconds."""
        return (datetime.now(UTC) - self.last_used_at).total_seconds()

    @property
    def age_seconds(self) -> float:
        """Connection age in seconds."""
        return (datetime.now(UTC) - self.created_at).total_seconds()

    def mark_used(self) -> None:
        """Mark connection as used."""
        self.last_used_at = datetime.now(UTC)
        self.use_count += 1

    def acquire(self) -> None:
        """Acquire the connection for use."""
        self.is_acquired = True
        self.acquired_at = datetime.now(UTC)
        self.mark_used()

    def release(self) -> None:
        """Release the connection back to pool."""
        self.is_acquired = False
        self.acquired_at = None


@dataclass
class PoolStats:
    """Pool statistics."""

    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    connections_per_controller: dict[str, int] = field(default_factory=dict)
    total_acquisitions: int = 0
    total_releases: int = 0
    total_creates: int = 0
    total_destroys: int = 0
    avg_connection_age_seconds: float = 0.0
    avg_idle_time_seconds: float = 0.0


class AdapterConnectionPool:
    """
    Pool of adapter connections for efficient reuse.

    Features:
    - Connection reuse to avoid repeated authentication
    - Automatic cleanup of idle connections
    - Health checking before connection reuse
    - Per-controller connection limits
    - Async context manager support

    Usage:
        pool = AdapterConnectionPool()

        async with pool.acquire("omada", controller_id, host, user, pwd) as adapter:
            devices = await adapter.discover_devices()
    """

    def __init__(
        self,
        max_connections_per_controller: int = 5,
        max_idle_time_seconds: int = 300,
        max_connection_age_seconds: int = 3600,
        health_check_interval_seconds: int = 60,
        cleanup_interval_seconds: int = 30,
    ):
        """
        Initialize the connection pool.

        Args:
            max_connections_per_controller: Max connections per controller
            max_idle_time_seconds: Close connections idle longer than this
            max_connection_age_seconds: Close connections older than this
            health_check_interval_seconds: Interval for health checks
            cleanup_interval_seconds: Interval for cleanup task
        """
        self.max_per_controller = max_connections_per_controller
        self.max_idle_seconds = max_idle_time_seconds
        self.max_age_seconds = max_connection_age_seconds
        self.health_check_interval = health_check_interval_seconds
        self.cleanup_interval = cleanup_interval_seconds

        # Connection storage by controller_id
        self._connections: dict[str, list[PooledConnection]] = {}
        self._lock = asyncio.Lock()

        # Statistics
        self._stats = PoolStats()

        # Background tasks
        self._cleanup_task: asyncio.Task[Any] | None = None
        self._running = False

    async def start(self) -> None:
        """Start the connection pool background tasks."""
        if self._running:
            return

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Adapter connection pool started")

    async def stop(self) -> None:
        """Stop the connection pool and close all connections."""
        self._running = False

        if self._cleanup_task:
            self._cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._cleanup_task

        # Close all connections
        await self._close_all_connections()
        logger.info("Adapter connection pool stopped")

    async def _cleanup_loop(self) -> None:
        """Background task to clean up idle/old connections."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in cleanup loop: %s", e)

    async def _cleanup_connections(self) -> None:
        """Remove idle and old connections."""
        async with self._lock:
            datetime.now(UTC)

            for controller_id, connections in list(self._connections.items()):
                # Find connections to remove
                to_remove = []

                for conn in connections:
                    # Skip acquired connections
                    if conn.is_acquired:
                        continue

                    # Check idle time
                    if conn.idle_time_seconds > self.max_idle_seconds:
                        to_remove.append(conn)
                        continue

                    # Check age
                    if conn.age_seconds > self.max_age_seconds:
                        to_remove.append(conn)
                        continue

                # Remove connections
                for conn in to_remove:
                    await self._destroy_connection(conn)
                    connections.remove(conn)

                # Clean up empty controller entries
                if not connections:
                    del self._connections[controller_id]

    async def _close_all_connections(self) -> None:
        """Close all connections in the pool."""
        async with self._lock:
            for _controller_id, connections in self._connections.items():
                for conn in connections:
                    await self._destroy_connection(conn)

            self._connections.clear()

    async def _destroy_connection(self, conn: PooledConnection) -> None:
        """Destroy a single connection.

        Critical: must clear ``_pool_managed`` BEFORE calling
        ``disconnect()``. Pool-managed adapters (UniFi today; future
        vendors as they adopt the pattern) short-circuit ``disconnect``
        as a no-op so endpoint-level ``finally: await
        adapter.disconnect()`` clauses don't tear down the shared
        session mid-use. The cleanup loop's destroy path is the one
        place where we DO want the real close — without flipping the
        flag first, the underlying ``httpx.AsyncClient`` (and the
        UniFi OS Identity TOKEN cookie) leaks on every eviction.

        Root cause of the UniFi OS Identity rate-limit cascade — every evicted
        adapter that was never re-used left a live httpx session in
        the controller's session table, multiplying until login
        429'd.
        """
        try:
            # Flip pool-managed off so the adapter's disconnect()
            # actually runs its close path. The flag was a workaround
            # for endpoint-level disconnect-on-every-request; in the
            # cleanup-loop context that workaround would leak.
            try:
                conn.adapter._pool_managed = False  # noqa: SLF001
            except Exception:
                pass
            if hasattr(conn.adapter, "disconnect"):
                await conn.adapter.disconnect()
            elif hasattr(conn.adapter, "close"):
                await conn.adapter.close()
        except Exception as e:
            logger.warning("Error closing connection: %s", e)

        self._stats.total_destroys += 1
        logger.debug("Destroyed connection to %s", conn.host)

    async def _create_connection(
        self,
        adapter_id: str,
        controller_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> PooledConnection:
        """Create a new pooled connection."""
        adapter = adapter_registry.create_adapter(adapter_id, host, username, password, **kwargs)

        # Connect. Credentials were already passed to create_adapter
        # above (which calls __init__); the BaseAdapter.connect()
        # contract is a zero-arg method on the constructed instance.
        # Passing kwargs here would TypeError on every adapter — verified
        # via integration test against real MikroTik CHR 7.21.3.
        if hasattr(adapter, "connect"):
            await adapter.connect()

        conn = PooledConnection(
            adapter=adapter,
            adapter_id=adapter_id,
            controller_id=controller_id,
            host=host,
        )

        self._stats.total_creates += 1
        logger.debug("Created new connection to %s", host)

        return conn

    async def _check_health(self, conn: PooledConnection) -> bool:
        """Check if a connection is healthy."""
        try:
            if hasattr(conn.adapter, "ping"):
                return await conn.adapter.ping()
            elif hasattr(conn.adapter, "is_connected"):
                return conn.adapter.is_connected
            return True
        except (ConnectionError, TimeoutError, OSError):
            return False

    @asynccontextmanager
    async def acquire(
        self,
        adapter_id: str,
        controller_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> AsyncGenerator[BaseAdapter]:
        """
        Acquire a connection from the pool.

        Args:
            adapter_id: Adapter type identifier
            controller_id: Controller unique ID
            host: Controller host address
            username: Authentication username
            password: Authentication password
            **kwargs: Additional adapter configuration

        Yields:
            Connected adapter instance
        """
        conn = await self._acquire_connection(
            adapter_id, controller_id, host, username, password, **kwargs
        )

        try:
            yield conn.adapter
        finally:
            await self._release_connection(conn)

    async def _acquire_connection(
        self,
        adapter_id: str,
        controller_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> PooledConnection:
        """
        Acquire a connection, creating if necessary.
        """
        async with self._lock:
            connections = self._connections.get(controller_id, [])

            # Try to find an available connection
            for conn in connections:
                if not conn.is_acquired and conn.is_healthy:
                    # Health check before reuse
                    if await self._check_health(conn):
                        conn.acquire()
                        self._stats.total_acquisitions += 1
                        logger.debug("Reusing connection to %s", host)
                        return conn
                    else:
                        conn.is_healthy = False

            # Check if we can create a new connection
            active_count = sum(1 for c in connections if c.is_acquired)
            if active_count >= self.max_per_controller:
                raise RuntimeError(
                    f"Maximum connections ({self.max_per_controller}) "
                    f"reached for controller {controller_id}"
                )

            # Create new connection
            conn = await self._create_connection(
                adapter_id, controller_id, host, username, password, **kwargs
            )
            conn.acquire()

            # Add to pool
            if controller_id not in self._connections:
                self._connections[controller_id] = []
            self._connections[controller_id].append(conn)

            self._stats.total_acquisitions += 1
            self._stats.connections_per_controller[controller_id] = len(
                self._connections[controller_id]
            )

            return conn

    async def _release_connection(self, conn: PooledConnection) -> None:
        """Release a connection back to the pool."""
        async with self._lock:
            conn.release()
            self._stats.total_releases += 1
            logger.debug("Released connection to %s", conn.host)

    def get_stats(self) -> PoolStats:
        """Get pool statistics."""
        stats = PoolStats(
            total_connections=sum(len(c) for c in self._connections.values()),
            active_connections=sum(
                1 for conns in self._connections.values() for c in conns if c.is_acquired
            ),
            connections_per_controller=self._stats.connections_per_controller.copy(),
            total_acquisitions=self._stats.total_acquisitions,
            total_releases=self._stats.total_releases,
            total_creates=self._stats.total_creates,
            total_destroys=self._stats.total_destroys,
        )

        stats.idle_connections = stats.total_connections - stats.active_connections

        # Calculate averages
        all_connections = [c for conns in self._connections.values() for c in conns]
        if all_connections:
            stats.avg_connection_age_seconds = sum(c.age_seconds for c in all_connections) / len(
                all_connections
            )

            idle_connections = [c for c in all_connections if not c.is_acquired]
            if idle_connections:
                stats.avg_idle_time_seconds = sum(
                    c.idle_time_seconds for c in idle_connections
                ) / len(idle_connections)

        return stats

    async def close_controller_connections(self, controller_id: str) -> int:
        """
        Close all connections for a specific controller.

        Useful when a controller is deleted or credentials change.

        Returns:
            Number of connections closed
        """
        async with self._lock:
            connections = self._connections.pop(controller_id, [])

            for conn in connections:
                await self._destroy_connection(conn)

            return len(connections)

    # ─── Shared-singleton lookup (single-conn-per-controller reuse) ─────
    #
    # The acquire/release context manager assumes each request takes the
    # connection out of the pool while it works. For gateway-feature
    # services the dominant access pattern is "single short-lived REST
    # call per request" against the same controller from many concurrent
    # endpoints — turning that into a one-connection-per-request lease
    # serialises the controller's worth of dashboard polling behind a
    # single TCP socket and triples the latency.
    #
    # ``get_or_create_shared`` returns the same adapter to every caller
    # for the same ``(controller_id, vendor)`` tuple. Reused as a shared
    # client (the underlying ``httpx.AsyncClient`` is async-safe by
    # design and connection-pools internally). TTL/age eviction still
    # applies; the cleanup loop will close idle shared connections.
    async def get_or_create_shared(
        self,
        adapter_id: str,
        controller_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> BaseAdapter:
        """Return a reusable adapter for a ``(controller_id, vendor)`` pair.

        Unlike :meth:`_acquire_connection`, this does NOT mark the
        connection ``is_acquired`` — multiple callers can share the same
        instance simultaneously. The adapter must be implemented such
        that concurrent calls against it are safe (true for every adapter
        in FreeSDN today; httpx.AsyncClient is the underlying transport).

        NOT for stateful multi-socket adapters: the FreePBX adapter holds a
        persistent AMI TCP socket with a single demux read-loop plus an OAuth2
        session, so sharing one instance across concurrent callers would
        interleave AMI responses by ActionID and race token refresh. FreePBX
        therefore uses :meth:`adopt` (per-call instance, pooled only for
        teardown), never ``get_or_create_shared``. Reserve this method for
        stateless ``httpx.AsyncClient``-backed adapters (Omada, OPNsense,
        pfSense, MikroTik, UniFi).

        Eviction: cleanup loop closes connections idle > ``max_idle_seconds``
        (default 300s) and older than ``max_age_seconds`` (default 3600s).
        """
        async with self._lock:
            connections = self._connections.get(controller_id, [])
            # Reuse first connection that matches our adapter type.
            for conn in connections:
                if conn.adapter_id == adapter_id and conn.is_healthy:
                    conn.mark_used()
                    self._stats.total_acquisitions += 1
                    logger.debug(
                        "Reusing shared connection to %s (use_count=%d)",
                        host,
                        conn.use_count,
                    )
                    # Mark the adapter as pool-managed so endpoint-level
                    # ``finally: await adapter.disconnect()`` clauses
                    # don't tear down the shared session. Without this,
                    # every ``async with adapter`` exit ran a disconnect that
                    # invalidated the pooled TOKEN cookie — defeating
                    # the pool and re-triggering the login rate-limit
                    # cascade. The cleanup loop still evicts via
                    # ``_destroy_connection`` which calls the real
                    # disconnect path.
                    try:
                        conn.adapter._pool_managed = True  # noqa: SLF001
                    except Exception:
                        pass
                    return conn.adapter

            # Cap: respect the per-controller limit even for shared
            # connections — though for shared mode this is effectively
            # a "max distinct adapter types" cap, not a concurrency cap.
            if len(connections) >= self.max_per_controller:
                # Should never happen in practice (a controller has one
                # vendor type), but defend against pool runaway.
                logger.warning(
                    "Controller %s already has %d pooled connections; refusing to add another",
                    controller_id,
                    len(connections),
                )
                # Fall through to creating a fresh, untracked adapter so
                # the request still succeeds.
                fresh = adapter_registry.create_adapter(
                    adapter_id, host, username, password, **kwargs
                )
                if hasattr(fresh, "connect"):
                    await fresh.connect(host=host, username=username, password=password, **kwargs)
                return fresh

            # Create + register.
            conn = await self._create_connection(
                adapter_id, controller_id, host, username, password, **kwargs
            )
            # Mark pool-managed on first creation too (see comment above).
            try:
                conn.adapter._pool_managed = True  # noqa: SLF001
            except Exception:
                pass
            if controller_id not in self._connections:
                self._connections[controller_id] = []
            self._connections[controller_id].append(conn)
            self._stats.total_acquisitions += 1
            self._stats.connections_per_controller[controller_id] = len(
                self._connections[controller_id]
            )
            return conn.adapter

    async def adopt(
        self,
        adapter: BaseAdapter,
        adapter_id: str,
        controller_id: str,
        host: str,
    ) -> BaseAdapter:
        """Register an already-connected adapter into the pool so the cleanup
        loop owns its teardown.

        Used by the ``_get_client`` / ``_get_adapter`` fallback path in
        adapter_base: when ``get_or_create_shared`` itself raises, the caller
        builds a fresh adapter and connects it — previously that adapter was
        returned un-pooled and un-managed, so nothing ever closed its httpx
        session / TOKEN cookie (per-request leak under a pool outage, audit-2
        #11). Adopting it makes the cleanup loop evict + truly disconnect it
        like any pooled connection. If the controller is already at its cap we
        leave the adapter un-pooled (caller still uses it) rather than exceed it.
        """
        async with self._lock:
            existing = self._connections.get(controller_id, [])
            if len(existing) >= self.max_per_controller:
                return adapter  # at cap — don't over-pool; caller still uses it
            try:
                adapter._pool_managed = True  # noqa: SLF001 — cleanup owns teardown
            except Exception:
                pass
            conn = PooledConnection(
                adapter=adapter,
                adapter_id=adapter_id,
                controller_id=controller_id,
                host=host,
            )
            if controller_id not in self._connections:
                self._connections[controller_id] = []
            self._connections[controller_id].append(conn)
            self._stats.connections_per_controller[controller_id] = len(
                self._connections[controller_id]
            )
            logger.debug("Adopted fallback adapter into pool for %s", host)
            return adapter

    def invalidate_controller(self, controller_id: str) -> int:
        """Synchronous evict hook for controller delete / credential rotation.

        Marks every pooled connection for the controller as unhealthy and
        schedules a destroy. The cleanup loop reaps them on its next pass
        (≤ ``cleanup_interval`` seconds, default 30s). Synchronous so the
        controllers endpoint can call it from non-async sites or hooks.
        """
        connections = self._connections.get(controller_id, [])
        count = 0
        for conn in connections:
            if conn.is_healthy:
                conn.is_healthy = False
                count += 1
        return count


# Global connection pool instance
adapter_pool = AdapterConnectionPool()
