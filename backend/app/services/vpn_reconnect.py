# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Reconnect Service
==========================================

Auto-reconnect logic with exponential backoff.
Called by Celery task ``vpn.auto_reconnect`` every 1 minute.
"""

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vpn import (
    SiteVPNConfiguration,
    VPNConnectionRecord,
    VPNReconnectState,
    VPNReconnectStatus,
    VPNStatus,
)

logger = logging.getLogger(__name__)


class VPNReconnectService:
    """
    State machine for auto-reconnecting failed VPN connections.

    Backoff schedule: 30s → 60s → 120s → 240s → 480s → 960s → 1920s → 3600s (cap)
    After MAX_ATTEMPTS failures → state='exhausted', CRITICAL alert.
    """

    INITIAL_BACKOFF = 30
    MAX_BACKOFF = 3600
    MAX_ATTEMPTS = 10
    BACKOFF_MULTIPLIER = 2
    # Defensive: validate names/interfaces before passing to subprocess
    _SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9][\w\-]{0,62}$")

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def check_and_reconnect(self) -> dict[str, Any]:
        """
        Main loop: find connections needing reconnect, attempt each.
        Returns summary dict with counts.
        """
        now = datetime.now(UTC)
        attempted = 0
        succeeded = 0
        failed = 0
        exhausted_count = 0

        # Find connections in ERROR/DISCONNECTED with auto_connect site configs
        conns = await self._get_reconnectable_connections()

        # Pre-fetch all reconnect states in bulk (avoid N+1)
        conn_ids = [c.id for c, _ in conns]
        states_by_conn: dict[UUID, VPNReconnectState] = {}
        if conn_ids:
            state_result = await self._session.execute(
                select(VPNReconnectState).where(VPNReconnectState.connection_id.in_(conn_ids))
            )
            for s in state_result.scalars().all():
                states_by_conn[s.connection_id] = s

        for conn, site_config in conns:
            state = states_by_conn.get(conn.id)
            if not state:
                state = await self._get_or_create_state(conn.id, site_config)
                states_by_conn[conn.id] = state

            # Skip exhausted connections
            if state.state == VPNReconnectStatus.EXHAUSTED:
                continue

            # Skip if not due yet
            if state.next_retry_at and state.next_retry_at > now:
                continue

            attempted += 1

            # Fire alert service event
            alert_svc = await self._get_alert_service()
            if alert_svc:
                await alert_svc.on_reconnect_started(
                    conn,
                    state.attempt_count + 1,
                    state.max_attempts,
                )

            # Attempt reconnect
            success, error = await self._attempt_reconnect(conn)

            if success:
                succeeded += 1
                actual_attempts = state.attempt_count + 1
                state.state = VPNReconnectStatus.SUCCESS
                state.attempt_count = 0
                state.backoff_seconds = self.INITIAL_BACKOFF
                state.next_retry_at = None
                state.last_error = None
                conn.status = VPNStatus.CONNECTED
                conn.connected_at = now

                if alert_svc:
                    await alert_svc.on_reconnect_success(conn, actual_attempts)
            else:
                failed += 1
                state.attempt_count += 1
                state.last_error = (error or "Unknown error")[:1000]
                state.state = VPNReconnectStatus.RETRYING

                # Calculate next backoff
                new_backoff = min(
                    state.backoff_seconds * self.BACKOFF_MULTIPLIER,
                    self.MAX_BACKOFF,
                )
                state.backoff_seconds = new_backoff
                state.next_retry_at = now + timedelta(seconds=new_backoff)

                # Check if exhausted — try failover before giving up
                if state.attempt_count >= state.max_attempts:
                    # Attempt provider failover before marking exhausted
                    failover = await self.try_failover(conn, state)
                    if failover.get("success"):
                        state.state = VPNReconnectStatus.SUCCESS
                        state.attempt_count = 0
                        state.backoff_seconds = self.INITIAL_BACKOFF
                        state.next_retry_at = None
                        state.last_error = None
                        succeeded += 1
                        failed -= 1  # undo the failed count
                    else:
                        state.state = VPNReconnectStatus.EXHAUSTED
                        state.next_retry_at = None
                        exhausted_count += 1

                        if alert_svc:
                            await alert_svc.on_reconnect_exhausted(conn, state.attempt_count)

            state.updated_at = now
            await self._session.flush()

        return {
            "attempted": attempted,
            "succeeded": succeeded,
            "failed": failed,
            "exhausted": exhausted_count,
            "timestamp": now.isoformat(),
        }

    async def reset_reconnect_state(self, connection_id: UUID) -> bool:
        """
        Reset an exhausted reconnect state for manual retry.
        Returns True if state was found and reset.
        """
        result = await self._session.execute(
            select(VPNReconnectState)
            .where(
                VPNReconnectState.connection_id == connection_id,
            )
            .with_for_update()
        )
        state = result.scalar_one_or_none()
        if not state:
            return False

        state.state = VPNReconnectStatus.IDLE
        state.attempt_count = 0
        state.backoff_seconds = self.INITIAL_BACKOFF
        state.next_retry_at = datetime.now(UTC) + timedelta(seconds=5)
        state.last_error = None
        state.updated_at = datetime.now(UTC)
        await self._session.flush()
        return True

    async def get_reconnect_status(self, connection_id: UUID) -> dict[str, Any] | None:
        """Return current reconnect state for a connection."""
        result = await self._session.execute(
            select(VPNReconnectState).where(
                VPNReconnectState.connection_id == connection_id,
            )
        )
        state = result.scalar_one_or_none()
        if not state:
            return None

        return {
            "connection_id": str(state.connection_id),
            "attempt_count": state.attempt_count,
            "max_attempts": state.max_attempts,
            "next_retry_at": state.next_retry_at.isoformat() if state.next_retry_at else None,
            "backoff_seconds": state.backoff_seconds,
            "state": state.state,
            "last_error": state.last_error,
        }

    # ── internal helpers ─────────────────────────────────────────────────

    async def try_failover(
        self,
        connection: VPNConnectionRecord,
        state: VPNReconnectState | None = None,
    ) -> dict[str, Any]:
        """
        Provider failover chain.
        When a primary VPN connection exhausts all reconnect attempts,
        check if the site has alternative VPN configs and try them in priority order.
        Returns {failover_attempted: bool, success: bool, failover_provider: str|None}
        """
        # Scope to the specific site via the reconnect state's config reference
        site_id = None
        if state and state.site_vpn_config_id:
            ref_config = (
                await self._session.execute(
                    select(SiteVPNConfiguration.site_id).where(
                        SiteVPNConfiguration.id == state.site_vpn_config_id,
                    )
                )
            ).scalar_one_or_none()
            site_id = ref_config

        configs_q = (
            select(SiteVPNConfiguration)
            .where(
                SiteVPNConfiguration.enabled.is_(True),
                SiteVPNConfiguration.organization_id == connection.organization_id,
            )
            .order_by(SiteVPNConfiguration.priority.desc())
        )
        # Filter to same site if known; otherwise fall back to org-wide
        if site_id:
            configs_q = configs_q.where(SiteVPNConfiguration.site_id == site_id)

        configs_result = await self._session.execute(configs_q)
        configs = list(configs_result.scalars().all())

        if len(configs) <= 1:
            return {
                "failover_attempted": False,
                "success": False,
                "failover_provider": None,
                "reason": "No alternative VPN configs available",
            }

        for config in configs:
            # Skip the current provider type that already failed
            if config.vpn_type == connection.vpn_type and config.is_primary:
                continue

            logger.info(
                "Attempting failover to %s (priority=%d) for connection %s",
                config.vpn_type,
                config.priority,
                connection.name,
            )

            success, error = await self._attempt_reconnect_with_config(connection, config)
            if success:
                # Update connection to reflect the new provider
                connection.status = VPNStatus.CONNECTED
                connection.connected_at = datetime.now(UTC)
                await self._session.flush()

                alert_svc = await self._get_alert_service()
                if alert_svc:
                    await alert_svc.on_reconnect_success(connection, 0)

                return {
                    "failover_attempted": True,
                    "success": True,
                    "failover_provider": config.vpn_type,
                }

        return {
            "failover_attempted": True,
            "success": False,
            "failover_provider": None,
            "reason": "All alternative providers failed",
        }

    @staticmethod
    async def _run_cmd(*args: str, timeout: float = 30.0) -> tuple[int, str]:
        """Run a VPN helper, ALWAYS killing+reaping the child on timeout/error.

        asyncio.wait_for only cancels the communicate() coroutine — it does NOT
        terminate the spawned OS process, so a hung wg-quick/systemctl/tailscale/
        netbird left an orphan process + 2 leaked pipe FDs every time.
        Returns (returncode, stderr_text); returncode == -1 on timeout.
        """
        import contextlib

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, (stderr or b"").decode(errors="replace")[:500]
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()  # reap zombie + close pipe transports
            return -1, "command timed out"

    async def _attempt_reconnect_with_config(
        self,
        connection: VPNConnectionRecord,
        config: SiteVPNConfiguration,
    ) -> tuple[bool, str | None]:
        """Attempt reconnect using a specific site VPN config."""
        try:
            from app.services.vpn_integration import get_vpn_manager

            get_vpn_manager()
            vpn_type = config.vpn_type

            if vpn_type == "wireguard" and config.wireguard_interface:
                if not self._SAFE_NAME_RE.match(config.wireguard_interface):
                    return (
                        False,
                        f"Invalid WireGuard interface name: {config.wireguard_interface[:64]}",
                    )
                rc, err = await self._run_cmd(
                    "wg-quick", "up", config.wireguard_interface, timeout=30
                )
                return rc == 0, (None if rc == 0 else err)

            elif vpn_type == "tailscale":
                rc, err = await self._run_cmd("tailscale", "up", timeout=30)
                return rc == 0, (None if rc == 0 else err)

            elif vpn_type == "openvpn" and config.openvpn_config_path:
                name = config.openvpn_config_path.rsplit("/", 1)[-1].replace(".conf", "")
                if not self._SAFE_NAME_RE.match(name):
                    return False, f"Invalid OpenVPN config name derived from path: {name[:64]}"
                rc, err = await self._run_cmd(
                    "systemctl", "start", f"openvpn-client@{name}", timeout=30
                )
                return rc == 0, (None if rc == 0 else err)

            elif vpn_type == "netbird":
                rc, err = await self._run_cmd("netbird", "up", timeout=30)
                return rc == 0, (None if rc == 0 else err)

            return False, f"No failover strategy for {vpn_type}"

        except Exception as exc:
            logger.warning("Failover attempt failed: %s", exc)
            return False, str(exc)[:500]

    async def _get_reconnectable_connections(
        self,
    ) -> list[tuple[VPNConnectionRecord, SiteVPNConfiguration | None]]:
        """Find connections that should be auto-reconnected (org-scoped)."""
        # Get error/disconnected connections — must have an org_id for tenant isolation
        conn_q = select(VPNConnectionRecord).where(
            VPNConnectionRecord.status.in_(
                [
                    VPNStatus.ERROR,
                    VPNStatus.DISCONNECTED,
                ]
            ),
            VPNConnectionRecord.organization_id.isnot(None),
        )
        conn_result = await self._session.execute(conn_q)
        connections = list(conn_result.scalars().all())

        if not connections:
            return []

        # Pre-load all auto_connect site configs grouped by org to avoid N+1
        org_ids = {c.organization_id for c in connections}
        config_q = select(SiteVPNConfiguration).where(
            and_(
                SiteVPNConfiguration.auto_connect.is_(True),
                SiteVPNConfiguration.enabled.is_(True),
                SiteVPNConfiguration.organization_id.in_(org_ids),
            )
        )
        config_result = await self._session.execute(config_q)
        all_configs = list(config_result.scalars().all())
        # Map org_id → first matching config
        configs_by_org: dict[UUID, SiteVPNConfiguration] = {}
        for cfg in all_configs:
            if cfg.organization_id and cfg.organization_id not in configs_by_org:
                configs_by_org[cfg.organization_id] = cfg

        results: list[tuple[VPNConnectionRecord, SiteVPNConfiguration | None]] = []
        for conn in connections:
            site_config = configs_by_org.get(conn.organization_id)
            # Include connection even without site config if it was previously connected
            if site_config or conn.connected_at is not None:
                results.append((conn, site_config))

        return results

    async def _get_or_create_state(
        self,
        connection_id: UUID,
        site_config: SiteVPNConfiguration | None,
    ) -> VPNReconnectState:
        result = await self._session.execute(
            select(VPNReconnectState).where(
                VPNReconnectState.connection_id == connection_id,
            )
        )
        state = result.scalar_one_or_none()
        if state:
            return state

        now = datetime.now(UTC)
        state = VPNReconnectState(
            connection_id=connection_id,
            site_vpn_config_id=site_config.id if site_config else None,
            attempt_count=0,
            max_attempts=self.MAX_ATTEMPTS,
            backoff_seconds=self.INITIAL_BACKOFF,
            next_retry_at=now,
            state=VPNReconnectStatus.IDLE,
            created_at=now,
            updated_at=now,
        )
        self._session.add(state)
        try:
            await self._session.flush()
        except Exception:
            # TOCTOU race — another worker may have inserted; re-fetch
            await self._session.rollback()
            result = await self._session.execute(
                select(VPNReconnectState).where(
                    VPNReconnectState.connection_id == connection_id,
                )
            )
            state = result.scalar_one_or_none()
            if not state:
                raise  # Genuine error, not a race
        return state

    async def _attempt_reconnect(
        self,
        connection: VPNConnectionRecord,
    ) -> tuple[bool, str | None]:
        """
        Provider-specific reconnect logic.
        Returns (success, error_message).
        """
        try:
            from app.services.vpn_integration import get_vpn_manager

            vpn_type = connection.vpn_type
            manager = get_vpn_manager()

            if vpn_type == "wireguard":
                iface = connection.name
                if not self._SAFE_NAME_RE.match(iface):
                    return False, f"Invalid WireGuard interface name: {iface[:64]}"
                wg = manager.wireguard
                health = await wg.check_tunnel_health(iface)
                if health.get("healthy"):
                    return True, None
                # Try to bring interface up
                rc, err = await self._run_cmd("wg-quick", "up", iface, timeout=30)
                return (True, None) if rc == 0 else (False, err)

            elif vpn_type == "tailscale":
                ts = manager.tailscale
                status = await ts.get_status(refresh=True)
                if status and getattr(status, "is_connected", False):
                    return True, None
                rc, err = await self._run_cmd(
                    "tailscale",
                    "up",
                    timeout=30,
                )
                return (True, None) if rc == 0 else (False, err)

            elif vpn_type == "openvpn":
                conn_name = connection.name
                if not self._SAFE_NAME_RE.match(conn_name):
                    return False, f"Invalid OpenVPN connection name: {conn_name[:64]}"
                rc, err = await self._run_cmd(
                    "systemctl",
                    "start",
                    f"openvpn-client@{conn_name}",
                    timeout=30,
                )
                return (True, None) if rc == 0 else (False, err)

            elif vpn_type == "netbird":
                rc, err = await self._run_cmd(
                    "netbird",
                    "up",
                    timeout=30,
                )
                return (True, None) if rc == 0 else (False, err)

            else:
                return False, f"Unsupported VPN type for auto-reconnect: {vpn_type}"

        except TimeoutError:
            return False, "Reconnect attempt timed out (30s)"
        except Exception as exc:
            logger.warning("Reconnect attempt failed for %s: %s", connection.name, exc)
            return False, str(exc)[:500]

    async def _get_alert_service(self) -> Any:
        try:
            from app.services.vpn_alerts import VPNAlertService

            return VPNAlertService(self._session)
        except Exception:
            return None
