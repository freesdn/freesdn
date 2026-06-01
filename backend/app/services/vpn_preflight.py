# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Pre-flight Check Service
=================================================

Pre-flight VPN connectivity check before device API calls.
Validates that the VPN tunnel to a site is up before attempting management operations.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vpn import SiteVPNConfiguration, VPNStatus

logger = logging.getLogger(__name__)


@dataclass
class PreflightResult:
    """Result of a VPN pre-flight check."""

    reachable: bool = False
    vpn_type: str | None = None
    latency_ms: float | None = None
    vpn_status: str | None = None
    error: str | None = None
    skipped: bool = False  # True if site has no VPN config (direct access)


@dataclass
class DeviceReachability:
    """Result of a single device reachability check."""

    device_id: str
    device_name: str
    device_type: str
    ip: str | None = None
    reachable: bool = False
    latency_ms: float | None = None
    error: str | None = None


class VPNPreflightService:
    """
    Check VPN connectivity to a site/device before management operations.
    """

    PING_TIMEOUT = 3.0  # seconds per host
    TOTAL_TIMEOUT = 30.0  # seconds for all devices
    MAX_CONCURRENT = 10  # bounded ping concurrency

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def check_site_reachable(self, site_id: UUID) -> PreflightResult:
        """
        Check VPN connectivity to a site.

        1. Load SiteVPNConfiguration for site
        2. If no VPN config, return skipped (direct access assumed)
        3. Check live status via provider service
        4. Ping health_check_ip if configured
        """
        config = await self._get_site_vpn_config(site_id)
        if not config:
            return PreflightResult(reachable=True, skipped=True)

        if not config.enabled:
            return PreflightResult(reachable=True, skipped=True, vpn_type=config.vpn_type)

        result = PreflightResult(vpn_type=config.vpn_type, vpn_status=config.status)

        # Quick check: if cached status is connected and recent health check is OK
        if config.status == VPNStatus.CONNECTED:
            result.reachable = True

        # Try live status check from provider
        try:
            live_ok, latency = await self._check_provider_status(config)
            result.reachable = live_ok
            result.latency_ms = latency
            if not live_ok:
                result.error = f"{config.vpn_type} tunnel not healthy"
        except Exception as exc:
            result.reachable = False
            result.error = str(exc)[:200]

        # If provider says OK but we have a health_check_ip, verify with ping
        if result.reachable and config.health_check_ip:
            try:
                latency = await self._ping(config.health_check_ip)
                if latency is not None:
                    result.latency_ms = latency
                else:
                    result.reachable = False
                    result.error = f"Health check IP {config.health_check_ip} unreachable"
            except Exception as exc:
                result.error = str(exc)[:200]

        return result

    async def check_device_reachable(
        self, device_id: UUID, organization_id: UUID | None = None
    ) -> PreflightResult:
        """
        Resolve device → site → VPN config, then check_site_reachable().
        Additionally ping the device's management IP if VPN is up.
        """
        # Device lives in app.models.devices, NOT app.models.core (the
        # old import raised ImportError at call time). It's tenant-scoped
        # via the Site join below.
        from app.models.core import Site
        from app.models.devices import Device

        filters = [Device.id == device_id]
        if organization_id:
            filters.append(Site.organization_id == organization_id)
        result_q = await self._session.execute(
            select(Device).join(Site, Device.site_id == Site.id, isouter=True).where(*filters)
        )
        device = result_q.scalar_one_or_none()
        if not device:
            return PreflightResult(reachable=False, error="Device not found")

        site_id = getattr(device, "site_id", None)
        if not site_id:
            return PreflightResult(reachable=True, skipped=True)

        # Defense-in-depth: even though the endpoint resolves the device by org
        # AND now asserts the per-user site grant, enforce the grant again at
        # this service chokepoint using the request-scoped current user. A
        # site-limited operator must not preflight a device in a sibling site of
        # the same org. No-op for super_admin / org_admin and in system /
        # background contexts (no request user). 404 (HTTPException) to avoid an
        # existence oracle, matching the endpoint shape.
        from app.core.site_access import assert_site_access_for_request

        assert_site_access_for_request(site_id, detail="Device not found")

        result = await self.check_site_reachable(site_id)

        # If site VPN is up, also try pinging the device
        if result.reachable and not result.skipped:
            device_ip = getattr(device, "ip_address", None) or getattr(device, "host", None)
            if device_ip:
                latency = await self._ping(str(device_ip))
                if latency is not None:
                    result.latency_ms = latency
                else:
                    result.reachable = False
                    result.error = f"Device IP {device_ip} unreachable via VPN"

        return result

    async def check_site_device_reachability(
        self,
        site_id: UUID,
        organization_id: UUID,
    ) -> list[DeviceReachability]:
        """
        Check reachability of all devices at a site via VPN.
        Returns per-device results with bounded concurrency.
        """
        # Device is in app.models.devices and is org-scoped via the Site
        # join (no Device.organization_id column). The old
        # ``from app.models.core import Device`` raised ImportError.
        from app.models.core import Site
        from app.models.devices import Device

        # First check VPN is up for the site
        vpn_result = await self.check_site_reachable(site_id)
        if not vpn_result.reachable and not vpn_result.skipped:
            # VPN down — all devices unreachable
            devices_q = await self._session.execute(
                select(Device)
                .join(Site, Device.site_id == Site.id)
                .where(
                    Device.site_id == site_id,
                    Site.organization_id == organization_id,
                    Device.deleted_at.is_(None),
                )
            )
            devices = list(devices_q.scalars().all())
            return [
                DeviceReachability(
                    device_id=str(d.id),
                    device_name=d.name or str(d.id)[:8],
                    device_type=getattr(d, "device_type", "unknown"),
                    ip=getattr(d, "ip_address", None) or getattr(d, "host", None),
                    reachable=False,
                    error=f"VPN to site is down: {vpn_result.error}",
                )
                for d in devices
            ]

        # VPN up — ping each device with bounded concurrency
        devices_q = await self._session.execute(
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.site_id == site_id,
                Site.organization_id == organization_id,
                Device.deleted_at.is_(None),
            )
        )
        devices = list(devices_q.scalars().all())

        sem = asyncio.Semaphore(self.MAX_CONCURRENT)
        results: list[DeviceReachability] = []

        async def check_one(device: Any) -> DeviceReachability:
            ip = getattr(device, "ip_address", None) or getattr(device, "host", None)
            dr = DeviceReachability(
                device_id=str(device.id),
                device_name=device.name or str(device.id)[:8],
                device_type=getattr(device, "device_type", "unknown"),
                ip=str(ip) if ip else None,
            )
            if not ip:
                dr.error = "No management IP"
                return dr

            async with sem:
                try:
                    latency = await asyncio.wait_for(
                        self._ping(str(ip)),
                        timeout=self.PING_TIMEOUT,
                    )
                    dr.reachable = latency is not None
                    dr.latency_ms = latency
                    if not dr.reachable:
                        dr.error = "Ping failed"
                except TimeoutError:
                    dr.error = "Ping timeout"
                except Exception as exc:
                    dr.error = str(exc)[:100]
            return dr

        try:
            tasks = [check_one(d) for d in devices]
            raw_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.TOTAL_TIMEOUT,
            )
            results = [r for r in raw_results if isinstance(r, DeviceReachability)]
        except TimeoutError:
            logger.warning(
                "Site %s reachability check timed out after %ss", site_id, self.TOTAL_TIMEOUT
            )

        return results

    # ── internal helpers ─────────────────────────────────────────────────

    async def _get_site_vpn_config(self, site_id: UUID) -> SiteVPNConfiguration | None:
        result = await self._session.execute(
            select(SiteVPNConfiguration)
            .where(
                SiteVPNConfiguration.site_id == site_id,
                SiteVPNConfiguration.enabled.is_(True),
            )
            .order_by(SiteVPNConfiguration.is_primary.desc(), SiteVPNConfiguration.priority.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _check_provider_status(
        self,
        config: SiteVPNConfiguration,
    ) -> tuple[bool, float | None]:
        """Check live VPN status from the provider CLI. Returns (is_healthy, latency_ms)."""
        from app.services.vpn_integration import get_vpn_manager

        vpn_type = config.vpn_type
        manager = get_vpn_manager()

        if vpn_type == "tailscale":
            status = await manager.tailscale.get_status(refresh=True)
            connected = status.get("connected", False) if status else False
            return connected, None

        elif vpn_type == "wireguard" and config.wireguard_interface:
            health = await manager.wireguard.check_tunnel_health(config.wireguard_interface)
            return health.get("healthy", False), health.get("latency_ms")

        elif vpn_type == "netbird":
            status = await manager.netbird.get_status(refresh=True)
            connected = status.get("connected", False) if status else False
            return connected, None

        elif vpn_type == "openvpn":
            name = config.openvpn_config_path or ""
            if name:
                name = name.rsplit("/", 1)[-1].replace(".conf", "")
                health = await manager.openvpn.check_health(name)
                return health.get("healthy", False), health.get("latency_ms")
            return False, None

        # For types we can't check live, trust cached status
        return config.status == VPNStatus.CONNECTED, None

    @staticmethod
    def _validate_ping_target(target: str) -> None:
        """Reject hostnames and dangerous IP ranges to prevent SSRF."""
        import ipaddress

        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            raise ValueError(f"Invalid IP address for ping target: {target!r}")
        if addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            raise ValueError(f"Ping target {target} is in a restricted IP range")

    async def _ping(self, target: str, timeout: float = 3.0) -> float | None:
        """
        Ping a target and return latency in ms, or None if unreachable.
        Uses system ping with 1-packet, bounded timeout.
        """
        try:
            self._validate_ping_target(target)
            proc = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                "1",
                "-W",
                str(int(timeout)),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
            if proc.returncode == 0:
                # Parse latency from ping output
                output = stdout.decode(errors="replace")
                for line in output.splitlines():
                    if "time=" in line:
                        import re

                        m = re.search(r"time=([\d.]+)", line)
                        if m:
                            return float(m.group(1))
                return 0.0  # Reachable but couldn't parse latency
            return None
        except (TimeoutError, OSError, ValueError):
            return None
