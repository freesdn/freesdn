# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Integration Service
======================================

VPN service integration for accessing remote sites.

Features:
- Tailscale integration (zero-config mesh VPN)
- WireGuard tunnel management
- Generic VPN status monitoring
- Site connectivity verification
- Magic DNS for device names

Ported from FreeSDN v1 with async/await improvements.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import signal
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.schemas.vpn import _assert_openvpn_config_safe, _assert_wireguard_config_safe

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.vpn import (
        SiteVPNConfiguration,
        VPNConnectionRecord,
    )

logger = logging.getLogger(__name__)


# Interactive ``tailscale up`` is a FOREGROUND process: it prints the login URL,
# then BLOCKS until the admin authorizes in the browser. If we let it be
# garbage-collected after grabbing the URL, asyncio's subprocess transport kills
# the child on __del__, which ABORTS the login — the daemon stays NeedsLogin with
# a now-stale URL and the browser auth can never complete. Hold the keep-alive
# tasks at module scope so neither the task nor the proc is GC'd until the login
# completes (daemon → Running) or times out.
_pending_login_tasks: set[asyncio.Task] = set()


async def _await_tailscale_login(proc: asyncio.subprocess.Process, timeout: float = 300.0) -> None:
    """Keep an interactive ``tailscale up`` alive until login completes or times
    out, draining its output so the pipe can't fill, then reap it."""

    async def _drain_and_wait() -> None:
        if proc.stderr is not None:
            try:
                while await proc.stderr.readline():
                    pass
            except Exception:  # noqa: BLE001 - best-effort drain
                pass
        await proc.wait()

    try:
        await asyncio.wait_for(_drain_and_wait(), timeout=timeout)
        logger.info("Tailscale interactive login process exited (rc=%s)", proc.returncode)
    except TimeoutError:
        logger.warning("Tailscale interactive login not completed in %ss; terminating", timeout)
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    except Exception:
        logger.exception("Tailscale interactive login keep-alive failed")


# =============================================================================
# Argument-injection guards for subprocess calls
# =============================================================================

# Allow IPv4/IPv6/hostname-ish tokens. Rejects anything starting with '-' (so
# an attacker can't smuggle an extra ``--help`` / ``--cmd`` option) as well
# as shell metacharacters.
_HOST_TOKEN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._:-]{0,253})$")


def _is_safe_host_token(value: str) -> bool:
    """Return True if ``value`` is safe to pass as a positional host arg.

    Rejects tokens that begin with ``-`` (option injection) and any value
    containing characters outside of the hostname/IP character set. IPv4
    and IPv6 literals are explicitly accepted.
    """
    if not value or not isinstance(value, str):
        return False
    # Explicitly allow IP literals (ipaddress accepts IPv6 with ':').
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(_HOST_TOKEN_RE.match(value))


# Interface names: Linux caps at IFNAMSIZ=16 and allows alnum plus a few
# punctuation characters. We conservatively allow [A-Za-z0-9._-] up to 15
# characters and reject anything starting with '-'.
_IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,14}$")


def _is_safe_iface_name(value: str) -> bool:
    """Return True if ``value`` is safe to pass as a positional interface arg."""
    if not value or not isinstance(value, str):
        return False
    return bool(_IFACE_NAME_RE.match(value))


# Safe connection-name token: alnum plus a limited punctuation set; reject any
# leading '-' and anything outside the charset. Used as an OpenVPN client
# connection name that becomes a config filename / pid+log filename / process
# tag, so it must never carry path separators or shell/arg-injection chars.
_UNIT_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _is_safe_unit_instance(value: str) -> bool:
    """Return True if ``value`` is a safe OpenVPN connection name (no path
    traversal / injection — it is embedded in file and process names)."""
    if not value or not isinstance(value, str):
        return False
    return bool(_UNIT_INSTANCE_RE.match(value))


# =============================================================================
# Enums
# =============================================================================


class VPNType(StrEnum):
    """Supported VPN types."""

    TAILSCALE = "tailscale"
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    NETBIRD = "netbird"
    IPSEC = "ipsec"
    GENERIC = "generic"


class VPNStatus(StrEnum):
    """VPN connection status."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


class TailscaleNodeStatus(StrEnum):
    """Tailscale node connection status."""

    ONLINE = "online"
    OFFLINE = "offline"
    IDLE = "idle"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class VPNConnection:
    """VPN connection configuration and status."""

    id: str
    name: str
    vpn_type: VPNType

    # Connection details
    endpoint: str | None = None
    port: int = 0

    # Routing
    allowed_ips: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)

    # Status
    status: VPNStatus = VPNStatus.NOT_CONFIGURED
    connected_at: datetime | None = None
    last_handshake: datetime | None = None

    # Metrics
    rx_bytes: int = 0
    tx_bytes: int = 0
    latency_ms: float | None = None

    # Metadata
    extra_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vpn_type": self.vpn_type.value,
            "endpoint": self.endpoint,
            "port": self.port,
            "allowed_ips": self.allowed_ips,
            "dns_servers": self.dns_servers,
            "status": self.status.value,
            "connected_at": self.connected_at.isoformat() if self.connected_at else None,
            "last_handshake": self.last_handshake.isoformat() if self.last_handshake else None,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "latency_ms": self.latency_ms,
        }


@dataclass
class TailscaleNode:
    """Tailscale node information."""

    id: str
    name: str
    hostname: str
    dns_name: str  # Magic DNS name

    # Network
    tailscale_ips: list[str] = field(default_factory=list)
    advertised_routes: list[str] = field(default_factory=list)

    # Status
    status: TailscaleNodeStatus = TailscaleNodeStatus.OFFLINE
    online: bool = False
    active: bool = False
    is_exit_node: bool = False

    # Peer info
    relay: str = ""  # DERP relay being used
    direct: bool = False  # Direct connection vs relayed

    # Last activity
    last_seen: datetime | None = None
    last_write: datetime | None = None

    # Device info
    os: str = ""
    user: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def primary_ip(self) -> str | None:
        """Get primary Tailscale IP."""
        return self.tailscale_ips[0] if self.tailscale_ips else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "dns_name": self.dns_name,
            "tailscale_ips": self.tailscale_ips,
            "primary_ip": self.primary_ip,
            "advertised_routes": self.advertised_routes,
            "status": self.status.value,
            "online": self.online,
            "active": self.active,
            "is_exit_node": self.is_exit_node,
            "relay": self.relay,
            "direct": self.direct,
            "os": self.os,
            "user": self.user,
            "tags": self.tags,
        }


@dataclass
class TailscaleStatus:
    """Tailscale daemon status."""

    backend_state: str  # Running, Stopped, NeedsLogin
    self_node: TailscaleNode | None = None
    peers: list[TailscaleNode] = field(default_factory=list)
    tailnet_name: str = ""
    magic_dns_suffix: str = ""

    # Feature status
    magic_dns_enabled: bool = False
    has_exit_node: bool = False

    @property
    def is_connected(self) -> bool:
        return self.backend_state == "Running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_state": self.backend_state,
            "is_connected": self.is_connected,
            "self_node": self.self_node.to_dict() if self.self_node else None,
            "peers": [p.to_dict() for p in self.peers],
            "tailnet_name": self.tailnet_name,
            "magic_dns_suffix": self.magic_dns_suffix,
            "magic_dns_enabled": self.magic_dns_enabled,
            "has_exit_node": self.has_exit_node,
            "peer_count": len(self.peers),
        }


# =============================================================================
# Exceptions
# =============================================================================


class VPNError(Exception):
    """Base VPN error."""

    pass


class TailscaleNotFoundError(VPNError):
    """Tailscale CLI not found."""

    pass


class WireGuardError(VPNError):
    """WireGuard error."""

    pass


# =============================================================================
# Tailscale Service
# =============================================================================


class TailscaleService:
    """
    Service for integrating with Tailscale VPN.

    Tailscale provides:
    - Zero-config mesh VPN
    - NAT traversal
    - Magic DNS for device names
    - ACL-based access control

    This service enables:
    - Discovering devices on the tailnet
    - Connecting to remote sites via Tailscale
    - Managing Tailscale nodes
    """

    def __init__(self, api_key: str | None = None):
        """
        Initialize Tailscale service.

        Args:
            api_key: Optional Tailscale API key for control plane operations
        """
        self.api_key = api_key or os.environ.get("TAILSCALE_API_KEY")
        self._status_cache: TailscaleStatus | None = None
        self._cache_time: datetime | None = None
        self._cache_ttl_seconds = 30

    async def get_status(self, refresh: bool = False) -> TailscaleStatus:
        """
        Get Tailscale daemon status.

        Uses local Tailscale CLI for status information.
        """
        # Check cache
        if not refresh and self._status_cache and self._cache_time:
            elapsed = (datetime.now(UTC) - self._cache_time).total_seconds()
            if elapsed < self._cache_ttl_seconds:
                return self._status_cache

        try:
            # Use tailscale CLI to get status
            result = await asyncio.create_subprocess_exec(
                "tailscale",
                "status",
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=15)

            if result.returncode != 0:
                msg = stderr.decode().strip()
                if "doesn't appear to be running" in msg:
                    logger.debug("Tailscale daemon not running (expected in worker containers)")
                else:
                    logger.error("Tailscale status error: %s", msg)
                return TailscaleStatus(backend_state="Stopped")

            data = json.loads(stdout.decode())
            status = self._parse_status(data)

            # Update cache
            self._status_cache = status
            self._cache_time = datetime.now(UTC)

            return status

        except FileNotFoundError:
            logger.debug("Tailscale CLI not found")
            return TailscaleStatus(backend_state="NotInstalled")
        except Exception as e:
            logger.error("Failed to get Tailscale status: %s", e)
            return TailscaleStatus(backend_state="Error")

    def _parse_status(self, data: dict[str, Any]) -> TailscaleStatus:
        """Parse Tailscale status JSON."""
        # NOTE: `or {}` (not a default arg): when tailscaled is up-but-NeedsLogin
        # (the fresh-install state, before an auth key is added), `tailscale
        # status --json` emits these keys with an explicit JSON null, so
        # `.get(k, {})` returns None and `None.get(...)` would crash — making a
        # perfectly-wired daemon report backend_state="Error".
        tailnet = data.get("CurrentTailnet") or {}
        status = TailscaleStatus(
            backend_state=data.get("BackendState", "Unknown"),
            tailnet_name=tailnet.get("Name", ""),
            magic_dns_suffix=tailnet.get("MagicDNSSuffix", ""),
            magic_dns_enabled=tailnet.get("MagicDNSEnabled", False),
        )

        # Parse self node
        if data.get("Self"):
            self_data = data["Self"]
            status.self_node = self._parse_node(self_data)

        # Parse peers
        peers_data = data.get("Peer") or {}
        for peer_id, peer_data in peers_data.items():
            node = self._parse_node(peer_data)
            node.id = peer_id
            status.peers.append(node)

            if node.is_exit_node and node.online:
                status.has_exit_node = True

        return status

    def _parse_node(self, data: dict[str, Any]) -> TailscaleNode:
        """Parse Tailscale node from status data."""
        return TailscaleNode(
            id=str(data.get("ID", "")),
            name=data.get("HostName", ""),
            hostname=data.get("HostName", ""),
            dns_name=data.get("DNSName", ""),
            # `tailscale status --json` emits these list fields as JSON `null`
            # (not absent) when the node is logged out / has no routes/tags, so
            # `.get(key, [])` returns None and breaks the `list[str]` response
            # schema (500). Coerce null -> [] with `or []`.
            tailscale_ips=data.get("TailscaleIPs") or [],
            advertised_routes=data.get("AllowedIPs") or [],
            status=TailscaleNodeStatus.ONLINE
            if data.get("Online")
            else TailscaleNodeStatus.OFFLINE,
            online=data.get("Online", False),
            active=data.get("Active", False),
            is_exit_node=data.get("ExitNode", False) or data.get("ExitNodeOption", False),
            relay=data.get("Relay", ""),
            direct=data.get("CurAddr", "") != "",
            os=data.get("OS", ""),
            user=str(data.get("UserID", "")) if data.get("UserID") is not None else "",
            tags=data.get("Tags") or [],
        )

    async def list_devices(self) -> list[TailscaleNode]:
        """List all devices on the tailnet."""
        status = await self.get_status(refresh=True)

        devices = []
        if status.self_node:
            devices.append(status.self_node)
        devices.extend(status.peers)

        return devices

    async def get_device(self, name_or_ip: str) -> TailscaleNode | None:
        """Get device by name or Tailscale IP."""
        status = await self.get_status()

        all_nodes = [status.self_node] + status.peers if status.self_node else status.peers

        for device in all_nodes:
            if device is None:
                continue
            if device.name == name_or_ip or device.hostname == name_or_ip:
                return device
            if device.dns_name and name_or_ip in device.dns_name:
                return device
            if name_or_ip in device.tailscale_ips:
                return device

        return None

    async def ping(self, target: str, timeout: float = 5.0) -> float | None:
        """
        Ping a Tailscale device.

        Returns:
            Latency in milliseconds, or None if unreachable
        """
        # Validate target to prevent argument injection (e.g. user passing
        # ``--help`` or ``-foo``). Accept IPv4, IPv6, and plain tailnet
        # hostnames only.
        if not _is_safe_host_token(target):
            logger.warning("Tailscale ping: rejecting unsafe target %r", target)
            return None
        try:
            result = await asyncio.create_subprocess_exec(
                "tailscale",
                "ping",
                "--c",
                "1",
                "--timeout",
                str(timeout),
                "--",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                result.communicate(),
                timeout=timeout + 1,
            )

            if result.returncode == 0:
                # Parse latency from output
                output = stdout.decode()
                # Output format: "pong from device (100.x.x.x) via DERP(sfo) in 45ms"
                if "in " in output and "ms" in output:
                    latency_str = output.split("in ")[-1].split("ms")[0]
                    return float(latency_str)

            return None

        except Exception as e:
            logger.debug("Tailscale ping failed: %s", e)
            return None

    async def check_connectivity(self, target: str) -> dict[str, Any]:
        """
        Check connectivity to a Tailscale target.

        Returns detailed connectivity information.
        """
        device = await self.get_device(target)

        result: dict[str, Any] = {
            "target": target,
            "reachable": False,
            "device": None,
            "latency_ms": None,
            "connection_type": None,  # direct or relayed
        }

        if device:
            result["device"] = {
                "name": device.name,
                "ip": device.primary_ip,
                "online": device.online,
                "direct": device.direct,
            }
            result["connection_type"] = "direct" if device.direct else "relayed"

        # Try ping
        latency = await self.ping(target)
        if latency is not None:
            result["reachable"] = True
            result["latency_ms"] = latency

        return result

    async def discover_site_devices(
        self,
        site_subnet: str,
    ) -> list[dict[str, Any]]:
        """
        Discover devices on a remote site accessible via Tailscale.

        This uses Tailscale's subnet routing feature to discover devices
        on advertised subnets.

        Args:
            site_subnet: CIDR notation subnet (e.g., "192.168.1.0/24")
        """
        status = await self.get_status()

        # Find devices advertising this subnet
        subnet_network = ipaddress.ip_network(site_subnet, strict=False)
        devices_on_subnet = []

        for peer in status.peers:
            for route in peer.advertised_routes:
                try:
                    route_network = ipaddress.ip_network(route, strict=False)
                    if route_network.overlaps(subnet_network):
                        devices_on_subnet.append(
                            {
                                "node": peer.name,
                                "node_ip": peer.primary_ip,
                                "advertised_subnet": route,
                                "online": peer.online,
                            }
                        )
                except ValueError:
                    continue

        return devices_on_subnet


# =============================================================================
# Tailscale Setup / Enrollment Service
# =============================================================================


class TailscaleSetupService:
    """
    Enterprise-grade Tailscale agent setup and lifecycle management.

    Handles the full enrollment flow:
    1. Check if tailscaled daemon is running
    2. Start the daemon if needed
    3. Authenticate via auth key or interactive browser login
    4. Configure hostname, routes, DNS, exit node preferences
    5. Monitor connection health
    6. Logout / reset
    """

    TAILSCALE_SOCKET = "/var/run/tailscale/tailscaled.sock"

    # ── daemon lifecycle ─────────────────────────────────────────────────

    async def _run_cmd(
        self, *args: str, timeout: float = 30.0, env: dict[str, str] | None = None
    ) -> tuple[int, str, str]:
        """Run a tailscale CLI command and return (returncode, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout.decode(), stderr.decode()
        except FileNotFoundError:
            return -1, "", "tailscale binary not found"
        except TimeoutError:
            return -2, "", "command timed out"
        except Exception as e:
            return -3, "", str(e)

    async def get_setup_status(self) -> dict[str, Any]:
        """
        Return comprehensive setup status.

        Possible states:
          - not_installed: tailscale binary missing
          - daemon_stopped: tailscaled not running
          - needs_login: daemon running, not authenticated
          - connected: fully operational
          - error: unexpected state
        """
        # 1. Check binary exists
        rc, stdout, stderr = await self._run_cmd("tailscale", "version")
        if rc == -1:
            return {
                "state": "not_installed",
                "installed": False,
                "daemon_running": False,
                "authenticated": False,
                "connected": False,
                "version": None,
                "hostname": None,
                "tailscale_ip": None,
                "tailnet": None,
                "login_url": None,
                "message": "Tailscale is not installed in this container.",
            }
        version = stdout.strip().split("\n")[0] if stdout else None

        # 2. Check daemon / auth state via status
        rc, stdout, stderr = await self._run_cmd("tailscale", "status", "--json")
        if rc != 0:
            # daemon not running or socket not available
            return {
                "state": "daemon_stopped",
                "installed": True,
                "daemon_running": False,
                "authenticated": False,
                "connected": False,
                "version": version,
                "hostname": None,
                "tailscale_ip": None,
                "tailnet": None,
                "login_url": None,
                "message": f"Tailscale daemon is not running. {stderr.strip()}",
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {
                "state": "error",
                "installed": True,
                "daemon_running": True,
                "authenticated": False,
                "connected": False,
                "version": version,
                "hostname": None,
                "tailscale_ip": None,
                "tailnet": None,
                "login_url": None,
                "message": "Failed to parse tailscale status.",
            }

        backend_state = data.get("BackendState", "Unknown")
        self_node = data.get("Self", {})
        tailnet = data.get("CurrentTailnet", {})

        if backend_state == "Running":
            return {
                "state": "connected",
                "installed": True,
                "daemon_running": True,
                "authenticated": True,
                "connected": True,
                "version": version,
                "hostname": self_node.get("HostName"),
                "tailscale_ip": (self_node.get("TailscaleIPs") or [None])[0],
                "tailscale_ips": self_node.get("TailscaleIPs") or [],
                "tailnet": tailnet.get("Name"),
                "magic_dns_suffix": tailnet.get("MagicDNSSuffix"),
                "magic_dns_enabled": tailnet.get("MagicDNSEnabled", False),
                "online": self_node.get("Online", False),
                "os": self_node.get("OS", ""),
                "login_url": None,
                "peer_count": len(data.get("Peer", {})),
                "message": "Tailscale is connected and operational.",
            }

        if backend_state in ("NeedsLogin", "NeedsMachineAuth"):
            return {
                "state": "needs_login",
                "installed": True,
                "daemon_running": True,
                "authenticated": False,
                "connected": False,
                "version": version,
                "hostname": None,
                "tailscale_ip": None,
                "tailnet": None,
                "login_url": None,
                "message": "Tailscale daemon running but not authenticated. Provide an auth key or use browser login.",
            }

        # Stopped, Starting, etc.
        return {
            "state": "daemon_stopped" if backend_state == "Stopped" else "error",
            "installed": True,
            "daemon_running": backend_state not in ("Stopped",),
            "authenticated": False,
            "connected": False,
            "version": version,
            "hostname": None,
            "tailscale_ip": None,
            "tailnet": None,
            "login_url": None,
            "message": f"Tailscale backend state: {backend_state}",
        }

    # ── daemon start ─────────────────────────────────────────────────────

    async def start_daemon(self) -> dict[str, Any]:
        """
        Ensure the tailscaled daemon is running.

        In Docker the daemon is started by the container entrypoint.
        This restarts it if it crashed.
        """
        # Check if already running
        status = await self.get_setup_status()
        if status["daemon_running"]:
            return {
                "success": True,
                "message": "Tailscale daemon is already running.",
                "state": status["state"],
            }

        try:
            proc = await asyncio.create_subprocess_exec(
                "tailscaled",
                "--state=/var/lib/tailscale/tailscaled.state",
                "--socket=/var/run/tailscale/tailscaled.sock",
                "--tun=userspace-networking",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Give it a couple seconds to start
            await asyncio.sleep(2)

            # Check if it started OK
            if proc.returncode is not None:
                _, stderr = await proc.communicate()
                return {
                    "success": False,
                    "message": f"Daemon failed to start: {stderr.decode()}",
                    "state": "error",
                }

            # Re-check
            new_status = await self.get_setup_status()
            return {
                "success": new_status["daemon_running"],
                "message": "Tailscale daemon started."
                if new_status["daemon_running"]
                else "Daemon start may still be in progress.",
                "state": new_status["state"],
            }
        except Exception as e:
            logger.error("Failed to start tailscaled: %s", e)
            return {"success": False, "message": str(e), "state": "error"}

    # ── authentication ───────────────────────────────────────────────────

    async def login_with_authkey(
        self,
        auth_key: str,
        hostname: str | None = None,
        accept_routes: bool = True,
        advertise_routes: list[str] | None = None,
        advertise_exit_node: bool = False,
        shields_up: bool = False,
        netfilter_mode: str | None = None,
    ) -> dict[str, Any]:
        """
        Authenticate and connect using a pre-authenticated key.

        This is the enterprise-recommended approach.
        Generate keys at: https://login.tailscale.com/admin/settings/keys

        ``netfilter_mode`` ("off"/"nodivert"/"on") sets `tailscale up
        --netfilter-mode`; "off" lets Tailscale COEXIST with NetBird, which
        otherwise fight over the shared 100.64.0.0/10 range (Tailscale's daemon
        aggressively grabs the packets). The endpoint passes "off" automatically
        when a NetBird connection is also configured.
        """
        if not auth_key:
            return {"success": False, "message": "Auth key is required.", "state": "needs_login"}

        cmd = ["tailscale", "up", "--reset"]
        if hostname:
            cmd.append(f"--hostname={hostname}")
        if accept_routes:
            cmd.append("--accept-routes")
        if advertise_routes:
            cmd.append(f"--advertise-routes={','.join(advertise_routes)}")
        if advertise_exit_node:
            cmd.append("--advertise-exit-node")
        if shields_up:
            cmd.append("--shields-up")
        if netfilter_mode in ("off", "nodivert", "on"):
            cmd.append(f"--netfilter-mode={netfilter_mode}")

        # Pass auth key via env var to avoid exposure in process listing
        import os

        env = {**os.environ, "TS_AUTHKEY": auth_key}
        rc, stdout, stderr = await self._run_cmd(*cmd, timeout=60.0, env=env)

        if rc == 0:
            # Wait for connection to stabilize
            await asyncio.sleep(2)
            new_status = await self.get_setup_status()
            return {
                "success": True,
                "message": "Tailscale connected successfully.",
                "state": new_status["state"],
                "hostname": new_status.get("hostname"),
                "tailscale_ip": new_status.get("tailscale_ip"),
                "tailnet": new_status.get("tailnet"),
            }

        return {
            "success": False,
            "message": f"Login failed: {stderr.strip() or stdout.strip()}",
            "state": "needs_login",
        }

    async def login_interactive(
        self,
        hostname: str | None = None,
        accept_routes: bool = True,
        netfilter_mode: str | None = None,
    ) -> dict[str, Any]:
        """
        Start interactive (browser-based) login.

        Returns a URL the admin opens in their browser to authorize this node.
        ``netfilter_mode="off"`` lets Tailscale coexist with NetBird on the shared
        100.64.0.0/10 range (see login_with_authkey).
        """
        cmd = ["tailscale", "up", "--reset"]
        if hostname:
            cmd.append(f"--hostname={hostname}")
        if accept_routes:
            cmd.append("--accept-routes")
        if netfilter_mode in ("off", "nodivert", "on"):
            cmd.append(f"--netfilter-mode={netfilter_mode}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # detach from the request's process group
            )
            # tailscale up prints the login URL to stderr, then blocks
            # We read stderr line by line for up to 15 seconds
            login_url = None
            try:
                deadline = asyncio.get_running_loop().time() + 15
                while asyncio.get_running_loop().time() < deadline:
                    try:
                        line = await asyncio.wait_for(
                            proc.stderr.readline(),
                            timeout=2.0,  # type: ignore[union-attr]
                        )
                        text = line.decode().strip()
                        if "https://" in text:
                            # Extract URL
                            for word in text.split():
                                if word.startswith("https://"):
                                    login_url = word
                                    break
                            if login_url:
                                break
                    except TimeoutError:
                        continue
            except Exception:
                logger.exception("Tailscale interactive login failed")

            if login_url:
                # Keep `tailscale up` ALIVE in the background so the login can
                # finalize once the admin authorizes in the browser. Without
                # this the proc is GC-killed on return and the login aborts
                # (daemon stuck at NeedsLogin). The status poll then flips the
                # UI to connected automatically when the daemon reaches Running.
                task = asyncio.create_task(_await_tailscale_login(proc))
                _pending_login_tasks.add(task)
                task.add_done_callback(_pending_login_tasks.discard)
                return {
                    "success": True,
                    "message": "Open this URL in your browser to authorize this device.",
                    "login_url": login_url,
                    "state": "awaiting_auth",
                }
            else:
                # Maybe it connected immediately (existing auth)
                await asyncio.sleep(2)
                new_status = await self.get_setup_status()
                if new_status["connected"]:
                    return {
                        "success": True,
                        "message": "Tailscale connected (existing auth reused).",
                        "login_url": None,
                        "state": "connected",
                    }

                return {
                    "success": False,
                    "message": "Could not obtain login URL. Check tailscaled logs.",
                    "login_url": None,
                    "state": "error",
                }

        except Exception as e:
            logger.error("Interactive login failed: %s", e)
            return {"success": False, "message": str(e), "login_url": None, "state": "error"}

    # ── configuration ────────────────────────────────────────────────────

    async def configure(
        self,
        hostname: str | None = None,
        accept_routes: bool | None = None,
        advertise_routes: list[str] | None = None,
        accept_dns: bool | None = None,
        advertise_exit_node: bool | None = None,
        shields_up: bool | None = None,
    ) -> dict[str, Any]:
        """
        Reconfigure the running Tailscale agent.

        Only applies to a connected agent; use login_* first.
        """
        cmd = ["tailscale", "set"]
        if hostname is not None:
            cmd.append(f"--hostname={hostname}")
        if accept_routes is not None:
            cmd.append(f"--accept-routes={'true' if accept_routes else 'false'}")
        if advertise_routes is not None:
            cmd.append(f"--advertise-routes={','.join(advertise_routes)}")
        if accept_dns is not None:
            cmd.append(f"--accept-dns={'true' if accept_dns else 'false'}")
        if advertise_exit_node is not None and advertise_exit_node:
            cmd.append("--advertise-exit-node")
        if shields_up is not None:
            cmd.append(f"--shields-up={'true' if shields_up else 'false'}")

        if len(cmd) == 2:
            return {"success": True, "message": "No configuration changes specified."}

        rc, stdout, stderr = await self._run_cmd(*cmd)
        if rc == 0:
            return {"success": True, "message": "Configuration applied."}
        return {
            "success": False,
            "message": f"Configuration failed: {stderr.strip() or stdout.strip()}",
        }

    # ── disconnect / logout ──────────────────────────────────────────────

    async def logout(self) -> dict[str, Any]:
        """Disconnect and deauthorize this node from the tailnet."""
        rc, stdout, stderr = await self._run_cmd("tailscale", "logout")
        if rc == 0:
            return {
                "success": True,
                "message": "Logged out from Tailscale. Node removed from tailnet.",
            }
        return {"success": False, "message": f"Logout failed: {stderr.strip() or stdout.strip()}"}

    async def disconnect(self) -> dict[str, Any]:
        """Temporarily disconnect (keeps auth, can reconnect without re-auth)."""
        rc, stdout, stderr = await self._run_cmd("tailscale", "down")
        if rc == 0:
            return {"success": True, "message": "Tailscale disconnected."}
        return {
            "success": False,
            "message": f"Disconnect failed: {stderr.strip() or stdout.strip()}",
        }

    async def reconnect(self, netfilter_mode: str | None = None) -> dict[str, Any]:
        """Reconnect a previously disconnected (but still authed) agent.

        ``netfilter_mode`` MUST be re-passed here: this uses ``tailscale up
        --reset``, which wipes unspecified prefs including --netfilter-mode — so
        without it a reconnect would silently revert NetBird coexistence to the
        default (on) and break the overlay sharing 100.64.0.0/10.
        """
        cmd = ["tailscale", "up", "--accept-routes", "--reset"]
        if netfilter_mode in ("off", "nodivert", "on"):
            cmd.append(f"--netfilter-mode={netfilter_mode}")
        rc, stdout, stderr = await self._run_cmd(*cmd)
        if rc == 0:
            await asyncio.sleep(2)
            new_status = await self.get_setup_status()
            return {
                "success": True,
                "message": "Tailscale reconnected.",
                "state": new_status["state"],
            }
        return {
            "success": False,
            "message": f"Reconnect failed: {stderr.strip() or stdout.strip()}",
        }


# Singleton
_tailscale_setup_service: TailscaleSetupService | None = None


def get_tailscale_setup() -> TailscaleSetupService:
    global _tailscale_setup_service
    if _tailscale_setup_service is None:
        _tailscale_setup_service = TailscaleSetupService()
    return _tailscale_setup_service


# =============================================================================
# WireGuard Service
# =============================================================================


class WireGuardService:
    """
    Service for managing WireGuard VPN connections.

    WireGuard is a simple, fast VPN that can be used for:
    - Site-to-site connections
    - Point-to-point device access
    - Secure tunnel for agent communication
    """

    def __init__(self, config_dir: str = "/etc/wireguard"):
        self.config_dir = config_dir
        # Sidecar topology (mirrors OpenVPNService): `wg-quick up` needs NET_ADMIN,
        # which only the privileged vpn sidecar holds. In sidecar mode the api
        # materializes the config + touches a desired-state marker; the sidecar
        # reconciler runs wg-quick and publishes a status file the api reads.
        self.run_dir = os.environ.get("WIREGUARD_RUN_DIR", "/run/wireguard")
        self.desired_dir = os.path.join(self.run_dir, "desired")
        self.sidecar = os.environ.get("FREESDN_WIREGUARD_SIDECAR", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

    def _conf_path(self, interface: str) -> str:
        return os.path.join(self.config_dir, f"{interface}.conf")

    def _materialize_config(self, interface: str, content: str) -> str:
        """Write the wg-quick INI to /etc/wireguard/<iface>.conf (0600, atomic).

        Mirrors OpenVPNService._materialize_config — the config carries the
        interface PrivateKey + PSK, so 0600 on the shared wireguard_config volume
        (which the sidecar chowns to the app uid so this unprivileged process can
        write). Without this `wg-quick up` has no config and a connect always fails.
        """
        # Re-validate at the disk chokepoint (PostUp/PostDown/PreUp/PreDown run as
        # root via wg-quick), regardless of how the row was populated.
        _assert_wireguard_config_safe(content)
        cfg = self._conf_path(interface)
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(cfg), prefix=f".{interface}.", suffix=".tmp")
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cfg)  # atomic
        return cfg

    async def connect(self, interface: str, config_content: str | None = None) -> dict[str, Any]:
        """Bring up a WireGuard interface (materializing its config first).

        In sidecar mode the api writes the config + a desired-state marker and the
        sidecar runs `wg-quick up`; otherwise (single-container) it runs wg-quick
        directly. ``config_content`` is the stored wg-quick INI.
        """
        if not _is_safe_iface_name(interface):
            return {"success": False, "message": "Invalid interface name"}
        cfg = self._conf_path(interface)
        if config_content:
            try:
                self._materialize_config(interface, config_content)
            except ValueError as e:
                return {"success": False, "message": f"Rejected WireGuard config: {e}"}
            except OSError as e:
                return {"success": False, "message": f"Could not write WireGuard config: {e}"}
        if not os.path.exists(cfg):
            return {"success": False, "message": f"No WireGuard config found at {cfg}"}
        if self.sidecar:
            try:
                os.makedirs(self.desired_dir, exist_ok=True)
                with open(os.path.join(self.desired_dir, interface), "w"):
                    pass
            except OSError as e:
                return {"success": False, "message": f"Could not request connection: {e}"}
            return {
                "success": True,
                "message": f"WireGuard {interface} requested (the VPN sidecar will bring it up)",
            }
        return await self._wg_quick(interface, "up")

    async def disconnect(self, interface: str) -> dict[str, Any]:
        """Tear down a WireGuard interface (sidecar marker removal or wg-quick down)."""
        if not _is_safe_iface_name(interface):
            return {"success": False, "message": "Invalid interface name"}
        if self.sidecar:
            try:
                os.remove(os.path.join(self.desired_dir, interface))
            except FileNotFoundError:
                pass
            except OSError as e:
                return {"success": False, "message": f"Could not request disconnect: {e}"}
            return {
                "success": True,
                "message": f"WireGuard {interface} stop requested (sidecar will take it down)",
            }
        return await self._wg_quick(interface, "down")

    async def cleanup(self, interface: str) -> None:
        """Disconnect AND remove the materialized config (used on connection delete)
        so no interface stays up and no wg key material lingers on disk."""
        if not _is_safe_iface_name(interface):
            return
        try:
            await self.disconnect(interface)
        except Exception:
            logger.debug("WireGuard cleanup disconnect failed", exc_info=True)
        for p in (self._conf_path(interface), os.path.join(self.run_dir, f"{interface}.status")):
            try:
                os.remove(p)
            except OSError:
                pass

    async def _wg_quick(self, interface: str, cmd: str) -> dict[str, Any]:
        """Run `wg-quick up|down <iface>` (single-container path; needs NET_ADMIN)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "wg-quick",
                cmd,
                interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            if proc.returncode == 0:
                return {"success": True, "message": f"WireGuard interface {cmd}"}
            return {"success": False, "message": stderr.decode(errors="replace")[:500]}
        except TimeoutError:
            return {"success": False, "message": "WireGuard command timed out"}
        except FileNotFoundError:
            return {"success": False, "message": "wg-quick binary not found"}

    async def _get_connection_status(self, interface: str) -> VPNStatus:
        """Resolve a WireGuard interface's status.

        Sidecar mode: read the status file the sidecar publishes. Single-container:
        the interface exists in `wg show interfaces` ⇒ connected.
        """
        if not _is_safe_iface_name(interface):
            return VPNStatus.NOT_CONFIGURED
        if self.sidecar:
            try:
                with open(os.path.join(self.run_dir, f"{interface}.status")) as f:
                    state = f.read().strip()
            except (FileNotFoundError, OSError):
                state = ""
            if state == "connected":
                return VPNStatus.CONNECTED
            if state == "connecting":
                return VPNStatus.CONNECTING
            return (
                VPNStatus.DISCONNECTED
                if os.path.exists(self._conf_path(interface))
                else VPNStatus.NOT_CONFIGURED
            )
        return (
            VPNStatus.CONNECTED
            if interface in await self.get_interfaces()
            else VPNStatus.DISCONNECTED
        )

    async def get_status(self, interface: str) -> dict[str, Any]:
        """Status dict for a single interface (used by the connect endpoint)."""
        status = await self._get_connection_status(interface)
        return {
            "name": interface,
            "status": status.value,
            "connected": status == VPNStatus.CONNECTED,
        }

    async def get_interfaces(self) -> list[str]:
        """List WireGuard interfaces."""
        if self.sidecar:
            # `wg show` needs NET_ADMIN, which the unprivileged api lacks. List the
            # interfaces the sidecar is currently reporting up (status file present
            # + not "down") instead of shelling out to wg.
            ifaces: list[str] = []
            try:
                import glob

                for sf in glob.glob(os.path.join(self.run_dir, "*.status")):
                    name = os.path.basename(sf)[: -len(".status")]
                    try:
                        with open(sf) as f:
                            state = f.read().strip()
                    except OSError:
                        continue
                    if state in ("connected", "connecting"):
                        ifaces.append(name)
            except Exception as e:
                logger.debug("Failed to list WireGuard interfaces (sidecar): %s", e)
            return ifaces
        try:
            result = await asyncio.create_subprocess_exec(
                "wg",
                "show",
                "interfaces",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=10)

            interfaces = stdout.decode().strip().split()
            return interfaces

        except Exception as e:
            logger.debug("Failed to list WireGuard interfaces: %s", e)
            return []

    async def get_interface_status(self, interface: str) -> VPNConnection | None:
        """Get status of WireGuard interface."""
        if not _is_safe_iface_name(interface):
            logger.warning("WireGuard: rejecting unsafe interface name %r", interface)
            return None
        if self.sidecar:
            # Detailed peer stats need `wg show <iface> dump` (NET_ADMIN); the api
            # doesn't have it. Report status from the sidecar-published status file;
            # rx/tx/handshake are unavailable from here (left at defaults).
            st = await self._get_connection_status(interface)
            if st == VPNStatus.NOT_CONFIGURED:
                return None
            return VPNConnection(
                id=interface, name=interface, vpn_type=VPNType.WIREGUARD, status=st
            )
        try:
            result = await asyncio.create_subprocess_exec(
                "wg",
                "show",
                interface,
                "dump",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=10)

            if result.returncode != 0:
                logger.error("WireGuard show failed: %s", stderr.decode())
                return None

            lines = stdout.decode().strip().split("\n")
            if not lines:
                return None

            conn = VPNConnection(
                id=interface,
                name=interface,
                vpn_type=VPNType.WIREGUARD,
                status=VPNStatus.CONNECTED,
            )

            for line in lines[1:]:  # Skip interface line
                parts = line.split("\t")
                if len(parts) >= 7:
                    # public_key, psk, endpoint, allowed_ips, latest_handshake, rx, tx
                    conn.endpoint = parts[2] if parts[2] != "(none)" else None
                    conn.allowed_ips = parts[3].split(",") if parts[3] != "(none)" else []

                    # Parse handshake timestamp
                    handshake_ts = int(parts[4]) if parts[4] != "0" else 0
                    if handshake_ts:
                        conn.last_handshake = datetime.fromtimestamp(handshake_ts, tz=UTC)

                    conn.rx_bytes = int(parts[5])
                    conn.tx_bytes = int(parts[6])

            return conn

        except Exception as e:
            logger.error("Failed to get WireGuard status: %s", e)
            return None

    async def check_tunnel_health(self, interface: str) -> dict[str, Any]:
        """Check health of WireGuard tunnel."""
        status = await self.get_interface_status(interface)

        result: dict[str, Any] = {
            "interface": interface,
            "healthy": False,
            "status": "unknown",
            "last_handshake": None,
            "rx_bytes": 0,
            "tx_bytes": 0,
        }

        if not status:
            result["status"] = "not_found"
            return result

        result["status"] = status.status.value
        result["rx_bytes"] = status.rx_bytes
        result["tx_bytes"] = status.tx_bytes

        if status.last_handshake:
            result["last_handshake"] = status.last_handshake.isoformat()

            # Consider healthy if handshake within last 3 minutes
            elapsed = (datetime.now(UTC) - status.last_handshake).total_seconds()
            result["healthy"] = elapsed < 180
            result["handshake_age_seconds"] = elapsed

        return result

    async def get_all_tunnels(self) -> list[VPNConnection]:
        """Get status of all WireGuard tunnels (parallel interface queries)."""
        interfaces = await self.get_interfaces()
        if not interfaces:
            return []

        results = await asyncio.gather(
            *[self.get_interface_status(iface) for iface in interfaces],
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, VPNConnection)]

    # ── Key generation & config provisioning ──────────────────

    # Regex for values safe to embed in WireGuard INI configs.
    # Prevents newline injection (PostUp/PostDown RCE) and other config directive injection.
    _WG_SAFE_VALUE = re.compile(r"^[A-Za-z0-9+/=.:,\- ]+$")
    _WG_BASE64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
    _WG_ENDPOINT = re.compile(r"^[a-zA-Z0-9.\-]+:\d{1,5}$")

    @staticmethod
    def _sanitize_wg_value(name: str, value: str) -> str:
        """Validate a value is safe for WireGuard INI interpolation (no newlines, no injection)."""
        if "\n" in value or "\r" in value:
            raise WireGuardError(f"Invalid {name}: must not contain newlines")
        if not WireGuardService._WG_SAFE_VALUE.match(value):
            raise WireGuardError(f"Invalid {name}: contains disallowed characters")
        return value

    @staticmethod
    def validate_wg_key(value: str, name: str = "key") -> str:
        """Validate a WireGuard base64 key (44 chars, proper base64 with trailing =)."""
        if not WireGuardService._WG_BASE64_KEY.match(value):
            raise WireGuardError(f"Invalid {name}: must be a 44-char base64 WireGuard key")
        return value

    @staticmethod
    def validate_endpoint(value: str) -> str:
        """Validate a WireGuard endpoint (host:port format)."""
        if not WireGuardService._WG_ENDPOINT.match(value):
            raise WireGuardError(f"Invalid endpoint: must be host:port (got {value!r})")
        # Validate port range
        port = int(value.rsplit(":", 1)[1])
        if port < 1 or port > 65535:
            raise WireGuardError(f"Invalid endpoint port: {port}")
        return value

    @staticmethod
    def validate_allowed_ips(ips: list[str]) -> list[str]:
        """Validate each entry in AllowedIPs is a legitimate CIDR."""
        import ipaddress as _ipaddress

        validated: list[str] = []
        for ip in ips:
            try:
                net = _ipaddress.ip_network(ip, strict=False)
                validated.append(str(net))
            except ValueError:
                raise WireGuardError(f"Invalid CIDR in AllowedIPs: {ip!r}")
        return validated

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """
        Generate a WireGuard Curve25519 keypair using Python-native crypto.
        Returns (private_key_base64, public_key_base64).
        """
        import base64

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key = X25519PrivateKey.generate()
        private_raw = bytearray(
            private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        try:
            return (
                base64.b64encode(bytes(private_raw)).decode(),
                base64.b64encode(public_raw).decode(),
            )
        finally:
            # Best-effort zeroing of private key material in memory
            for i in range(len(private_raw)):
                private_raw[i] = 0

    @staticmethod
    def generate_agent_config(
        *,
        agent_private_key: str,
        agent_address: str,
        server_public_key: str,
        server_endpoint: str,
        allowed_ips: list[str] | None = None,
        dns: str | None = None,
        persistent_keepalive: int = 25,
    ) -> str:
        """
        Generate a WireGuard config file for an agent.

        All values are sanitized to prevent INI config injection (newlines, PostUp RCE, etc.).
        Returns the INI-style WireGuard config as a string.
        """
        import ipaddress as _ipaddress

        _s = WireGuardService._sanitize_wg_value

        # Validate all interpolated values before building config
        WireGuardService.validate_wg_key(agent_private_key, "agent_private_key")
        # Validate agent_address as a proper IP/CIDR
        try:
            _ipaddress.ip_interface(agent_address)
        except ValueError:
            raise WireGuardError(
                f"Invalid agent_address: must be IP/prefix (got {agent_address!r})"
            )
        WireGuardService.validate_wg_key(server_public_key, "server_public_key")
        WireGuardService.validate_endpoint(server_endpoint)
        safe_allowed = WireGuardService.validate_allowed_ips(allowed_ips or ["0.0.0.0/0"])

        lines = [
            "[Interface]",
            f"PrivateKey = {agent_private_key}",
            f"Address = {agent_address}",
        ]
        if dns:
            _s("dns", dns)
            lines.append(f"DNS = {dns}")
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {server_public_key}")
        lines.append(f"Endpoint = {server_endpoint}")
        lines.append(f"AllowedIPs = {', '.join(safe_allowed)}")
        if persistent_keepalive > 0:
            lines.append(f"PersistentKeepalive = {persistent_keepalive}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def generate_server_peer_block(
        *,
        agent_public_key: str,
        agent_allowed_ips: list[str],
    ) -> str:
        """
        Generate the server-side [Peer] block to add to the server's WireGuard config.
        """
        WireGuardService.validate_wg_key(agent_public_key, "agent_public_key")
        safe_allowed = WireGuardService.validate_allowed_ips(agent_allowed_ips)
        lines = [
            "[Peer]",
            f"PublicKey = {agent_public_key}",
            f"AllowedIPs = {', '.join(safe_allowed)}",
        ]
        return "\n".join(lines) + "\n"


# =============================================================================
# OpenVPN Service
# =============================================================================


class OpenVPNService:
    """
    Service for managing OpenVPN connections.

    Supports:
    - Connection status via management interface or CLI
    - Starting/stopping tunnels
    - Importing .ovpn config files
    """

    def __init__(self, config_dir: str = "/etc/openvpn"):
        self.config_dir = config_dir
        # Container-friendly: we manage the openvpn process directly (NOT via
        # systemd, which does not run in a container) and track it by pidfile.
        self.run_dir = os.environ.get("OPENVPN_RUN_DIR", "/run/openvpn-client")
        self.log_dir = os.environ.get("OPENVPN_LOG_DIR", "/var/log/openvpn")
        # SIDECAR mode: the hardened (read-only, no-NET_ADMIN) api/worker can't
        # spawn openvpn, so they hand desired-state to the privileged `vpn`
        # sidecar over a shared volume — touch a marker to bring a connection up,
        # remove it to take it down, and read a status file the sidecar publishes.
        self.sidecar = os.environ.get("FREESDN_OPENVPN_SIDECAR", "").lower() in (
            "1",
            "true",
            "yes",
        )
        self.desired_dir = os.path.join(self.run_dir, "desired")

    def _paths(self, connection_name: str) -> tuple[str, str, str]:
        """(config, pidfile, logfile) for a named client connection."""
        return (
            os.path.join(self.config_dir, "client", f"{connection_name}.conf"),
            os.path.join(self.run_dir, f"{connection_name}.pid"),
            os.path.join(self.log_dir, f"{connection_name}.log"),
        )

    @staticmethod
    def _read_pid(pidfile: str) -> int | None:
        try:
            with open(pidfile) as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError, OSError):
            return None

    @staticmethod
    def _pid_alive(pid: int | None) -> bool:
        if pid is None:
            return False
        try:
            os.kill(pid, 0)  # signal 0 = existence check, no signal delivered
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists but owned by another uid

    @staticmethod
    def _remove_pidfile(pidfile: str) -> None:
        try:
            os.remove(pidfile)
        except FileNotFoundError:
            pass
        except OSError:
            logger.debug("Could not remove stale openvpn pidfile %s", pidfile, exc_info=True)

    async def get_connections(self) -> list[VPNConnection]:
        """List configured OpenVPN connections."""
        connections: list[VPNConnection] = []
        try:
            import glob

            configs = glob.glob(f"{self.config_dir}/client/*.conf") + glob.glob(
                f"{self.config_dir}/*.conf"
            )
            for cfg in configs:
                name = os.path.splitext(os.path.basename(cfg))[0]
                status = await self._get_connection_status(name)
                connections.append(
                    VPNConnection(
                        id=f"openvpn-{name}",
                        name=f"OpenVPN ({name})",
                        vpn_type=VPNType.OPENVPN,
                        status=status,
                        extra_data={"config_path": cfg},
                    )
                )
        except Exception as e:
            logger.warning("Failed to list OpenVPN connections: %s", e)
        return connections

    async def _get_connection_status(self, connection_name: str) -> VPNStatus:
        """Check whether the managed OpenVPN process for ``connection_name`` is
        running, and whether its tunnel has finished initialising.

        Container-friendly replacement for ``systemctl is-active``: the process
        is tracked by a pidfile we wrote at connect-time; the log tells us
        whether the tunnel actually came up ("Initialization Sequence Completed")
        versus still negotiating.
        """
        if not _is_safe_unit_instance(connection_name):
            logger.warning("OpenVPN: rejecting unsafe connection name %r", connection_name)
            return VPNStatus.NOT_CONFIGURED
        cfg, pidfile, logfile = self._paths(connection_name)
        if self.sidecar:
            # the privileged sidecar owns the process; read the status it publishes
            try:
                with open(os.path.join(self.run_dir, f"{connection_name}.status")) as f:
                    state = f.read().strip()
            except (FileNotFoundError, OSError):
                state = ""
            if state == "connected":
                return VPNStatus.CONNECTED
            if state == "connecting":
                return VPNStatus.CONNECTING
            return VPNStatus.DISCONNECTED if os.path.exists(cfg) else VPNStatus.NOT_CONFIGURED
        if not self._pid_alive(self._read_pid(pidfile)):
            # not running — configured (DISCONNECTED) iff a config exists, else NOT_CONFIGURED
            return VPNStatus.DISCONNECTED if os.path.exists(cfg) else VPNStatus.NOT_CONFIGURED
        try:
            with open(logfile, encoding="utf-8", errors="ignore") as f:
                tail = f.read()[-4000:]
            if "Initialization Sequence Completed" in tail:
                return VPNStatus.CONNECTED
        except OSError:
            pass
        return VPNStatus.CONNECTING

    async def get_status(self, connection_name: str) -> dict[str, Any]:
        """Get detailed status of OpenVPN connection."""
        status = await self._get_connection_status(connection_name)
        result: dict[str, Any] = {
            "name": connection_name,
            "status": status.value,
            "connected": status == VPNStatus.CONNECTED,
            "local_ip": None,
            "remote_ip": None,
            "bytes_received": 0,
            "bytes_sent": 0,
        }

        if status == VPNStatus.CONNECTED:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip",
                    "addr",
                    "show",
                    "tun0",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode()
                # Parse tun0 IP
                for line in output.split("\n"):
                    line = line.strip()
                    if line.startswith("inet "):
                        parts = line.split()
                        result["local_ip"] = parts[1].split("/")[0]
                        if "peer" in parts:
                            idx = parts.index("peer")
                            result["remote_ip"] = parts[idx + 1].split("/")[0]
            except Exception:
                logger.debug("Failed to parse OpenVPN tun0 IP address", exc_info=True)

        return result

    def _materialize_config(self, connection_name: str, content: str) -> str:
        """Write the .ovpn ``content`` to the daemon's config path (0600, atomic).

        The daemon (here, or the privileged sidecar supervisor) consumes
        ``/etc/openvpn/client/<name>.conf``; the app stores the config text in the
        DB, so SOMETHING must put it on disk before connect — that missing step is
        why an app-configured OpenVPN connection never came up. Written 0600 (it
        can carry inline private keys) on the shared openvpn_config volume, which
        the sidecar chowns to the app uid so this unprivileged process can write.
        """
        # Re-validate at the disk chokepoint: this runs regardless of how the row
        # was populated (legacy rows written before the schema validator existed),
        # so a dangerous directive can never reach the root daemon via this path.
        _assert_openvpn_config_safe(content)
        cfg = self._paths(connection_name)[0]
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(cfg), prefix=f".{connection_name}.", suffix=".tmp"
        )
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cfg)  # atomic
        return cfg

    async def connect(
        self, connection_name: str, config_content: str | None = None
    ) -> dict[str, Any]:
        """Start an OpenVPN client connection as a managed daemon process.

        Replaces ``systemctl start openvpn-client@`` (no systemd in a container).
        Runs ``openvpn --daemon`` so it backgrounds itself, recording its pid via
        ``--writepid`` and output via ``--log`` so status/disconnect can find it.
        Needs CAP_NET_ADMIN + /dev/net/tun (granted in compose).

        ``config_content`` (the stored .ovpn text) is materialized to the on-disk
        config path first; without it connect() requires a pre-existing file.
        """
        if not _is_safe_unit_instance(connection_name):
            return {"success": False, "message": "Invalid connection name"}
        cfg, pidfile, logfile = self._paths(connection_name)
        if config_content:
            try:
                self._materialize_config(connection_name, config_content)
            except ValueError as e:
                return {"success": False, "message": f"Rejected OpenVPN config: {e}"}
            except OSError as e:
                return {"success": False, "message": f"Could not write OpenVPN config: {e}"}
        if not os.path.exists(cfg):
            return {"success": False, "message": f"No OpenVPN config found at {cfg}"}
        if self.sidecar:
            # hand desired-state to the sidecar (touch a marker); it brings it up
            try:
                os.makedirs(self.desired_dir, exist_ok=True)
                with open(os.path.join(self.desired_dir, connection_name), "w"):
                    pass
            except OSError as e:
                return {"success": False, "message": f"Could not request connection: {e}"}
            return {
                "success": True,
                "message": f"OpenVPN {connection_name} requested (the VPN sidecar will bring it up)",
            }
        if self._pid_alive(self._read_pid(pidfile)):
            return {"success": True, "message": f"OpenVPN {connection_name} is already running"}
        try:
            os.makedirs(self.run_dir, exist_ok=True)
            os.makedirs(self.log_dir, exist_ok=True)
            result = await asyncio.create_subprocess_exec(
                "openvpn",
                "--config",
                cfg,
                "--cd",
                os.path.join(self.config_dir, "client"),  # resolve relative cert paths
                "--daemon",
                f"ovpn-{connection_name}",
                "--writepid",
                pidfile,
                "--log",
                logfile,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(result.communicate(), timeout=20)
            # --daemon: the launching process double-forks and exits 0; rc!=0 means
            # openvpn rejected the args/config before backgrounding.
            if result.returncode not in (0, None):
                return {
                    "success": False,
                    "message": stderr.decode().strip() or "openvpn failed to start",
                }
            await asyncio.sleep(1.0)  # let the daemon write its pidfile + begin negotiating
            status = await self._get_connection_status(connection_name)
            if status in (VPNStatus.CONNECTED, VPNStatus.CONNECTING):
                return {
                    "success": True,
                    "message": f"OpenVPN {connection_name} started ({status.value})",
                }
            return {
                "success": False,
                "message": f"OpenVPN {connection_name} did not stay up; check {logfile}",
            }
        except FileNotFoundError:
            return {"success": False, "message": "openvpn is not installed in this container"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def disconnect(self, connection_name: str) -> dict[str, Any]:
        """Stop the managed OpenVPN process (SIGTERM, then SIGKILL if it lingers).

        Replaces ``systemctl stop openvpn-client@``.
        """
        if not _is_safe_unit_instance(connection_name):
            return {"success": False, "message": "Invalid connection name"}
        if self.sidecar:
            try:
                os.remove(os.path.join(self.desired_dir, connection_name))
            except FileNotFoundError:
                pass
            except OSError as e:
                return {"success": False, "message": f"Could not request disconnect: {e}"}
            return {
                "success": True,
                "message": f"OpenVPN {connection_name} stop requested (sidecar will take it down)",
            }
        _, pidfile, _ = self._paths(connection_name)
        pid = self._read_pid(pidfile)
        if not self._pid_alive(pid):
            self._remove_pidfile(pidfile)
            return {"success": True, "message": f"OpenVPN {connection_name} is not running"}
        try:
            os.kill(pid, signal.SIGTERM)  # type: ignore[arg-type]
            for _ in range(20):  # up to ~5s for a graceful exit
                await asyncio.sleep(0.25)
                if not self._pid_alive(pid):
                    break
            else:
                try:
                    os.kill(pid, signal.SIGKILL)  # type: ignore[arg-type]
                except ProcessLookupError:
                    pass
            self._remove_pidfile(pidfile)
            return {"success": True, "message": f"OpenVPN {connection_name} stopped"}
        except ProcessLookupError:
            self._remove_pidfile(pidfile)
            return {"success": True, "message": f"OpenVPN {connection_name} already stopped"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def cleanup(self, connection_name: str) -> None:
        """Disconnect AND remove the materialized config (used on connection delete)
        so no tunnel is left running and no .ovpn key material lingers on disk."""
        if not _is_safe_unit_instance(connection_name):
            return
        try:
            await self.disconnect(connection_name)
        except Exception:
            logger.debug("OpenVPN cleanup disconnect failed", exc_info=True)
        for p in (
            self._paths(connection_name)[0],
            os.path.join(self.run_dir, f"{connection_name}.status"),
        ):
            try:
                os.remove(p)
            except OSError:
                pass

    async def check_health(self, connection_name: str) -> dict[str, Any]:
        """Check health of OpenVPN tunnel."""
        status_data = await self.get_status(connection_name)
        healthy = status_data["connected"]
        latency = None

        remote_ip = status_data.get("remote_ip")
        if healthy and remote_ip and _is_safe_host_token(remote_ip):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "3",
                    "--",
                    remote_ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode == 0:
                    output = stdout.decode()
                    if "time=" in output:
                        latency = float(output.split("time=")[-1].split(" ")[0])
            except Exception:
                logger.debug("VPN latency ping failed for %s", connection_name, exc_info=True)

        return {
            "connection": connection_name,
            "healthy": healthy,
            "latency_ms": latency,
            **status_data,
        }


# =============================================================================
# Netbird Service
# =============================================================================


class NetbirdService:
    """
    Service for managing Netbird VPN connections.

    Netbird is a WireGuard-based mesh VPN (similar to Tailscale) that provides:
    - Zero-config mesh networking
    - ACL-based access control
    - Self-hosted management server support
    - Peer-to-peer connectivity
    """

    def __init__(self, management_url: str | None = None):
        self.management_url = management_url or os.environ.get(
            "NETBIRD_MANAGEMENT_URL", "https://api.netbird.io"
        )
        # In the sidecar topology the NetBird daemon runs in the privileged `vpn`
        # container while THIS process (api/worker) only runs the `netbird` CLI.
        # They share a network namespace but NOT a filesystem, so the default
        # unix socket (/var/run/netbird.sock) created by the daemon is not visible
        # here. Point both ends at a tcp daemon address (carried by the shared
        # netns) via NETBIRD_DAEMON_ADDR — the sidecar daemon LISTENS on it, this
        # CLI CONNECTS to it. Unset (single-container deploys) ⇒ default socket.
        self.daemon_addr = os.environ.get("NETBIRD_DAEMON_ADDR") or None
        self._status_cache: dict[str, Any] | None = None
        self._cache_time: datetime | None = None
        self._cache_ttl_seconds = 30

    def _nb_cmd(self, subcommand: str, *args: str) -> tuple[str, ...]:
        """Build a ``netbird`` argv, injecting ``--daemon-addr`` when configured.

        ``--daemon-addr`` is a per-subcommand flag, so it goes right after the
        subcommand (``netbird status --daemon-addr tcp://… --json``).
        """
        addr_flag = ("--daemon-addr", self.daemon_addr) if self.daemon_addr else ()
        return ("netbird", subcommand, *addr_flag, *args)

    async def get_status(self, refresh: bool = False) -> dict[str, Any]:
        """Get Netbird daemon status."""
        if not refresh and self._status_cache and self._cache_time:
            elapsed = (datetime.now(UTC) - self._cache_time).total_seconds()
            if elapsed < self._cache_ttl_seconds:
                return self._status_cache

        try:
            result = await asyncio.create_subprocess_exec(
                *self._nb_cmd("status", "--json"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=15)

            if result.returncode != 0:
                logger.error("Netbird status error: %s", stderr.decode())
                return {"connected": False, "management_state": "Error", "peers": []}

            data = json.loads(stdout.decode())
            status = self._parse_status(data)

            self._status_cache = status
            self._cache_time = datetime.now(UTC)

            return status

        except FileNotFoundError:
            logger.debug("Netbird CLI not found")
            return {"connected": False, "management_state": "NotInstalled", "peers": []}
        except Exception as e:
            logger.error("Failed to get Netbird status: %s", e)
            return {"connected": False, "management_state": "Error", "peers": []}

    def _parse_status(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse Netbird status JSON output."""
        # `or {}` / `or []` guard the NeedsLogin state: a reachable-but-not-yet-
        # authenticated daemon emits `"peers": null` (and null management/signal),
        # so `.get(k, {})` returns None and the parse would crash — reporting
        # management_state="Error" for a correctly-wired daemon.
        peers = []
        for peer in (data.get("peers") or {}).get("details") or []:
            peers.append(
                {
                    "id": peer.get("fqdn", peer.get("ip", "")),
                    "name": peer.get("fqdn", "").split(".")[0],
                    "hostname": peer.get("fqdn", ""),
                    "ip": peer.get("ip", ""),
                    "status": peer.get("connStatus", "disconnected"),
                    "direct": peer.get("direct", False),
                    "relay": peer.get("relayAddress", ""),
                    "last_handshake": peer.get("lastWireguardHandshake", ""),
                    "routes": peer.get("routes", []),
                }
            )

        mgmt = data.get("management") or {}
        signal = data.get("signal") or {}
        management_connected = mgmt.get("connected", False)
        signal_connected = signal.get("connected", False)

        return {
            "connected": management_connected and signal_connected,
            "management_state": "Running" if management_connected else "Disconnected",
            "signal_state": "Running" if signal_connected else "Disconnected",
            "management_url": mgmt.get("url", ""),
            "self_ip": data.get("ip", ""),
            "fqdn": data.get("fqdn", ""),
            "interface": data.get("interfaceName", ""),
            "peers": peers,
            "peer_count": len(peers),
            "connected_peers": sum(1 for p in peers if p["status"] == "connected"),
        }

    async def list_peers(self) -> list[dict[str, Any]]:
        """List all Netbird peers (including self)."""
        status = await self.get_status(refresh=True)
        result: list[dict[str, Any]] = status.get("peers", [])
        return result

    async def get_peer(self, name_or_ip: str) -> dict[str, Any] | None:
        """Get a peer by name or IP."""
        status = await self.get_status()
        peers: list[dict[str, Any]] = status.get("peers", [])
        for peer in peers:
            if peer["name"] == name_or_ip or peer["ip"] == name_or_ip:
                return peer
            if name_or_ip in peer.get("hostname", ""):
                return peer
        return None

    async def ping(self, target: str, timeout: float = 5.0) -> float | None:
        """Ping a Netbird peer."""
        if not _is_safe_host_token(target):
            logger.warning("Netbird ping: rejecting unsafe target %r", target)
            return None
        try:
            result = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                "1",
                "-W",
                str(int(timeout)),
                "--",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                result.communicate(),
                timeout=timeout + 1,
            )

            if result.returncode == 0:
                output = stdout.decode()
                if "time=" in output:
                    latency_str = output.split("time=")[-1].split(" ")[0]
                    return float(latency_str)
            return None
        except Exception as e:
            logger.debug("Netbird ping failed: %s", e)
            return None

    async def connect(
        self, setup_key: str | None = None, management_url: str | None = None
    ) -> dict[str, Any]:
        """Connect Netbird (register the peer + bring up the daemon).

        A fresh daemon is in NeedsLogin until it is registered with a management
        server via a setup key — bare ``netbird up`` would sit unauthenticated
        forever. The setup key is passed via ``--setup-key-file`` (a 0600 temp
        file we delete immediately) rather than ``--setup-key`` so the secret
        never lands on the process arg list (/proc/<pid>/cmdline). ``--management-url``
        targets a self-hosted management server when the connection specifies one.
        """
        key_file: str | None = None
        try:
            extra: list[str] = []
            if management_url:
                extra += ["--management-url", management_url]
            if setup_key:
                fd, key_file = tempfile.mkstemp(prefix="nb-setup-", suffix=".key")
                try:
                    os.write(fd, setup_key.encode("utf-8"))
                finally:
                    os.close(fd)
                os.chmod(key_file, 0o600)
                extra += ["--setup-key-file", key_file]
            # Clear any stale daemon state first. A daemon left pointing at a
            # different management server (e.g. the boot-time default) does NOT
            # reliably switch management on a plain `up` — it sits in a dial
            # backoff. `down` first makes (re)connecting to the requested
            # management deterministic; it is best-effort + idempotent (a no-op if
            # already down). Only when we have something to (re)register with.
            if setup_key or management_url:
                try:
                    down = await asyncio.create_subprocess_exec(
                        *self._nb_cmd("down"),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(down.communicate(), timeout=20)
                except Exception:
                    pass
            result = await asyncio.create_subprocess_exec(
                *self._nb_cmd("up", *extra),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=60)
            except TimeoutError:
                result.kill()  # don't leak the backing-off CLI process
                await result.communicate()
                return {
                    "success": False,
                    "message": "netbird up timed out — could not reach the management server "
                    "(check the management URL / setup key)",
                }
            if result.returncode == 0:
                return {"success": True, "message": "Netbird connected"}
            # The netbird CLI prints registration errors ("Error: daemon up
            # failed: …") to stdout, not stderr — fall back to stdout so the
            # failure is never reported with an empty message.
            msg = stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip()
            return {"success": False, "message": msg or "netbird up failed"}
        except Exception as e:
            return {"success": False, "message": str(e) or repr(e)}
        finally:
            if key_file:
                try:
                    os.remove(key_file)
                except OSError:
                    pass

    async def disconnect(self) -> dict[str, Any]:
        """Disconnect Netbird."""
        try:
            result = await asyncio.create_subprocess_exec(
                *self._nb_cmd("down"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)
            if result.returncode == 0:
                return {"success": True, "message": "Netbird disconnected"}
            return {"success": False, "message": stderr.decode().strip()}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def discover_site_devices(self, subnet: str) -> list[dict[str, Any]]:
        """Discover devices accessible via Netbird routes."""
        status = await self.get_status()
        subnet_network = ipaddress.ip_network(subnet, strict=False)
        devices = []
        for peer in status.get("peers", []):
            for route in peer.get("routes", []):
                try:
                    route_network = ipaddress.ip_network(route, strict=False)
                    if route_network.overlaps(subnet_network):
                        devices.append(
                            {
                                "node": peer["name"],
                                "node_ip": peer["ip"],
                                "advertised_subnet": route,
                                "online": peer["status"] == "connected",
                            }
                        )
                except ValueError:
                    continue
        return devices


# =============================================================================
# VPN Manager Service
# =============================================================================


class VPNManagerService:
    """
    High-level VPN management service.

    Aggregates Tailscale, WireGuard, OpenVPN, and Netbird services for unified management.
    """

    def __init__(
        self,
        tailscale_api_key: str | None = None,
        wireguard_config_dir: str = "/etc/wireguard",
        openvpn_config_dir: str = "/etc/openvpn",
        netbird_management_url: str | None = None,
    ):
        self.tailscale = TailscaleService(api_key=tailscale_api_key)
        self.wireguard = WireGuardService(config_dir=wireguard_config_dir)
        self.openvpn = OpenVPNService(config_dir=openvpn_config_dir)
        self.netbird = NetbirdService(management_url=netbird_management_url)

    async def get_all_connections(self) -> list[VPNConnection]:
        """Get all VPN connections from all providers."""
        connections: list[VPNConnection] = []

        # Get Tailscale status
        try:
            ts_status = await self.tailscale.get_status()
            if ts_status.is_connected and ts_status.self_node:
                connections.append(
                    VPNConnection(
                        id="tailscale-self",
                        name=f"Tailscale ({ts_status.tailnet_name})",
                        vpn_type=VPNType.TAILSCALE,
                        status=VPNStatus.CONNECTED,
                        extra_data={
                            "self_ip": ts_status.self_node.primary_ip,
                            "peer_count": len(ts_status.peers),
                            "magic_dns": ts_status.magic_dns_enabled,
                        },
                    )
                )
        except Exception as e:
            logger.warning("Failed to get Tailscale status: %s", e)

        # Get WireGuard tunnels
        try:
            wg_tunnels = await self.wireguard.get_all_tunnels()
            connections.extend(wg_tunnels)
        except Exception as e:
            logger.warning("Failed to get WireGuard status: %s", e)

        # Get OpenVPN connections
        try:
            ovpn_conns = await self.openvpn.get_connections()
            connections.extend(ovpn_conns)
        except Exception as e:
            logger.warning("Failed to get OpenVPN status: %s", e)

        # Get Netbird status
        try:
            nb_status = await self.netbird.get_status()
            if nb_status.get("connected"):
                connections.append(
                    VPNConnection(
                        id="netbird-self",
                        name=f"Netbird ({nb_status.get('fqdn', 'mesh')})",
                        vpn_type=VPNType.NETBIRD,
                        status=VPNStatus.CONNECTED,
                        extra_data={
                            "self_ip": nb_status.get("self_ip"),
                            "peer_count": nb_status.get("peer_count", 0),
                            "connected_peers": nb_status.get("connected_peers", 0),
                            "management_url": nb_status.get("management_url"),
                        },
                    )
                )
        except Exception as e:
            logger.warning("Failed to get Netbird status: %s", e)

        return connections

    async def check_site_connectivity(
        self,
        site_subnet: str,
    ) -> dict[str, Any]:
        """Check connectivity to a remote site subnet via any VPN provider."""
        result: dict[str, Any] = {
            "subnet": site_subnet,
            "reachable": False,
            "vpn_type": None,
            "via_node": None,
        }

        # Check Tailscale routes
        try:
            ts_routes = await self.tailscale.discover_site_devices(site_subnet)
            if ts_routes:
                for route in ts_routes:
                    if route["online"]:
                        result["reachable"] = True
                        result["vpn_type"] = VPNType.TAILSCALE.value
                        result["via_node"] = route["node"]
                        return result
        except Exception:
            logger.warning(
                "Tailscale route discovery failed for subnet %s", site_subnet, exc_info=True
            )

        # Check Netbird routes
        try:
            nb_devices = await self.netbird.discover_site_devices(site_subnet)
            if nb_devices:
                for dev in nb_devices:
                    if dev["online"]:
                        result["reachable"] = True
                        result["vpn_type"] = VPNType.NETBIRD.value
                        result["via_node"] = dev["node"]
                        return result
        except Exception:
            logger.warning(
                "Netbird device discovery failed for subnet %s", site_subnet, exc_info=True
            )

        return result

    async def discover_vpn_accessible_subnets(self) -> list[dict[str, Any]]:
        """
        Discover all subnets accessible through any VPN provider.
        Returns a list of subnet info dicts with via, node, interface info.
        """
        subnets: list[dict[str, Any]] = []

        # Tailscale advertised routes
        try:
            ts_status = await self.tailscale.get_status()
            for peer in ts_status.peers:
                for route in peer.advertised_routes:
                    subnets.append(
                        {
                            "subnet": route,
                            "via": "tailscale",
                            "node": peer.name,
                            "interface": None,
                            "direct": peer.direct,
                        }
                    )
        except Exception:
            logger.warning("Failed to discover Tailscale subnets", exc_info=True)

        # Netbird routes
        try:
            nb_status = await self.netbird.get_status()
            for peer in nb_status.get("peers", []):
                for route in peer.get("routes", []):
                    subnets.append(
                        {
                            "subnet": route,
                            "via": "netbird",
                            "node": peer["name"],
                            "interface": nb_status.get("interface"),
                            "direct": peer.get("direct", False),
                        }
                    )
        except Exception:
            logger.warning("Failed to discover Netbird subnets", exc_info=True)

        # WireGuard allowed IPs
        try:
            wg_tunnels = await self.wireguard.get_all_tunnels()
            for tunnel in wg_tunnels:
                for ip in tunnel.allowed_ips:
                    subnets.append(
                        {
                            "subnet": ip,
                            "via": "wireguard",
                            "node": tunnel.name,
                            "interface": tunnel.name,
                            "direct": True,
                        }
                    )
        except Exception:
            logger.warning("Failed to discover WireGuard subnets", exc_info=True)

        return subnets

    async def get_status_summary(self) -> dict[str, Any]:
        """Get summary of all VPN statuses."""
        connections = await self.get_all_connections()

        connected = sum(1 for c in connections if c.status == VPNStatus.CONNECTED)
        disconnected = sum(1 for c in connections if c.status == VPNStatus.DISCONNECTED)
        error = sum(1 for c in connections if c.status == VPNStatus.ERROR)

        return {
            "total_connections": len(connections),
            "connected": connected,
            "disconnected": disconnected,
            "error": error,
            "connections": [c.to_dict() for c in connections],
        }


# =============================================================================
# Singleton Instance
# =============================================================================

_vpn_manager: VPNManagerService | None = None


def get_vpn_manager() -> VPNManagerService:
    """Get or create the global VPN manager."""
    global _vpn_manager
    if _vpn_manager is None:
        _vpn_manager = VPNManagerService()
    return _vpn_manager


# =============================================================================
# Persistent VPN Service (DB-backed)
# =============================================================================


class PersistentVPNService:
    """
    DB-backed VPN service that persists connection state, site configs,
    and health check results. Bridges the in-memory VPN managers with
    the database for UI consumption.
    """

    # ------- Connection Records -------

    @staticmethod
    async def list_connections(
        session: "AsyncSession",
        organization_id: "UUID | None" = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list["VPNConnectionRecord"]:
        from sqlalchemy import select

        from app.models.vpn import VPNConnectionRecord

        stmt = select(VPNConnectionRecord)
        if organization_id:
            stmt = stmt.where(VPNConnectionRecord.organization_id == organization_id)
        stmt = stmt.order_by(VPNConnectionRecord.name)
        if limit is not None:
            stmt = stmt.limit(limit).offset(offset)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def upsert_connection(
        session: "AsyncSession",
        name: str,
        vpn_type: str,
        status: str,
        **kwargs: Any,
    ) -> "VPNConnectionRecord":
        """Create or update a VPN connection record."""
        from sqlalchemy import select

        from app.models.vpn import VPNConnectionRecord

        org_id = kwargs.get("organization_id")
        q = select(VPNConnectionRecord).where(VPNConnectionRecord.name == name)
        if org_id:
            q = q.where(VPNConnectionRecord.organization_id == org_id)
        result = await session.execute(q)
        record = result.scalar_one_or_none()
        if record:
            record.vpn_type = vpn_type
            record.status = status
            for k, v in kwargs.items():
                if hasattr(record, k) and v is not None:
                    setattr(record, k, v)
        else:
            record = VPNConnectionRecord(
                name=name,
                vpn_type=vpn_type,
                status=status,
                **kwargs,
            )
            session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def sync_live_connections(session: "AsyncSession") -> int:
        """
        Sync live VPN state (from Tailscale/WireGuard CLI) into the database.
        Called periodically by Celery task.
        """
        manager = get_vpn_manager()
        synced = 0

        try:
            connections = await manager.get_all_connections()
            for conn in connections:
                await PersistentVPNService.upsert_connection(
                    session,
                    name=conn.name,
                    vpn_type=conn.vpn_type.value
                    if hasattr(conn.vpn_type, "value")
                    else conn.vpn_type,
                    status=conn.status.value if hasattr(conn.status, "value") else conn.status,
                    endpoint=conn.endpoint,
                    rx_bytes=conn.rx_bytes,
                    tx_bytes=conn.tx_bytes,
                    latency_ms=conn.latency_ms,
                    connected_at=conn.connected_at,
                    last_handshake=conn.last_handshake,
                    extra_data=conn.extra_data,
                )
                synced += 1
        except Exception as e:
            logger.debug("Error syncing live connections: %s", e)

        return synced

    # ------- Site VPN Config -------

    @staticmethod
    async def get_site_config(
        session: "AsyncSession",
        site_id: "UUID",
    ) -> "SiteVPNConfiguration | None":
        from sqlalchemy import select

        from app.models.vpn import SiteVPNConfiguration

        result = await session.execute(
            select(SiteVPNConfiguration).where(SiteVPNConfiguration.site_id == site_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def upsert_site_config(
        session: "AsyncSession",
        site_id: "UUID",
        data: dict[str, Any],
        created_by: "UUID | None" = None,
    ) -> "SiteVPNConfiguration":
        from sqlalchemy import select

        from app.models.vpn import SiteVPNConfiguration

        result = await session.execute(
            select(SiteVPNConfiguration).where(SiteVPNConfiguration.site_id == site_id)
        )
        config = result.scalar_one_or_none()
        if config:
            for k, v in data.items():
                if v is not None and hasattr(config, k):
                    setattr(config, k, v)
        else:
            config = SiteVPNConfiguration(site_id=site_id, **data)
            if created_by:
                config.created_by = created_by
            session.add(config)
        await session.flush()
        return config

    # ------- Health Checks -------

    @staticmethod
    async def record_health_check(
        session: "AsyncSession",
        connection_id: "UUID",
        site_id: "UUID | None",
        is_healthy: bool,
        latency_ms: float | None,
        status: str,
        error_message: str | None = None,
        rx_bytes: int = 0,
        tx_bytes: int = 0,
        peer_count: int = 0,
    ) -> None:
        from app.models.vpn import VPNHealthCheck

        check = VPNHealthCheck(
            time=datetime.now(UTC),
            connection_id=connection_id,
            site_id=site_id,
            is_healthy=is_healthy,
            latency_ms=latency_ms,
            status=status,
            error_message=error_message,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            peer_count=peer_count,
        )
        session.add(check)
        await session.flush()

    @staticmethod
    async def get_health_history(
        session: "AsyncSession",
        connection_id: "UUID",
        hours: int = 24,
        limit: int = 100,
    ) -> list[Any]:
        from sqlalchemy import text

        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        result = await session.execute(
            text("""
                SELECT time, is_healthy, latency_ms, status, error_message, rx_bytes, tx_bytes, peer_count
                FROM vpn.vpn_health_checks
                WHERE connection_id = :conn_id AND time >= :cutoff
                ORDER BY time DESC
                LIMIT :limit
            """),
            {"conn_id": connection_id, "cutoff": cutoff, "limit": limit},
        )
        return [dict(row._mapping) for row in result.fetchall()]

    # ------- Status Summary -------

    @staticmethod
    async def get_status_summary(
        session: "AsyncSession",
    ) -> dict[str, Any]:
        from sqlalchemy import func, select

        from app.models.vpn import VPNConnectionRecord

        q = select(
            func.count().label("total"),
            func.count().filter(VPNConnectionRecord.status == "connected").label("connected"),
            func.count().filter(VPNConnectionRecord.status == "disconnected").label("disconnected"),
            func.count().filter(VPNConnectionRecord.status == "error").label("errors"),
            func.sum(VPNConnectionRecord.rx_bytes).label("total_rx"),
            func.sum(VPNConnectionRecord.tx_bytes).label("total_tx"),
        ).select_from(VPNConnectionRecord)

        row = (await session.execute(q)).one()
        return {
            "total_connections": row.total,
            "connected": row.connected,
            "disconnected": row.disconnected,
            "error": row.errors,
            "tailscale_connected": False,
            "wireguard_tunnels": 0,
            "total_peers": 0,
            "total_rx_bytes": row.total_rx or 0,
            "total_tx_bytes": row.total_tx or 0,
        }

    # ------- Cleanup -------

    @staticmethod
    async def purge_old_health_checks(
        session: "AsyncSession",
        retention_days: int = 30,
    ) -> int:
        from sqlalchemy import text

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        result = await session.execute(
            text("DELETE FROM vpn.vpn_health_checks WHERE time < :cutoff"),
            {"cutoff": cutoff},
        )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]
