# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Base Adapter
==========================

Abstract base class for all vendor adapters.
Provides standardized interface for device management across vendors.
"""

import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

from app.adapters.capabilities import Capability

logger = logging.getLogger(__name__)


class AdapterMaturity(StrEnum):
    """Honest live-validation status of an adapter — drives UI badges + docs.

    Mirrors the FEATURE-READINESS honesty rule: an adapter is **VERIFIED only
    once proven against real hardware**, so the manifest default is
    EXPERIMENTAL. Never label VERIFIED on assumption (protocol similarity) alone
    — that is exactly the "oversell" this field exists to prevent.
    """

    VERIFIED = "verified"
    """Live-tested against real hardware. Safe to present as supported."""

    EXPERIMENTAL = "experimental"
    """Implemented but NOT yet verified on real hardware (e.g. ONVIF-generic
    cameras, an assumed-compatible firewall). Works in principle; use at your
    own risk and please report results."""

    PLANNED = "planned"
    """Declared but no working adapter behind it. Must NOT be shippable as a
    selectable option — surfaced only for roadmap/docs."""


class WriteMaturity(StrEnum):
    """Honest proof-state of an adapter's WRITE surface, GRADED SEPARATELY from
    reads.

    Reads being live-validated (the ``AdapterMaturity`` grade) does NOT mean the
    writes are: a release-honesty audit found most adapters' write paths are
    code-complete + unit-tested but never proven on real hardware. This field
    exists so a public badge says "Reads: Verified · Writes: mock-tested" instead
    of a single ``Verified`` that oversells the writes. Default is MOCK_TESTED —
    the honest, non-overselling default (a write is only LIVE_VALIDATED with
    PERSISTED real-device evidence: a recorded cassette or reproducible record).
    """

    LIVE_VALIDATED = "live_validated"
    """Core write paths proven on real hardware with persisted evidence."""

    PARTIAL = "partial"
    """Some write paths proven live (persisted); others mock-tested only."""

    MOCK_TESTED = "mock_tested"
    """Write code exists + unit-tested against mocks/stubs; NOT yet proven on
    real hardware. The honest default for an unproven write surface."""

    DISABLED = "disabled"
    """Writes intentionally turned off by design (e.g. Proxmox read-only)."""

    NOT_IMPLEMENTED = "not_implemented"
    """Write transport not built."""

    EXPERIMENTAL = "experimental"
    """Experimental adapter — writes not verified."""


# =============================================================================
# SSRF Host Validation
# =============================================================================

# Hostnames that resolve to cloud metadata endpoints
_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "169.254.169.254",
    }
)


def validate_host(host: str) -> str:
    """Validate a host string is safe to connect to (SSRF prevention).

    Blocks:
    - Loopback addresses (127.0.0.0/8, ::1)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
    - Known dangerous hostnames

    Allows:
    - RFC1918 private addresses (10.x, 172.16-31.x, 192.168.x) — required for on-prem NVRs
    - All public addresses

    Returns the validated host string.
    Raises ValueError if the host is blocked.
    """
    # Strip protocol prefix if accidentally included
    clean = host.strip().lower()
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    # Strip port suffix
    if ":" in clean and not clean.startswith("["):
        clean = clean.rsplit(":", 1)[0]

    # Check blocked hostnames
    if clean in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Blocked host: connection to {clean} is not allowed")

    # Try to parse as IP address
    try:
        ipaddress.ip_address(clean)
        # F5-sibling: use the CENTRAL SSRF blocklist instead of ad-hoc checks —
        # loopback / link-local / multicast / reserved / unspecified PLUS every
        # cloud-metadata literal (AWS/GCP/Azure 169.254.169.254, Alibaba
        # 100.100.100.200, Oracle 192.0.0.192, AWS IPv6 fd00:ec2::254). RFC1918
        # stays allowed (required for on-prem gear).
        from app.core.security_utils import is_ssrf_blocked_ip

        if is_ssrf_blocked_ip(clean):
            raise ValueError(f"Blocked host: {clean} is an SSRF-unsafe address")
    except ValueError as e:
        if "Blocked host" in str(e):
            raise
        # Not a valid IP — must be a hostname, check against blocked list
        pass

    return host


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class AdapterManifest:
    """
    Adapter metadata describing capabilities and configuration.

    Each adapter defines its manifest to declare:
    - Vendor and version information
    - Supported device types and their capabilities
    - Authentication requirements
    - Rate limiting configuration
    """

    # Identification
    id: str
    name: str
    vendor: str
    version: str
    description: str

    # Controller/device support
    controller_type: str | None = None
    supports_controller: bool = True
    supports_direct: bool = False

    # Version support
    supported_versions: list[str] = field(default_factory=list)

    # Device types and capabilities
    device_types: dict[str, "DeviceTypeCapabilities"] = field(default_factory=dict)

    # Authentication
    auth_methods: list[str] = field(default_factory=lambda: ["username_password"])

    # Rate limiting
    rate_limit_calls_per_minute: int = 60
    rate_limit_concurrent: int = 5

    # Sync intervals
    default_sync_interval: int = 300  # 5 minutes
    min_sync_interval: int = 60

    # Features
    supports_webhooks: bool = False
    supports_real_time_events: bool = False
    supports_bulk_operations: bool = False


@dataclass
class DeviceTypeCapabilities:
    """Capabilities for a specific device type."""

    module: str  # Which module handles this device type
    capabilities: list[Capability]
    models: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class DiscoveredDevice:
    """Device discovered by adapter."""

    mac_address: str
    ip_address: str | None
    name: str
    vendor: str
    model: str
    firmware_version: str | None
    device_type: str  # ap, switch, router, camera, nvr, phone, etc.
    status: str  # online, offline, unknown
    serial_number: str | None = None
    capabilities: list[Capability] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "name": self.name,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "device_type": self.device_type,
            "status": self.status,
            "serial_number": self.serial_number,
            "capabilities": [c.value for c in self.capabilities],
        }


@dataclass
class AdapterResult:
    """Standard result from adapter operations."""

    success: bool
    data: Any | None = None
    message: str | None = None
    error: str | None = None
    error_code: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def ok(
        cls,
        data: Any = None,
        message: str | None = None,
    ) -> "AdapterResult":
        """Create successful result."""
        return cls(success=True, data=data, message=message)

    @classmethod
    def fail(
        cls,
        error: str,
        error_code: str | None = None,
        message: str | None = None,
    ) -> "AdapterResult":
        """Create failed result."""
        return cls(
            success=False,
            message=message,
            error=error,
            error_code=error_code,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict representation."""
        return {
            "success": self.success,
            "data": self.data,
            "message": self.message,
            "error": self.error,
            "error_code": self.error_code,
            "timestamp": self.timestamp.isoformat(),
        }


# Legacy support - keep AdapterDevice for backwards compatibility
@dataclass
class AdapterDevice:
    """
    Normalized device representation from adapter.

    This is the legacy format from v1, maintained for compatibility.
    New code should use DiscoveredDevice.
    """

    vendor: str
    model: str
    device_type: str
    serial: str
    mac: str
    ip: str
    name: str
    hostname: str | None = None
    firmware_version: str | None = None
    status: str = "unknown"
    capabilities: dict[str, Any] = field(default_factory=dict)
    vendor_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "model": self.model,
            "device_type": self.device_type,
            "serial": self.serial,
            "mac_address": self.mac,
            "ip_address": self.ip,
            "name": self.name,
            "hostname": self.hostname,
            "firmware_version": self.firmware_version,
            "status": self.status,
            "capabilities": self.capabilities,
            "vendor_data": self.vendor_data,
        }

    def to_discovered_device(self) -> DiscoveredDevice:
        """Convert to DiscoveredDevice."""
        return DiscoveredDevice(
            mac_address=self.mac,
            ip_address=self.ip,
            name=self.name,
            vendor=self.vendor,
            model=self.model,
            firmware_version=self.firmware_version,
            device_type=self.device_type,
            status=self.status,
            serial_number=self.serial,
            raw_data=self.vendor_data,
        )


# ============================================================================
# Base Adapter Class
# ============================================================================


class BaseAdapter(ABC):
    """
    Abstract base class for all vendor adapters.

    All adapters must implement this interface to ensure
    consistent behavior across different vendor platforms.

    Usage:
        async with OmadaAdapter(host, user, password) as adapter:
            devices = await adapter.discover_devices()
            for device in devices:
                status = await adapter.get_device_status(device.mac_address)
    """

    # Subclasses must define their manifest
    manifest: ClassVar[AdapterManifest]

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        """
        Initialize adapter with connection credentials.

        Args:
            host: Controller/device hostname or IP
            username: Authentication username
            password: Authentication password
            **kwargs: Additional vendor-specific configuration
        """
        self.host = validate_host(host)
        self.username = username
        self.password = password
        self.config = kwargs
        self._connected = False
        self._session: Any = None

    @property
    def is_connected(self) -> bool:
        """Check if adapter is currently connected."""
        return self._connected

    @property
    def client(self) -> Any:
        """The underlying vendor HTTP client.

        Adapters wrap a low-level transport (httpx, RouterOS REST
        client, Proxmox API client, etc.). Some adapters store the
        wrapped client as ``self._api`` (OPNsense, pfSense, MikroTik),
        others as ``self._client`` (Omada, Proxmox). This property
        normalises so service-layer callers can use ``adapter.client``
        regardless of the naming convention picked by each adapter.

        Subclasses MAY override this to add lazy-init or logging, but
        the default behaviour covers every existing adapter.

        Raises ``AttributeError`` if neither attribute is set — the
        adapter is malformed and the dispatcher should refuse to use
        it (rather than the ``__getattr__`` fallback below silently
        returning a stub).
        """
        api = self.__dict__.get("_api")
        if api is not None:
            return api
        wrapped = self.__dict__.get("_client")
        if wrapped is not None:
            return wrapped
        raise AttributeError(
            f"{type(self).__name__} does not expose an underlying "
            f"vendor client (no _api or _client attribute set)"
        )

    def __getattr__(self, name: str) -> Any:
        """Return a stub for unimplemented adapter methods.

        When the service layer calls a method that a vendor adapter hasn't
        implemented (e.g. ``get_proxy_settings`` on OpenWRT), return an
        async callable that yields ``AdapterResult.fail(...)`` instead of
        raising ``AttributeError``.  Only intercepts ``get_*`` / ``create_*``
        / ``delete_*`` / ``update_*`` / ``toggle_*`` / ``apply_*`` / ``run_*``
        / ``start_*`` / ``stop_*`` / ``restart_*`` / ``flush_*`` / ``kill_*``
        / ``connect_*`` / ``disconnect_*`` / ``drop_*`` / ``reboot_*``
        / ``halt_*`` / ``revert_*`` / ``download_*`` / ``firmware_*``
        / ``suppress_*`` style method names.  Anything else raises the
        normal ``AttributeError``.
        """
        _STUB_PREFIXES = (
            "get_",
            "create_",
            "delete_",
            "update_",
            "toggle_",
            "apply_",
            "run_",
            "start_",
            "stop_",
            "restart_",
            "flush_",
            "kill_",
            "connect_",
            "disconnect_",
            "drop_",
            "reboot_",
            "halt_",
            "revert_",
            "download_",
            "firmware_",
            "suppress_",
        )
        if any(name.startswith(p) for p in _STUB_PREFIXES):

            async def _not_supported(*args: Any, **kwargs: Any) -> "AdapterResult":
                return AdapterResult.fail(
                    f"{self.__class__.__name__} does not support '{name}'",
                    error_code="NOT_SUPPORTED",
                )

            return _not_supported
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    # =========================================================================
    # Context Manager Support
    # =========================================================================

    async def __aenter__(self) -> "BaseAdapter":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    # =========================================================================
    # Connection Methods (Required)
    # =========================================================================

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the device/controller.

        Returns:
            bool: True if connection successful

        Raises:
            AdapterConnectionError: If connection fails
            AdapterAuthenticationError: If authentication fails
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the device/controller."""
        pass

    @abstractmethod
    async def test_connection(self) -> AdapterResult:
        """
        Test connection and credentials without full session.

        Returns:
            AdapterResult: Success/failure with details
        """
        pass

    # =========================================================================
    # Discovery Methods (Required)
    # =========================================================================

    @abstractmethod
    async def discover_devices(self) -> list[DiscoveredDevice]:
        """
        Discover all devices managed by the controller.

        Returns:
            list[DiscoveredDevice]: List of discovered devices
        """
        pass

    @abstractmethod
    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """
        Get current status of a device.

        Args:
            device_id: Device identifier (usually MAC address)

        Returns:
            dict: Device status information
        """
        pass

    @abstractmethod
    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """
        Get detailed information about a specific device.

        Args:
            device_id: Device identifier (usually MAC address)

        Returns:
            DiscoveredDevice or None if not found
        """
        pass

    # =========================================================================
    # Capability Methods
    # =========================================================================

    def supports_capability(
        self,
        device_type: str,
        capability: Capability,
    ) -> bool:
        """
        Check if adapter supports a capability for a device type.

        Args:
            device_type: Device type (ap, switch, camera, etc.)
            capability: Capability to check

        Returns:
            bool: True if capability is supported
        """
        device_caps = self.manifest.device_types.get(device_type)
        if not device_caps:
            return False
        return capability in device_caps.capabilities

    def has_capability(
        self,
        capability: Capability,
        device_type: str | None = None,
    ) -> bool:
        """
        Compatibility capability check.

        If ``device_type`` is provided, checks only that device type.
        Otherwise checks whether any declared device type supports the capability.
        """
        if device_type:
            return self.supports_capability(device_type, capability)
        return any(
            capability in device_caps.capabilities
            for device_caps in self.manifest.device_types.values()
        )

    def get_capabilities(self, device_type: str) -> list[Capability]:
        """
        Get all capabilities for a device type.

        Args:
            device_type: Device type (ap, switch, camera, etc.)

        Returns:
            list[Capability]: List of supported capabilities
        """
        device_caps = self.manifest.device_types.get(device_type)
        if not device_caps:
            return []
        return list(device_caps.capabilities)

    def get_supported_device_types(self) -> list[str]:
        """Get all device types supported by this adapter."""
        return list(self.manifest.device_types.keys())

    # =========================================================================
    # Legacy Compatibility Methods
    # =========================================================================

    async def get_devices(self) -> list[AdapterDevice]:
        """
        Legacy method for backwards compatibility.

        Use discover_devices() for new code.
        """
        devices = await self.discover_devices()
        return [
            AdapterDevice(
                vendor=d.vendor,
                model=d.model,
                device_type=d.device_type,
                serial=d.serial_number or d.mac_address,
                mac=d.mac_address,
                ip=d.ip_address or "",
                name=d.name,
                firmware_version=d.firmware_version,
                status=d.status,
                vendor_data=d.raw_data,
            )
            for d in devices
        ]

    # =========================================================================
    # Enterprise Config Methods (Three-State Model)
    # =========================================================================

    async def get_running_config(self, device_id: str) -> dict[str, Any]:
        """
        Read the actual running configuration from the device.

        This is the "ground truth" — what the device reports it's running.
        Used by the reconciliation loop to detect drift against desired_config.

        Adapters SHOULD override this with vendor-specific config retrieval.
        The default falls back to get_device_config() for backwards compat.

        Returns:
            dict: Normalized running configuration
        """
        config = await self.get_device_config(device_id)
        return config or {}

    async def normalize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize a config dict for comparison.

        Strips volatile/ephemeral fields (uptime, timestamps, counters)
        so that drift detection compares only meaningful config state.

        Adapters SHOULD override this to remove vendor-specific volatile fields.

        Returns:
            dict: Config with volatile fields removed
        """
        # Default: strip common volatile keys
        volatile_keys = {"uptime", "last_seen", "timestamp", "boot_time", "sys_time"}
        return {k: v for k, v in config.items() if k not in volatile_keys}

    async def push_full_config(
        self,
        device_id: str,
        config: dict[str, Any],
    ) -> "AdapterResult":
        """
        Push a complete desired config to a device.

        This is the enterprise config push — applies the full resolved
        desired_config (from template hierarchy) to the device.

        Adapters SHOULD override this. Default returns NOT_SUPPORTED.

        Args:
            device_id: Device identifier
            config: Full resolved desired config to apply

        Returns:
            AdapterResult: Success/failure with details
        """
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support full config push",
            error_code="NOT_SUPPORTED",
        )

    async def diff_config(
        self,
        desired: dict[str, Any],
        running: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Compute diff between desired and running config.

        Returns None if configs are equivalent, otherwise returns
        a dict describing the differences.

        Adapters CAN override for vendor-specific comparison logic.

        Returns:
            None if no drift, dict of differences otherwise
        """
        desired_n = await self.normalize_config(desired)
        running_n = await self.normalize_config(running)
        if desired_n == running_n:
            return None
        # Basic diff: keys only in desired, only in running, or different
        diff: dict[str, Any] = {"added": {}, "removed": {}, "changed": {}}
        all_keys = set(desired_n.keys()) | set(running_n.keys())
        for key in all_keys:
            if key not in running_n:
                diff["added"][key] = desired_n[key]
            elif key not in desired_n:
                diff["removed"][key] = running_n[key]
            elif desired_n[key] != running_n[key]:
                diff["changed"][key] = {
                    "desired": desired_n[key],
                    "running": running_n[key],
                }
        # Return None if diff is empty after filtering
        if not diff["added"] and not diff["removed"] and not diff["changed"]:
            return None
        return diff

    # =========================================================================
    # Optional Methods - Override if vendor supports
    # =========================================================================

    async def get_device_config(self, device_id: str) -> dict[str, Any] | None:
        """Get full configuration for a specific device."""
        device = await self.get_device_info(device_id)
        if device:
            return device.raw_data
        return None

    async def reboot_device(self, device_id: str) -> AdapterResult:
        """Reboot a device."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support device reboot",
            error_code="NOT_SUPPORTED",
        )

    async def locate_device(self, device_id: str, duration: int = 30) -> AdapterResult:
        """Flash LEDs to locate a device."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support device locate",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # Switch / PoE Methods
    # -------------------------------------------------------------------------

    async def get_ports(self, device_id: str) -> list[dict[str, Any]]:
        """Get port information for a switch device."""
        return []

    async def set_port_enabled(
        self,
        device_id: str,
        port: int,
        enabled: bool,
    ) -> AdapterResult:
        """Enable or disable a port."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support port control",
            error_code="NOT_SUPPORTED",
        )

    async def set_port_poe(
        self,
        device_id: str,
        port: int,
        enabled: bool,
    ) -> AdapterResult:
        """Enable or disable PoE on a port."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support PoE control",
            error_code="NOT_SUPPORTED",
        )

    async def cycle_poe_port(
        self,
        device_id: str,
        port: int,
        duration: int = 5,
    ) -> AdapterResult:
        """Cycle PoE power on a switch port."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support PoE cycle",
            error_code="NOT_SUPPORTED",
        )

    async def get_poe_status(self, device_id: str) -> dict[str, Any]:
        """Get PoE status for all ports on a device."""
        return {}

    # -------------------------------------------------------------------------
    # WiFi Methods
    # -------------------------------------------------------------------------

    async def get_ssids(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get all SSIDs."""
        return []

    async def toggle_ssid(self, ssid_id: str, enabled: bool) -> AdapterResult:
        """Enable or disable an SSID."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support SSID control",
            error_code="NOT_SUPPORTED",
        )

    async def get_clients(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get connected clients."""
        return []

    async def kick_client(self, client_mac: str) -> AdapterResult:
        """Disconnect a client."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support client kick",
            error_code="NOT_SUPPORTED",
        )

    async def block_client(self, client_mac: str) -> AdapterResult:
        """Block a client."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support client block",
            error_code="NOT_SUPPORTED",
        )

    async def unblock_client(self, client_mac: str) -> AdapterResult:
        """Unblock a client."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support client unblock",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # Camera Methods
    # -------------------------------------------------------------------------

    async def get_snapshot(
        self,
        device_id: str,
        channel: int = 1,
        stream: str = "main",
    ) -> bytes:
        """Capture a snapshot from a camera."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support snapshots")

    async def get_rtsp_url(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        **kwargs: Any,
    ) -> str:
        """Get RTSP URL for live streaming."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support RTSP")

    async def ptz_control(
        self,
        device_id: str,
        action: str,
        speed: int = 50,
    ) -> AdapterResult:
        """Control PTZ camera."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support PTZ control",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # Adoption / Firmware Methods
    # -------------------------------------------------------------------------

    async def adopt_device(self, device_id: str) -> AdapterResult:
        """Adopt (claim) a device into the controller."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support device adoption",
            error_code="NOT_SUPPORTED",
        )

    async def upgrade_firmware(self, device_id: str) -> AdapterResult:
        """Trigger firmware upgrade for a device."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support firmware upgrade",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # 802.1X / RADIUS Methods
    # -------------------------------------------------------------------------

    async def get_dot1x_config(self) -> dict[str, Any]:
        """Get 802.1X / RADIUS authentication configuration."""
        return {}

    async def update_dot1x_config(self, config: dict[str, Any]) -> AdapterResult:
        """Push 802.1X / RADIUS configuration to the controller."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support 802.1X config",
            error_code="NOT_SUPPORTED",
        )

    async def get_dot1x_auth_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Pull recent 802.1X authentication events from the controller."""
        return []

    # -------------------------------------------------------------------------
    # SSID Config Methods
    # -------------------------------------------------------------------------

    async def update_ssid_config(
        self,
        ssid_id: str,
        config: dict[str, Any],
    ) -> AdapterResult:
        """Update SSID-level configuration (roaming, band steering, etc.)."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support SSID config update",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # VPN Orchestration Methods
    # -------------------------------------------------------------------------

    async def push_vpn_config(
        self,
        device_id: str,
        config: dict[str, Any],
    ) -> AdapterResult:
        """Push VPN tunnel configuration to a gateway device."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support VPN config push",
            error_code="NOT_SUPPORTED",
        )

    async def remove_vpn_config(
        self,
        device_id: str,
        tunnel_id: str,
    ) -> AdapterResult:
        """Remove VPN tunnel configuration from a gateway device."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support VPN config removal",
            error_code="NOT_SUPPORTED",
        )

    # -------------------------------------------------------------------------
    # VLAN Methods
    # -------------------------------------------------------------------------

    async def get_vlans(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get all VLANs."""
        return []

    async def create_vlan(
        self,
        vlan_id: int,
        name: str,
        **kwargs: Any,
    ) -> AdapterResult:
        """Create a VLAN."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support VLAN creation",
            error_code="NOT_SUPPORTED",
        )

    async def delete_vlan(self, vlan_id: int) -> AdapterResult:
        """Delete a VLAN."""
        return AdapterResult.fail(
            f"{self.__class__.__name__} does not support VLAN deletion",
            error_code="NOT_SUPPORTED",
        )
