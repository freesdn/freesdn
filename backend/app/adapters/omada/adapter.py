# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN - TP-Link Omada Controller Adapter."""

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import Any, ClassVar

from app.adapters.base import (
    AdapterDevice,
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
)
from app.adapters.omada.client import OmadaApiClient, OmadaClientConfig
from app.adapters.omada.constants import (
    DEVICE_STATUS_CATEGORY_MAP,
    DEVICE_STATUS_MAP,
    DEVICE_TYPE_ENDPOINT,
    DEVICE_TYPE_MAP,
    REBOOT_COOLDOWN_SECONDS,
)
from app.adapters.omada.exceptions import (
    OmadaApiError,
    OmadaAuthError,
    OmadaAuthorizationError,
    OmadaNotFoundError,
    OmadaRateLimitError,
    OmadaSessionExpiredError,
    OmadaTimeoutError,
    OmadaValidationError,
)
from app.adapters.omada.exceptions import (
    OmadaConnectionError as OmadaClientConnectionError,
)
from app.adapters.omada.models import (
    NormalizedACLRule,
    NormalizedAPDetail,
    NormalizedChannelUtil,
    NormalizedClient,
    NormalizedDHCPReservation,
    NormalizedEvent,
    NormalizedFirewallRule,
    NormalizedFirmwareOverview,
    NormalizedFirmwareStatus,
    NormalizedGatewayDetail,
    NormalizedGatewayPort,
    NormalizedIPGroup,
    NormalizedIPMACBinding,
    NormalizedMACTableEntry,
    NormalizedPoESchedule,
    NormalizedPort,
    NormalizedPortProfile,
    NormalizedRogueAP,
    NormalizedSsid,
    NormalizedStaticRoute,
    NormalizedSwitchDetail,
    NormalizedTopologyDevice,
    NormalizedVlan,
    OmadaDeviceMetrics,
)
from app.adapters.omada.utils import normalize_mac

logger = logging.getLogger(__name__)


def _compute_snr(rssi: int | float | None, noise_floor: int | float | None) -> int | None:
    """Compute SNR from RSSI and noise floor (both in dBm)."""
    if rssi is None:
        return None
    nf = noise_floor if noise_floor is not None else -95  # typical 2.4/5GHz floor
    try:
        return int(rssi) - int(nf)
    except (ValueError, TypeError):
        return None


def _resolve_device_status(raw_data: dict[str, Any]) -> str:
    """Resolve device status while tolerating inconsistent statusCategory payloads."""
    status = DEVICE_STATUS_MAP.get(raw_data.get("status"), "unknown")
    status_category = raw_data.get("statusCategory")
    category_status = DEVICE_STATUS_CATEGORY_MAP.get(status_category)
    if category_status == "offline" and status == "online":
        return status
    return category_status or status


# Canonical radio band codes the Omada controller accepts as the radioSetting key.
_RADIO_BAND_ALIASES = {
    "2g": "2g",
    "2.4g": "2g",
    "2.4 ghz": "2g",
    "2.4ghz": "2g",
    "5g": "5g",
    "5 ghz": "5g",
    "5ghz": "5g",
    "5g2": "5g2",
    "5g-2": "5g2",
    "5g_2": "5g2",
    "5 ghz-2": "5g2",
    "5ghz-2": "5g2",
    "6g": "6g",
    "6 ghz": "6g",
    "6ghz": "6g",
}


def _canonical_radio_band(band: str) -> str:
    """Map any band label/alias to the canonical Omada radio key (2g|5g|5g2|6g).

    The AP-detail producer, the list-summary, and live ``radioConfig`` payloads
    have historically used inconsistent band identifiers (human labels, ``5g-2``
    with a hyphen, etc.). The controller's ``radioSetting`` write key must be one
    of ``2g|5g|5g2|6g``, so normalize here before sending. Unknown values are
    passed through unchanged so a genuinely new band is not silently dropped.
    """
    return _RADIO_BAND_ALIASES.get(str(band).strip().lower(), band)


class OmadaAdapter(BaseAdapter):
    """
    Adapter for TP-Link Omada SDN Controller.

    Supports:
    - Switches (TL-SG series)
    - Access Points (EAP series)
    - Routers/Gateways (ER series)
    """

    # Adapter manifest
    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="omada",
        name="TP-Link Omada SDN Controller",
        vendor="TP-Link",
        version="1.0.0",
        description="Enterprise-grade Omada integration for switches, APs, and gateways",
        controller_type="omada",
        supports_controller=True,
        supports_direct=False,
        # 6.2 validated live against an OC300; the 6.x line shares the same
        # core API surface (a few advanced endpoints differ across versions —
        # the client degrades gracefully on those). 5.9–5.14 remain supported.
        supported_versions=["5.9", "5.12", "5.13", "5.14", "6.0", "6.1", "6.2"],
        device_types={
            "switch": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_LOCATE,
                    Capability.DEVICE_METRICS,
                    Capability.SWITCH_PORT_CONFIG,
                    Capability.SWITCH_PORT_ENABLE,
                    Capability.SWITCH_PORT_STATUS,
                    Capability.VLAN_MANAGEMENT,
                    Capability.POE_CONTROL,
                    Capability.POE_STATUS,
                    Capability.PORT_STATISTICS,
                    Capability.SPANNING_TREE,
                    Capability.LINK_AGGREGATION,
                    Capability.PORT_MIRRORING,
                    Capability.MAC_TABLE,
                    Capability.STORM_CONTROL,
                    Capability.LLDP_NEIGHBORS,
                    Capability.DEVICE_FIRMWARE_CHECK,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                    # Enterprise additions
                    Capability.FIRMWARE_BATCH,
                    Capability.SWITCH_ACL,
                    Capability.DOT1X_AUTH,
                    Capability.DHCP_SNOOPING,
                    Capability.EVENTS_ALERTS,
                    # v26.05 switch-advanced
                    Capability.SWITCH_SFLOW,
                    Capability.SWITCH_LLDP_MED,
                    Capability.SWITCH_QINQ,
                    Capability.SWITCH_MSTP,
                    Capability.SWITCH_VOICE_VLAN,
                    Capability.SWITCH_POE_BUDGET,
                    Capability.SWITCH_PORT_JUMBO,
                ],
                models=["TL-SG3428", "TL-SG2428P", "TL-SG2210P", "TL-SG3210", "*"],
            ),
            "access_point": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_LOCATE,
                    Capability.DEVICE_METRICS,
                    Capability.WIFI_SSID_MANAGEMENT,
                    Capability.WIFI_CLIENT_LIST,
                    Capability.WIFI_CLIENT_KICK,
                    Capability.WIFI_CLIENT_BLOCK,
                    Capability.WIFI_RADIO_CONFIG,
                    Capability.WIFI_STATISTICS,
                    Capability.BAND_STEERING,
                    Capability.CLIENT_ISOLATION,
                    Capability.MESH_NETWORKING,
                    Capability.WIFI_ROAMING,
                    Capability.DEVICE_FIRMWARE_CHECK,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                    # Enterprise additions
                    Capability.FIRMWARE_BATCH,
                    Capability.ROGUE_AP_DETECTION,
                    Capability.CHANNEL_UTILIZATION,
                    Capability.SITE_RADIO_SETTINGS,
                    Capability.CAPTIVE_PORTAL,
                    Capability.HOTSPOT_VOUCHERS,
                    Capability.EVENTS_ALERTS,
                    # v26.05 wifi-advanced
                    Capability.WIFI_WIDS_WIPS,
                    Capability.WIFI_MESH_DETAIL,
                    Capability.WIFI_REGULATORY,
                    Capability.WIFI_DFS,
                    Capability.WIFI_CHANNEL_PILOT,
                    Capability.WIFI_LOCATE_AP,
                ],
                models=["EAP225", "EAP245", "EAP620", "EAP660", "EAP670", "*"],
            ),
            "gateway": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_METRICS,
                    Capability.ROUTING_STATIC,
                    Capability.NAT,
                    Capability.DHCP_SERVER,
                    Capability.DNS,
                    Capability.WAN_FAILOVER,
                    Capability.LOAD_BALANCING,
                    Capability.VPN_IPSEC,
                    Capability.VPN_L2TP,
                    Capability.VPN_PPTP,
                    Capability.VPN_OPENVPN,
                    Capability.VPN_WIREGUARD,
                    Capability.FIREWALL_BASIC,
                    Capability.DEVICE_FIRMWARE_CHECK,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                    # Enterprise additions
                    Capability.FIRMWARE_BATCH,
                    Capability.DHCP_RESERVATIONS,
                    Capability.IP_GROUPS,
                    Capability.URL_FILTERING,
                    Capability.STATIC_ROUTES,
                    Capability.IP_MAC_BINDING,
                    Capability.DDNS,
                    Capability.SITE_SETTINGS,
                    Capability.CONTROLLER_BACKUP,
                    Capability.EVENTS_ALERTS,
                    # v26.05 deepening — gateway-* feature modules
                    Capability.CONTROLLER_SMTP,
                    Capability.CONTROLLER_SSL_CERT,
                    Capability.CONTROLLER_ADMINS,
                    Capability.CONTROLLER_NOTIFICATIONS,
                    Capability.CONTROLLER_GLOBAL_SETTINGS,
                    Capability.CONTROLLER_MAINTENANCE,
                    Capability.CONTROLLER_CLOUD_ACCESS,
                    Capability.SITE_TIME_NTP,
                    Capability.SITE_LED_SCHEDULE,
                    Capability.SITE_REBOOT_SCHEDULE,
                    Capability.SITE_NOTIFICATIONS,
                    Capability.MONITORING_SNMP,
                    Capability.MONITORING_SYSLOG,
                    Capability.SITE_TEMPLATES,
                    Capability.SITE_CLONE,
                    Capability.BULK_DEVICE_OPS,
                    Capability.BULK_CLIENT_OPS,
                    Capability.BULK_SSID_OPS,
                    Capability.HOTSPOT_OPERATORS,
                    Capability.HOTSPOT_SMS_GATEWAY,
                    Capability.HOTSPOT_FREE_AUTH,
                    Capability.ROUTING_VRRP,
                    Capability.ROUTING_BGP,
                    Capability.ROUTING_IPV6_STATIC,
                    Capability.ROUTING_TABLE_VIEW,
                    Capability.GATEWAY_SPEED_TEST,
                    Capability.GATEWAY_SESSION_STATS,
                ],
                models=["ER605", "ER7206", "ER8411", "*"],
            ),
        },
        auth_methods=["username_password", "oauth2_client_credentials"],
        rate_limit_calls_per_minute=60,
        rate_limit_concurrent=5,
        default_sync_interval=300,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=True,
    )

    def __init__(self, host: str = "", username: str = "", password: str = "", **kwargs: Any):
        super().__init__(host, username, password, **kwargs)
        mode = kwargs.get("mode", "local")
        self.verify_ssl = kwargs.get("verify_ssl", False)
        self.controller_id: str | None = None
        self.csrf_token: str | None = None
        self.base_url = f"https://{host}" if host and not host.startswith("http") else host
        self._client = OmadaApiClient(
            OmadaClientConfig(
                mode=mode,
                # Local mode fields
                host=host,
                username=username or "",
                password=password or "",
                port=kwargs.get("port", 8043),
                # Cloud mode fields
                client_id=kwargs.get("client_id", ""),
                client_secret=kwargs.get("client_secret", ""),
                omada_id=kwargs.get("omada_id", ""),
                cloud_region=kwargs.get("cloud_region", ""),
                # Common fields
                use_ssl=kwargs.get("use_ssl", True),
                verify_ssl=self.verify_ssl,
                timeout=kwargs.get("timeout", 30.0),
                connect_timeout=kwargs.get("connect_timeout", 10.0),
                max_retries=kwargs.get("max_retries", 3),
                retry_backoff=kwargs.get("retry_backoff", 1.0),
                rate_limit_rpm=kwargs.get("rate_limit_rpm", 60),
                rate_limit_concurrent=kwargs.get("rate_limit_concurrent", 5),
                cache_ttl_devices=kwargs.get("cache_ttl_devices", 30),
                cache_ttl_ports=kwargs.get("cache_ttl_ports", 15),
                cache_ttl_clients=kwargs.get("cache_ttl_clients", 30),
                cache_ttl_config=kwargs.get("cache_ttl_config", 60),
            )
        )
        self._site_id: str | None = kwargs.get("site_id")
        self._last_reboot_by_device: dict[str, float] = {}

    @property
    def connection_mode(self) -> str:
        """Return 'local' or 'cloud'."""
        return self._client.config.mode

    async def test_connection(self) -> AdapterResult:
        """Test if Omada controller is reachable (local or cloud)."""
        try:
            info = await self._client.login()
            await self._client.logout()
            return AdapterResult.ok(
                {
                    "controller_id": info.get("controller_id"),
                    "controller_version": info.get("version"),
                    "mode": info.get("mode"),
                },
                message="Connection successful",
            )
        except Exception as e:
            logger.error("Connection test failed: %s", e)
            return AdapterResult.fail(str(e), error_code="CONNECTION_FAILED", message=str(e))

    async def connect(self) -> bool:
        """Connect to Omada controller (local session or cloud OAuth2)."""
        try:
            info = await self._client.login()
            self.controller_id = info.get("controller_id")
            self._connected = True
            logger.info("Connected to Omada controller at %s", self.host)
            return True

        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except OmadaAuthError as e:
            raise AdapterAuthenticationError(str(e), adapter_id="omada") from e
        except Exception as e:
            logger.error("Failed to connect to Omada controller: %s", e)
            self._connected = False
            raise AdapterConnectionError(f"Omada connection failed: {e}", adapter_id="omada")

    async def disconnect(self) -> None:
        """Logout and close session."""
        try:
            await self._client.logout()
        finally:
            self._connected = False

    async def _api_request(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make authenticated API request to Omada controller."""
        if not self._connected:
            await self.connect()

        params = kwargs.pop("params", None)
        json_data = kwargs.pop("json", None)
        cache_ttl = kwargs.pop("cache_ttl", None)
        retry = kwargs.pop("retry", True)
        if kwargs:
            logger.debug("Ignoring unsupported _api_request kwargs: %s", list(kwargs.keys()))

        return await self._client._request(
            method,
            endpoint,
            params=params,
            json_data=json_data,
            cache_ttl=cache_ttl,
            retry=retry,
        )

    def _fail_from_exception(
        self,
        exc: Exception,
        *,
        default_error_code: str,
        default_message: str | None = None,
    ) -> AdapterResult:
        """Translate Omada/client exceptions into stable adapter error results."""
        if isinstance(exc, OmadaValidationError):
            code = "VALIDATION_ERROR"
            error = "invalid_configuration"
            message = default_message or str(exc)
        elif isinstance(exc, OmadaAuthorizationError):
            code = "PERMISSION_DENIED"
            error = "insufficient_permissions"
            message = default_message or str(exc)
        elif isinstance(exc, (OmadaAuthError, OmadaSessionExpiredError)):
            code = "AUTHENTICATION_FAILED"
            error = "authentication_failed"
            message = default_message or str(exc)
        elif isinstance(exc, OmadaNotFoundError):
            code = "NOT_FOUND"
            error = "resource_not_found"
            message = default_message or str(exc)
        elif isinstance(exc, OmadaRateLimitError):
            code = "RATE_LIMITED"
            error = "rate_limited"
            message = default_message or str(exc)
        elif isinstance(exc, (OmadaTimeoutError, OmadaClientConnectionError)):
            code = "CONNECTION_ERROR"
            error = "controller_unreachable"
            message = default_message or str(exc)
        elif isinstance(exc, OmadaApiError):
            code = default_error_code
            error = "controller_error"
            message = default_message or str(exc)
        else:
            code = default_error_code
            error = str(exc)
            message = default_message or str(exc)

        logger.warning(
            "adapter.omada.error_translated",
            extra={
                "source": exc.__class__.__name__,
                "error_code": code,
                "error": error,
            },
        )
        return AdapterResult.fail(error, error_code=code, message=message)

    # =========================================================================
    # Discovery Methods
    # =========================================================================

    async def get_sites(self) -> list[dict[str, Any]]:
        """Get all sites from controller.

        Raises on failure so callers (e.g. probe endpoint) can surface
        the real error instead of silently returning an empty list.
        """
        sites = await self._client.get_sites()
        return [
            {"id": site.get("siteId") or site.get("id"), "name": site.get("name")} for site in sites
        ]

    async def _ensure_site_id(self) -> str | None:
        """Resolve active site ID, defaulting to first discovered site."""
        if self._site_id:
            return self._site_id
        sites = await self.get_sites()
        if sites:
            self._site_id = sites[0].get("id")
        return self._site_id

    def set_active_site(self, site_id: str) -> None:
        """Explicitly set the active site for all subsequent operations."""
        self._site_id = site_id
        logger.info("adapter.omada.site_changed", extra={"site_id": site_id})

    def get_active_site_id(self) -> str | None:
        """Return the currently active site ID (may be None if not yet resolved)."""
        return self._site_id

    async def _find_device_site(self, device_id: str) -> tuple[str, dict[str, Any]] | None:
        """
        Find device across sites by MAC address.

        Returns:
            (site_id, raw_device) tuple when found.
        """
        target = normalize_mac(device_id)
        sites = await self.get_sites()
        for site in sites:
            site_id = site.get("id")
            if not site_id:
                continue
            if self._site_id and site_id != self._site_id:
                continue
            try:
                rows = await self._client.get_devices(site_id)
            except Exception as exc:
                logger.warning("Failed to enumerate devices for site %s: %s", site_id, exc)
                continue
            for row in rows:
                row_mac = normalize_mac(row.get("mac"))
                if row_mac == target:
                    return site_id, row

        return None

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """Discover all devices managed by Omada controller.

        Each discovered device's ``raw_data`` includes ``_omada_site_id`` and
        ``_omada_site_name`` so the caller can resolve site mappings.
        """
        devices = []

        try:
            sites = await self.get_sites()

            for site in sites:
                site_id = site.get("id")
                site_name = site.get("name", "")
                if self._site_id and site_id != self._site_id:
                    continue

                try:
                    site_devices = await self._client.get_devices(site_id)

                    for device_data in site_devices:
                        # Tag device with its Omada site origin
                        device_data["_omada_site_id"] = site_id
                        device_data["_omada_site_name"] = site_name
                        device = self._normalize_to_discovered(device_data)
                        devices.append(device)
                except Exception as e:
                    logger.error("Failed to get devices for site %s: %s", site_id, e)
        except Exception as e:
            logger.exception("Failed to get devices: %s", e)

        return devices

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get current status of a device."""
        device = await self.get_device_info(device_id)
        if device:
            return {
                "status": device.status,
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
            }
        return {"status": "unknown"}

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get detailed info about specific device."""
        target = normalize_mac(device_id)
        devices = await self.discover_devices()
        for device in devices:
            if device.mac_address == target or device.serial_number == device_id:
                return device
        return None

    def _normalize_to_discovered(self, raw_data: dict) -> DiscoveredDevice:
        """Convert Omada device data to DiscoveredDevice."""
        omada_type = str(raw_data.get("type", "unknown"))
        device_type = DEVICE_TYPE_MAP.get(omada_type, omada_type)
        status = _resolve_device_status(raw_data)
        mac = normalize_mac(raw_data.get("mac"))

        # Get capabilities for device type
        caps = self.get_capabilities(device_type)

        return DiscoveredDevice(
            mac_address=mac,
            ip_address=raw_data.get("ip"),
            name=raw_data.get("name", mac or "Unknown"),
            vendor="TP-Link",
            model=raw_data.get("model", "unknown"),
            firmware_version=raw_data.get("firmwareVersion"),
            device_type=device_type,
            status=status,
            serial_number=raw_data.get("serialNumber") or mac.replace(":", ""),
            capabilities=caps,
            raw_data=raw_data,
        )

    # =========================================================================
    # Legacy Support (get_devices returns AdapterDevice for backwards compat)
    # =========================================================================

    def _normalize_device(self, raw_data: dict, site_info: dict) -> AdapterDevice:
        """Convert Omada device data to AdapterDevice (legacy)."""
        omada_type = str(raw_data.get("type", "unknown"))
        device_type = DEVICE_TYPE_MAP.get(omada_type, omada_type)
        status = _resolve_device_status(raw_data)
        mac = normalize_mac(raw_data.get("mac"))

        capabilities = {}
        if device_type == "access_point":
            capabilities["wifi"] = {"ssid": True, "band_24": True, "band_5": True}
        if device_type == "switch":
            capabilities["switch"] = {
                "poe": raw_data.get("poe", False),
                "ports": raw_data.get("portNum", 0),
            }

        return AdapterDevice(
            vendor="TP-Link",
            model=raw_data.get("model", "unknown"),
            device_type=device_type,
            serial=raw_data.get("serialNumber") or mac.replace(":", ""),
            mac=mac,
            ip=raw_data.get("ip", ""),
            name=raw_data.get("name", mac or "Unknown"),
            hostname=raw_data.get("name"),
            firmware_version=raw_data.get("firmwareVersion"),
            status=status,
            capabilities=capabilities,
            vendor_data=raw_data,
        )

    # =========================================================================
    # Normalization Helpers (raw Omada dict → typed model)
    # =========================================================================

    @staticmethod
    def _normalize_port(raw: dict[str, Any]) -> NormalizedPort:
        """Normalize a single Omada port dict to cross-vendor representation."""
        poe_raw = raw.get("poe", {})
        operation = (raw.get("operation") or "switching").lower()
        port_type_int = raw.get("type")
        if isinstance(port_type_int, str):
            port_type_name = port_type_int
        else:
            port_type_name = {1: "copper", 2: "combo", 3: "sfp"}.get(port_type_int or 0, "copper")

        # Resolve port status from nested portStatus or top-level fields
        port_status = raw.get("portStatus") or {}
        stp_discarding = raw.get("stpDiscarding") or port_status.get("stpDiscarding", False)
        rx_bytes = raw.get("rxBytes") or port_status.get("rx", 0)
        tx_bytes = raw.get("txBytes") or port_status.get("tx", 0)
        rx_packets = port_status.get("rxPkt")
        tx_packets = port_status.get("txPkt")

        link_status_raw = raw.get("linkStatus")
        if link_status_raw is None and port_status:
            link_status_raw = port_status.get("linkStatus")

        # Negotiated speed: portStatus.linkSpeed is an Omada enum:
        # 0=Auto, 1=10M, 2=100M, 3=1G, 4=2.5G, 5=10G
        # Top-level linkSpeed is always 0 (configured auto-negotiate), NOT the negotiated speed.
        _OMADA_SPEED_MAP = {0: None, 1: 10, 2: 100, 3: 1000, 4: 2500, 5: 10000}
        negotiated_speed_enum = port_status.get("linkSpeed")
        negotiated_speed = _OMADA_SPEED_MAP.get(negotiated_speed_enum)
        if negotiated_speed is None and isinstance(link_status_raw, bool):
            raw_link_speed = raw.get("linkSpeed")
            if isinstance(raw_link_speed, int) and raw_link_speed > 5:
                negotiated_speed = raw_link_speed
        # Only report speed when port is actually linked up
        if not link_status_raw:
            negotiated_speed = None

        # PoE: Omada returns poe as an int (0=disabled, 1=enabled) or a dict
        if isinstance(poe_raw, dict):
            poe_enabled = poe_raw.get("enable", False)
            poe_max_power = poe_raw.get("maxPower")
            poe_power = poe_raw.get("power", port_status.get("poePower", 0.0) or 0.0)
        elif isinstance(poe_raw, int):
            # 0=disabled, 1=enabled (PoE mode enum)
            poe_enabled = poe_raw >= 1
            poe_max_power = None
            poe_power = port_status.get("poePower", 0.0) or 0.0
        else:
            poe_enabled = False
            poe_max_power = None
            poe_power = port_status.get("poePower", 0.0) or 0.0

        return NormalizedPort(
            port_number=raw.get("port", 0),
            port_id=raw.get("id") or raw.get("portId"),
            name=raw.get("name"),
            enabled=raw.get("enable", True),
            status="up" if link_status_raw else "down",
            speed=negotiated_speed,
            duplex=raw.get("duplex"),
            port_type=port_type_name,
            operation=operation,
            is_lag_member=(operation == "aggregating"),
            is_mirror_port=(operation == "mirroring"),
            # PoE
            poe_supported=raw.get("supportPoe", False),
            poe_enabled=poe_enabled,
            poe_power=poe_power,
            poe_max_power=poe_max_power,
            # VLAN
            native_vlan=raw.get("pvid") or raw.get("nativeVlan"),
            tagged_vlans=raw.get("taggedVlans", []),
            native_network_id=raw.get("nativeNetworkId"),
            tagged_network_ids=raw.get("tagNetworkIds", []),
            untagged_network_ids=raw.get("untagNetworkIds", []),
            # Profile
            profile_id=raw.get("profileId"),
            profile_name=raw.get("profileName"),
            profile_override_enabled=raw.get("profileOverrideEnable", False),
            # L2 features
            stp_enabled=raw.get("spanningTreeEnable", False),
            stp_discarding=stp_discarding,
            lldp_med_enabled=raw.get("lldpMedEnable", False),
            loopback_detect_enabled=raw.get("loopbackDetectEnable", False),
            port_isolation_enabled=raw.get("portIsolationEnable", False),
            flow_control_enabled=raw.get("flowControlEnable", False),
            eee_enabled=raw.get("eeeEnable", False),
            dot1x_mode=raw.get("dot1x"),
            # Voice VLAN
            voice_vlan_enabled=raw.get("voiceNetworkEnable", False),
            voice_vlan_id=raw.get("voiceNetworkId"),
            # Bandwidth/storm
            bandwidth_limit_mode=raw.get("bandWidthCtrlType"),
            bandwidth_ctrl=raw.get("bandCtrl"),
            storm_ctrl=raw.get("stormCtrl"),
            # SFP module info (clamp sensor values to reasonable ranges)
            sfp_vendor=port_status.get("sfpVendor") or raw.get("sfpVendor"),
            sfp_part_number=port_status.get("sfpPartNumber") or raw.get("sfpPartNumber"),
            sfp_serial=port_status.get("sfpSerialNumber") or raw.get("sfpSerialNumber"),
            sfp_type=port_status.get("sfpType") or raw.get("sfpType"),
            sfp_temperature=max(-40.0, min(125.0, float(v)))
            if (v := port_status.get("sfpTemperature") or raw.get("sfpTemperature")) is not None
            else None,
            sfp_tx_power=max(-40.0, min(10.0, float(v)))
            if (v := port_status.get("sfpTxPower") or raw.get("sfpTxPower")) is not None
            else None,
            sfp_rx_power=max(-40.0, min(10.0, float(v)))
            if (v := port_status.get("sfpRxPower") or raw.get("sfpRxPower")) is not None
            else None,
            sfp_wavelength=max(400, min(2000, int(v)))
            if (v := port_status.get("sfpWavelength") or raw.get("sfpWavelength")) is not None
            else None,
            # Traffic
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            rx_packets=rx_packets,
            tx_packets=tx_packets,
        )

    @staticmethod
    def _normalize_vlan(raw: dict[str, Any]) -> NormalizedVlan:
        """Normalize a single Omada network/VLAN dict."""
        # Extract gateway and subnet from gatewaySubnet "ip/mask" format
        gw_subnet = raw.get("gatewaySubnet")
        gateway = raw.get("gateway")
        subnet = raw.get("subnet") or raw.get("subnetMask")
        cidr: str | None = None
        if isinstance(gw_subnet, str) and "/" in gw_subnet:
            gateway = gateway or gw_subnet.split("/")[0]
            subnet = subnet or gw_subnet
            cidr = gw_subnet
        # DHCP settings can be a nested dict
        dhcp_settings = raw.get("dhcpSettings") or {}
        dhcp_enabled = raw.get("dhcpEnable") or raw.get("dhcp_enabled")
        dhcp_range = raw.get("dhcpRange")
        dhcp_lease_time: int | None = None
        dhcp_dns_servers: list[str] | None = None
        dhcp_pool_start: str | None = None
        dhcp_pool_end: str | None = None
        if isinstance(dhcp_settings, dict):
            dhcp_enabled = dhcp_enabled or dhcp_settings.get("enable", False)
            dhcp_lease_time = dhcp_settings.get("leaseTime")
            dns1 = dhcp_settings.get("primaryDns") or dhcp_settings.get("dnsServer1")
            dns2 = dhcp_settings.get("secondaryDns") or dhcp_settings.get("dnsServer2")
            if dns1:
                dhcp_dns_servers = [s for s in [dns1, dns2] if s]
            # Pool range
            dhcp_pool_start = dhcp_settings.get("startIp")
            dhcp_pool_end = dhcp_settings.get("endIp")
        # Parse range string "start-end" if no structured pool
        if not dhcp_pool_start and isinstance(dhcp_range, str) and "-" in dhcp_range:
            parts = dhcp_range.split("-", 1)
            dhcp_pool_start = parts[0].strip()
            dhcp_pool_end = parts[1].strip()
        return NormalizedVlan(
            id=raw.get("id") or raw.get("networkId"),
            vlan_id=raw.get("vlanId") or raw.get("vlan_id") or raw.get("vlan"),
            name=raw.get("name"),
            gateway=gateway,
            subnet=subnet,
            cidr=cidr,
            dhcp_enabled=dhcp_enabled,
            dhcp_range=dhcp_range,
            dhcp_lease_time=dhcp_lease_time,
            dhcp_dns_servers=dhcp_dns_servers,
            dhcp_pool_start=dhcp_pool_start,
            dhcp_pool_end=dhcp_pool_end,
            igmp_snooping=raw.get("igmpSnooping") or raw.get("igmpSnoopingEnable"),
            domain=raw.get("domain"),
            internet_access=raw.get("internetAccess")
            if raw.get("internetAccess") is not None
            else True,
            purpose=raw.get("purpose"),
        )

    # Omada security enum → string mapping
    _OMADA_SECURITY_MAP = {
        0: "open",
        1: "wep",
        2: "wpa_wpa2_personal",
        3: "wpa2_personal",  # refine by pskSetting.versionPsk
        4: "wpa2_enterprise",  # refine by enterprise version
    }
    _OMADA_PSK_VERSION_MAP = {
        1: "wpa_wpa2_personal",
        2: "wpa2_personal",
        3: "wpa_wpa2_personal",
        4: "wpa2_wpa3_personal",
        5: "wpa3_personal",
    }
    # Omada band enum → string  (for SSIDs)
    _OMADA_BAND_MAP = {
        0: "both",
        1: "2.4ghz",
        2: "5ghz",
        3: "both",  # 2.4+5
        7: "all",  # 2.4+5+6
    }
    # Client RadioId enum → band string  (per Omada firmware)
    _OMADA_RADIO_MAP: dict[int, str] = {
        0: "2.4GHz",  # FREQ_2_4
        1: "5GHz",  # FREQ_5_1
        2: "5GHz",  # FREQ_5_2  (second 5 GHz radio)
        3: "6GHz",  # FREQ_6
    }

    @staticmethod
    def _normalize_ssid(raw: dict[str, Any]) -> NormalizedSsid:
        """Normalize a single Omada SSID dict (from wlans/{id}/ssids)."""
        # --- Security ---
        sec_raw = raw.get("security")
        if isinstance(sec_raw, int):
            security = OmadaAdapter._OMADA_SECURITY_MAP.get(sec_raw, "wpa2_personal")
            # Refine PSK-based security by versionPsk
            if sec_raw == 3:
                psk = raw.get("pskSetting") or {}
                vpsk = psk.get("versionPsk")
                if vpsk is not None:
                    security = OmadaAdapter._OMADA_PSK_VERSION_MAP.get(vpsk, security)
        else:
            security = sec_raw or "wpa2_personal"

        # --- Band ---
        band_raw = raw.get("band")
        if isinstance(band_raw, int):
            band = OmadaAdapter._OMADA_BAND_MAP.get(band_raw, "both")
        else:
            band = band_raw or "both"

        # --- Rate limit ---
        rl = raw.get("rateLimit") or {}
        ssid_rl = raw.get("ssidRateLimit") or {}
        rl.get("upLimitKbps") if rl.get("upLimitEnable") else None
        rl.get("downLimitKbps") if rl.get("downLimitEnable") else None
        bool(
            rl.get("upLimitEnable")
            or rl.get("downLimitEnable")
            or ssid_rl.get("upLimitEnable")
            or ssid_rl.get("downLimitEnable")
        )

        # --- VLAN ---
        vlan_id = None
        if raw.get("vlanEnable"):
            vlan_id = raw.get("vlanId")
        vs = raw.get("vlanSetting") or {}
        if not vlan_id and vs.get("mode") == 1:
            vlan_id = vs.get("currentVlanId") or vs.get("vlanId")

        return NormalizedSsid(
            id=raw.get("id"),
            name=raw.get("name") or raw.get("ssid"),
            enabled=raw.get("enable", True) if "enable" in raw else True,
            vlan_id=vlan_id,
            security=security,
            band=band,
            guest_network=raw.get("guestNetEnable", False),
            client_isolation=raw.get("clientIsolation", False),
            band_steering=raw.get("bandSteering", False),
            broadcast=raw.get("broadcast", True),
        )

    @staticmethod
    def _normalize_client(raw: dict[str, Any]) -> NormalizedClient:
        """Normalize a single Omada client dict.

        Handles both list-endpoint (minimal) and detail-endpoint (full) payloads.

        SNR is computed from RSSI - noise_floor when the controller doesn't
        provide it directly.
        """
        is_wireless = raw.get("wireless")
        if is_wireless is None:
            conn_type = "wired" if raw.get("switchMac") else "wireless"
        else:
            conn_type = "wireless" if is_wireless else "wired"

        # Band / channel / wifi mode (wireless clients)
        band: str | None = None
        channel: int | None = None
        wifi_mode: str | None = None
        radio_id = raw.get("radioId")
        if radio_id is not None:
            band = OmadaAdapter._OMADA_RADIO_MAP.get(radio_id)
        channel = raw.get("channel")
        wifi_mode_raw = raw.get("wifiMode") or raw.get("dot11Protocol")
        if isinstance(wifi_mode_raw, int):
            _WIFI_MODE_MAP = {0: "a", 1: "b", 2: "g", 3: "na", 4: "ng", 5: "ac", 6: "axa", 7: "axg"}
            wifi_mode = _WIFI_MODE_MAP.get(wifi_mode_raw)
        else:
            wifi_mode = wifi_mode_raw

        # Timestamps — convert epoch-millis → ISO string (model expects str)
        def _epoch_to_iso(val: int | None) -> str | None:
            if val is None:
                return None
            try:
                ts = val / 1000.0 if val > 1e12 else float(val)
                return datetime.fromtimestamp(ts, tz=UTC).isoformat()
            except (OSError, ValueError, OverflowError):
                return None

        last_seen = _epoch_to_iso(raw.get("lastSeen") or raw.get("lastSeenTime"))
        first_seen = _epoch_to_iso(raw.get("firstSeen") or raw.get("firstSeenTime"))

        # Traffic — detail endpoint uses trafficDown/trafficUp, list uses download/upload
        download = raw.get("trafficDown") or raw.get("download") or 0
        upload = raw.get("trafficUp") or raw.get("upload") or 0

        return NormalizedClient(
            mac_address=raw.get("mac", ""),
            name=raw.get("name") or raw.get("hostName"),
            hostname=raw.get("hostName"),
            ip_address=raw.get("ip"),
            connection_type=conn_type,
            ssid=raw.get("ssid"),
            ap_mac=raw.get("apMac"),
            ap_name=raw.get("apName"),
            switch_mac=raw.get("switchMac"),
            switch_port=raw.get("switchPort") or raw.get("port"),
            vlan_id=raw.get("vlanId") or raw.get("vid"),
            uptime=raw.get("uptime"),
            signal=raw.get("signalLevel"),
            rssi=raw.get("rssi"),
            snr=raw.get("snr") or (_compute_snr(raw.get("rssi"), raw.get("noiseFloor"))),
            activity=raw.get("activity"),
            rx_rate=raw.get("rxRate"),
            tx_rate=raw.get("txRate"),
            download=download,
            upload=upload,
            blocked=raw.get("blocked") or raw.get("block", False),
            guest=raw.get("guest", False),
            os_type=raw.get("osName") or raw.get("osType") or raw.get("os"),
            device_category=raw.get("deviceCategory") or raw.get("deviceType"),
            channel=channel,
            band=band,
            wifi_mode=wifi_mode,
            last_seen=last_seen,
            first_seen=first_seen,
        )

    @staticmethod
    def _normalize_firewall_rule(raw: dict[str, Any]) -> NormalizedFirewallRule:
        """Normalize a single Omada firewall rule dict."""
        return NormalizedFirewallRule(
            id=raw.get("id"),
            name=raw.get("name"),
            enabled=raw.get("enabled", True),
            action=raw.get("action"),
            protocol=raw.get("protocol"),
            src_ip=raw.get("srcIp"),
            src_port=raw.get("srcPort"),
            dst_ip=raw.get("dstIp"),
            dst_port=raw.get("dstPort"),
            direction=raw.get("direction"),
            index=raw.get("index") or raw.get("priority"),
            src_type=raw.get("srcType"),
            src_ip_group_id=raw.get("srcIpGroupId"),
            dst_type=raw.get("dstType"),
            dst_ip_group_id=raw.get("dstIpGroupId"),
            log=raw.get("log", False),
            schedule=raw.get("schedule") or raw.get("timeRange"),
            comment=raw.get("comment") or raw.get("description"),
        )

    @staticmethod
    def _normalize_port_profile(raw: dict[str, Any]) -> NormalizedPortProfile:
        """Normalize a single Omada port profile dict."""
        return NormalizedPortProfile(
            id=raw.get("id") or raw.get("profileId"),
            name=raw.get("name"),
            native_vlan=raw.get("nativeVlan") or raw.get("pvid"),
            tagged_vlans=raw.get("taggedVlans", []),
            untagged_vlans=raw.get("untaggedVlans", []),
            type=raw.get("type"),
            poe_enabled=raw.get("poe") if raw.get("poe") is not None else raw.get("poeEnable"),
            stp_enabled=raw.get("stpEnable"),
            lldp_enabled=raw.get("lldpMedEnable"),
            bandwidth_limit=raw.get("bandwidthLimit") or raw.get("rateLimit"),
        )

    @staticmethod
    def _normalize_gateway_port_status(raw: dict[str, Any]) -> NormalizedGatewayPort:
        """Normalize a single gateway portStats entry."""
        ipv6_cfg = raw.get("wanPortIpv6Config") or {}
        port_type_map = {0: "wan", 1: "wan_lan", 2: "lan", 3: "sfp_wan"}
        mode_map = {0: "wan", 1: "lan"}
        return NormalizedGatewayPort(
            port_number=raw.get("port", 0),
            name=raw.get("name"),
            display_name=raw.get("portDesc") or raw.get("name") or f"Port {raw.get('port', '?')}",
            port_type=port_type_map.get(raw.get("type", -1), "unknown"),
            mode=mode_map.get(raw.get("mode", -1), "unknown"),
            link_status="up" if raw.get("status") == 1 else "down",
            speed=raw.get("speed"),
            duplex={0: "auto", 1: "half", 2: "full"}.get(raw.get("duplex", -1)),
            # PoE
            poe_active=raw.get("poe", False),
            # WAN-specific
            wan_connected=raw.get("internetState") == 1,
            ipv6_wan_connected=ipv6_cfg.get("internetState", 0) == 1,
            online_detection=raw.get("onlineDetection") == 1,
            ip_address=raw.get("ip"),
            ipv6_enabled=ipv6_cfg.get("enable", False),
            ipv6_address=ipv6_cfg.get("addr"),
            wan_protocol=raw.get("proto"),
            gateway_ip=raw.get("gateway"),
            # Mirroring
            mirror_enabled=False,
            mirrored_ports=raw.get("mirroredPorts", []),
            # Traffic counters
            bytes_tx=raw.get("tx", 0),
            bytes_rx=raw.get("rx", 0),
            packets_tx=raw.get("txPkt"),
            packets_rx=raw.get("rxPkt"),
            tx_rate=raw.get("txRate"),
            rx_rate=raw.get("rxRate"),
        )

    @staticmethod
    def _normalize_gateway_port_config(
        raw_config: dict[str, Any],
        raw_status: dict[str, Any] | None = None,
    ) -> NormalizedGatewayPort:
        """Normalize a gateway portConfigs entry, merged with portStats if available."""
        base = (
            OmadaAdapter._normalize_gateway_port_status(raw_status)
            if raw_status
            else NormalizedGatewayPort(
                port_number=raw_config.get("port", 0),
            )
        )
        poe_mode_map = {-1: "none", 0: "disabled", 1: "enabled", 2: "use_device_settings"}
        poe_mode = raw_config.get("poeMode") or raw_config.get("poe")
        base.poe_mode = poe_mode_map.get(poe_mode) if poe_mode is not None else None
        base.mirror_enabled = raw_config.get("mirrorEnable", False)
        return base

    # =========================================================================
    # Switch / Port Methods
    # =========================================================================

    async def get_ports(self, device_id: str) -> list[dict[str, Any]]:
        """Get port information for a switch.

        Enriches each port with resolved VLAN numbers by cross-referencing
        network IDs against the site's network definitions.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return []

        try:
            raw_ports = await self._client.get_switch_ports(site_id, normalize_mac(device_id))

            # Build network_id → vlan_id lookup for resolving Omada network IDs
            net_id_to_vlan: dict[str, int] = {}
            try:
                networks = await self._client.get_networks(site_id)
                for net in networks:
                    nid = net.get("id") or net.get("networkId")
                    vid = net.get("vlan") or net.get("vid")
                    if nid and vid is not None:
                        net_id_to_vlan[str(nid)] = int(vid)
            except Exception:
                logger.debug("Could not fetch networks for VLAN resolution")

            # Also try to get LLDP neighbor info from the switch detail
            lldp_by_port: dict[int, dict[str, str]] = {}
            try:
                switch_detail = await self._client.get_switch(site_id, normalize_mac(device_id))
                if not isinstance(switch_detail, dict):
                    switch_detail = {}
                # Omada returns port details with LLDP in the switch detail response
                for p_detail in switch_detail.get("portConfigs", []):
                    port_num = p_detail.get("port")
                    lldp_name = p_detail.get("lldpNeighborName") or p_detail.get(
                        "connectedDeviceName"
                    )
                    lldp_port = p_detail.get("lldpNeighborPort") or p_detail.get("connectedPort")
                    if port_num and lldp_name:
                        lldp_by_port[port_num] = {"name": lldp_name, "port": lldp_port or ""}
                # Also check downlinks / uplinks for device name resolution
                for dl in switch_detail.get("downlinkList", []):
                    port_num = dl.get("port") or dl.get("localPort")
                    name = dl.get("name") or dl.get("deviceName")
                    if port_num and name and port_num not in lldp_by_port:
                        lldp_by_port[port_num] = {"name": name, "port": ""}
                uplink_port = switch_detail.get("uplinkPort")
                uplink_name = switch_detail.get("uplinkDeviceName") or switch_detail.get(
                    "gatewayName"
                )
                if uplink_port and uplink_name:
                    lldp_by_port[uplink_port] = {"name": uplink_name, "port": ""}
            except Exception:
                logger.debug("Could not fetch switch detail for LLDP data")

            result = []
            for raw_port in raw_ports:
                np = self._normalize_port(raw_port)
                d = np.model_dump()

                # Resolve nativeNetworkId → native_vlan integer
                if not d.get("native_vlan") and d.get("native_network_id"):
                    resolved = net_id_to_vlan.get(str(d["native_network_id"]))
                    if resolved is not None:
                        d["native_vlan"] = resolved

                # Resolve tagNetworkIds → tagged_vlans integers
                tag_net_ids = d.get("tagged_network_ids") or []
                if tag_net_ids and not d.get("tagged_vlans"):
                    resolved_tags = []
                    for tnid in tag_net_ids:
                        vid = net_id_to_vlan.get(str(tnid))
                        if vid is not None:
                            resolved_tags.append(vid)
                    d["tagged_vlans"] = resolved_tags

                # Determine vlan_mode from profile or tagged VLANs
                profile_name = (d.get("profile_name") or "").lower()
                if (
                    profile_name == "all"
                    or len(d.get("tagged_vlans", [])) > 0
                    or len(tag_net_ids) > 0
                ):
                    d["vlan_mode"] = "trunk"
                else:
                    d["vlan_mode"] = "access"

                # Inject LLDP neighbor data
                port_num = d.get("port_number")
                if port_num and port_num in lldp_by_port:
                    d["lldpNeighborDevice"] = lldp_by_port[port_num]["name"]
                    d["lldpNeighborPort"] = lldp_by_port[port_num]["port"]

                result.append(d)
            return result
        except Exception as e:
            logger.error("Failed to get ports for %s: %s", device_id, e)
            return []

    async def get_switch_ports(self, device_mac: str) -> list[dict[str, Any]]:
        """Alias used by network service wiring matrix."""
        return await self.get_ports(device_mac)

    async def get_port_statistics(self, device_id: str, port: int) -> dict[str, Any]:
        """Get statistics for a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}

        try:
            return await self._client.get_port_statistics(site_id, normalize_mac(device_id), port)
        except Exception as e:
            logger.error("Failed to get port statistics: %s", e)
            return {}

    async def configure_switch_port(
        self,
        device_mac: str,
        port: int,
        config: dict[str, Any],
    ) -> AdapterResult:
        """Configure switch port from arbitrary config payload."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_port(
                site_id,
                normalize_mac(device_mac),
                port,
                config,
            )
            return AdapterResult.ok(data, message="Port updated")
        except Exception as e:
            logger.error("Failed to configure port: %s", e)
            return self._fail_from_exception(e, default_error_code="PORT_UPDATE_FAILED")

    async def set_port_enabled(self, device_id: str, port: int, enabled: bool) -> AdapterResult:
        """Enable or disable a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        try:
            await self._client.update_switch_port(
                site_id,
                normalize_mac(device_id),
                port,
                {"enable": enabled},
            )
            return AdapterResult.ok(
                {"port": port, "enabled": enabled},
                message="Port updated",
            )
        except Exception as e:
            logger.error("Failed to set port state: %s", e)
            return self._fail_from_exception(e, default_error_code="PORT_UPDATE_FAILED")

    async def set_port_poe(
        self,
        device_id: str,
        port: int,
        enabled: bool,
    ) -> AdapterResult:
        """Enable or disable PoE on a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        try:
            await self._client.set_port_poe(site_id, normalize_mac(device_id), port, enabled)
            return AdapterResult.ok(
                {"port": port, "poe_enabled": enabled},
                message="PoE updated",
            )
        except Exception as e:
            logger.error("Failed to set PoE: %s", e)
            return self._fail_from_exception(e, default_error_code="POE_FAILED")

    async def cycle_poe_port(
        self,
        device_id: str,
        port: int,
        duration: int = 5,
    ) -> AdapterResult:
        """Cycle PoE power on a switch port."""
        try:
            result = await self.set_port_poe(device_id, port, False)
            if not result.success:
                return result

            await asyncio.sleep(duration)

            result = await self.set_port_poe(device_id, port, True)
            return result
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="POE_CYCLE_FAILED")

    async def get_poe_status(self, device_id: str) -> dict[str, Any]:
        """Get PoE status for all ports on a device."""
        ports = await self.get_ports(device_id)
        return {
            "device_id": device_id,
            "ports": [
                {
                    "port": p["port_number"],
                    "poe_enabled": p["poe_enabled"],
                    "poe_power": p["poe_power"],
                    "poe_supported": p.get("poe_supported", False),
                    "poe_max_power": p.get("poe_max_power"),
                }
                for p in ports
            ],
        }

    # =========================================================================
    # Switch Detail Methods
    # =========================================================================

    async def get_switches(self) -> list[dict[str, Any]]:
        """Get all switches with full detail (capabilities, ports, uplinks)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_switches(site_id)
        except Exception as e:
            logger.error("Failed to get switches: %s", e)
            return []

    async def get_switch_detail(self, device_mac: str) -> dict[str, Any]:
        """Get detailed switch info: ports, device_capabilities, uplinks, downlinks."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            raw = await self._client.get_switch(site_id, normalize_mac(device_mac))
            caps = raw.get("deviceCaps") or raw.get("deviceCapabilities") or {}
            uplink = raw.get("uplink") or {}
            downlinks = raw.get("downlink") or raw.get("downlinks") or []

            # PoE power budget
            poe_budget = caps.get("poePower") or raw.get("poePower") or raw.get("poeTotalPower")
            poe_consumed = raw.get("poeConsumedPower") or raw.get("poeConsumption")
            poe_remaining: float | None = None
            # Derive consumed from remaining if not directly available
            if poe_consumed is None and poe_budget is not None and raw.get("poeRemain") is not None:
                with contextlib.suppress(ValueError, TypeError):
                    poe_consumed = float(poe_budget) - float(raw["poeRemain"])
            if poe_budget is not None and poe_consumed is not None:
                with contextlib.suppress(ValueError, TypeError):
                    poe_remaining = float(poe_budget) - float(poe_consumed)

            detail = NormalizedSwitchDetail(
                mac=normalize_mac(raw.get("mac", "")),
                name=raw.get("name"),
                model=raw.get("model") or raw.get("showModel"),
                ip=raw.get("ip"),
                status=DEVICE_STATUS_MAP.get(raw.get("status"), "unknown"),
                firmware_version=raw.get("firmwareVersion"),
                hardware_version=raw.get("hardwareVersion"),
                serial_number=raw.get("serialNumber") or raw.get("sn"),
                number_of_ports=raw.get("portNum", 0),
                poe_ports=caps.get("poePorts", 0),
                supports_poe=caps.get("supportPoe", False),
                poe_budget_watts=poe_budget,
                poe_consumed_watts=poe_consumed,
                poe_remaining_watts=poe_remaining,
                lldp_enabled=raw.get("lldpEnable", False),
                temperature=raw.get("temperature"),
                uplink_device_mac=uplink.get("mac"),
                uplink_device_name=uplink.get("name"),
                uplink_port=uplink.get("port"),
                downlinks=[
                    {
                        "mac": dl.get("mac"),
                        "name": dl.get("name"),
                        "type": dl.get("type"),
                        "port": dl.get("port"),
                        "model": dl.get("model"),
                    }
                    for dl in (downlinks if isinstance(downlinks, list) else [])
                ],
                uptime=raw.get("uptimeLong"),
                cpu_usage=raw.get("cpuUtil"),
                memory_usage=raw.get("memUtil"),
                led_setting=raw.get("ledSetting"),
            ).model_dump()

            # Add extra fields not in the model but useful for display
            detail["ipv6_address"] = raw.get("ipv6Address") or raw.get("ipv6")
            detail["controller_connection_ip"] = raw.get("controllerIp") or raw.get(
                "connectControllerIp"
            )
            detail["model_version"] = raw.get("showModel") or raw.get("model")
            fan_info = raw.get("fanStatus") or raw.get("fans") or []
            detail["fan_status"] = (
                fan_info if isinstance(fan_info, list) else [fan_info] if fan_info else []
            )
            detail["poe_total_power"] = poe_budget
            detail["client_count"] = raw.get("clientNum") or 0
            return detail
        except Exception as e:
            logger.error("Failed to get switch detail for %s: %s", device_mac, e)
            return {}

    async def get_switch_port_overrides(self, device_mac: str, port_id: int) -> dict[str, Any]:
        """Get port profile override settings for a specific switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_switch_port_overrides(
                site_id, normalize_mac(device_mac), port_id
            )
        except Exception as e:
            logger.error("Failed to get port overrides: %s", e)
            return {}

    async def set_switch_port_stp(
        self, device_mac: str, port_id: int, enabled: bool
    ) -> AdapterResult:
        """Enable / disable STP on a single switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_stp(
                site_id, normalize_mac(device_mac), port_id, enabled
            )
            return AdapterResult.ok(data, message=f"STP {'enabled' if enabled else 'disabled'}")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="STP_FAILED")

    async def set_switch_port_lldp(
        self, device_mac: str, port_id: int, enabled: bool
    ) -> AdapterResult:
        """Enable / disable LLDP-MED on a single switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_lldp(
                site_id, normalize_mac(device_mac), port_id, enabled
            )
            return AdapterResult.ok(data, message=f"LLDP {'enabled' if enabled else 'disabled'}")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LLDP_FAILED")

    async def set_switch_port_isolation(
        self, device_mac: str, port_id: int, enabled: bool
    ) -> AdapterResult:
        """Enable / disable port isolation."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_isolation(
                site_id, normalize_mac(device_mac), port_id, enabled
            )
            return AdapterResult.ok(
                data, message=f"Port isolation {'enabled' if enabled else 'disabled'}"
            )
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="PORT_ISOLATION_FAILED")

    async def set_switch_port_speed_duplex(
        self,
        device_mac: str,
        port_id: int,
        speed: str = "auto",
        duplex: str = "auto",
    ) -> AdapterResult:
        """Set link speed / duplex on a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_speed_duplex(
                site_id, normalize_mac(device_mac), port_id, speed, duplex
            )
            return AdapterResult.ok(data, message=f"Speed/duplex set to {speed}/{duplex}")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="SPEED_DUPLEX_FAILED")

    async def get_switch_stp_config(self) -> dict[str, Any]:
        """Get site-level STP / RSTP global config."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_switch_stp_config(site_id)
        except Exception as e:
            logger.error("Failed to get STP config: %s", e)
            return {}

    async def update_switch_stp_config(self, config: dict[str, Any]) -> AdapterResult:
        """Update site-level STP config (mode, priority, hello, max_age)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_stp_config(site_id, config)
            return AdapterResult.ok(data, message="STP config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="STP_CONFIG_FAILED")

    async def get_switch_lag_groups(self, device_mac: str) -> list[dict[str, Any]]:
        """Get LAG / LAGG groups for a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_switch_lag_groups(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get LAG groups: %s", e)
            return []

    async def create_switch_lag(self, device_mac: str, config: dict[str, Any]) -> AdapterResult:
        """Create a LAG group on a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_switch_lag(site_id, normalize_mac(device_mac), config)
            return AdapterResult.ok(data, message="LAG created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LAG_CREATE_FAILED")

    async def update_switch_lag(
        self, device_mac: str, lag_id: int, config: dict[str, Any]
    ) -> AdapterResult:
        """Update a LAG group on a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_lag(
                site_id, normalize_mac(device_mac), lag_id, config
            )
            return AdapterResult.ok(data, message="LAG updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LAG_UPDATE_FAILED")

    async def delete_switch_lag(self, device_mac: str, lag_id: int) -> AdapterResult:
        """Delete a LAG group from a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.delete_switch_lag(site_id, normalize_mac(device_mac), lag_id)
            return AdapterResult.ok(data, message="LAG deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LAG_DELETE_FAILED")

    async def get_switch_mirror_config(self, device_mac: str) -> dict[str, Any]:
        """Get port mirror config for a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_switch_mirror_config(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get mirror config: %s", e)
            return {}

    async def update_switch_mirror_config(
        self, device_mac: str, config: dict[str, Any]
    ) -> AdapterResult:
        """Update port mirror config (session/source/dest)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_mirror_config(
                site_id, normalize_mac(device_mac), config
            )
            return AdapterResult.ok(data, message="Mirror config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="MIRROR_FAILED")

    # =========================================================================
    # Gateway / WAN / LAN Port Methods
    # =========================================================================

    async def get_gateways(self) -> list[dict[str, Any]]:
        """Get all gateways for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_gateways(site_id)
        except Exception as e:
            logger.error("Failed to get gateways: %s", e)
            return []

    async def get_gateway_detail(self, device_mac: str) -> dict[str, Any]:
        """Get full gateway detail: normalized with ports, metrics, features."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            raw = await self._client.get_gateway(site_id, normalize_mac(device_mac))
            caps = raw.get("deviceCaps") or raw.get("deviceCapabilities") or {}
            uplink = raw.get("uplink") or {}
            port_stats = raw.get("portStats") or []
            raw.get("portConfigs") or []

            # Classify WAN / LAN ports
            wan_ports: list[dict[str, Any]] = []
            lan_ports: list[dict[str, Any]] = []
            for ps in port_stats:
                mode_val = ps.get("mode", -1)
                summary = {
                    "port": ps.get("port"),
                    "name": ps.get("name") or ps.get("portDesc"),
                    "link_status": "up" if ps.get("status") == 1 else "down",
                    "speed": ps.get("speed"),
                    "ip": ps.get("ip"),
                    "gateway": ps.get("gateway"),
                    "poe_active": ps.get("poe", False),
                    "rx_bytes": ps.get("rx"),
                    "tx_bytes": ps.get("tx"),
                }
                if mode_val == 0:  # WAN
                    wan_ports.append(summary)
                else:
                    lan_ports.append(summary)

            # WAN public IP (from first up WAN port)
            wan_ipv4: str | None = None
            public_ip: str | None = None
            for wp in wan_ports:
                if wp.get("link_status") == "up":
                    wan_ipv4 = wp.get("ip")
                    break
            # public IP from raw device field
            public_ip = raw.get("publicIp") or raw.get("wanIp")

            return NormalizedGatewayDetail(
                mac=normalize_mac(raw.get("mac", "")),
                name=raw.get("name"),
                model=raw.get("model") or raw.get("showModel"),
                ip=raw.get("ip"),
                status=DEVICE_STATUS_MAP.get(raw.get("status"), "unknown"),
                firmware_version=raw.get("firmwareVersion"),
                hardware_version=raw.get("hardwareVersion"),
                serial_number=raw.get("serialNumber") or raw.get("sn"),
                number_of_ports=len(port_stats),
                wan_port_count=len(wan_ports),
                lan_port_count=len(lan_ports),
                supports_poe=caps.get("supportPoe", False),
                poe_budget_watts=caps.get("poePower")
                or raw.get("poePower")
                or raw.get("poeTotalPower"),
                poe_consumed_watts=raw.get("poeConsumedPower") or raw.get("poeConsumption"),
                wan_ipv4=wan_ipv4,
                public_ip=public_ip,
                uplink_ip=uplink.get("ip"),
                uplink_device_mac=uplink.get("mac"),
                uplink_device_name=uplink.get("name"),
                combined_gateway=raw.get("combinedGateway", False),
                lldp_enabled=raw.get("lldpEnable", False),
                echo_server=raw.get("echoServer"),
                led_setting=raw.get("ledSetting"),
                uptime=raw.get("uptimeLong"),
                cpu_usage=raw.get("cpuUtil"),
                memory_usage=raw.get("memUtil"),
                wan_ports=wan_ports,
                lan_ports=lan_ports,
            ).model_dump()
        except Exception as e:
            logger.error("Failed to get gateway detail for %s: %s", device_mac, e)
            return {}

    async def get_gateway_ports(self, device_mac: str) -> list[dict[str, Any]]:
        """Get ALL gateway ports with full status (WAN/LAN, PoE, IP, IPv6, link, traffic)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            gw = await self._client.get_gateway(site_id, normalize_mac(device_mac))
            port_stats = gw.get("portStats", [])
            port_configs = gw.get("portConfigs", [])

            # Build a config lookup by port number
            config_by_port: dict[int, dict[str, Any]] = {}
            for cfg in port_configs:
                config_by_port[cfg.get("port", -1)] = cfg

            # Merge poeSettings into configs
            poe_settings = gw.get("poeSettings", [])
            for poe in poe_settings:
                port_num = poe.get("port")
                if port_num is not None and port_num in config_by_port:
                    config_by_port[port_num]["poeMode"] = poe.get("poe")

            results: list[dict[str, Any]] = []
            for ps in port_stats:
                port_num = ps.get("port", -1)
                cfg = config_by_port.get(port_num, {})
                normalized = self._normalize_gateway_port_config(cfg, ps)
                results.append(normalized.model_dump())

            return results
        except Exception as e:
            logger.error("Failed to get gateway ports for %s: %s", device_mac, e)
            return []

    async def get_wan_ports(self, device_mac: str) -> list[dict[str, Any]]:
        """Get only WAN ports from gateway (filtered from get_gateway_ports)."""
        all_ports = await self.get_gateway_ports(device_mac)
        return [p for p in all_ports if p.get("mode") == "wan"]

    async def get_lan_ports(self, device_mac: str) -> list[dict[str, Any]]:
        """Get only LAN ports from gateway (filtered from get_gateway_ports)."""
        all_ports = await self.get_gateway_ports(device_mac)
        return [p for p in all_ports if p.get("mode") == "lan"]

    async def set_gateway_wan_connect(
        self,
        device_mac: str,
        port_number: int,
        connect: bool,
        ipv6: bool = False,
    ) -> AdapterResult:
        """Connect/disconnect a WAN port on gateway (IPv4 or IPv6)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.set_gateway_wan_port_connect_state(
                site_id, normalize_mac(device_mac), port_number, connect, ipv6=ipv6
            )
            return AdapterResult.ok(
                data,
                message=f"WAN port {'connected' if connect else 'disconnected'}",
            )
        except Exception as e:
            logger.error("Failed to set WAN connect state: %s", e)
            return self._fail_from_exception(e, default_error_code="WAN_CONTROL_FAILED")

    async def set_gateway_port_poe(
        self, device_mac: str, port_number: int, enabled: bool
    ) -> AdapterResult:
        """Enable/disable PoE on a gateway port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.set_gateway_port_settings(
                site_id,
                normalize_mac(device_mac),
                port_number,
                {"poeMode": 1 if enabled else 0},
            )
            return AdapterResult.ok(data, message="Gateway PoE updated")
        except Exception as e:
            logger.error("Failed to set gateway PoE: %s", e)
            return self._fail_from_exception(e, default_error_code="POE_FAILED")

    # =========================================================================
    # Access Point Methods
    # =========================================================================

    async def get_access_points(self) -> list[dict[str, Any]]:
        """Get all APs for active site with full detail."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_aps(site_id)
        except Exception as e:
            logger.error("Failed to get access points: %s", e)
            return []

    async def get_ap_detail(self, device_mac: str) -> dict[str, Any]:
        """Get detailed AP info: radio config, LAN port, mesh, LED."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            raw = await self._client.get_ap(site_id, normalize_mac(device_mac))
            lan_settings = raw.get("lanPortSettings") or raw.get("lanPort") or {}
            radios = raw.get("radioConfig") or raw.get("radios") or []
            if isinstance(radios, dict):
                radios = [radios]
            elif not isinstance(radios, list):
                radios = []

            # Handle per-band keys: radioSetting2g, radioSetting5g, etc.
            # Band codes are canonical (2g|5g|5g2|6g) so the FE channel dropdown
            # and the update_ap_radio apply path round-trip the same identifier.
            if not radios:
                for suffix, band_name in [
                    ("2g", "2g"),
                    ("5g", "5g"),
                    ("5g2", "5g2"),
                    ("6g", "6g"),
                ]:
                    key = f"radioSetting{suffix}"
                    if key in raw and raw[key]:
                        entry = dict(raw[key])
                        entry["band"] = band_name
                        radios.append(entry)

            return NormalizedAPDetail(
                mac=normalize_mac(raw.get("mac", "")),
                name=raw.get("name"),
                model=raw.get("model") or raw.get("showModel"),
                ip=raw.get("ip"),
                status=DEVICE_STATUS_MAP.get(raw.get("status"), "unknown"),
                firmware_version=raw.get("firmwareVersion"),
                clients=raw.get("clientNum", 0),
                radios=[
                    {
                        "band": r.get("band"),
                        "channel": r.get("channel"),
                        "channel_width": r.get("channelWidth"),
                        "tx_power": r.get("txPower"),
                        "tx_power_mode": r.get("txPowerMode"),
                        "clients": r.get("clients", 0),
                    }
                    for r in radios
                ],
                mesh_enabled=raw.get("isMeshStatus", raw.get("meshEnabled", False)),
                led_enabled=raw.get("ledSetting") == 1
                if raw.get("ledSetting") is not None
                else None,
                lan_port_vlan_enabled=lan_settings.get("localVlanEnable", False)
                if isinstance(lan_settings, dict)
                else False,
                lan_port_vlan_id=lan_settings.get("localVlanId")
                if isinstance(lan_settings, dict)
                else None,
                lan_port_poe_enabled=lan_settings.get("poeEnable")
                if isinstance(lan_settings, dict)
                else None,
                uptime=raw.get("uptimeLong"),
                cpu_usage=raw.get("cpuUtil"),
                memory_usage=raw.get("memUtil"),
            ).model_dump()
        except Exception as e:
            logger.error("Failed to get AP detail for %s: %s", device_mac, e)
            return {}

    async def get_ap_lan_port(self, device_mac: str) -> dict[str, Any]:
        """Get AP LAN port settings (VLAN, PoE passthrough)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_ap_lan_port(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get AP LAN port: %s", e)
            return {}

    async def configure_ap_lan_port(self, device_mac: str, config: dict[str, Any]) -> AdapterResult:
        """Configure AP LAN port (VLAN tagging, PoE passthrough)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.update_ap_lan_port(site_id, normalize_mac(device_mac), config)
            return AdapterResult.ok(data, message="AP LAN port updated")
        except Exception as e:
            logger.error("Failed to configure AP LAN port: %s", e)
            return self._fail_from_exception(e, default_error_code="AP_CONFIG_FAILED")

    async def get_ap_radios(self, device_mac: str) -> list[dict[str, Any]]:
        """Get radio config for an AP (channels, tx power, band, width)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_ap_radios(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get AP radios: %s", e)
            return []

    async def update_ap_radio(
        self, device_mac: str, radio_band: str, config: dict[str, Any]
    ) -> AdapterResult:
        """Update radio settings for a specific band (2g, 5g, 5g2, 6g)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        # Normalize whatever band identifier the caller produced (human label,
        # hyphenated 5g-2, etc.) to the canonical key the controller expects.
        radio_band = _canonical_radio_band(radio_band)
        try:
            data = await self._client.update_ap_radio(
                site_id, normalize_mac(device_mac), radio_band, config
            )
            return AdapterResult.ok(data, message=f"Radio {radio_band} updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="RADIO_CONFIG_FAILED")

    async def get_ap_ssid_overrides(self, device_mac: str) -> list[dict[str, Any]]:
        """Get per-AP SSID overrides (which WLANs enabled/disabled)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_ap_ssid_overrides(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get AP SSID overrides: %s", e)
            return []

    async def update_ap_ssid_override(
        self, device_mac: str, overrides: list[dict[str, Any]]
    ) -> AdapterResult:
        """Set per-AP SSID overrides."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_ap_ssid_override(
                site_id, normalize_mac(device_mac), overrides
            )
            return AdapterResult.ok(data, message="SSID overrides updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="SSID_OVERRIDE_FAILED")

    async def get_ap_clients(self, device_mac: str) -> list[dict[str, Any]]:
        """Get clients connected to a specific AP."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_ap_clients(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get AP clients: %s", e)
            return []

    async def set_ap_mesh(self, device_mac: str, enabled: bool) -> AdapterResult:
        """Enable / disable mesh networking on an AP."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_ap_mesh(site_id, normalize_mac(device_mac), enabled)
            return AdapterResult.ok(data, message=f"Mesh {'enabled' if enabled else 'disabled'}")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="MESH_FAILED")

    async def set_ap_location(
        self, device_mac: str, latitude: float, longitude: float
    ) -> AdapterResult:
        """Set AP geographical location."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_ap_location(
                site_id, normalize_mac(device_mac), latitude, longitude
            )
            return AdapterResult.ok(data, message="AP location set")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LOCATION_FAILED")

    async def get_ap_rf_scan(self, device_mac: str) -> dict[str, Any]:
        """Get RF scan results for an AP."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_ap_rf_scan(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get RF scan: %s", e)
            return {}

    # =========================================================================
    # Known Clients / Client Details
    # =========================================================================

    async def get_known_clients(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get all known clients (including previously connected / offline)."""
        site = site_id or await self._ensure_site_id()
        if not site:
            return []
        try:
            rows = await self._client.get_known_clients(site)
            return [self._normalize_client(c).model_dump() for c in rows]
        except Exception as e:
            logger.error("Failed to get known clients: %s", e)
            return []

    async def get_client_detail(self, client_mac: str) -> dict[str, Any]:
        """Get detailed info for a single client."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_client(site_id, normalize_mac(client_mac))
        except Exception as e:
            logger.error("Failed to get client detail: %s", e)
            return {}

    async def update_client_settings(
        self, client_mac: str, settings: dict[str, Any]
    ) -> AdapterResult:
        """Update client settings (name, lock to APs, fixed IP)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.update_client(site_id, normalize_mac(client_mac), settings)
            return AdapterResult.ok(data, message="Client settings updated")
        except Exception as e:
            logger.error("Failed to update client settings: %s", e)
            return self._fail_from_exception(e, default_error_code="CLIENT_UPDATE_FAILED")

    async def reconnect_client(self, client_mac: str) -> AdapterResult:
        """Force client reconnection (distinct from kick/block)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            await self._client.reconnect_client(site_id, normalize_mac(client_mac))
            return AdapterResult.ok(
                {"client_mac": normalize_mac(client_mac)},
                message="Client reconnected",
            )
        except Exception as e:
            logger.error("Failed to reconnect client: %s", e)
            return self._fail_from_exception(e, default_error_code="CLIENT_RECONNECT_FAILED")

    # =========================================================================
    # LED Control (generic — any device type)
    # =========================================================================

    async def set_device_led(self, device_id: str, setting: int = 1) -> AdapterResult:
        """Set device LED mode (0=off, 1=on, 2=site_settings). Works for any device type."""
        found = await self._find_device_site(device_id)
        if not found:
            return AdapterResult.fail("Device not found", error_code="NOT_FOUND")
        site_id, raw = found
        mac = normalize_mac(raw.get("mac"))
        device_type = raw.get("type", "")
        try:
            await self._client.set_device_led(site_id, mac, device_type, setting)
            return AdapterResult.ok(
                {"device_id": mac, "led_setting": setting},
                message="LED setting updated",
            )
        except Exception as e:
            logger.error("Failed to set device LED: %s", e)
            return self._fail_from_exception(e, default_error_code="LED_FAILED")

    async def adopt_device(self, device_mac: str) -> AdapterResult:
        """Adopt a pending device into the controller."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            mac = normalize_mac(device_mac)
            await self._client.adopt_device(site_id, mac)
            return AdapterResult.ok(
                {"device_mac": mac, "action": "adopt"},
                message="Device adoption initiated",
            )
        except Exception as e:
            logger.error("Failed to adopt device %s: %s", device_mac, e)
            return self._fail_from_exception(e, default_error_code="ADOPT_FAILED")

    async def forget_device(self, device_mac: str) -> AdapterResult:
        """Forget (remove) a device from the controller."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            mac = normalize_mac(device_mac)
            await self._client.forget_device(site_id, mac)
            return AdapterResult.ok(
                {"device_mac": mac, "action": "forget"},
                message="Device forgotten",
            )
        except Exception as e:
            logger.error("Failed to forget device %s: %s", device_mac, e)
            return self._fail_from_exception(e, default_error_code="FORGET_FAILED")

    # =========================================================================
    # VLAN / Network Methods
    # =========================================================================

    async def get_vlans(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get VLAN/network definitions from active site."""
        site = site_id or await self._ensure_site_id()
        if not site:
            return []
        try:
            rows = await self._client.get_networks(site)
            return [self._normalize_vlan(row).model_dump() for row in rows]
        except Exception as e:
            logger.error("Failed to get VLANs: %s", e)
            return []

    async def create_vlan(
        self,
        vlan_id: int | dict[str, Any],
        name: str | None = None,
        **kwargs: Any,
    ) -> AdapterResult:
        """Create VLAN with idempotent behavior for duplicates."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        if isinstance(vlan_id, dict):
            payload = dict(vlan_id)
            target_vlan = int(payload.get("vlanId") or payload.get("vlan_id") or 0)
        else:
            payload = {"vlanId": vlan_id, "name": name, **kwargs}
            target_vlan = int(vlan_id)

        existing = await self.get_vlans(site_id)
        existing_match = next(
            (row for row in existing if int(row.get("vlan_id") or -1) == target_vlan),
            None,
        )
        if existing_match:
            return AdapterResult.ok(existing_match, message="VLAN already exists")

        if "vlan_id" in payload and "vlanId" not in payload:
            payload["vlanId"] = payload.pop("vlan_id")
        if "subnet_mask" in payload and "subnetMask" not in payload:
            payload["subnetMask"] = payload.pop("subnet_mask")

        try:
            data = await self._client.create_network(site_id, payload)
            return AdapterResult.ok(data, message="VLAN created")
        except Exception as e:
            logger.error("Failed to create VLAN: %s", e)
            return self._fail_from_exception(e, default_error_code="VLAN_CREATE_FAILED")

    async def update_vlan(self, vlan_id: str, config: dict[str, Any]) -> AdapterResult:
        """Update VLAN by network ID or VLAN number."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        existing = await self.get_vlans(site_id)
        target = next(
            (
                row
                for row in existing
                if str(row.get("id")) == str(vlan_id) or str(row.get("vlan_id")) == str(vlan_id)
            ),
            None,
        )
        if not target:
            return AdapterResult.fail("VLAN not found", error_code="NOT_FOUND")

        network_id = str(target.get("id"))
        payload = dict(config)
        if "vlan_id" in payload and "vlanId" not in payload:
            payload["vlanId"] = payload.pop("vlan_id")
        if "subnet_mask" in payload and "subnetMask" not in payload:
            payload["subnetMask"] = payload.pop("subnet_mask")

        try:
            data = await self._client.update_network(site_id, network_id, payload)
            return AdapterResult.ok(data, message="VLAN updated")
        except Exception as e:
            logger.error("Failed to update VLAN: %s", e)
            return self._fail_from_exception(e, default_error_code="VLAN_UPDATE_FAILED")

    async def delete_vlan(self, vlan_id: str | int) -> AdapterResult:
        """Delete VLAN by network ID or VLAN number (idempotent)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        existing = await self.get_vlans(site_id)
        target = next(
            (
                row
                for row in existing
                if str(row.get("id")) == str(vlan_id) or str(row.get("vlan_id")) == str(vlan_id)
            ),
            None,
        )
        if not target:
            return AdapterResult.ok(None, message="VLAN already absent")

        network_id = str(target.get("id"))
        try:
            await self._client.delete_network(site_id, network_id)
            return AdapterResult.ok(None, message="VLAN deleted")
        except Exception as e:
            logger.error("Failed to delete VLAN: %s", e)
            return self._fail_from_exception(e, default_error_code="VLAN_DELETE_FAILED")

    # =========================================================================
    # WiFi / Client Methods
    # =========================================================================

    async def get_clients(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get connected clients with full WiFi detail for wireless clients."""
        site = site_id or await self._ensure_site_id()
        if not site:
            return []

        try:
            get_clients_enriched = getattr(self._client, "get_clients_enriched", None)
            rows: Any = None
            if callable(get_clients_enriched):
                rows = await get_clients_enriched(site)
            if not isinstance(rows, list):
                rows = await self._client.get_clients(site)
            return [self._normalize_client(c).model_dump() for c in rows]
        except Exception as e:
            logger.error("Failed to get clients: %s", e)
            return []

    async def get_ssids(self, site_id: str | None = None) -> list[dict[str, Any]]:
        """Get all SSIDs across all WLAN groups."""
        site = site_id or await self._ensure_site_id()
        if not site:
            return []

        try:
            rows = await self._client.get_ssids(site)
            results = []
            for s in rows:
                normalized = self._normalize_ssid(s).model_dump()
                # Carry through Omada-specific metadata for sync
                normalized["_raw"] = s
                normalized["wlan_group_id"] = s.get("_wlanGroupId")
                normalized["wlan_group_name"] = s.get("_wlanGroupName")
                normalized["fast_roaming"] = bool(s.get("enable11r", False))
                normalized["schedule_enabled"] = bool(s.get("wlanScheduleEnable", False))
                normalized["mac_filter_enabled"] = bool(s.get("macFilterEnable", False))
                normalized["portal_enabled"] = bool(s.get("portalEnable", False))
                # Rate limit info
                rl = s.get("rateLimit") or {}
                ssid_rl = s.get("ssidRateLimit") or {}
                normalized["rate_limit_enabled"] = bool(
                    rl.get("upLimitEnable")
                    or rl.get("downLimitEnable")
                    or ssid_rl.get("upLimitEnable")
                    or ssid_rl.get("downLimitEnable")
                )
                normalized["rate_limit_up"] = (
                    rl.get("upLimitKbps") if rl.get("upLimitEnable") else None
                )
                normalized["rate_limit_down"] = (
                    rl.get("downLimitKbps") if rl.get("downLimitEnable") else None
                )
                results.append(normalized)
            return results
        except Exception as e:
            logger.error("Failed to get SSIDs: %s", e)
            return []

    async def toggle_ssid(self, ssid_id: str, enabled: bool) -> AdapterResult:
        """Enable or disable an SSID."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        try:
            await self._client.update_ssid(site_id, ssid_id, {"enable": enabled})
            return AdapterResult.ok(
                {"ssid_id": ssid_id, "enabled": enabled},
                message="SSID updated",
            )
        except Exception as e:
            logger.error("Failed to toggle SSID: %s", e)
            return self._fail_from_exception(e, default_error_code="SSID_FAILED")

    async def create_ssid(self, config: dict[str, Any]) -> AdapterResult:
        """Create WiFi SSID with duplicate-name protection."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        wlan_id = config.pop("wlan_group_id", None)

        # Idempotency: reject duplicate SSID name
        ssid_name = config.get("name") or config.get("ssid")
        if ssid_name:
            try:
                existing = await self._client.get_ssids(site_id)
                for row in existing:
                    existing_name = row.get("name") or row.get("ssid")
                    if existing_name and existing_name.lower() == ssid_name.lower():
                        return AdapterResult.fail(
                            "duplicate_name",
                            error_code="DUPLICATE_SSID",
                            message=f"SSID '{ssid_name}' already exists",
                        )
            except Exception:
                pass  # proceed anyway — Omada will reject duplicates too

        try:
            data = await self._client.create_ssid(site_id, config, wlan_id=wlan_id)
            return AdapterResult.ok(data, message="SSID created")
        except Exception as e:
            logger.error("Failed to create SSID: %s", e)
            return self._fail_from_exception(e, default_error_code="SSID_CREATE_FAILED")

    async def update_ssid(self, ssid_id: str, config: dict[str, Any]) -> AdapterResult:
        """Update WiFi SSID."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")

        wlan_id = config.pop("wlan_group_id", None)
        try:
            data = await self._client.update_ssid(site_id, ssid_id, config, wlan_id=wlan_id)
            return AdapterResult.ok(data, message="SSID updated")
        except Exception as e:
            logger.error("Failed to update SSID: %s", e)
            return self._fail_from_exception(e, default_error_code="SSID_UPDATE_FAILED")

    async def delete_ssid(self, ssid_id: str, wlan_id: str | None = None) -> AdapterResult:
        """Delete WiFi SSID with idempotent behavior."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            await self._client.delete_ssid(site_id, ssid_id, wlan_id=wlan_id)
            return AdapterResult.ok(None, message="SSID deleted")
        except OmadaNotFoundError:
            return AdapterResult.ok(None, message="SSID already absent")
        except Exception as e:
            if isinstance(e, OmadaApiError) and "not found" in str(e).lower():
                return AdapterResult.ok(None, message="SSID already absent")
            logger.error("Failed to delete SSID: %s", e)
            return self._fail_from_exception(e, default_error_code="SSID_DELETE_FAILED")

    async def get_wifi_clients(self) -> list[dict[str, Any]]:
        """Alias used by network service matrix."""
        return await self.get_clients()

    async def kick_client(self, client_mac: str) -> AdapterResult:
        """Disconnect (kick) WiFi client."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            normalized = normalize_mac(client_mac)
            await self._client.kick_client(site_id, normalized)
            return AdapterResult.ok(
                {"client_mac": normalize_mac(client_mac)},
                message="Client disconnected",
            )
        except Exception as e:
            logger.error("Failed to kick client: %s", e)
            return self._fail_from_exception(e, default_error_code="CLIENT_KICK_FAILED")

    async def block_client(self, client_mac: str) -> AdapterResult:
        """Block WiFi client (idempotent — already blocked returns ok)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            normalized = normalize_mac(client_mac)
            await self._client.block_client(site_id, normalized)
            return AdapterResult.ok(
                {"client_mac": normalized},
                message="Client blocked",
            )
        except OmadaNotFoundError:
            return AdapterResult.ok(
                {"client_mac": normalize_mac(client_mac)},
                message="Client already blocked or not found",
            )
        except Exception as e:
            # Omada sometimes returns generic error if already blocked
            if isinstance(e, OmadaApiError) and "already" in str(e).lower():
                return AdapterResult.ok(
                    {"client_mac": normalize_mac(client_mac)},
                    message="Client already blocked",
                )
            logger.error("Failed to block client: %s", e)
            return self._fail_from_exception(e, default_error_code="CLIENT_BLOCK_FAILED")

    async def unblock_client(self, client_mac: str) -> AdapterResult:
        """Unblock WiFi client."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            normalized = normalize_mac(client_mac)
            await self._client.unblock_client(site_id, normalized)
            return AdapterResult.ok(
                {"client_mac": normalize_mac(client_mac)},
                message="Client unblocked",
            )
        except OmadaNotFoundError:
            return AdapterResult.ok(
                {"client_mac": normalize_mac(client_mac)},
                message="Client already unblocked",
            )
        except Exception as e:
            if isinstance(e, OmadaApiError) and "not found" in str(e).lower():
                return AdapterResult.ok(
                    {"client_mac": normalize_mac(client_mac)},
                    message="Client already unblocked",
                )
            logger.error("Failed to unblock client: %s", e)
            return self._fail_from_exception(e, default_error_code="CLIENT_UNBLOCK_FAILED")

    # =========================================================================
    # Device Control Methods
    # =========================================================================

    async def reboot_device(self, device_id: str) -> AdapterResult:
        """Reboot a device."""
        found = await self._find_device_site(device_id)
        if not found:
            return AdapterResult.fail("Device not found", error_code="NOT_FOUND")
        site_id, raw = found
        normalized_mac = normalize_mac(raw.get("mac"))

        now = time.monotonic()
        last_reboot = self._last_reboot_by_device.get(normalized_mac)
        if last_reboot is not None and (now - last_reboot) < REBOOT_COOLDOWN_SECONDS:
            return AdapterResult.fail(
                "reboot_rate_limited",
                error_code="RATE_LIMITED",
                message="Device reboot requested too recently",
            )

        endpoint = DEVICE_TYPE_ENDPOINT.get(DEVICE_TYPE_MAP.get(raw.get("type"), raw.get("type")))
        if not endpoint:
            return AdapterResult.fail("Unknown device type", error_code="NOT_SUPPORTED")

        try:
            omada_type = str(raw.get("type") or "")
            await self._client.reboot_device(site_id, normalized_mac, omada_type)
            self._last_reboot_by_device[normalized_mac] = now
            return AdapterResult.ok(
                {"device_id": normalized_mac, "action": "reboot"},
                message="Reboot initiated",
            )
        except Exception as e:
            logger.error("Failed to reboot device: %s", e)
            return self._fail_from_exception(e, default_error_code="REBOOT_FAILED")

    async def locate_device(self, device_id: str, duration: int = 30) -> AdapterResult:
        """Flash LEDs to locate a device (APs only)."""
        found = await self._find_device_site(device_id)
        if not found:
            return AdapterResult.fail("Device not found", error_code="NOT_FOUND")
        site_id, raw = found
        normalized_mac = normalize_mac(raw.get("mac"))

        if raw.get("type") != "ap":
            return AdapterResult.fail(
                "unsupported_operation",
                error_code="NOT_SUPPORTED",
                message="Locate is supported for access points",
            )

        try:
            await self._client.set_ap_led(site_id, normalized_mac, True, duration)
            return AdapterResult.ok(
                {"device_id": normalized_mac, "action": "locate", "duration": duration},
                message="Locate initiated",
            )
        except Exception as e:
            logger.error("Failed to locate device: %s", e)
            return self._fail_from_exception(e, default_error_code="LOCATE_FAILED")

    # =========================================================================
    # Port profiles / gateway / firmware / health
    # =========================================================================

    async def get_port_profiles(self) -> list[dict[str, Any]]:
        """Get switch port profiles for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_port_profiles(site_id)
            return [self._normalize_port_profile(r).model_dump() for r in rows]
        except Exception as e:
            logger.error("Failed to get port profiles: %s", e)
            return []

    async def create_port_profile(self, config: dict[str, Any]) -> AdapterResult:
        """Create switch port profile."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.create_port_profile(site_id, config)
            return AdapterResult.ok(data, message="Port profile created")
        except Exception as e:
            logger.error("Failed to create port profile: %s", e)
            return self._fail_from_exception(e, default_error_code="PORT_PROFILE_CREATE_FAILED")

    async def update_port_profile(self, profile_id: str, config: dict[str, Any]) -> AdapterResult:
        """Update switch port profile."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            data = await self._client.update_port_profile(site_id, profile_id, config)
            return AdapterResult.ok(data, message="Port profile updated")
        except Exception as e:
            logger.error("Failed to update port profile: %s", e)
            return self._fail_from_exception(e, default_error_code="PORT_PROFILE_UPDATE_FAILED")

    async def delete_port_profile(self, profile_id: str) -> AdapterResult:
        """Delete switch port profile."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site available", error_code="NO_SITE")
        try:
            await self._client.delete_port_profile(site_id, profile_id)
            return AdapterResult.ok(None, message="Port profile deleted")
        except Exception as e:
            logger.error("Failed to delete port profile: %s", e)
            return self._fail_from_exception(e, default_error_code="PORT_PROFILE_DELETE_FAILED")

    async def get_wan_status(self) -> dict[str, Any]:
        """Get WAN settings for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_wan_config(site_id)
        except Exception as e:
            logger.error("Failed to get WAN status: %s", e)
            return {}

    async def get_dhcp_config(self) -> dict[str, Any]:
        """Get DHCP settings for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_dhcp_config(site_id)
        except Exception as e:
            logger.error("Failed to get DHCP config: %s", e)
            return {}

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        """Get firewall rules for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_firewall_rules(site_id)
            return [self._normalize_firewall_rule(r).model_dump() for r in rows]
        except Exception as e:
            logger.error("Failed to get firewall rules: %s", e)
            return []

    async def get_vpn_config(self) -> dict[str, Any]:
        """Get VPN settings for active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_vpn_config(site_id)
        except Exception as e:
            logger.error("Failed to get VPN config: %s", e)
            return {}

    async def get_firmware_info(self, device_mac: str) -> dict[str, Any]:
        """Get firmware info for a device — normalized into NormalizedFirmwareStatus."""
        found = await self._find_device_site(device_mac)
        if not found:
            return {}
        site_id, raw = found
        try:
            fw = await self._client.get_firmware_info(site_id, normalize_mac(raw.get("mac")))
            current = (
                fw.get("curFwVer")
                or fw.get("currentVersion")
                or fw.get("firmwareVersion")
                or raw.get("firmwareVersion")
            )
            latest = fw.get("latestFwVer") or fw.get("latestVersion") or fw.get("newFwVer")
            need_upgrade = fw.get("needUpgrade", False)
            # Infer need_upgrade from version comparison if API doesn't set it
            if not need_upgrade and current and latest and current != latest:
                need_upgrade = True
            release_notes = fw.get("fwReleaseLog") or fw.get("releaseNotes")
            normalized = NormalizedFirmwareStatus(
                mac=normalize_mac(raw.get("mac", "")),
                device_name=raw.get("name") or raw.get("showModel"),
                device_type=DEVICE_TYPE_MAP.get(raw.get("type"), "unknown"),
                model=raw.get("model") or raw.get("showModel"),
                current_version=current,
                latest_version=latest,
                needs_upgrade=need_upgrade,
                auto_upgrade=fw.get("autoUpgrade", False),
                release_notes=release_notes,
                last_upgrade_time=fw.get("lastUpgradeTime"),
            ).model_dump()
            normalized["needUpgrade"] = normalized["needs_upgrade"]
            normalized["latestVersion"] = normalized["latest_version"]
            normalized["currentVersion"] = normalized["current_version"]
            return normalized
        except Exception as e:
            logger.error("Failed to get firmware info: %s", e)
            return {}

    async def upgrade_firmware(self, device_mac: str) -> AdapterResult:
        """Trigger firmware upgrade for a device."""
        found = await self._find_device_site(device_mac)
        if not found:
            return AdapterResult.fail("Device not found", error_code="NOT_FOUND")
        site_id, raw = found
        try:
            data = await self._client.trigger_firmware_upgrade(
                site_id,
                normalize_mac(raw.get("mac")),
            )
            return AdapterResult.ok(data, message="Firmware upgrade initiated")
        except Exception as e:
            logger.error("Failed to upgrade firmware: %s", e)
            return self._fail_from_exception(e, default_error_code="FIRMWARE_UPGRADE_FAILED")

    async def get_device_metrics(self, device_mac: str) -> dict[str, Any]:
        """Get CPU/memory/traffic metrics from cached device payload."""
        found = await self._find_device_site(device_mac)
        if not found:
            return {}
        _, raw = found
        metrics = OmadaDeviceMetrics(
            mac=normalize_mac(raw.get("mac")),
            cpu=raw.get("cpuUtil"),
            memory=raw.get("memUtil"),
            uptime=raw.get("uptimeLong"),
            clients=raw.get("clientNum"),
            download=raw.get("download"),
            upload=raw.get("upload"),
            temperature=raw.get("temperature"),
        )
        return metrics.model_dump()

    async def batch_reboot(self, device_macs: list[str]) -> list[AdapterResult]:
        """Batch reboot devices sequentially."""
        results: list[AdapterResult] = []
        for mac in device_macs:
            results.append(await self.reboot_device(mac))
        return results

    async def batch_firmware_upgrade(self, device_macs: list[str]) -> list[AdapterResult]:
        """Batch firmware upgrades sequentially."""
        results: list[AdapterResult] = []
        for mac in device_macs:
            results.append(await self.upgrade_firmware(mac))
        return results

    async def run_compatibility_probe(self) -> dict[str, Any]:
        """
        Probe key Omada endpoints for runtime compatibility validation.

        This is intended for live-controller validation during rollout.
        """
        site_id = await self._ensure_site_id()
        checks: dict[str, dict[str, Any]] = {}

        async def _probe(name: str, call: Any) -> None:
            try:
                await call
                checks[name] = {"ok": True}
            except Exception as exc:
                checks[name] = {"ok": False, "error": exc.__class__.__name__, "message": str(exc)}

        await _probe("sites", self._client.get_sites())

        if site_id:
            await _probe("devices", self._client.get_devices(site_id))
            await _probe("networks", self._client.get_networks(site_id))
            await _probe("ssids", self._client.get_ssids(site_id))
            await _probe("clients", self._client.get_clients(site_id))
        else:
            checks["site_resolution"] = {
                "ok": False,
                "error": "NO_SITE",
                "message": "No site available",
            }

        passed = all(check.get("ok") for check in checks.values())
        return {
            "controller_id": self._client.controller_id,
            "controller_version": self._client.controller_version,
            "site_id": site_id,
            "passed": passed,
            "checks": checks,
        }

    async def health_check(self) -> dict[str, Any]:
        """Adapter-level health summary."""
        health = self._client.get_health()
        sites = await self.get_sites()
        devices_count = 0
        for site in sites:
            site_id = site.get("id")
            if not site_id:
                continue
            try:
                devices_count += len(await self._client.get_devices(site_id))
            except Exception:
                continue

        payload = {
            "adapter_id": "omada",
            "connected": self._connected,
            "controller_version": health.get("controller_version"),
            "controller_id": health.get("controller_id"),
            "uptime_seconds": 0,
            "sites_count": len(sites),
            "devices_count": devices_count,
            "request_count": health.get("request_count", 0),
            "error_count": health.get("error_count", 0),
            "error_rate": health.get("error_rate", 0.0),
            "avg_latency_ms": health.get("avg_latency_ms", 0.0),
            "cache_hit_rate": health.get("cache_hit_rate", 0.0),
            "rate_limit_remaining": health.get("rate_limit_remaining", 0),
            "last_successful_request": health.get("last_successful_request"),
        }
        logger.info("adapter.omada.health", extra=payload)
        return payload

    # =========================================================================
    # Running Config & Drift Detection
    # =========================================================================

    async def get_running_config(self, device_id: str) -> dict[str, Any]:
        """
        Read the actual running configuration from an Omada device.

        Detects device type (switch/AP/gateway) and gathers all relevant
        config sections into a normalized dict for reconciliation.

        Args:
            device_id: Device MAC address or external ID.

        Returns:
            dict with config sections keyed by category.
        """
        mac = normalize_mac(device_id)
        device_info = await self.get_device_info(mac)
        if not device_info:
            logger.warning("get_running_config: device %s not found", mac)
            return {}

        device_type = device_info.device_type
        config: dict[str, Any] = {
            "device": {
                "mac": mac,
                "name": device_info.name,
                "model": device_info.model,
                "firmware_version": device_info.firmware_version,
                "device_type": device_type,
            },
        }

        try:
            if device_type == "switch":
                config.update(await self._get_switch_config(mac))
            elif device_type == "access_point":
                config.update(await self._get_ap_config(mac))
            elif device_type == "gateway":
                config.update(await self._get_gateway_config(mac))
        except Exception as e:
            logger.error("get_running_config error for %s (%s): %s", mac, device_type, e)

        # Shared config sections (site-level)
        try:
            config["vlans"] = await self.get_vlans()
        except Exception:
            config["vlans"] = []

        try:
            config["port_profiles"] = await self.get_port_profiles()
        except Exception:
            config["port_profiles"] = []

        return await self.normalize_config(config)

    async def _get_switch_config(self, mac: str) -> dict[str, Any]:
        """Gather switch-specific config sections (enterprise-enriched)."""
        sections: dict[str, Any] = {}

        try:
            detail = await self.get_switch_detail(mac)
            sections["switch_detail"] = {
                k: v for k, v in detail.items() if k not in {"uptime", "cpu_usage", "memory_usage"}
            }
        except Exception:
            sections["switch_detail"] = {}

        try:
            sections["ports"] = await self.get_ports(mac)
        except Exception:
            sections["ports"] = []

        try:
            sections["stp_config"] = await self.get_switch_stp_config()
        except Exception:
            sections["stp_config"] = {}

        try:
            sections["lag_groups"] = await self.get_switch_lag_groups(mac)
        except Exception:
            sections["lag_groups"] = []

        # Enterprise enrichments
        try:
            sections["mac_table"] = await self.get_switch_mac_table(mac)
        except Exception:
            sections["mac_table"] = []

        try:
            sections["acl_rules"] = await self.get_switch_acl_rules(mac)
        except Exception:
            sections["acl_rules"] = []

        try:
            sections["igmp_config"] = await self.get_switch_igmp_config(mac)
        except Exception:
            sections["igmp_config"] = {}

        try:
            sections["dot1x_config"] = await self.get_dot1x_config()
        except Exception:
            sections["dot1x_config"] = {}

        try:
            sections["qos_config"] = await self.get_qos_config()
        except Exception:
            sections["qos_config"] = {}

        try:
            sections["dhcp_snooping"] = await self.get_dhcp_snooping_config()
        except Exception:
            sections["dhcp_snooping"] = {}

        return sections

    async def _get_ap_config(self, mac: str) -> dict[str, Any]:
        """Gather AP-specific config sections (enterprise-enriched)."""
        sections: dict[str, Any] = {}

        try:
            detail = await self.get_ap_detail(mac)
            sections["ap_detail"] = {
                k: v
                for k, v in detail.items()
                if k not in {"uptime", "cpu_usage", "memory_usage", "client_count"}
            }
        except Exception:
            sections["ap_detail"] = {}

        try:
            sections["ssids"] = await self.get_ssids()
        except Exception:
            sections["ssids"] = []

        # Enterprise enrichments
        try:
            sections["rogue_aps"] = await self.get_rogue_aps()
        except Exception:
            sections["rogue_aps"] = []

        try:
            sections["channel_utilization"] = await self.get_channel_utilization()
        except Exception:
            sections["channel_utilization"] = []

        try:
            sections["site_radio_settings"] = await self.get_site_radio_settings()
        except Exception:
            sections["site_radio_settings"] = {}

        try:
            sections["hotspot_config"] = await self.get_hotspot_config()
        except Exception:
            sections["hotspot_config"] = {}

        try:
            sections["captive_portal"] = await self.get_captive_portal_config()
        except Exception:
            sections["captive_portal"] = {}

        return sections

    async def _get_gateway_config(self, mac: str) -> dict[str, Any]:
        """Gather gateway-specific config sections (enterprise-enriched)."""
        sections: dict[str, Any] = {}

        try:
            detail = await self.get_gateway_detail(mac)
            sections["gateway_detail"] = {
                k: v for k, v in detail.items() if k not in {"uptime", "cpu_usage", "memory_usage"}
            }
        except Exception:
            sections["gateway_detail"] = {}

        try:
            sections["firewall_rules"] = await self.get_firewall_rules()
        except Exception:
            sections["firewall_rules"] = []

        try:
            sections["dhcp_config"] = await self.get_dhcp_config()
        except Exception:
            sections["dhcp_config"] = {}

        try:
            sections["wan_status"] = await self.get_wan_status()
        except Exception:
            sections["wan_status"] = {}

        # Enterprise enrichments
        try:
            sections["static_routes"] = await self.get_static_routes()
        except Exception:
            sections["static_routes"] = []

        try:
            sections["ip_groups"] = await self.get_ip_groups()
        except Exception:
            sections["ip_groups"] = []

        try:
            sections["ip_mac_bindings"] = await self.get_ip_mac_bindings()
        except Exception:
            sections["ip_mac_bindings"] = []

        try:
            sections["url_filter"] = await self.get_url_filter()
        except Exception:
            sections["url_filter"] = {}

        try:
            sections["ddns_config"] = await self.get_ddns_config()
        except Exception:
            sections["ddns_config"] = {}

        try:
            sections["wan_failover"] = await self.get_wan_failover_config()
        except Exception:
            sections["wan_failover"] = {}

        try:
            sections["wan_load_balance"] = await self.get_wan_load_balance_config()
        except Exception:
            sections["wan_load_balance"] = {}

        try:
            sections["site_settings"] = await self.get_site_settings()
        except Exception:
            sections["site_settings"] = {}

        return sections

    async def normalize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize an Omada config dict for drift comparison.

        Strips volatile/ephemeral fields (uptime, counters, traffic stats,
        CPU/memory, PoE power draw) so that only meaningful config state
        is compared.
        """
        # Top-level volatile keys to strip everywhere
        volatile_keys = {
            "uptime",
            "uptimeLong",
            "uptime_seconds",
            "last_seen",
            "lastSeen",
            "timestamp",
            "boot_time",
            "sys_time",
            "sysTime",
            "cpuUtil",
            "cpu_usage",
            "cpu_utilization",
            "memUtil",
            "memory_usage",
            "mem_utilization",
            "clientNum",
            "client_count",
            "clients",
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "rx_rate",
            "tx_rate",
            "rx_errors",
            "tx_errors",
            "tx_dropped",
            "rx_dropped",
            "latency",
            "avg_latency_ms",
            "request_count",
            "error_count",
            "poe_power",
            "poe_power_watts",
            "power_consumption",
            "led_setting",  # cosmetic, not config
        }

        def _strip(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: _strip(v) for k, v in obj.items() if k not in volatile_keys}
            if isinstance(obj, list):
                return [_strip(item) for item in obj]
            return obj

        return _strip(config)

    # =========================================================================
    # Enterprise: Firmware Management
    # =========================================================================

    async def get_firmware_overview(self) -> dict[str, Any]:
        """Get fleet-wide firmware compliance overview.

        Returns a summary with per-device firmware status including
        which devices need upgrades and overall compliance percentage.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return NormalizedFirmwareOverview().model_dump()

        try:
            devices = await self.discover_devices()
            statuses: list[dict[str, Any]] = []
            up_to_date = 0
            needs_upgrade = 0
            upgrading = 0
            unknown = 0

            for device in devices:
                mac = device.mac_address
                fw_status = NormalizedFirmwareStatus(
                    mac=mac,
                    device_name=device.name,
                    device_type=device.device_type,
                    model=device.model,
                    current_version=device.firmware_version,
                )

                raw = device.raw_data or {}
                if raw.get("needUpgrade"):
                    fw_status.needs_upgrade = True
                    fw_status.latest_version = raw.get("fwDownload") or raw.get(
                        "latestFirmwareVersion"
                    )
                    needs_upgrade += 1
                elif raw.get("status") == 5:  # Omada "upgrading" status
                    fw_status.is_upgrading = True
                    upgrading += 1
                elif device.firmware_version:
                    up_to_date += 1
                else:
                    unknown += 1

                # Try to get detailed firmware info
                try:
                    fw_info = await self.get_firmware_info(mac)
                    if fw_info:
                        fw_status.latest_version = fw_info.get("latestVersion") or fw_info.get(
                            "latestFirmwareVersion"
                        )
                        fw_status.release_notes = fw_info.get("releaseNotes") or fw_info.get(
                            "releaseLog"
                        )
                        fw_status.release_date = fw_info.get("releaseDate")
                        fw_status.download_url = fw_info.get("downloadUrl") or fw_info.get("fwUrl")
                        fw_status.file_size = fw_info.get("fileSize") or fw_info.get("fwSize")
                        if (
                            fw_status.latest_version
                            and fw_status.latest_version != fw_status.current_version
                        ):
                            if not fw_status.needs_upgrade:
                                fw_status.needs_upgrade = True
                                needs_upgrade += 1
                                up_to_date = max(0, up_to_date - 1)
                except Exception:
                    pass

                statuses.append(fw_status.model_dump())

            total = len(devices)
            compliance = (up_to_date / total * 100) if total > 0 else 100.0

            return NormalizedFirmwareOverview(
                total_devices=total,
                up_to_date=up_to_date,
                needs_upgrade=needs_upgrade,
                upgrading=upgrading,
                unknown=unknown,
                compliance_percent=round(compliance, 1),
                devices=statuses,
            ).model_dump()
        except Exception as e:
            logger.error("Failed to get firmware overview: %s", e)
            return NormalizedFirmwareOverview().model_dump()

    async def batch_firmware_check(self) -> list[dict[str, Any]]:
        """Check firmware updates for all devices in one call."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.batch_firmware_check(site_id)
        except Exception as e:
            logger.error("Batch firmware check failed: %s", e)
            return []

    async def get_firmware_upgrade_log(self) -> list[dict[str, Any]]:
        """Get firmware upgrade history."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_firmware_upgrade_log(site_id)
        except Exception as e:
            logger.error("Failed to get firmware upgrade log: %s", e)
            return []

    # =========================================================================
    # Enterprise: DHCP Reservations
    # =========================================================================

    async def get_dhcp_reservations(self, network_id: str) -> list[dict[str, Any]]:
        """Get DHCP static reservations for a network/VLAN."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_dhcp_reservations(site_id, network_id)
            return [
                NormalizedDHCPReservation(
                    id=r.get("id"),
                    mac_address=r.get("mac") or r.get("clientMac"),
                    ip_address=r.get("ip") or r.get("fixedIp"),
                    hostname=r.get("hostname") or r.get("clientName"),
                    description=r.get("description"),
                    enabled=r.get("enable", True),
                    network_id=network_id,
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get DHCP reservations: %s", e)
            return []

    async def create_dhcp_reservation(
        self, network_id: str, config: dict[str, Any]
    ) -> AdapterResult:
        """Create a DHCP static reservation."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_dhcp_reservation(site_id, network_id, config)
            return AdapterResult.ok(data, message="DHCP reservation created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DHCP_RESERVATION_FAILED")

    async def delete_dhcp_reservation(self, network_id: str, reservation_id: str) -> AdapterResult:
        """Delete a DHCP static reservation."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_dhcp_reservation(site_id, network_id, reservation_id)
            return AdapterResult.ok(None, message="DHCP reservation deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DHCP_RESERVATION_DELETE_FAILED")

    # =========================================================================
    # Enterprise: IP Groups
    # =========================================================================

    async def get_ip_groups(self) -> list[dict[str, Any]]:
        """Get IP groups for firewall/ACL rules."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_ip_groups(site_id)
            return [
                NormalizedIPGroup(
                    id=r.get("id") or r.get("groupId"),
                    name=r.get("name"),
                    type=r.get("type"),
                    ip_list=r.get("ipList", []),
                    subnet=r.get("subnet"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get IP groups: %s", e)
            return []

    async def create_ip_group(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_ip_group(site_id, config)
            return AdapterResult.ok(data, message="IP group created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="IP_GROUP_CREATE_FAILED")

    async def update_ip_group(self, group_id: str, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_ip_group(site_id, group_id, config)
            return AdapterResult.ok(data, message="IP group updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="IP_GROUP_UPDATE_FAILED")

    async def delete_ip_group(self, group_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_ip_group(site_id, group_id)
            return AdapterResult.ok(None, message="IP group deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="IP_GROUP_DELETE_FAILED")

    # =========================================================================
    # Enterprise: URL Filtering
    # =========================================================================

    async def get_url_filter(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_url_filter(site_id)
        except Exception as e:
            logger.error("Failed to get URL filter: %s", e)
            return {}

    async def update_url_filter(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_url_filter(site_id, config)
            return AdapterResult.ok(data, message="URL filter updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="URL_FILTER_FAILED")

    # =========================================================================
    # Enterprise: Firewall Rules (full CRUD)
    # =========================================================================

    async def create_firewall_rule(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_firewall_rule(site_id, config)
            return AdapterResult.ok(data, message="Firewall rule created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="FIREWALL_RULE_CREATE_FAILED")

    async def update_firewall_rule(self, rule_id: str, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_firewall_rule(site_id, rule_id, config)
            return AdapterResult.ok(data, message="Firewall rule updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="FIREWALL_RULE_UPDATE_FAILED")

    async def delete_firewall_rule(self, rule_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_firewall_rule(site_id, rule_id)
            return AdapterResult.ok(None, message="Firewall rule deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="FIREWALL_RULE_DELETE_FAILED")

    # =========================================================================
    # Enterprise: Static Routes
    # =========================================================================

    async def get_static_routes(self) -> list[dict[str, Any]]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_static_routes(site_id)
            return [
                NormalizedStaticRoute(
                    id=r.get("id"),
                    name=r.get("name"),
                    enabled=r.get("enable", True),
                    destination=r.get("destination") or r.get("dest"),
                    subnet_mask=r.get("subnetMask") or r.get("mask"),
                    gateway=r.get("gateway") or r.get("nexthop"),
                    interface=r.get("interface"),
                    metric=r.get("metric") or r.get("distance"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get static routes: %s", e)
            return []

    async def create_static_route(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_static_route(site_id, config)
            return AdapterResult.ok(data, message="Static route created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ROUTE_CREATE_FAILED")

    async def update_static_route(self, route_id: str, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_static_route(site_id, route_id, config)
            return AdapterResult.ok(data, message="Static route updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ROUTE_UPDATE_FAILED")

    async def delete_static_route(self, route_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_static_route(site_id, route_id)
            return AdapterResult.ok(None, message="Static route deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ROUTE_DELETE_FAILED")

    # =========================================================================
    # Enterprise: IP-MAC Binding
    # =========================================================================

    async def get_ip_mac_bindings(self) -> list[dict[str, Any]]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_ip_mac_bindings(site_id)
            return [
                NormalizedIPMACBinding(
                    id=r.get("id"),
                    mac_address=r.get("mac"),
                    ip_address=r.get("ip"),
                    hostname=r.get("hostname") or r.get("name"),
                    enabled=r.get("enable", True),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get IP-MAC bindings: %s", e)
            return []

    async def create_ip_mac_binding(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_ip_mac_binding(site_id, config)
            return AdapterResult.ok(data, message="IP-MAC binding created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="BINDING_CREATE_FAILED")

    async def delete_ip_mac_binding(self, binding_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_ip_mac_binding(site_id, binding_id)
            return AdapterResult.ok(None, message="IP-MAC binding deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="BINDING_DELETE_FAILED")

    # =========================================================================
    # Enterprise: DDNS
    # =========================================================================

    async def get_ddns_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_ddns_config(site_id)
        except Exception as e:
            logger.error("Failed to get DDNS config: %s", e)
            return {}

    async def update_ddns_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_ddns_config(site_id, config)
            return AdapterResult.ok(data, message="DDNS config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DDNS_FAILED")

    # =========================================================================
    # Enterprise: WAN Failover / Load Balancing
    # =========================================================================

    async def get_wan_failover_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_wan_failover_config(site_id)
        except Exception as e:
            logger.error("Failed to get WAN failover config: %s", e)
            return {}

    async def update_wan_failover_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_wan_failover_config(site_id, config)
            return AdapterResult.ok(data, message="WAN failover config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="WAN_FAILOVER_FAILED")

    async def get_wan_load_balance_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_wan_load_balance_config(site_id)
        except Exception as e:
            logger.error("Failed to get WAN load balance config: %s", e)
            return {}

    async def update_wan_load_balance_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_wan_load_balance_config(site_id, config)
            return AdapterResult.ok(data, message="WAN load balance config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="WAN_LB_FAILED")

    async def get_switch_clients(self, device_mac: str) -> list[dict[str, Any]]:
        """Get clients connected to a specific switch.

        Tries Omada switch-specific client endpoint first, then falls back
        to filtering the full client list by switchMac OR by apMac matching
        APs that are downlinks of this switch (wireless clients served by
        APs plugged into this switch).
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        mac = normalize_mac(device_mac)
        # Try switch-specific client endpoints
        for path in [
            f"/sites/{site_id}/switches/{mac}/clients",
            f"/sites/{site_id}/stat/switches/{mac}/clients",
        ]:
            try:
                rows = await self._client._paginated_request(
                    "GET", path, page_size=500, cache_ttl=15
                )
                if rows:
                    logger.info("Switch clients via %s: %d", path.split("/")[-1], len(rows))
                    return [self._normalize_client(c).model_dump() for c in rows]
            except Exception:
                pass
            try:
                data = await self._client._request("GET", path, cache_ttl=15)
                rows = (
                    data.get("data", [])
                    if isinstance(data, dict)
                    else data
                    if isinstance(data, list)
                    else []
                )
                if rows:
                    return [self._normalize_client(c).model_dump() for c in rows]
            except Exception:
                pass

        # Fallback: get all clients and match by switchMac, MAC table, or AP downlinks
        try:
            # Build set of AP MACs that are downlinks of this switch
            downlink_ap_macs: set[str] = set()
            try:
                detail = await self._client.get_switch(site_id, mac)
                for dl in (
                    detail.get("downlink")
                    or detail.get("downlinks")
                    or detail.get("downlinkList")
                    or []
                ):
                    dl_mac = dl.get("mac", "")
                    if dl_mac:
                        downlink_ap_macs.add(normalize_mac(dl_mac))
                logger.info("Switch %s has %d downlink device MACs", mac, len(downlink_ap_macs))
            except Exception:
                logger.debug("Could not fetch switch detail for downlink AP discovery")

            all_clients = await self.get_clients(site_id)
            norm_switch = normalize_mac(mac)

            # Build a MAC→client lookup for cross-referencing
            client_by_mac: dict[str, dict[str, Any]] = {}
            for c in all_clients:
                c_mac = normalize_mac(c.get("mac_address") or "")
                if c_mac:
                    client_by_mac[c_mac] = c

            matched_macs: set[str] = set()
            matched: list[dict[str, Any]] = []

            # Match by switchMac (wired clients directly on this switch)
            for c in all_clients:
                c_switch = normalize_mac(c.get("switch_mac") or "")
                if c_switch == norm_switch:
                    c_mac = normalize_mac(c.get("mac_address") or "")
                    if c_mac not in matched_macs:
                        matched_macs.add(c_mac)
                        matched.append(c)
                    continue
                # Match by apMac (wireless clients on APs plugged into this switch)
                if downlink_ap_macs:
                    c_ap = normalize_mac(c.get("ap_mac") or "")
                    if c_ap in downlink_ap_macs:
                        c_mac = normalize_mac(c.get("mac_address") or "")
                        if c_mac not in matched_macs:
                            matched_macs.add(c_mac)
                            matched.append(c)

            # Cross-reference with MAC table to catch wired clients missing switchMac
            # (Omada often doesn't populate switchMac in the client list for wired devices)
            if len(matched) == 0 or not any(c.get("connection_type") == "wired" for c in matched):
                try:
                    mac_table = await self._client.get_switch_mac_table(site_id, mac)
                    for entry in mac_table or []:
                        entry_mac = normalize_mac(entry.get("mac", ""))
                        if entry_mac and entry_mac not in matched_macs:
                            # Check if we know this MAC from the client list
                            if entry_mac in client_by_mac:
                                client = dict(client_by_mac[entry_mac])
                                client["switch_mac"] = norm_switch
                                client["switch_port"] = entry.get("port")
                                client["connection_type"] = "wired"
                                if entry.get("vlanId") or entry.get("vid"):
                                    client["vlan_id"] = entry.get("vlanId") or entry.get("vid")
                                matched_macs.add(entry_mac)
                                matched.append(client)
                            else:
                                # MAC table entry with no matching client — create minimal entry
                                matched_macs.add(entry_mac)
                                matched.append(
                                    {
                                        "mac_address": entry_mac,
                                        "name": None,
                                        "hostname": None,
                                        "ip_address": None,
                                        "connection_type": "wired",
                                        "switch_mac": norm_switch,
                                        "switch_port": entry.get("port"),
                                        "vlan_id": entry.get("vlanId") or entry.get("vid"),
                                    }
                                )
                except Exception:
                    logger.debug("MAC table cross-reference unavailable for %s", mac)

            logger.info(
                "Switch %s client fallback: %d matched (switchMac=%d, mac_table=%d, ap_downstream=%d)",
                mac,
                len(matched),
                sum(1 for c in matched if normalize_mac(c.get("switch_mac") or "") == norm_switch),
                sum(
                    1
                    for c in matched
                    if c.get("mac_address")
                    and normalize_mac(c["mac_address"]) in matched_macs
                    and normalize_mac(c.get("ap_mac") or "") not in downlink_ap_macs
                    and normalize_mac(c.get("switch_mac") or "") != norm_switch
                ),
                sum(1 for c in matched if normalize_mac(c.get("ap_mac") or "") in downlink_ap_macs),
            )
            return matched
        except Exception as e:
            logger.error("Failed to get switch clients fallback: %s", e)
        return []

    # =========================================================================
    # Enterprise: Switch Advanced (MAC Table, IGMP, ACL, QoS, 802.1x)
    # =========================================================================

    async def get_switch_mac_table(self, device_mac: str) -> list[dict[str, Any]]:
        """Get MAC address table from a switch.

        Tries the Omada macTable API first.  If the firmware doesn't support
        it, builds a synthetic table from connected clients (both wired
        clients on this switch and wireless clients on downstream APs).
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            logger.warning("get_switch_mac_table: no site_id resolved")
            return []
        mac = normalize_mac(device_mac)
        logger.info("Fetching MAC table for %s (site=%s)", mac, site_id)

        # Try real macTable API first
        try:
            rows = await self._client.get_switch_mac_table(site_id, mac)
            logger.info("MAC table returned %d rows for %s", len(rows) if rows else 0, mac)
            if rows:
                return [
                    NormalizedMACTableEntry(
                        mac_address=r.get("mac", ""),
                        vlan_id=r.get("vlanId") or r.get("vid"),
                        port=r.get("port"),
                        type=r.get("type", "dynamic"),
                    ).model_dump()
                    for r in rows
                ]
        except Exception as e:
            logger.debug("macTable API unavailable for %s: %s", mac, e)

        # Fallback: build synthetic MAC table from connected clients
        try:
            clients = await self.get_switch_clients(device_mac)
            entries = []
            for c in clients:
                c_mac = c.get("mac_address") or ""
                if not c_mac:
                    continue
                entries.append(
                    NormalizedMACTableEntry(
                        mac_address=c_mac,
                        vlan_id=c.get("vlan_id"),
                        port=c.get("switch_port"),
                        type="dynamic",
                    ).model_dump()
                )
            logger.info("Synthetic MAC table for %s: %d entries from clients", mac, len(entries))
            return entries
        except Exception as e:
            logger.error("Failed to build synthetic MAC table for %s: %s", mac, e)
            return []

    async def get_switch_igmp_config(self, device_mac: str) -> dict[str, Any]:
        """Get IGMP snooping config for a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_switch_igmp_config(site_id, normalize_mac(device_mac))
        except Exception as e:
            logger.error("Failed to get IGMP config: %s", e)
            return {}

    async def update_switch_igmp_config(
        self, device_mac: str, config: dict[str, Any]
    ) -> AdapterResult:
        """Update IGMP snooping config for a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_igmp_config(
                site_id, normalize_mac(device_mac), config
            )
            return AdapterResult.ok(data, message="IGMP config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="IGMP_FAILED")

    async def get_switch_acl_rules(self, device_mac: str) -> list[dict[str, Any]]:
        """Get ACL rules for a switch."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_switch_acl_rules(site_id, normalize_mac(device_mac))
            return [
                NormalizedACLRule(
                    id=r.get("id"),
                    name=r.get("name"),
                    enabled=r.get("enable", True),
                    index=r.get("index"),
                    action=r.get("action"),
                    protocol=r.get("protocol"),
                    src_ip=r.get("srcIp"),
                    src_mask=r.get("srcMask"),
                    dst_ip=r.get("dstIp"),
                    dst_mask=r.get("dstMask"),
                    src_port=r.get("srcPort"),
                    dst_port=r.get("dstPort"),
                    direction=r.get("direction"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get ACL rules: %s", e)
            return []

    async def create_switch_acl_rule(
        self, device_mac: str, config: dict[str, Any]
    ) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_switch_acl_rule(
                site_id, normalize_mac(device_mac), config
            )
            return AdapterResult.ok(data, message="ACL rule created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ACL_CREATE_FAILED")

    async def update_switch_acl_rule(
        self, device_mac: str, rule_id: str, config: dict[str, Any]
    ) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_acl_rule(
                site_id, normalize_mac(device_mac), rule_id, config
            )
            return AdapterResult.ok(data, message="ACL rule updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ACL_UPDATE_FAILED")

    async def delete_switch_acl_rule(self, device_mac: str, rule_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_switch_acl_rule(site_id, normalize_mac(device_mac), rule_id)
            return AdapterResult.ok(None, message="ACL rule deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="ACL_DELETE_FAILED")

    async def get_dot1x_config(self) -> dict[str, Any]:
        """Get 802.1x / RADIUS authentication config."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_dot1x_config(site_id)
        except Exception as e:
            logger.error("Failed to get 802.1x config: %s", e)
            return {}

    async def update_dot1x_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_dot1x_config(site_id, config)
            return AdapterResult.ok(data, message="802.1x config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DOT1X_FAILED")

    async def get_qos_config(self) -> dict[str, Any]:
        """Get site-level QoS configuration."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_qos_config(site_id)
        except Exception as e:
            logger.error("Failed to get QoS config: %s", e)
            return {}

    async def update_qos_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_qos_config(site_id, config)
            return AdapterResult.ok(data, message="QoS config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="QOS_FAILED")

    async def get_dhcp_snooping_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_dhcp_snooping_config(site_id)
        except Exception as e:
            logger.error("Failed to get DHCP snooping config: %s", e)
            return {}

    async def update_dhcp_snooping_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_dhcp_snooping_config(site_id, config)
            return AdapterResult.ok(data, message="DHCP snooping config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DHCP_SNOOPING_FAILED")

    # =========================================================================
    # Enterprise: AP Advanced (Rogue APs, Channel Util, Site Radios)
    # =========================================================================

    async def get_rogue_aps(self) -> list[dict[str, Any]]:
        """Get detected rogue / neighboring APs."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_rogue_aps(site_id)
            return [
                NormalizedRogueAP(
                    mac_address=r.get("mac") or r.get("bssid"),
                    ssid=r.get("ssid"),
                    channel=r.get("channel"),
                    band=r.get("band") or r.get("radioType"),
                    signal=r.get("signal") or r.get("rssi"),
                    security=r.get("security") or r.get("encryption"),
                    first_seen=r.get("firstSeen"),
                    last_seen=r.get("lastSeen"),
                    detecting_ap_mac=r.get("apMac") or r.get("radioMac"),
                    detecting_ap_name=r.get("apName") or r.get("radioName"),
                    classification=r.get("classification", "unknown"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get rogue APs: %s", e)
            return []

    async def get_channel_utilization(self) -> list[dict[str, Any]]:
        """Get RF channel utilization stats across all APs for optimization."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_channel_utilization(site_id)
            return [
                NormalizedChannelUtil(
                    ap_mac=r.get("mac") or r.get("apMac", ""),
                    ap_name=r.get("name") or r.get("apName"),
                    band=r.get("band") or r.get("radioType"),
                    channel=r.get("channel"),
                    channel_width=r.get("channelWidth"),
                    utilization_percent=r.get("utilization", 0.0),
                    interference_percent=r.get("interference", 0.0),
                    noise_floor_dbm=r.get("noiseFloor"),
                    client_count=r.get("clientNum", 0),
                    tx_utilization=r.get("txUtil", 0.0),
                    rx_utilization=r.get("rxUtil", 0.0),
                    timestamp=r.get("timestamp"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get channel utilization: %s", e)
            return []

    async def get_site_radio_settings(self) -> dict[str, Any]:
        """Get site-level radio settings (global channel plan, tx power, etc.)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_site_radio_settings(site_id)
        except Exception as e:
            logger.error("Failed to get site radio settings: %s", e)
            return {}

    async def update_site_radio_settings(self, band: str, config: dict[str, Any]) -> AdapterResult:
        """Update site-level radio settings for a specific band (2g, 5g, 6g)."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_site_radio_settings(site_id, band, config)
            return AdapterResult.ok(data, message=f"Site radio {band} settings updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="SITE_RADIO_FAILED")

    # =========================================================================
    # Enterprise: Hotspot / Captive Portal
    # =========================================================================

    async def get_hotspot_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_hotspot_config(site_id)
        except Exception as e:
            logger.error("Failed to get hotspot config: %s", e)
            return {}

    async def update_hotspot_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_hotspot_config(site_id, config)
            return AdapterResult.ok(data, message="Hotspot config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="HOTSPOT_FAILED")

    async def get_captive_portal_config(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_captive_portal_config(site_id)
        except Exception as e:
            logger.error("Failed to get captive portal config: %s", e)
            return {}

    async def update_captive_portal_config(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_captive_portal_config(site_id, config)
            return AdapterResult.ok(data, message="Captive portal config updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="PORTAL_FAILED")

    async def get_vouchers(self) -> list[dict[str, Any]]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            return await self._client.get_vouchers(site_id)
        except Exception as e:
            logger.error("Failed to get vouchers: %s", e)
            return []

    async def create_vouchers(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_vouchers(site_id, config)
            return AdapterResult.ok(data, message="Vouchers created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="VOUCHER_CREATE_FAILED")

    async def delete_voucher(self, voucher_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_voucher(site_id, voucher_id)
            return AdapterResult.ok(None, message="Voucher deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="VOUCHER_DELETE_FAILED")

    # =========================================================================
    # Enterprise: Events / Alerts
    # =========================================================================

    async def get_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent events from the controller."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_events(site_id, limit=limit)
            return [
                NormalizedEvent(
                    id=r.get("id"),
                    timestamp=r.get("timestamp") or r.get("time"),
                    level=r.get("level") or r.get("type"),
                    category=r.get("category") or r.get("module"),
                    message=r.get("msg") or r.get("message"),
                    device_mac=r.get("deviceMac"),
                    device_name=r.get("deviceName"),
                    client_mac=r.get("clientMac"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get events: %s", e)
            return []

    async def get_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get active alerts from the controller."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_alerts(site_id, limit=limit)
            return [
                NormalizedEvent(
                    id=r.get("id"),
                    timestamp=r.get("timestamp") or r.get("time"),
                    level=r.get("level") or "warning",
                    category=r.get("category") or r.get("module"),
                    message=r.get("msg") or r.get("message"),
                    device_mac=r.get("deviceMac"),
                    device_name=r.get("deviceName"),
                    client_mac=r.get("clientMac"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get alerts: %s", e)
            return []

    # =========================================================================
    # Enterprise: 802.1X Auth Events
    # =========================================================================

    async def get_dot1x_auth_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Pull 802.1X authentication events from the controller.

        Filters the generic event stream for authentication-related
        events and normalises them into the format expected by the
        RADIUS service: {client_mac, auth_result, username, timestamp, ...}.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return []

        # Omada auth-related event categories / keywords
        _AUTH_KEYWORDS = {"802.1x", "dot1x", "radius", "eap-", "eapol", "authentication"}

        try:
            raw_events = await self._client.get_events(site_id, limit=limit * 3)
        except Exception as e:
            logger.error("Failed to fetch events for auth filtering: %s", e)
            return []

        auth_events: list[dict[str, Any]] = []
        for ev in raw_events:
            msg = (ev.get("msg") or ev.get("message") or "").lower()
            category = (ev.get("category") or ev.get("module") or "").lower()
            (ev.get("level") or ev.get("type") or "").lower()

            # Check if this event is auth-related
            is_auth = any(kw in msg or kw in category for kw in _AUTH_KEYWORDS)
            if not is_auth:
                continue

            # Determine auth result from message content
            if any(w in msg for w in ("success", "authenticated", "accepted")):
                auth_result = "success"
            elif any(w in msg for w in ("reject", "denied", "failed", "timeout")):
                auth_result = "reject"
            else:
                auth_result = "unknown"

            client_mac = ev.get("clientMac")
            if not client_mac:
                continue

            auth_events.append(
                {
                    "client_mac": normalize_mac(client_mac),
                    "auth_result": auth_result,
                    "username": ev.get("userName") or ev.get("username"),
                    "reject_reason": msg if auth_result == "reject" else None,
                    "device_id": None,
                    "timestamp": ev.get("timestamp") or ev.get("time"),
                }
            )

            if len(auth_events) >= limit:
                break

        return auth_events

    # =========================================================================
    # Enterprise: SSID Config (Roaming / Band Steering)
    # =========================================================================

    async def update_ssid_config(
        self,
        ssid_id: str,
        config: dict[str, Any],
    ) -> AdapterResult:
        """
        Update SSID-level config for roaming/band steering.

        Maps FreeSDN roaming fields to Omada's SSID update payload:
        - fast_roaming -> enable11r (802.11r)
        - roaming_protocol -> enable11k, enable11v, enable11r
        - minimum_rssi -> minRssi / rssiThreshold
        """
        omada_payload: dict[str, Any] = {}

        # Map roaming protocol to Omada flags
        roaming_protocol = config.get("roaming_protocol")
        if roaming_protocol:
            proto_lower = roaming_protocol.lower().replace(" ", "")
            omada_payload["enable11r"] = "11r" in proto_lower
            omada_payload["enable11k"] = "11k" in proto_lower
            omada_payload["enable11v"] = "11v" in proto_lower

        # Fast roaming flag (overrides enable11r if set)
        if "fast_roaming" in config:
            omada_payload["enable11r"] = bool(config["fast_roaming"])

        # Minimum RSSI for band steering
        if "minimum_rssi" in config and config["minimum_rssi"] is not None:
            omada_payload["rssiThreshold"] = config["minimum_rssi"]
            omada_payload["bandSteeringEnabled"] = True

        if not omada_payload:
            return AdapterResult.ok(None, message="No SSID config changes to apply")

        # Delegate to the existing update_ssid method
        return await self.update_ssid(ssid_id, omada_payload)

    # =========================================================================
    # Enterprise: PoE Schedules
    # =========================================================================

    async def get_poe_schedules(self) -> list[dict[str, Any]]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_poe_schedules(site_id)
            return [
                NormalizedPoESchedule(
                    id=r.get("id"),
                    name=r.get("name"),
                    enabled=r.get("enable", True),
                    ports=r.get("ports", []),
                    days=r.get("days", []),
                    start_time=r.get("startTime"),
                    end_time=r.get("endTime"),
                    action=r.get("action", "disable"),
                ).model_dump()
                for r in rows
            ]
        except Exception as e:
            logger.error("Failed to get PoE schedules: %s", e)
            return []

    async def create_poe_schedule(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.create_poe_schedule(site_id, config)
            return AdapterResult.ok(data, message="PoE schedule created")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="POE_SCHEDULE_CREATE_FAILED")

    async def update_poe_schedule(self, schedule_id: str, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_poe_schedule(site_id, schedule_id, config)
            return AdapterResult.ok(data, message="PoE schedule updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="POE_SCHEDULE_UPDATE_FAILED")

    async def delete_poe_schedule(self, schedule_id: str) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            await self._client.delete_poe_schedule(site_id, schedule_id)
            return AdapterResult.ok(None, message="PoE schedule deleted")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="POE_SCHEDULE_DELETE_FAILED")

    # =========================================================================
    # Enterprise: Site Settings
    # =========================================================================

    async def get_site_settings(self) -> dict[str, Any]:
        site_id = await self._ensure_site_id()
        if not site_id:
            return {}
        try:
            return await self._client.get_site_settings(site_id)
        except Exception as e:
            logger.error("Failed to get site settings: %s", e)
            return {}

    async def update_site_settings(self, config: dict[str, Any]) -> AdapterResult:
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_site_settings(site_id, config)
            return AdapterResult.ok(data, message="Site settings updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="SITE_SETTINGS_FAILED")

    # =========================================================================
    # Enterprise: Controller Maintenance
    # =========================================================================

    async def create_controller_backup(self) -> AdapterResult:
        """Trigger a controller backup."""
        try:
            data = await self._client.create_controller_backup()
            return AdapterResult.ok(data, message="Controller backup initiated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="BACKUP_FAILED")

    async def get_controller_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get controller maintenance/system logs."""
        try:
            return await self._client.get_controller_logs(limit=limit)
        except Exception as e:
            logger.error("Failed to get controller logs: %s", e)
            return []

    # =========================================================================
    # Enterprise: Full Topology with uplink/downlink/client mapping
    # =========================================================================

    async def get_topology_data(self) -> dict[str, Any]:
        """Build comprehensive topology data with device connections.

        Unlike the basic ``discover_devices()`` which only returns per-device
        metadata, this method fetches type-specific detail endpoints to extract
        the ``uplink``, ``downlink``, and ``lldpNeighbors`` arrays that reveal
        the actual physical connections between devices.

        Returns:
            dict with ``devices``, ``links``, and ``clients`` arrays suitable for
            the TopologyService to persist as TopologyLink records.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return {"devices": [], "links": [], "clients": []}

        try:
            enriched = await self._client.get_devices_with_topology(site_id)
        except Exception as e:
            logger.error("Failed to get topology data: %s", e)
            return {"devices": [], "links": [], "clients": []}

        # Build MAC → device index
        mac_index: dict[str, dict[str, Any]] = {}
        topo_devices: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []

        for raw in enriched:
            mac = normalize_mac(raw.get("mac"))
            if not mac:
                continue

            dtype = DEVICE_TYPE_MAP.get(str(raw.get("type", "")), str(raw.get("type", "unknown")))
            status_cat = raw.get("statusCategory")
            if status_cat is not None:
                status = DEVICE_STATUS_CATEGORY_MAP.get(status_cat, "unknown")
            else:
                status = DEVICE_STATUS_MAP.get(raw.get("status"), "unknown")

            # Extract uplink info (available in type-specific detail)
            uplink = raw.get("uplink") or {}
            uplink_mac = normalize_mac(uplink.get("mac")) if isinstance(uplink, dict) else None
            uplink_port = uplink.get("port") if isinstance(uplink, dict) else None
            uplink_name = uplink.get("name") if isinstance(uplink, dict) else None

            # Extract downlinks
            downlinks = raw.get("downlink") or raw.get("downlinks") or []
            if not isinstance(downlinks, list):
                downlinks = []

            # Determine layer
            layer = 2  # default: endpoint/AP
            if dtype == "gateway":
                layer = 0
            elif dtype == "switch":
                layer = 1

            device = NormalizedTopologyDevice(
                mac=mac,
                name=raw.get("name"),
                model=raw.get("model") or raw.get("showModel"),
                device_type=dtype,
                ip=raw.get("ip"),
                status=status,
                uplink_mac=uplink_mac,
                uplink_port=uplink_port,
                uplink_name=uplink_name,
                downlinks=[
                    {
                        "mac": normalize_mac(dl.get("mac", "")),
                        "name": dl.get("name"),
                        "type": dl.get("type"),
                        "port": dl.get("port"),
                        "model": dl.get("model"),
                    }
                    for dl in downlinks
                ],
                connected_clients=raw.get("clientNum", 0),
                layer=layer,
            ).model_dump()

            mac_index[mac] = device
            topo_devices.append(device)

        # Build links from uplinks (authoritative) and downlinks (supplementary)
        seen_links: set[str] = set()

        for device in topo_devices:
            src_mac = device["mac"]
            uplink_mac = device.get("uplink_mac")

            # Uplink → link from this device to its uplink
            if uplink_mac and uplink_mac in mac_index:
                link_key = f"{src_mac}->{uplink_mac}"
                reverse_key = f"{uplink_mac}->{src_mac}"
                if link_key not in seen_links and reverse_key not in seen_links:
                    links.append(
                        {
                            "source_mac": src_mac,
                            "target_mac": uplink_mac,
                            "source_port": str(device.get("uplink_port"))
                            if device.get("uplink_port")
                            else None,
                            "target_port": None,
                            "status": "up" if device["status"] == "online" else "down",
                            "link_type": "ethernet",
                            "discovered_via": "controller",
                        }
                    )
                    seen_links.add(link_key)

            # Downlinks → supplementary links
            for dl in device.get("downlinks", []):
                dl_mac = normalize_mac(dl.get("mac", ""))
                if dl_mac and dl_mac in mac_index:
                    link_key = f"{src_mac}->{dl_mac}"
                    reverse_key = f"{dl_mac}->{src_mac}"
                    if link_key not in seen_links and reverse_key not in seen_links:
                        links.append(
                            {
                                "source_mac": src_mac,
                                "target_mac": dl_mac,
                                "source_port": str(dl.get("port")) if dl.get("port") else None,
                                "target_port": None,
                                "status": "up",
                                "link_type": "ethernet",
                                "discovered_via": "controller_downlink",
                            }
                        )
                        seen_links.add(link_key)

        # Get client → device mapping for topology overlay
        try:
            raw_clients = await self._client.get_clients(site_id)
            client_links: list[dict[str, Any]] = []
            for c in raw_clients:
                client_mac = normalize_mac(c.get("mac", ""))
                # Wireless client → connected AP
                connected_ap = normalize_mac(c.get("apMac", ""))
                connected_switch = normalize_mac(c.get("switchMac", ""))
                connected_port = c.get("switchPort")

                target_mac = connected_ap or connected_switch
                if client_mac and target_mac and target_mac in mac_index:
                    client_links.append(
                        {
                            "client_mac": client_mac,
                            "client_name": c.get("name") or c.get("hostName"),
                            "client_ip": c.get("ip"),
                            "target_device_mac": target_mac,
                            "target_port": connected_port,
                            "connection_type": "wireless" if connected_ap else "wired",
                            "ssid": c.get("ssid"),
                            "vlan_id": c.get("vlanId"),
                            "signal": c.get("signalLevel"),
                        }
                    )
        except Exception:
            client_links = []

        return {
            "devices": topo_devices,
            "links": links,
            "clients": client_links,
            "stats": {
                "total_devices": len(topo_devices),
                "total_links": len(links),
                "total_clients": len(client_links) if client_links else 0,
                "gateways": sum(1 for d in topo_devices if d.get("layer") == 0),
                "switches": sum(1 for d in topo_devices if d.get("layer") == 1),
                "access_points": sum(1 for d in topo_devices if d.get("layer") == 2),
            },
        }

    # =========================================================================
    # Enterprise: Firmware Fleet Overview
    # =========================================================================

    async def get_firmware_list(self) -> list[dict[str, Any]]:
        """Get firmware status for ALL devices at once (efficient single call).

        Returns a list of NormalizedFirmwareStatus dicts for every device.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return []
        try:
            rows = await self._client.get_firmware_list(site_id)
            results: list[dict[str, Any]] = []
            for fw in rows:
                current = fw.get("curFwVer") or fw.get("firmwareVersion")
                latest = fw.get("latestFwVer") or fw.get("newFwVer")
                need_upgrade = fw.get("needUpgrade", False)
                if not need_upgrade and current and latest and current != latest:
                    need_upgrade = True
                results.append(
                    NormalizedFirmwareStatus(
                        mac=normalize_mac(fw.get("mac", "")),
                        device_name=fw.get("name") or fw.get("showModel"),
                        device_type=DEVICE_TYPE_MAP.get(fw.get("type"), "unknown"),
                        model=fw.get("model") or fw.get("showModel"),
                        current_version=current,
                        latest_version=latest,
                        needs_upgrade=need_upgrade,
                        auto_upgrade=fw.get("autoUpgrade", False),
                        release_notes=fw.get("fwReleaseLog"),
                        last_upgrade_time=fw.get("lastUpgradeTime"),
                    ).model_dump()
                )
            return results
        except Exception as e:
            logger.error("Failed to get firmware list: %s", e)
            return []

    async def get_firmware_overview_fast(self) -> dict[str, Any]:
        """Get a fast fleet-wide firmware summary using single API call.

        Less detailed than get_firmware_overview() but much faster — one API
        call instead of N+1 per-device lookups.
        """
        fw_list = await self.get_firmware_list()
        up_to_date = [f for f in fw_list if not f.get("needs_upgrade")]
        upgradable = [f for f in fw_list if f.get("needs_upgrade")]
        return NormalizedFirmwareOverview(
            total_devices=len(fw_list),
            up_to_date=len(up_to_date),
            needs_upgrade=len(upgradable),
            devices=fw_list,
        ).model_dump()

    # =========================================================================
    # Enterprise: Controller / System Info
    # =========================================================================

    async def get_controller_status(self) -> dict[str, Any]:
        """Get Omada controller health / status (no site required)."""
        try:
            return await self._client.get_controller_status()
        except Exception as e:
            logger.error("Failed to get controller status: %s", e)
            return {}

    async def get_system_info(self) -> dict[str, Any]:
        """Get Omada controller system information (version, uptime, etc.)."""
        try:
            return await self._client.get_system_info()
        except Exception as e:
            logger.error("Failed to get system info: %s", e)
            return {}

    # =========================================================================
    # Enterprise: WAN Configuration
    # =========================================================================

    async def update_wan_config(self, config: dict[str, Any]) -> AdapterResult:
        """Update WAN settings for the active site."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_wan_config(site_id, config)
            return AdapterResult.ok(data, message="WAN configuration updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="WAN_CONFIG_FAILED")

    # =========================================================================
    # Enterprise: Switch Port Advanced Controls
    # =========================================================================

    async def set_switch_port_loopback_detect(
        self, device_mac: str, port_id: int, enabled: bool
    ) -> AdapterResult:
        """Enable / disable loopback detection on a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_loopback_detect(
                site_id, normalize_mac(device_mac), port_id, enabled
            )
            return AdapterResult.ok(
                data,
                message=f"Loopback detection {'enabled' if enabled else 'disabled'}",
            )
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="LOOPBACK_DETECT_FAILED")

    async def set_switch_port_flow_control(
        self, device_mac: str, port_id: int, enabled: bool
    ) -> AdapterResult:
        """Enable / disable 802.3x flow control on a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.set_switch_port_flow_control(
                site_id, normalize_mac(device_mac), port_id, enabled
            )
            return AdapterResult.ok(
                data,
                message=f"Flow control {'enabled' if enabled else 'disabled'}",
            )
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="FLOW_CONTROL_FAILED")

    async def set_switch_port_bandwidth(
        self, device_mac: str, port_id: int, config: dict[str, Any]
    ) -> AdapterResult:
        """Set bandwidth control (rate limiting) on a switch port.

        config keys: bandWidthCtrlType (0=off, 1=rate_limit), bandCtrl (dict with ingressRate, egressRate in kbps)
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_port_profile(
                site_id, normalize_mac(device_mac), port_id, config
            )
            return AdapterResult.ok(data, message="Bandwidth control updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="BANDWIDTH_CTRL_FAILED")

    async def set_switch_port_storm_control(
        self, device_mac: str, port_id: int, config: dict[str, Any]
    ) -> AdapterResult:
        """Set storm control thresholds on a switch port.

        config keys: stormCtrl (dict with broadcastEnable, broadcastRate, multicastEnable, multicastRate,
        unknownUnicastEnable, unknownUnicastRate — rates in pps or kbps)
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_port_profile(
                site_id, normalize_mac(device_mac), port_id, {"stormCtrl": config}
            )
            return AdapterResult.ok(data, message="Storm control updated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="STORM_CTRL_FAILED")

    async def update_switch_port_overrides(
        self, device_mac: str, port_id: int, overrides: dict[str, Any]
    ) -> AdapterResult:
        """Apply arbitrary port-profile overrides to a switch port.

        This is the generic wrapper for _client.update_switch_port_profile().
        Use for OUI VLAN assignment, CLI profile application, etc.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.update_switch_port_profile(
                site_id, normalize_mac(device_mac), port_id, overrides
            )
            return AdapterResult.ok(data, message="Port overrides applied")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="PORT_OVERRIDE_FAILED")

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics (cable test, ping, traceroute)
    # ═══════════════════════════════════════════════════════════════════════

    async def run_cable_test(self, device_mac: str, port: int) -> AdapterResult:
        """Run cable diagnostic test on a switch port."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.run_cable_test(site_id, normalize_mac(device_mac), port)
            return AdapterResult.ok(data, message="Cable test initiated")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="CABLE_TEST_FAILED")

    async def run_ping(self, device_mac: str, target: str, count: int = 5) -> AdapterResult:
        """Run ping from a device to a target host."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.run_ping(site_id, normalize_mac(device_mac), target, count)
            return AdapterResult.ok(data, message="Ping test completed")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="PING_FAILED")

    async def run_traceroute(
        self, device_mac: str, target: str, max_hops: int = 30
    ) -> AdapterResult:
        """Run traceroute from a device to a target host."""
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            data = await self._client.run_traceroute(
                site_id, normalize_mac(device_mac), target, max_hops
            )
            return AdapterResult.ok(data, message="Traceroute completed")
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="TRACEROUTE_FAILED")

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Suppression  (Orchestration)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_server_status(self) -> AdapterResult:
        """
        Return the DHCP server status for all networks at the active site.

        Returns a list of networks with their DHCP enabled/disabled state.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            networks = await self._client.get_networks(site_id)
            dhcp_statuses: list[dict[str, Any]] = []
            for net in networks:
                if not isinstance(net, dict):
                    continue
                dhcp_settings = net.get("dhcpSettings", net.get("dhcpSetting", {}))
                if isinstance(dhcp_settings, dict):
                    enabled = dhcp_settings.get("dhcpEnable", False)
                else:
                    enabled = False
                dhcp_statuses.append(
                    {
                        "network_id": net.get("id", ""),
                        "name": net.get("name", ""),
                        "vlan_id": net.get("vlan", 0),
                        "dhcp_enabled": enabled,
                        "purpose": net.get("purpose", ""),
                    }
                )
            return AdapterResult.ok(
                data={
                    "networks": dhcp_statuses,
                    "count": len(dhcp_statuses),
                }
            )
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DHCP_STATUS_FAILED")

    async def suppress_dhcp_on_network(
        self, network_id: str, *, vlan_id: int | None = None
    ) -> AdapterResult:
        """
        Disable the DHCP server on a specific Omada network.

        This is used by the orchestration layer to ensure that
        limb devices (Omada gateways) don't serve DHCP when the
        brain (e.g. OPNsense) is authoritative for a VLAN's DHCP.

        Parameters
        ----------
        network_id : str
            Omada network/VLAN ID.
        vlan_id : int, optional
            VLAN tag — used to auto-find the network if *network_id*
            is not known.
        """
        site_id = await self._ensure_site_id()
        if not site_id:
            return AdapterResult.fail("No site", error_code="NO_SITE")
        try:
            # If network_id not provided, find by VLAN tag
            if not network_id and vlan_id is not None:
                networks = await self._client.get_networks(site_id)
                match = next(
                    (n for n in networks if isinstance(n, dict) and n.get("vlan") == vlan_id),
                    None,
                )
                if match is None:
                    return AdapterResult.fail(
                        f"No Omada network found for VLAN {vlan_id}",
                        error_code="NETWORK_NOT_FOUND",
                    )
                network_id = match.get("id", "")

            data = await self._client.update_network(
                site_id,
                network_id,
                {"dhcpSettings": {"dhcpEnable": False}},
            )
            return AdapterResult.ok(
                data,
                message=f"DHCP disabled on network {network_id}",
            )
        except Exception as e:
            return self._fail_from_exception(e, default_error_code="DHCP_SUPPRESS_FAILED")
