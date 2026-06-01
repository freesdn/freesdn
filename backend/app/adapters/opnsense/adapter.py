# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OPNsense Enterprise Adapter
=============================================

Full production BaseAdapter implementation for OPNsense firewalls / routers.

Domains covered:
  System          — info, resources, reboot, halt, firmware
  Config          — backup list / create / delete / revert / download
  Interfaces      — list, statistics, ARP, NDP, VIPs
  Firewall        — filter CRUD + toggle + apply
  Aliases         — CRUD + apply
  NAT             — source NAT CRUD + port-forward/DNAT CRUD + apply
  DHCP            — leases, static-mapping CRUD + apply
  DNS (Unbound)   — host overrides CRUD, domain overrides CRUD + apply
  VPN WireGuard   — server CRUD, peer CRUD, handshakes, apply
  VPN OpenVPN     — instance CRUD, sessions, kill, apply
  VPN IPsec       — tunnels list, phase-2, SAD, SPD, connect/disconnect, apply
  Routing         — static-route CRUD, kernel routing table, apply
  Services        — list / start / stop / restart
  IDS/IPS         — settings, rules, rulesets, alerts, toggle, apply, start/stop
  Traffic Shaper  — pipe CRUD, queue CRUD, rule CRUD, apply
  Diagnostics     — ping, traceroute, DNS-lookup, connections, PF stats
  Logs            — system, firewall
  Dashboard       — aggregate device summary

Every public method returns structured Pydantic models (models.py) wrapped
in an AdapterResult for consistency with the rest of the FreeSDN platform.
"""

from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, ClassVar

from app.adapters.base import (
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
from app.adapters.opnsense.client import OPNsenseAPIError, OPNsenseClient
from app.adapters.opnsense.models import (
    AliasType,
    DHCPLeaseStatus,
    # enums
    FirewallAction,
    FirewallDirection,
    FirewallProtocol,
    GatewayStatus,
    IDSAlertSeverity,
    InterfaceStatus,
    NormalizedAlias,
    NormalizedARPEntry,
    NormalizedBackupInfo,
    NormalizedDeviceSummary,
    NormalizedDHCPLease,
    NormalizedDHCPStaticMapping,
    NormalizedDNSDomainOverride,
    NormalizedDNSOverride,
    NormalizedFirewallRule,
    NormalizedFirmwareInfo,
    NormalizedGateway,
    NormalizedIDSAlert,
    NormalizedIDSSettings,
    NormalizedInterface,
    NormalizedPortForward,
    NormalizedRoutingTable,
    NormalizedService,
    NormalizedStaticRoute,
    # models
    NormalizedSystemInfo,
    NormalizedTrafficPipe,
    NormalizedTrafficQueue,
    NormalizedTrafficRule,
    NormalizedWireGuardPeer,
    NormalizedWireGuardServer,
    ServiceStatus,
)
from app.core.redaction import redact_secrets

logger = logging.getLogger(__name__)


class OPNsenseAdapter(BaseAdapter):
    """
    Enterprise adapter for OPNsense firewalls and routers.

    Covers every OPNsense API domain: system, firmware, config backup,
    interfaces, firewall rules, aliases, NAT (source + DNAT), DHCP,
    DNS (Unbound), WireGuard, OpenVPN, IPsec, static routing, services,
    IDS/IPS (Suricata), traffic shaper, diagnostics, and logs.
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="opnsense",
        name="OPNsense Firewall",
        vendor="Deciso B.V.",
        version="1.0.0",
        description="OPNsense firewall/router – full enterprise adapter (API key/secret auth)",
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["23.1", "23.7", "24.1", "24.7", "25.1"],
        device_types={
            "firewall": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_BACKUP,
                    Capability.DEVICE_LOGS,
                    Capability.FIREWALL_BASIC,
                    Capability.FIREWALL_ADVANCED,
                    Capability.FIREWALL_LOGGING,
                    Capability.NAT,
                    Capability.DHCP_SERVER,
                    Capability.DNS,
                    Capability.ROUTING_STATIC,
                    Capability.WAN_FAILOVER,
                    Capability.QOS,
                    Capability.TRAFFIC_SHAPING,
                    # OPNsense-specific surfaces backed by the
                    # ``OPNsenseClient`` methods. Mirrors what the
                    # Omada manifest does for the gateway-* feature
                    # domains: declare every domain the adapter
                    # exposes so the frontend can hide unsupported
                    # tabs.
                    Capability.IP_GROUPS,  # firewall aliases
                    Capability.URL_FILTERING,  # alias-based URL alias
                    Capability.STATIC_ROUTES,
                    Capability.IP_MAC_BINDING,  # via DHCP static mappings
                    Capability.DHCP_RESERVATIONS,
                    Capability.DDNS,  # if Dynamic DNS module enabled
                    Capability.SITE_SETTINGS,
                    Capability.CONTROLLER_BACKUP,
                    Capability.EVENTS_ALERTS,
                    # OPNsense feature surfaces — each backed by a
                    # adapter_opnsense_* service + endpoint module.
                    # Frontend reads these to gate per-feature tabs.
                    Capability.OPNSENSE_FIREWALL_RULES,
                    Capability.OPNSENSE_FIREWALL_ALIASES,
                    Capability.OPNSENSE_NAT_SOURCE,
                    Capability.OPNSENSE_NAT_PORT_FORWARD,
                    Capability.OPNSENSE_DHCP_LEASES,
                    Capability.OPNSENSE_DHCP_STATIC_MAPPINGS,
                    Capability.OPNSENSE_DHCP_KEA,
                    Capability.OPNSENSE_DNS_HOST_OVERRIDES,
                    Capability.OPNSENSE_DNS_DOMAIN_OVERRIDES,
                    Capability.OPNSENSE_ROUTING_STATIC,
                    Capability.OPNSENSE_ROUTING_TABLE,
                    Capability.OPNSENSE_GATEWAY_STATUS,
                    Capability.OPNSENSE_SERVICES_CONTROL,
                    Capability.OPNSENSE_SYSTEM_INFO,
                    Capability.OPNSENSE_SYSTEM_REBOOT,
                    Capability.OPNSENSE_SYSTEM_BACKUP,
                    Capability.OPNSENSE_SYSTEM_FIRMWARE,
                    Capability.OPNSENSE_DIAG_LOGS,
                    Capability.OPNSENSE_DIAG_TRAFFIC,
                    Capability.OPNSENSE_DIAG_PING,
                    Capability.OPNSENSE_DIAG_TRACEROUTE,
                    Capability.OPNSENSE_DIAG_DNS_LOOKUP,
                    Capability.OPNSENSE_SHAPER_PIPES,
                    Capability.OPNSENSE_SHAPER_QUEUES,
                    Capability.OPNSENSE_SHAPER_RULES,
                    Capability.OPNSENSE_INTERFACES_LIST,
                    Capability.OPNSENSE_INTERFACES_VLAN,
                    Capability.OPNSENSE_INTERFACES_ARP,
                    Capability.OPNSENSE_INTERFACES_NDP,
                    Capability.OPNSENSE_CRON_JOBS,
                ],
                models=["OPNsense*", "*"],
            ),
            "vpn_gateway": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.VPN_IPSEC,
                    Capability.VPN_OPENVPN,
                    Capability.VPN_WIREGUARD,
                    Capability.VPN_SERVER,
                    Capability.VPN_CLIENT,
                    # Per-protocol surfaces — frontend gates the
                    # WireGuard / OpenVPN / IPsec tabs on these.
                    Capability.OPNSENSE_VPN_WIREGUARD,
                    Capability.OPNSENSE_VPN_OPENVPN,
                    Capability.OPNSENSE_VPN_IPSEC,
                ],
                models=["OPNsense*", "*"],
            ),
            "utm": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.IDS_IPS,
                    Capability.GEO_BLOCKING,
                    Capability.APPLICATION_FILTER,
                    Capability.CONTENT_FILTER,
                    # IDS/IPS feature breakdown
                    Capability.OPNSENSE_IDS_SETTINGS,
                    Capability.OPNSENSE_IDS_RULES,
                    Capability.OPNSENSE_IDS_ALERTS,
                ],
                models=["OPNsense*", "*"],
            ),
        },
        auth_methods=["api_key"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=4,
        default_sync_interval=60,
        min_sync_interval=30,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=False,
    )

    # ── Initialisation ─────────────────────────────────────────────────────

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        # the high-level adapter write methods are
        # the DIRECT-route entry points (gateway-service / device-control).
        # They thread this flag to the client instead of hard-coding force=True,
        # so a direct live write is refused under ADAPTER_READ_ONLY unless the
        # caller opts in. The sanctioned write path is the staged applier, which
        # calls the client DIRECTLY with force=True (it does not use these
        # methods), so it is unaffected. Default False = direct routes refused.
        self._direct_write_force = bool(kwargs.pop("direct_write_force", False))
        super().__init__(host, username, password, **kwargs)
        # OPNsense's REST API is HTTPS-only. The platform
        # ships a controller-level ``use_ssl`` flag for vendor
        # symmetry, but plain HTTP is not a valid mode here. Reject
        # explicitly so an operator who toggles it sees a clear error
        # instead of an opaque "connection refused" 60 seconds later.
        use_ssl = kwargs.get("use_ssl", True)
        if use_ssl is False:
            raise ValueError(
                "OPNsense API is HTTPS-only; controller use_ssl=False is "
                "not supported. Re-enable HTTPS on the controller and "
                "set use_ssl=True (the default).",
            )
        self._api = OPNsenseClient(
            host=host,
            api_key=username,
            api_secret=password,
            port=kwargs.get("port", 443),
            verify_ssl=kwargs.get("verify_ssl", False),
            timeout=kwargs.get("timeout", 60),
        )

    # ── helpers ──────────────────────────────────────────────────────────

    def _safe(self, raw: dict | list | None, key: str = "", default: Any = "") -> Any:
        """Safely pluck a key from a dict, returning *default* on any miss."""
        if raw is None:
            return default
        if isinstance(raw, dict):
            return raw.get(key, default)
        return default

    def _rows(self, raw: dict | None, key: str = "rows") -> list[dict]:
        """Extract the row-list from a paginated search response."""
        if raw and isinstance(raw.get(key), list):
            return raw[key]
        return []

    # ═══════════════════════════════════════════════════════════════════════
    # BaseAdapter — required methods
    # ═══════════════════════════════════════════════════════════════════════

    # ── Validation helpers ──────────────────────────────────────────────
    _SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._:-]+$")
    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.I,
    )
    _SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")

    def _validate_host(self, host: str) -> str:
        """Validate diagnostic target is a safe hostname/IP."""
        if not host or len(host) > 253 or not self._SAFE_HOST_RE.match(host):
            raise ValueError("Invalid diagnostic target: must be a valid hostname or IP")
        return host

    def _validate_uuid(self, uuid: str) -> str:
        """Validate UUID format to prevent path traversal."""
        if not self._UUID_RE.match(uuid):
            raise ValueError("Invalid UUID format")
        return uuid

    def _validate_filename(self, filename: str) -> str:
        """Validate backup filename to prevent path traversal."""
        if not filename or not self._SAFE_FILENAME_RE.match(filename):
            raise ValueError("Invalid filename")
        return filename

    async def connect(self) -> bool:
        try:
            await self._api.connect()
            await self._api.get_system_status()
            self._connected = True
            return True
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.error("OPNsense connection failed to %s: %s", self.host, exc)
            raise AdapterConnectionError(
                "Failed to connect to OPNsense device",
                adapter_id="opnsense",
            ) from exc

    async def disconnect(self) -> None:
        await self._api.close()
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        # wrap in try/finally so the httpx client is always
        # closed, even when the auth probe raises. Previously a 401 or
        # network error left the session leaked.
        try:
            try:
                await self._api.connect()
                status = await self._api.get_system_status()
                return AdapterResult.ok(
                    data={"vendor": "OPNsense", "status": status},
                    message="Connection successful",
                )
            except AdapterAuthenticationError:
                # User-friendly: don't echo internal exception text,
                # but the auth-error class itself is useful signal.
                return AdapterResult.fail(
                    "OPNsense authentication failed",
                    error_code="AUTH_FAILED",
                )
            except AdapterConnectionError:
                return AdapterResult.fail(
                    "Could not connect to OPNsense",
                    error_code="CONN_FAILED",
                )
            except Exception:
                logger.exception(
                    "OPNsense test_connection failed for %s",
                    self.host,
                )
                return AdapterResult.fail("Connection test failed")
        finally:
            try:
                await self._api.close()
            except Exception:
                logger.exception("OPNsense test_connection close failed")

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """OPNsense is itself the managed device — returns a single entry."""
        try:
            status, fw = await asyncio.gather(
                self._api.get_system_status(),
                self._api.get_firmware_status(),
            )
            hostname = status.get("name", self.host)
            version = fw.get("product_version", "unknown")
            return [
                DiscoveredDevice(
                    device_type="firewall",
                    name=hostname,
                    vendor="OPNsense",
                    model=f"OPNsense {version}",
                    mac_address="",
                    ip_address=self.host,
                    firmware_version=version,
                    status="online",
                    raw_data={"status": status},
                )
            ]
        except Exception as exc:
            logger.warning("OPNsense discover_devices failed: %s", exc)
            return []

    async def get_device_status(self, device_id: str) -> AdapterResult:
        try:
            status, ifaces, gw = await asyncio.gather(
                self._api.get_system_status(),
                self._api.get_interface_statistics(),
                self._api.get_gateway_status(),
            )
            return AdapterResult.ok(
                data={
                    "system": status,
                    "interfaces": ifaces,
                    "gateways": gw,
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_device_info(self, device_id: str) -> AdapterResult:
        try:
            status, fw = await asyncio.gather(
                self._api.get_system_status(),
                self._api.get_firmware_status(),
            )
            return AdapterResult.ok(
                data={
                    "hostname": status.get("name"),
                    "version": fw.get("product_version"),
                    "firmware": fw,
                    "system": status,
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # System — normalised
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_info(self) -> AdapterResult:
        """Return NormalizedSystemInfo."""
        try:
            raw = await self._api.get_system_status()
            info = NormalizedSystemInfo(
                hostname=raw.get("name", ""),
                domain=raw.get("domain", ""),
                fqdn=f"{raw.get('name', '')}.{raw.get('domain', '')}".strip("."),
                version=raw.get("kernel", {}).get("pf_version", ""),
                architecture=raw.get("versions", {}).get("arch", ""),
                kernel_version=raw.get("kernel", {}).get("pf_version", ""),
                uptime_text=raw.get("uptime", ""),
            )
            return AdapterResult.ok(data=info.model_dump())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_firmware_info(self) -> AdapterResult:
        """Return NormalizedFirmwareInfo."""
        try:
            raw = await self._api.get_firmware_status()
            info = NormalizedFirmwareInfo(
                current_version=raw.get("product_version", ""),
                latest_version=raw.get("product_latest", raw.get("product_version", "")),
                needs_update=raw.get("needs_reboot", "") == "1"
                or raw.get("upgrade_needs_reboot", "") == "1",
                update_available=raw.get("status_upgrade_action", "") != "",
                product_name=raw.get("product_name", "OPNsense"),
                product_id=raw.get("product_id", ""),
                product_target=raw.get("product_target", ""),
                last_check=raw.get("last_check", {}).get("last_check_iso", None)
                if isinstance(raw.get("last_check"), dict)
                else raw.get("last_check"),
                download_size=raw.get("download_size", None),
                repository=raw.get("product_repo", None),
                mirror_url=raw.get("product_mirror", None),
            )
            return AdapterResult.ok(data=info.model_dump())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_system_resources(self) -> AdapterResult:
        """CPU/memory/disk from the activity endpoint."""
        try:
            data = await self._api.get_system_resources()
            return AdapterResult.ok(data=data)
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def reboot_device(self, device_id: str = "") -> AdapterResult:
        try:
            result = await self._api.reboot(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Reboot initiated")
        except Exception as exc:
            logger.exception("OPNsense reboot_device failed")
            return AdapterResult.fail(type(exc).__name__)

    async def halt_device(self, device_id: str = "") -> AdapterResult:
        try:
            result = await self._api.halt(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Halt initiated")
        except Exception as exc:
            logger.exception("OPNsense halt_device failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Firmware — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def firmware_check(self) -> AdapterResult:
        try:
            data = await self._api.firmware_check(force=self._direct_write_force)
            return AdapterResult.ok(data=data, message="Firmware check started")
        except Exception as exc:
            logger.exception("OPNsense firmware_check failed")
            return AdapterResult.fail(type(exc).__name__)

    async def firmware_update(self) -> AdapterResult:
        try:
            data = await self._api.firmware_update(force=self._direct_write_force)
            return AdapterResult.ok(data=data, message="Firmware update started")
        except Exception as exc:
            logger.exception("OPNsense firmware_update failed")
            return AdapterResult.fail(type(exc).__name__)

    async def firmware_upgrade_status(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.firmware_upgrade_status())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_firmware_changelog(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firmware_changelog())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_installed_packages(self) -> AdapterResult:
        """Return installed system packages from firmware/info."""
        try:
            raw = await self._api.get_installed_packages()
            # OPNsense /api/core/firmware/info returns {package: [...], plugin: [...], ...}
            pkgs = raw.get("package", []) if isinstance(raw, dict) else []
            packages = []
            for p in pkgs:
                if not isinstance(p, dict):
                    continue
                packages.append(
                    {
                        "name": p.get("name", ""),
                        "version": p.get("version", ""),
                        "comment": p.get("comment", ""),
                        "flatsize": p.get("flatsize", ""),
                        "repository": p.get("repository", ""),
                        "installed": p.get("installed", "0") == "1",
                        "automatic": p.get("automatic", "0") == "1",
                        "license": p.get("license", ""),
                    }
                )
            return AdapterResult.ok(data={"packages": packages, "count": len(packages)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_installed_plugins(self) -> AdapterResult:
        """Return installed plugins from firmware/info."""
        try:
            raw = await self._api.get_installed_packages()  # firmware/info has both
            all_plugins = raw.get("plugin", []) if isinstance(raw, dict) else []
            plugins = []
            for p in all_plugins:
                if not isinstance(p, dict):
                    continue
                if p.get("installed") != "1":
                    continue
                plugins.append(
                    {
                        "name": p.get("name", ""),
                        "version": p.get("version", ""),
                        "comment": p.get("comment", ""),
                        "flatsize": p.get("flatsize", ""),
                        "repository": p.get("repository", ""),
                        "license": p.get("license", ""),
                    }
                )
            return AdapterResult.ok(data={"plugins": plugins, "count": len(plugins)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Configuration Backup / Restore
    # ═══════════════════════════════════════════════════════════════════════

    async def get_backup_list(self) -> AdapterResult:
        """Return list of NormalizedBackupInfo."""
        try:
            raw = await self._api.get_backup_list()
            backups = []
            for item in raw.get("backups", []) if isinstance(raw.get("backups"), list) else []:
                backups.append(
                    NormalizedBackupInfo(
                        filename=item.get("filename", ""),
                        timestamp=item.get("timestamp", ""),
                        size_bytes=int(item.get("size", 0)),
                        description=item.get("description", ""),
                    ).model_dump()
                )
            return AdapterResult.ok(data={"backups": backups})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_backup(self) -> AdapterResult:
        # Thread force=True: this is a sanctioned write entry point.
        try:
            result = await self._api.create_backup(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Backup created")
        except Exception as exc:
            logger.exception("OPNsense create_backup failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_backup(self, filename: str) -> AdapterResult:
        # validate filename to block path-traversal payloads
        # before they hit the OPNsense API; force=True opts in to write.
        try:
            self._validate_filename(filename)
            result = await self._api.delete_backup(filename, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Backup deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_backup failed")
            return AdapterResult.fail(type(exc).__name__)

    async def revert_backup(self, filename: str) -> AdapterResult:
        # same validation + force=True pattern as delete_backup.
        try:
            self._validate_filename(filename)
            result = await self._api.revert_backup(filename, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Backup reverted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense revert_backup failed")
            return AdapterResult.fail(type(exc).__name__)

    async def download_config(self) -> AdapterResult:
        """Download running configuration (XML)."""
        try:
            result = await self._api.download_config()
            return AdapterResult.ok(data=result)
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ── Enterprise three-state config overrides ──────────────────────────

    async def get_running_config(self, device_id: str) -> dict[str, Any]:
        """Aggregate running config for drift detection."""
        try:
            import asyncio

            (
                fw_rules,
                aliases,
                nat,
                pf,
                dhcp,
                static,
                dns,
                ifaces,
                gw,
                services,
            ) = await asyncio.gather(
                self._api.get_firewall_rules(),
                self._api.get_aliases(),
                self._api.get_nat_rules(),
                self._api.get_port_forwards(),
                self._api.get_dhcp_leases(),
                self._api.get_dhcp_static_mappings(),
                self._api.get_dns_overrides(),
                self._api.get_interfaces(),
                self._api.get_gateway_status(),
                self._api.get_services(),
            )
            return {
                "firewall_rules": fw_rules,
                "aliases": aliases,
                "nat_rules": nat,
                "port_forwards": pf,
                "dhcp_leases": dhcp,
                "dhcp_static": static,
                "dns_overrides": dns,
                "interfaces": ifaces,
                "gateways": gw,
                "services": services,
            }
        except Exception as exc:
            logger.warning("get_running_config failed: %s", exc)
            return {}

    async def normalize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Strip volatile keys from running config for drift comparison."""
        volatile_keys = {
            "uptime",
            "last_seen",
            "timestamp",
            "boot_time",
            "sys_time",
            "bytes_received",
            "bytes_sent",
            "packets_received",
            "packets_sent",
            "errors_in",
            "errors_out",
            "collisions",
            "transfer_rx",
            "transfer_tx",
        }
        return {k: v for k, v in config.items() if k not in volatile_keys}

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> AdapterResult:
        """Return list of NormalizedInterface."""
        try:
            raw, stats_raw = await asyncio.gather(
                self._api.get_interfaces(),
                self._api.get_interface_statistics(),
            )
            # OPNsense wraps stats under a 'statistics' key — unwrap it
            if isinstance(stats_raw, dict) and "statistics" in stats_raw:
                stats_raw = stats_raw["statistics"]
            stats_map: dict[str, dict] = {}
            if isinstance(stats_raw, dict):
                for sname, sdata in stats_raw.items():
                    if isinstance(sdata, dict):
                        stats_map[sname] = sdata

            interfaces = []
            # Handle both dict-of-dicts (legacy) and list-of-dicts (export)
            if isinstance(raw, list):
                for iface_data in raw:
                    if not isinstance(iface_data, dict):
                        continue
                    iface_key = iface_data.get("identifier", iface_data.get("description", ""))
                    device_name = iface_data.get("device", iface_data.get("if", ""))
                    st = stats_map.get(device_name, stats_map.get(iface_key, {}))
                    status_str = str(iface_data.get("status", "down")).lower()
                    # Extract VLAN info from "vlan" sub-dict or top-level fields
                    vlan_info = iface_data.get("vlan", {})
                    vlan_tag = iface_data.get("vlan_tag") or vlan_info.get("tag")
                    vlan_parent = vlan_info.get("parent", "")
                    # Determine link type
                    link_type = iface_data.get("link_type", "")
                    if not link_type and vlan_tag:
                        link_type = "vlan"
                    elif not link_type and iface_data.get("is_physical"):
                        link_type = "ethernet"
                    # Get subnet from config or top-level
                    cfg = iface_data.get("config", {})
                    subnet = iface_data.get("subnet") or cfg.get("subnet", "")
                    ipv4_gw = iface_data.get("gateway") or cfg.get("gateway", "")
                    # Normalize ipv4_address: addr4 may contain CIDR (e.g. "192.168.1.1/24")
                    raw_addr4 = iface_data.get("addr4", iface_data.get("ipaddr")) or ""
                    if "/" in str(raw_addr4):
                        addr_part, cidr_part = str(raw_addr4).split("/", 1)
                        if not subnet:
                            subnet = cidr_part
                    else:
                        addr_part = raw_addr4
                    interfaces.append(
                        NormalizedInterface(
                            name=iface_data.get("description", iface_key),
                            description=cfg.get("descr", iface_data.get("description", "")),
                            identifier=iface_data.get("identifier", ""),
                            device=device_name,
                            status=InterfaceStatus(status_str)
                            if status_str in InterfaceStatus.__members__.values()
                            else InterfaceStatus.DOWN,
                            enabled=iface_data.get("enabled", True)
                            if isinstance(iface_data.get("enabled"), bool)
                            else iface_data.get("enable", "1") == "1",
                            link_type=link_type,
                            media=iface_data.get("media", ""),
                            mtu=int(iface_data["mtu"]) if iface_data.get("mtu") else None,
                            mac_address=iface_data.get("macaddr", iface_data.get("mac")),
                            ipv4_address=addr_part or None,
                            ipv4_subnet=subnet,
                            ipv4_gateway=ipv4_gw,
                            ipv6_address=iface_data.get("addr6", iface_data.get("ipaddrv6")),
                            is_wan="wan" in str(iface_data.get("description", "")).lower(),
                            is_lan="lan" in str(iface_data.get("description", "")).lower(),
                            vlan_id=int(vlan_tag) if vlan_tag else None,
                            parent_interface=vlan_parent or None,
                            bytes_received=int(st.get("bytes received", 0) or 0),
                            bytes_sent=int(st.get("bytes transmitted", 0) or 0),
                            packets_received=int(st.get("packets received", 0) or 0),
                            packets_sent=int(st.get("packets transmitted", 0) or 0),
                            errors_in=int(st.get("input errors", 0) or 0),
                            errors_out=int(st.get("output errors", 0) or 0),
                            collisions=int(st.get("collisions", 0) or 0),
                            raw=iface_data,
                        ).model_dump()
                    )
            elif isinstance(raw, dict):
                for iface_key, iface_data in raw.items():
                    if not isinstance(iface_data, dict):
                        continue
                    st = stats_map.get(iface_key, {})
                    status_str = str(iface_data.get("status", "down")).lower()
                    # VLAN info from legacy dict format
                    vlan_info = iface_data.get("vlan", {})
                    vlan_tag = iface_data.get("vlan_tag") or vlan_info.get("tag")
                    vlan_parent = vlan_info.get("parent", "")
                    device_name = iface_data.get("if", "")
                    link_type = ""
                    if vlan_tag:
                        link_type = "vlan"
                    elif iface_data.get("is_physical"):
                        link_type = "ethernet"
                    interfaces.append(
                        NormalizedInterface(
                            name=iface_key,
                            description=iface_data.get("descr", ""),
                            identifier=iface_data.get("if", ""),
                            device=device_name,
                            status=InterfaceStatus(status_str)
                            if status_str in InterfaceStatus.__members__.values()
                            else InterfaceStatus.DOWN,
                            enabled=iface_data.get("enable", "1") == "1",
                            link_type=link_type,
                            media=iface_data.get("media", ""),
                            mtu=int(iface_data["mtu"]) if iface_data.get("mtu") else None,
                            mac_address=iface_data.get("macaddr"),
                            ipv4_address=iface_data.get("ipaddr"),
                            ipv4_subnet=iface_data.get("subnet"),
                            ipv4_gateway=iface_data.get("gateway"),
                            ipv6_address=iface_data.get("ipaddrv6"),
                            is_wan="wan" in iface_key.lower(),
                            is_lan="lan" in iface_key.lower(),
                            vlan_id=int(vlan_tag) if vlan_tag else None,
                            parent_interface=vlan_parent or None,
                            bytes_received=int(st.get("bytes received", 0) or 0),
                            bytes_sent=int(st.get("bytes transmitted", 0) or 0),
                            packets_received=int(st.get("packets received", 0) or 0),
                            packets_sent=int(st.get("packets transmitted", 0) or 0),
                            errors_in=int(st.get("input errors", 0) or 0),
                            errors_out=int(st.get("output errors", 0) or 0),
                            collisions=int(st.get("collisions", 0) or 0),
                            raw=iface_data,
                        ).model_dump()
                    )
            return AdapterResult.ok(data={"interfaces": interfaces})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_interface_statistics(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_interface_statistics())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_arp_table(self) -> AdapterResult:
        """Return list of NormalizedARPEntry."""
        try:
            raw = await self._api.get_arp_table()
            entries = []
            rows = (
                raw
                if isinstance(raw, list)
                else raw.get("arp", [])
                if isinstance(raw, dict)
                else []
            )
            for row in rows:
                if not isinstance(row, dict):
                    continue
                entries.append(
                    NormalizedARPEntry(
                        ip_address=row.get("ip", ""),
                        mac_address=row.get("mac", ""),
                        hostname=row.get("hostname", ""),
                        interface=row.get("intf", ""),
                        interface_name=row.get("intf_description", ""),
                        manufacturer=row.get("manufacturer", None),
                        expires=row.get("expires", None),
                        permanent=row.get("permanent", False)
                        if isinstance(row.get("permanent"), bool)
                        else str(row.get("type", "")).lower() == "permanent",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"arp_entries": entries, "count": len(entries)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ndp_table(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_ndp_table())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def flush_arp(self) -> AdapterResult:
        # flush_arp is a write-shaped diagnostic — POSTs to the
        # controller. Thread force=True so the read-only gate lets it
        # through.
        try:
            result = await self._api.flush_arp(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="ARP cache flushed")
        except Exception as exc:
            logger.exception("OPNsense flush_arp failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_vip_status(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_vip_status())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Rules (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self, search: str = "") -> AdapterResult:
        """Return list of NormalizedFirewallRule.

        Strategy:
        1. Try the MVC filter module (searchRule) — works if rules are
           managed through the OPNsense API / plugin.
        2. If that returns zero rows, fall back to downloading config.xml
           and parsing the legacy ``<filter><rule>`` elements that virtually
           every OPNsense / pfSense box still uses.
        """
        try:
            raw = await self._api.get_firewall_rules(search)
            mvc_rows = self._rows(raw)

            if mvc_rows:
                # MVC filter rules present — use them directly
                rules = self._normalize_mvc_rules(mvc_rows)
            else:
                # Fall back to legacy config.xml rules
                logger.info(
                    "MVC filter module returned 0 rules — falling back to config.xml legacy rules"
                )
                rules = await self._get_legacy_firewall_rules(search)

            return AdapterResult.ok(data={"rules": rules, "count": len(rules)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    def _normalize_mvc_rules(self, rows: list[dict]) -> list[dict]:
        """Normalise rows returned by /api/firewall/filter/searchRule."""
        rules = []
        for row in rows:
            rules.append(
                NormalizedFirewallRule(
                    uuid=row.get("uuid", ""),
                    sequence=int(row["sequence"]) if row.get("sequence") else None,
                    enabled=str(row.get("enabled", "1")) == "1",
                    action=FirewallAction(row["action"])
                    if row.get("action") in FirewallAction.__members__.values()
                    else FirewallAction.PASS,
                    direction=FirewallDirection(row["direction"])
                    if row.get("direction") in FirewallDirection.__members__.values()
                    else FirewallDirection.IN,
                    interface=row.get("interface", ""),
                    protocol=FirewallProtocol(row["protocol"])
                    if row.get("protocol") in FirewallProtocol.__members__.values()
                    else FirewallProtocol.ANY,
                    source_net=row.get("source_net", ""),
                    source_port=row.get("source_port", ""),
                    source_invert=str(row.get("source_not", "0")) == "1",
                    destination_net=row.get("destination_net", ""),
                    destination_port=row.get("destination_port", ""),
                    destination_invert=str(row.get("destination_not", "0")) == "1",
                    gateway=row.get("gateway", ""),
                    log=str(row.get("log", "0")) == "1",
                    description=row.get("description", ""),
                    raw=row,
                ).model_dump()
            )
        return rules

    async def _get_legacy_firewall_rules(self, search: str = "") -> list[dict]:
        """Download config.xml and parse ``<filter><rule>`` elements."""
        try:
            xml_text = await self._api.download_config_xml()
        except Exception as exc:
            logger.warning("Failed to download config.xml for legacy rules: %s", exc)
            return []
        return self._parse_legacy_rules(xml_text, search)

    @staticmethod
    def _parse_legacy_rules(xml_text: str, search: str = "") -> list[dict]:
        """Parse legacy pfSense/OPNsense ``<filter><rule>`` XML into
        normalised firewall rule dicts.
        """
        # config.xml is fully device-controlled and downloaded via
        # get_raw (no body cap). defusedxml blocks entity-expansion but not a
        # large/deeply-nested document, so a compromised firewall could force
        # this fallback (MVC search returns 0 rules) then serve a huge config.xml
        # to exhaust worker memory. Bound the input before parsing.
        _MAX_CONFIG_XML_BYTES = 16 * 1024 * 1024
        if xml_text is not None and len(xml_text) > _MAX_CONFIG_XML_BYTES:
            logger.warning(
                "config.xml too large (%d bytes > %d cap), refusing to parse",
                len(xml_text),
                _MAX_CONFIG_XML_BYTES,
            )
            return []
        try:
            # CPython's xml.etree.ElementTree does not resolve external entities
            # by default, but we use defusedxml where available for defense-in-depth
            try:
                import defusedxml.ElementTree as SafeET

                root = SafeET.fromstring(xml_text)
            except ImportError:
                root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.error("Failed to parse config.xml: %s", exc)
            return []

        filter_el = root.find("filter")
        if filter_el is None:
            return []

        # Helper to read text of a child element
        def _txt(el: ET.Element, tag: str, default: str = "") -> str:
            child = el.find(tag)
            return (child.text or default) if child is not None else default

        # Helper to check if child element exists (boolean flags)
        def _has(el: ET.Element, tag: str) -> bool:
            return el.find(tag) is not None

        # Resolve interface descriptions from <interfaces> section
        iface_map: dict[str, str] = {}
        interfaces_el = root.find("interfaces")
        if interfaces_el is not None:
            for iface_el in interfaces_el:
                iface_tag = iface_el.tag  # e.g. "wan", "lan", "opt1"
                descr = _txt(iface_el, "descr", iface_tag.upper())
                iface_map[iface_tag] = descr

        # Map ipprotocol values
        IP_PROTO_MAP = {
            "inet": "IPv4",
            "inet6": "IPv6",
            "inet46": "IPv4+IPv6",
        }

        rules: list[dict] = []
        for idx, rule_el in enumerate(filter_el.findall("rule")):
            # Parse source
            source_el = rule_el.find("source")
            source_net = "any"
            source_port = ""
            source_invert = False
            if source_el is not None:
                if source_el.find("any") is not None:
                    source_net = "any"
                elif source_el.find("address") is not None:
                    source_net = source_el.find("address").text or ""
                elif source_el.find("network") is not None:
                    source_net = source_el.find("network").text or ""
                if source_el.find("port") is not None:
                    source_port = source_el.find("port").text or ""
                source_invert = source_el.find("not") is not None

            # Parse destination
            dest_el = rule_el.find("destination")
            dest_net = "any"
            dest_port = ""
            dest_invert = False
            if dest_el is not None:
                if dest_el.find("any") is not None:
                    dest_net = "any"
                elif dest_el.find("address") is not None:
                    dest_net = dest_el.find("address").text or ""
                elif dest_el.find("network") is not None:
                    dest_net = dest_el.find("network").text or ""
                if dest_el.find("port") is not None:
                    dest_port = dest_el.find("port").text or ""
                dest_invert = dest_el.find("not") is not None

            # Map action
            action_str = _txt(rule_el, "type", "pass").lower()
            try:
                action = FirewallAction(action_str)
            except ValueError:
                action = FirewallAction.PASS

            # Map protocol
            proto_str = _txt(rule_el, "protocol", "any")
            proto_upper = proto_str.upper() if proto_str else "ANY"
            # Handle tcp/udp combined
            if proto_upper in ("TCP/UDP", "TCP_UDP"):
                protocol = FirewallProtocol.TCP_UDP
            else:
                try:
                    protocol = FirewallProtocol(proto_upper)
                except ValueError:
                    protocol = FirewallProtocol.ANY

            # Map direction
            dir_str = _txt(rule_el, "direction", "in").lower()
            try:
                direction = FirewallDirection(dir_str)
            except ValueError:
                direction = FirewallDirection.IN

            # Interface
            iface_key = _txt(rule_el, "interface", "")
            iface_name = iface_map.get(iface_key, iface_key.upper()) if iface_key else ""

            description = _txt(rule_el, "descr", "")
            enabled = not _has(rule_el, "disabled")

            # Timestamps
            created_at = None
            created_el = rule_el.find("created")
            if created_el is not None:
                created_at = _txt(created_el, "time")

            updated_at = None
            updated_el = rule_el.find("updated")
            if updated_el is not None:
                updated_at = _txt(updated_el, "time")

            # Apply search filter if provided
            if search:
                search_lower = search.lower()
                searchable = f"{description} {iface_key} {iface_name} {source_net} {dest_net} {proto_str} {action_str}".lower()
                if search_lower not in searchable:
                    continue

            # Build raw dict for debugging
            raw_dict: dict[str, Any] = {}
            for child in rule_el:
                if len(child) == 0:
                    raw_dict[child.tag] = child.text or ""
                else:
                    raw_dict[child.tag] = {sub.tag: sub.text or "" for sub in child}

            rule = NormalizedFirewallRule(
                uuid=_txt(rule_el, "associated-rule-id", f"legacy-{idx}"),
                sequence=idx,
                enabled=enabled,
                action=action,
                direction=direction,
                quick=_has(rule_el, "quick"),
                interface=iface_key,
                interface_name=iface_name,
                ip_protocol=IP_PROTO_MAP.get(_txt(rule_el, "ipprotocol", "inet"), "IPv4"),
                protocol=protocol,
                source_net=source_net,
                source_port=source_port,
                source_invert=source_invert,
                destination_net=dest_net,
                destination_port=dest_port,
                destination_invert=dest_invert,
                gateway=_txt(rule_el, "gateway", ""),
                log=_has(rule_el, "log"),
                description=description,
                category=_txt(rule_el, "category", ""),
                state_type=_txt(rule_el, "statetype", ""),
                created_at=created_at,
                updated_at=updated_at,
                raw=raw_dict,
            ).model_dump()
            rules.append(rule)

        return rules

    async def get_firewall_rule(self, uuid: str) -> AdapterResult:
        try:
            data = await self._api.get_firewall_rule(uuid)
            return AdapterResult.ok(data=data)
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_firewall_rule(self, rule: dict[str, Any]) -> AdapterResult:
        # Direct-route entry point: threads ``self._direct_write_force``
        # (default False) to the client, so a direct live write is refused by
        # the client's read-only gate under ADAPTER_READ_ONLY. The sanctioned
        # write path is the staged applier, which calls the client DIRECTLY
        # with force=True (it does NOT use this method). Validators in item 9
        # are not added here because ``rule`` is a dict body, not a path value.
        try:
            result = await self._api.add_firewall_rule(rule, force=self._direct_write_force)
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule created and applied")
        except Exception as exc:
            logger.exception("OPNsense create_firewall_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_firewall_rule(self, uuid: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_firewall_rule(
                uuid, rule, force=self._direct_write_force
            )
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule updated and applied")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_firewall_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_firewall_rule(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_firewall_rule(uuid, force=self._direct_write_force)
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule deleted and applied")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_firewall_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def toggle_firewall_rule(self, uuid: str, enabled: bool) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.toggle_firewall_rule(
                uuid, enabled, force=self._direct_write_force
            )
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result)
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense toggle_firewall_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def apply_firewall_changes(self) -> AdapterResult:
        """Apply pending firewall changes (reconfigure filter)."""
        try:
            result = await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Firewall changes applied")
        except Exception as exc:
            logger.exception("OPNsense apply_firewall_changes failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Aliases (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_aliases(self, search: str = "") -> AdapterResult:
        """Return list of NormalizedAlias."""
        try:
            raw = await self._api.get_aliases(search)
            aliases = []
            for row in self._rows(raw):
                content = row.get("content", "")
                content_list = (
                    [c.strip() for c in content.split("\n") if c.strip()]
                    if isinstance(content, str)
                    else content
                    if isinstance(content, list)
                    else []
                )
                aliases.append(
                    NormalizedAlias(
                        uuid=row.get("uuid", ""),
                        name=row.get("name", ""),
                        alias_type=AliasType(row["type"])
                        if row.get("type") in AliasType.__members__.values()
                        else AliasType.HOST,
                        description=row.get("description", ""),
                        content=content_list,
                        enabled=str(row.get("enabled", "1")) == "1",
                        proto=row.get("proto", ""),
                        update_freq=row.get("updatefreq", ""),
                        counters=str(row.get("counters", "0")) == "1",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"aliases": aliases, "count": len(aliases)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_alias(
        self,
        alias: dict[str, Any] | None = None,
        *,
        name: str = "",
        type: str = "",
        members: list[str] | None = None,
        description: str = "",
    ) -> AdapterResult:
        """
        Create a firewall alias (address group).

        Accepts either a raw OPNsense alias dict (from gateway API
        live proxy) or individual parameters (from distribution engine).
        """
        try:
            if alias is None:
                # Distribution engine path — build the payload
                alias = {
                    "name": name,
                    "type": type or "network",
                    "content": "\n".join(members or []),
                    "description": description,
                }
            result = await self._api.add_alias(alias, force=self._direct_write_force)
            await self._api.apply_alias_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Alias created")
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.exception("OPNsense create_alias failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_alias(self, uuid: str, alias: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_alias(uuid, alias, force=self._direct_write_force)
            await self._api.apply_alias_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Alias updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_alias failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_alias(
        self,
        uuid: str | None = None,
        *,
        name: str = "",
    ) -> AdapterResult:
        """
        Delete a firewall alias by UUID or by name.

        The gateway service calls with ``uuid``; the distribution
        engine may call with ``name``.
        """
        try:
            target_uuid = uuid
            if not target_uuid and name:
                # Find alias by name
                aliases_result = await self.get_aliases()
                if aliases_result.success and aliases_result.data:
                    for a in aliases_result.data.get("aliases", []):
                        if isinstance(a, dict) and a.get("name") == name:
                            target_uuid = a.get("uuid")
                            break
            if not target_uuid:
                if name:
                    return AdapterResult.ok(
                        data={"name": name, "already_absent": True},
                        message=f"Alias '{name}' not found — nothing to delete",
                    )
                return AdapterResult.fail(
                    "Either uuid or name must be provided",
                    error_code="MISSING_IDENTIFIER",
                )
            # target_uuid resolved either from the explicit ``uuid`` arg
            # (already validated above when present) or from the
            # name-search lookup (server-trusted). Validate defensively
            # regardless — the lookup may return junk on a malformed
            # controller response.
            self._validate_uuid(target_uuid)
            result = await self._api.delete_alias(target_uuid, force=self._direct_write_force)
            await self._api.apply_alias_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Alias deleted")
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_alias failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # NAT — Source NAT (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_nat_rules())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_source_nat_rule(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_source_nat_rule(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_source_nat_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_source_nat_rule(rule, force=self._direct_write_force)
            await self._api.apply_source_nat_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Source NAT rule created")
        except Exception as exc:
            logger.exception("OPNsense create_source_nat_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_source_nat_rule(self, uuid: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_source_nat_rule(
                uuid, rule, force=self._direct_write_force
            )
            await self._api.apply_source_nat_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Source NAT rule updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_source_nat_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_source_nat_rule(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_source_nat_rule(uuid, force=self._direct_write_force)
            await self._api.apply_source_nat_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Source NAT rule deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_source_nat_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # NAT — Port Forwards / Destination NAT (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_port_forwards(self) -> AdapterResult:
        try:
            raw = await self._api.get_port_forward_rules()
            forwards = []
            for row in self._rows(raw):
                forwards.append(
                    NormalizedPortForward(
                        uuid=row.get("uuid", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        interface=row.get("interface", ""),
                        protocol=row.get("protocol", "tcp"),
                        source_net=row.get("source_net", ""),
                        source_port=row.get("source_port", ""),
                        destination_net=row.get("destination_net", ""),
                        destination_port=row.get("destination_port", ""),
                        target_ip=row.get("target", ""),
                        target_port=row.get("local_port", row.get("target_port", "")),
                        description=row.get("description", ""),
                        log=str(row.get("log", "0")) == "1",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"port_forwards": forwards, "count": len(forwards)})
        except OPNsenseAPIError as exc:
            # Classic Port Forward (rdr) rules are NOT exposed via the MVC API on
            # current OPNsense (no /api/firewall/dnat controller — 404 verified on
            # 26.1.10); they live in config.xml. Outbound NAT (source_nat) and 1:1
            # NAT DO have MVC endpoints and work. Degrade gracefully to an empty
            # list with a note rather than failing the whole firewall read, so the
            # dashboard still loads. (Reading rdr rules from config.xml is a
            # possible future enhancement.)
            if getattr(exc, "status_code", None) == 404:
                logger.info(
                    "OPNsense port-forward MVC endpoint unavailable (404) — classic "
                    "rdr rules are config.xml-only on this version; returning empty"
                )
                return AdapterResult.ok(
                    data={
                        "port_forwards": [],
                        "count": 0,
                        "note": "Port-forward listing is not available via the OPNsense "
                        "API on this version (no dnat MVC endpoint).",
                    }
                )
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_port_forward_rule(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_port_forward_rule(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_port_forward(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_port_forward_rule(rule, force=self._direct_write_force)
            await self._api.apply_port_forward_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Port forward created")
        except Exception as exc:
            logger.exception("OPNsense create_port_forward failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_port_forward(self, uuid: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_port_forward_rule(
                uuid, rule, force=self._direct_write_force
            )
            await self._api.apply_port_forward_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Port forward updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_port_forward failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_port_forward(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_port_forward_rule(uuid, force=self._direct_write_force)
            await self._api.apply_port_forward_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Port forward deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_port_forward failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_leases(self) -> AdapterResult:
        """Return list of NormalizedDHCPLease."""
        try:
            raw = await self._api.get_dhcp_leases()
            leases = []
            rows = raw if isinstance(raw, list) else self._rows(raw)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                leases.append(
                    NormalizedDHCPLease(
                        ip_address=row.get("address", row.get("ip", "")),
                        mac_address=row.get("mac", ""),
                        hostname=row.get("hostname", ""),
                        description=row.get("descr", ""),
                        interface=row.get("if", ""),
                        interface_name=row.get("if_descr", ""),
                        status=DHCPLeaseStatus(row["state"])
                        if row.get("state") in DHCPLeaseStatus.__members__.values()
                        else DHCPLeaseStatus.ACTIVE,
                        starts=row.get("starts", None),
                        ends=row.get("ends", None),
                        binding_state=row.get("binding", ""),
                        manufacturer=row.get("manufacturer", None),
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"leases": leases, "count": len(leases)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_dhcp_static_mappings(self) -> AdapterResult:
        """Return list of NormalizedDHCPStaticMapping."""
        try:
            raw = await self._api.get_dhcp_static_mappings()
            mappings = []
            rows = raw if isinstance(raw, list) else self._rows(raw)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                mappings.append(
                    NormalizedDHCPStaticMapping(
                        uuid=row.get("uuid", ""),
                        mac_address=row.get("mac", ""),
                        ip_address=row.get("ipaddr", ""),
                        hostname=row.get("hostname", ""),
                        description=row.get("descr", row.get("description", "")),
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"static_mappings": mappings, "count": len(mappings)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_dhcp_static_mapping(self, mapping: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_dhcp_static_mapping(
                mapping, force=self._direct_write_force
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static mapping created")
        except Exception as exc:
            logger.exception("OPNsense create_dhcp_static_mapping failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_dhcp_static_mapping(self, uuid: str, mapping: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_dhcp_static_mapping(
                uuid, mapping, force=self._direct_write_force
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static mapping updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_dhcp_static_mapping failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_dhcp_static_mapping(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_dhcp_static_mapping(
                uuid, force=self._direct_write_force
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static mapping deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_dhcp_static_mapping failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # DNS — Unbound (host + domain overrides)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_overrides(self) -> AdapterResult:
        """Return list of NormalizedDNSOverride."""
        try:
            raw = await self._api.get_dns_overrides()
            overrides = []
            for row in self._rows(raw):
                overrides.append(
                    NormalizedDNSOverride(
                        uuid=row.get("uuid", ""),
                        hostname=row.get("hostname", ""),
                        domain=row.get("domain", ""),
                        fqdn=f"{row.get('hostname', '')}.{row.get('domain', '')}".strip("."),
                        server=row.get("server", ""),
                        description=row.get("description", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"overrides": overrides, "count": len(overrides)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_dns_override(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_dns_override(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_dns_override(self, override: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_dns_override(override, force=self._direct_write_force)
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="DNS override created")
        except Exception as exc:
            logger.exception("OPNsense create_dns_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_dns_override(self, uuid: str, override: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_dns_override(
                uuid, override, force=self._direct_write_force
            )
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="DNS override updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_dns_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_dns_override(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_dns_override(uuid, force=self._direct_write_force)
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="DNS override deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_dns_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_dns_domain_overrides(self) -> AdapterResult:
        """Return list of NormalizedDNSDomainOverride."""
        try:
            raw = await self._api.get_dns_domain_overrides()
            overrides = []
            for row in self._rows(raw):
                overrides.append(
                    NormalizedDNSDomainOverride(
                        uuid=row.get("uuid", ""),
                        domain=row.get("domain", ""),
                        server=row.get("server", ""),
                        description=row.get("description", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"domain_overrides": overrides, "count": len(overrides)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_dns_domain_override(self, override: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_dns_domain_override(
                override, force=self._direct_write_force
            )
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Domain override created")
        except Exception as exc:
            logger.exception("OPNsense create_dns_domain_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_dns_domain_override(
        self, uuid: str, override: dict[str, Any]
    ) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_dns_domain_override(
                uuid, override, force=self._direct_write_force
            )
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Domain override updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_dns_domain_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_dns_domain_override(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_dns_domain_override(
                uuid, force=self._direct_write_force
            )
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Domain override deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_dns_domain_override failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_unbound_status(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_unbound_status())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — WireGuard (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_wireguard_status(self) -> AdapterResult:
        try:
            status, peers, servers, handshakes = await asyncio.gather(
                self._api.get_wireguard_status(),
                self._api.get_wireguard_peers(),
                self._api.get_wireguard_servers(),
                self._api.get_wireguard_handshakes(),
            )
            # Every WG row that comes off the controller carries
            # ``privkey``/``psk`` server-side. Strip them before the
            # aggregate is handed back to the caller — the adapter
            # contract is "no secrets leave the read path".
            return AdapterResult.ok(
                data={
                    "status": redact_secrets(status),
                    "peers": redact_secrets(peers),
                    "servers": redact_secrets(servers),
                    "handshakes": redact_secrets(handshakes),
                }
            )
        except Exception as exc:
            logger.exception("OPNsense get_wireguard_status failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_wireguard_servers(self) -> AdapterResult:
        """Return list of NormalizedWireGuardServer.

        OPNsense ships the server's ``privkey`` on every row. We
        redact the ``raw`` payload before stamping it onto the
        normalised model so a ``firewall:read`` consumer never sees
        the private key, even by walking ``.raw``.
        """
        try:
            raw = await self._api.get_wireguard_servers()
            servers = []
            for row in self._rows(raw):
                servers.append(
                    NormalizedWireGuardServer(
                        uuid=row.get("uuid", ""),
                        name=row.get("name", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        public_key=row.get("pubkey", ""),
                        listen_port=int(row["port"]) if row.get("port") else None,
                        tunnel_address=row.get("tunneladdress", ""),
                        dns_servers=row.get("dns", ""),
                        peers=row.get("peers", "").split(",") if row.get("peers") else [],
                        raw=redact_secrets(row),
                    ).model_dump()
                )
            return AdapterResult.ok(data={"servers": servers, "count": len(servers)})
        except Exception as exc:
            logger.exception("OPNsense get_wireguard_servers failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_wireguard_server(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_wireguard_server(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_wireguard_server(self, server: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_wireguard_server(server, force=self._direct_write_force)
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard server created")
        except Exception as exc:
            logger.exception("OPNsense create_wireguard_server failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_wireguard_server(self, uuid: str, server: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_wireguard_server(
                uuid, server, force=self._direct_write_force
            )
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard server updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_wireguard_server failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_wireguard_server(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_wireguard_server(uuid, force=self._direct_write_force)
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard server deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_wireguard_server failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_wireguard_peers(self) -> AdapterResult:
        """Return list of NormalizedWireGuardPeer.

        Security: the OPNsense response includes ``psk`` (the WG
        pre-shared key) on every peer row. We do NOT populate
        :pyattr:`NormalizedWireGuardPeer.preshared_key` from the
        controller's value (the model field is left at its empty
        default and the boolean ``has_preshared_key`` shows up via the
        ``raw`` redacted payload). The ``raw`` field is run through
        :func:`redact_secrets` before being attached so the read-path
        never re-exports key material even if a UI consumer walks
        ``raw``.
        """
        try:
            raw = await self._api.get_wireguard_peers()
            peers = []
            for row in self._rows(raw):
                peers.append(
                    NormalizedWireGuardPeer(
                        uuid=row.get("uuid", ""),
                        name=row.get("name", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        public_key=row.get("pubkey", ""),
                        # preshared_key intentionally NOT populated — it
                        # would echo the WG ``psk`` straight into the
                        # response. The redacted ``raw`` below carries a
                        # ``"psk": "***"`` marker so the UI can still tell
                        # whether a PSK is configured.
                        server_address=row.get("serveraddress", ""),
                        server_port=int(row["serverport"]) if row.get("serverport") else None,
                        tunnel_address=row.get("tunneladdress", ""),
                        endpoint_address=row.get("endpoint", ""),
                        keepalive=int(row["keepalive"]) if row.get("keepalive") else None,
                        raw=redact_secrets(row),
                    ).model_dump()
                )
            return AdapterResult.ok(data={"peers": peers, "count": len(peers)})
        except Exception as exc:
            logger.exception("OPNsense get_wireguard_peers failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_wireguard_peer(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_wireguard_peer(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_wireguard_peer(self, peer: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_wireguard_peer(peer, force=self._direct_write_force)
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard peer created")
        except Exception as exc:
            logger.exception("OPNsense create_wireguard_peer failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_wireguard_peer(self, uuid: str, peer: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_wireguard_peer(
                uuid, peer, force=self._direct_write_force
            )
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard peer updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_wireguard_peer failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_wireguard_peer(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_wireguard_peer(uuid, force=self._direct_write_force)
            await self._api.apply_wireguard_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="WireGuard peer deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_wireguard_peer failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_wireguard_handshakes(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_wireguard_handshakes())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — OpenVPN (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_openvpn_status(self) -> AdapterResult:
        try:
            providers, instances_raw, sessions_raw = await asyncio.gather(
                self._api.get_openvpn_providers(),
                self._api.get_openvpn_instances(),
                self._api.get_openvpn_sessions(),
            )
            # Unwrap paginated search results to plain lists
            instances = (
                self._rows(instances_raw) if isinstance(instances_raw, dict) else instances_raw
            )
            sessions = self._rows(sessions_raw) if isinstance(sessions_raw, dict) else sessions_raw
            return AdapterResult.ok(
                data={
                    "providers": providers,
                    "instances": instances if isinstance(instances, list) else [],
                    "sessions": sessions if isinstance(sessions, list) else [],
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_openvpn_instance(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_openvpn_instance(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_openvpn_instance(self, instance: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_openvpn_instance(instance, force=self._direct_write_force)
            await self._api.apply_openvpn_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="OpenVPN instance created")
        except Exception as exc:
            logger.exception("OPNsense create_openvpn_instance failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_openvpn_instance(self, uuid: str, instance: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_openvpn_instance(
                uuid, instance, force=self._direct_write_force
            )
            await self._api.apply_openvpn_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="OpenVPN instance updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_openvpn_instance failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_openvpn_instance(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_openvpn_instance(uuid, force=self._direct_write_force)
            await self._api.apply_openvpn_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="OpenVPN instance deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_openvpn_instance failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_openvpn_sessions(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_openvpn_sessions())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def kill_openvpn_session(self, session_id: str) -> AdapterResult:
        try:
            # session_id is interpolated into the OPNsense path
            # ``/killSession/{session_id}``. Real OPNsense session IDs
            # have the shape ``<remote_ip>:<port>`` or
            # ``<remote_ip>:<port>:<cn>`` and the CN may contain
            # hyphens, dots, underscores up to 64 chars — total length
            # can exceed the 64-char ``validate_id`` cap. Use a wider,
            # session-specific validator that admits ``:`` but still
            # rejects path-traversal payloads (``..``, ``/``,
            # whitespace, control bytes).
            import re

            _SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.\-:]{1,128}$")
            if not session_id or not _SESSION_ID_RE.match(session_id):
                from fastapi import HTTPException

                raise HTTPException(400, detail="invalid openvpn_session_id format")
            result = await self._api.kill_openvpn_session(
                session_id,
                force=self._direct_write_force,
            )
            return AdapterResult.ok(data=result, message="OpenVPN session killed")
        except Exception as exc:
            logger.exception("OPNsense kill_openvpn_session failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — Aggregate (convenience)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vpn_status(self) -> AdapterResult:
        """Aggregate WireGuard + OpenVPN + IPsec status."""
        try:
            import asyncio

            wg, wg_peers, wg_servers, ovpn, ovpn_instances, ipsec_raw = await asyncio.gather(
                self._api.get_wireguard_status(),
                self._api.get_wireguard_peers(),
                self._api.get_wireguard_servers(),
                self._api.get_openvpn_providers(),
                self._api.get_openvpn_instances(),
                self._api.get_ipsec_status(),
                return_exceptions=True,
            )

            # ``return_exceptions=True`` means each slot may be an
            # ``Exception`` instance. Stuffing one of those into the
            # response dict will explode at JSON serialization time
            # in production (FastAPI's encoder cannot stringify a raw
            # exception). Coerce every individual sub-result to a
            # safe shape: dict pass-through, list pass-through, or
            # the empty-dict sentinel for failures.
            def _safe(value: Any, default: Any) -> Any:
                if isinstance(value, BaseException):
                    return default
                return value

            wg = _safe(wg, {})
            wg_peers = _safe(wg_peers, [])
            wg_servers = _safe(wg_servers, [])
            ovpn = _safe(ovpn, [])
            ovpn_instances = _safe(ovpn_instances, [])
            ipsec = ipsec_raw if isinstance(ipsec_raw, dict) else {}
            return AdapterResult.ok(
                data={
                    "wireguard": {"status": wg, "peers": wg_peers, "servers": wg_servers},
                    "openvpn": {"providers": ovpn, "instances": ovpn_instances},
                    "ipsec": ipsec,
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — IPsec
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ipsec_tunnels(self) -> AdapterResult:
        try:
            import asyncio

            phase1_raw, phase2_raw = await asyncio.gather(
                self._api.get_ipsec_tunnels(),
                self._api.get_ipsec_phase2(),
            )
            # Unwrap paginated search results to plain lists
            phase1 = self._rows(phase1_raw) if isinstance(phase1_raw, dict) else phase1_raw
            phase2 = self._rows(phase2_raw) if isinstance(phase2_raw, dict) else phase2_raw
            return AdapterResult.ok(
                data={
                    "phase1": phase1 if isinstance(phase1, list) else [],
                    "phase2": phase2 if isinstance(phase2, list) else [],
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ipsec_status(self) -> AdapterResult:
        try:
            import asyncio

            sad_raw, spd_raw = await asyncio.gather(
                self._api.get_ipsec_status(),
                self._api.get_ipsec_spd(),
            )
            # Unwrap paginated search results to plain lists
            sad = self._rows(sad_raw) if isinstance(sad_raw, dict) else sad_raw
            spd = self._rows(spd_raw) if isinstance(spd_raw, dict) else spd_raw
            return AdapterResult.ok(
                data={
                    "sad": sad if isinstance(sad, list) else [],
                    "spd": spd if isinstance(spd, list) else [],
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def connect_ipsec_tunnel(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.connect_ipsec_tunnel(uuid, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IPsec tunnel connecting")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense connect_ipsec_tunnel failed")
            return AdapterResult.fail(type(exc).__name__)

    async def disconnect_ipsec_tunnel(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.disconnect_ipsec_tunnel(uuid, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IPsec tunnel disconnecting")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense disconnect_ipsec_tunnel failed")
            return AdapterResult.fail(type(exc).__name__)

    async def apply_ipsec_changes(self) -> AdapterResult:
        try:
            result = await self._api.apply_ipsec_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IPsec reconfigured")
        except Exception as exc:
            logger.exception("OPNsense apply_ipsec_changes failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN Orchestration — push / remove tunnel config
    # ═══════════════════════════════════════════════════════════════════════

    async def push_vpn_config(
        self,
        device_id: str,
        config: dict[str, Any],
    ) -> AdapterResult:
        """
        Push VPN tunnel configuration to OPNsense.

        Dispatches based on ``config.get("vpn_type")``:
        - "wireguard": creates WireGuard server + peer
        - "ipsec": (placeholder — IPsec tunnel CRUD via OPNsense API is complex)
        - "openvpn": creates OpenVPN instance

        ``device_id`` is unused for OPNsense (it's the firewall itself).
        """
        vpn_type = (config.get("vpn_type") or "wireguard").lower()

        try:
            if vpn_type == "wireguard":
                return await self._push_wireguard(config)
            elif vpn_type == "openvpn":
                return await self._push_openvpn(config)
            else:
                # IPsec or unknown — not supported
                logger.info(
                    "VPN type '%s' auto-push not yet supported on OPNsense; "
                    "config saved in DB for manual review",
                    vpn_type,
                )
                return AdapterResult.fail(
                    f"VPN type '{vpn_type}' is not supported for auto-push on OPNsense",
                    error_code="UNSUPPORTED_VPN_TYPE",
                )
        except Exception as exc:
            logger.exception("Failed to push VPN config")
            return AdapterResult.fail(
                type(exc).__name__,
                error_code="VPN_PUSH_FAILED",
            )

    async def _push_wireguard(self, config: dict[str, Any]) -> AdapterResult:
        """Create WireGuard server and/or peer from tunnel config."""
        server_cfg = config.get("server", {})
        peer_cfg = config.get("peer", {})

        results: dict[str, Any] = {}
        errors: list[str] = []
        any_succeeded = False

        if server_cfg:
            try:
                srv_result = await self._api.add_wireguard_server(
                    server_cfg,
                    force=self._direct_write_force,
                )
                results["server"] = srv_result
                any_succeeded = True
            except Exception as exc:
                logger.exception("WireGuard server creation failed")
                errors.append(f"Server creation failed: {type(exc).__name__}")

        if peer_cfg:
            try:
                peer_result = await self._api.add_wireguard_peer(
                    peer_cfg,
                    force=self._direct_write_force,
                )
                results["peer"] = peer_result
                any_succeeded = True
            except Exception as exc:
                logger.exception("WireGuard peer creation failed")
                errors.append(f"Peer creation failed: {type(exc).__name__}")

        # Only apply changes if at least one operation succeeded
        if any_succeeded:
            await self._api.apply_wireguard_changes(force=self._direct_write_force)

        if errors and not any_succeeded:
            return AdapterResult.fail(
                "; ".join(errors),
                error_code="WIREGUARD_PUSH_FAILED",
            )

        return AdapterResult.ok(
            data=results,
            message="WireGuard tunnel configured"
            + (f" (with warnings: {'; '.join(errors)})" if errors else ""),
        )

    async def _push_openvpn(self, config: dict[str, Any]) -> AdapterResult:
        """Create OpenVPN instance from tunnel config."""
        instance_cfg = config.get("instance", {})
        if not instance_cfg:
            return AdapterResult.fail(
                "No OpenVPN instance config provided",
                error_code="MISSING_CONFIG",
            )

        result = await self._api.add_openvpn_instance(
            instance_cfg,
            force=self._direct_write_force,
        )
        await self._api.apply_openvpn_changes(force=self._direct_write_force)

        return AdapterResult.ok(
            data=result,
            message="OpenVPN tunnel configured",
        )

    async def remove_vpn_config(
        self,
        device_id: str,
        tunnel_id: str,
    ) -> AdapterResult:
        """
        Remove VPN tunnel config from OPNsense.

        Searches WireGuard servers/peers and OpenVPN instances for
        entries whose description or name contains the FreeSDN
        ``tunnel_id``.  Deletes all matches and applies changes.

        Parameters
        ----------
        device_id : str
            Device identifier (unused for OPNsense — it IS the device).
        tunnel_id : str
            FreeSDN VPN tunnel UUID to search for and remove.
        """
        removed: list[str] = []
        errors: list[str] = []

        try:
            # ── WireGuard servers ────────────────────────────────────
            try:
                wg_servers = await self._api.get_wireguard_servers()
                for row in self._rows(wg_servers):
                    desc = str(row.get("name", "")) + str(row.get("tunneladdress", ""))
                    if tunnel_id in desc or tunnel_id in str(row.get("uuid", "")):
                        uuid = row.get("uuid", "")
                        if uuid:
                            await self._api.delete_wireguard_server(
                                uuid,
                                force=self._direct_write_force,
                            )
                            removed.append(f"wg_server:{uuid}")
            except Exception as exc:
                logger.exception("WireGuard server search failed")
                errors.append(f"WireGuard server search: {type(exc).__name__}")

            # ── WireGuard peers ──────────────────────────────────────
            try:
                wg_peers = await self._api.get_wireguard_peers()
                for row in self._rows(wg_peers):
                    desc = str(row.get("name", "")) + str(row.get("tunneladdress", ""))
                    if tunnel_id in desc or tunnel_id in str(row.get("uuid", "")):
                        uuid = row.get("uuid", "")
                        if uuid:
                            await self._api.delete_wireguard_peer(
                                uuid,
                                force=self._direct_write_force,
                            )
                            removed.append(f"wg_peer:{uuid}")
            except Exception as exc:
                logger.exception("WireGuard peer search failed")
                errors.append(f"WireGuard peer search: {type(exc).__name__}")

            # Apply WireGuard changes if anything was removed
            if any(r.startswith("wg_") for r in removed):
                await self._api.apply_wireguard_changes(force=self._direct_write_force)

            # ── OpenVPN instances ────────────────────────────────────
            try:
                ovpn_instances = await self._api.get_openvpn_instances()
                for row in self._rows(ovpn_instances):
                    desc = str(row.get("description", "")) + str(row.get("role", ""))
                    if tunnel_id in desc or tunnel_id in str(row.get("uuid", "")):
                        uuid = row.get("uuid", "")
                        if uuid:
                            await self._api.delete_openvpn_instance(
                                uuid,
                                force=self._direct_write_force,
                            )
                            removed.append(f"ovpn:{uuid}")
            except Exception as exc:
                logger.exception("OpenVPN instance search failed")
                errors.append(f"OpenVPN instance search: {type(exc).__name__}")

            # Apply OpenVPN changes if anything was removed
            if any(r.startswith("ovpn:") for r in removed):
                await self._api.apply_openvpn_changes(force=self._direct_write_force)

            if removed:
                return AdapterResult.ok(
                    data={"removed": removed, "tunnel_id": tunnel_id},
                    message=f"Removed {len(removed)} VPN resource(s)",
                )

            if errors:
                return AdapterResult.fail(
                    f"Errors searching VPN resources: {'; '.join(errors)}",
                    error_code="VPN_REMOVE_SEARCH_FAILED",
                )

            # Nothing found — might already be removed
            logger.info(
                "No VPN resources found for tunnel %s on device %s",
                tunnel_id,
                device_id,
            )
            return AdapterResult.ok(
                data={"removed": [], "tunnel_id": tunnel_id},
                message="No matching VPN resources found — may already be removed",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.exception("Failed to remove VPN config")
            return AdapterResult.fail(
                type(exc).__name__,
                error_code="VPN_REMOVE_FAILED",
            )

    # ═══════════════════════════════════════════════════════════════════════
    # Routing — Static Routes (CRUD) + Kernel Table
    # ═══════════════════════════════════════════════════════════════════════

    async def get_static_routes(self) -> AdapterResult:
        """Return list of NormalizedStaticRoute."""
        try:
            raw = await self._api.get_static_routes()
            routes = []
            for row in self._rows(raw):
                routes.append(
                    NormalizedStaticRoute(
                        uuid=row.get("uuid", ""),
                        network=row.get("network", ""),
                        gateway=row.get("gateway", ""),
                        description=row.get("descr", row.get("description", "")),
                        enabled=str(row.get("disabled", "0")) != "1",
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"routes": routes, "count": len(routes)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_static_route(self, uuid: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_static_route(uuid))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_static_route(self, route: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_static_route(route, force=self._direct_write_force)
            await self._api.apply_route_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static route created")
        except Exception as exc:
            logger.exception("OPNsense create_static_route failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_static_route(self, uuid: str, route: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_static_route(
                uuid, route, force=self._direct_write_force
            )
            await self._api.apply_route_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static route updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_static_route failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_static_route(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_static_route(uuid, force=self._direct_write_force)
            await self._api.apply_route_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Static route deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_static_route failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_routing_table(self) -> AdapterResult:
        """Kernel routing table (NormalizedRoutingTable)."""
        try:
            raw = await self._api.get_routing_table()
            entries = []
            rows = (
                raw
                if isinstance(raw, list)
                else raw.get("routes", [])
                if isinstance(raw, dict)
                else []
            )
            for row in rows:
                if not isinstance(row, dict):
                    continue
                entries.append(
                    NormalizedRoutingTable(
                        destination=row.get("destination", ""),
                        gateway=row.get("gateway", ""),
                        flags=row.get("flags", ""),
                        interface=row.get("netif", row.get("interface", "")),
                        mtu=int(row["mtu"]) if row.get("mtu") else None,
                        protocol=row.get("proto", ""),
                        type=row.get("type", ""),
                    ).model_dump()
                )
            return AdapterResult.ok(data={"routing_table": entries, "count": len(entries)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Gateway
    # ═══════════════════════════════════════════════════════════════════════

    async def get_gateway_status(self) -> AdapterResult:
        """Return list of NormalizedGateway."""
        try:
            raw = await self._api.get_gateway_status()
            gateways = []
            items = (
                raw.get("items", raw)
                if isinstance(raw, dict)
                else raw
                if isinstance(raw, list)
                else []
            )
            if isinstance(items, dict):
                items = list(items.values())
            for gw in items:
                if not isinstance(gw, dict):
                    continue
                status_str = str(gw.get("status_translated", gw.get("status", "unknown"))).lower()

                # OPNsense uses '~' for unavailable numeric fields (e.g. DHCPv6 gateways)
                def _safe_float(val: str, strip_suffix: str = "") -> float:
                    try:
                        s = str(val or "0")
                        if strip_suffix:
                            s = s.rstrip(strip_suffix).strip()
                        return float(s) if s and s != "~" else 0.0
                    except (ValueError, TypeError):
                        return 0.0

                gateways.append(
                    NormalizedGateway(
                        name=gw.get("name", ""),
                        address=gw.get("address", gw.get("gateway", "")),
                        status=GatewayStatus(status_str)
                        if status_str in GatewayStatus.__members__.values()
                        else GatewayStatus.UNKNOWN,
                        status_text=gw.get("status_translated", ""),
                        loss_pct=_safe_float(gw.get("loss", "0"), "%"),
                        delay_ms=_safe_float(gw.get("delay", "0"), "ms"),
                        stddev_ms=_safe_float(gw.get("stddev", "0"), "ms"),
                        interface=gw.get("if", ""),
                        monitor_ip=gw.get("monitor", "") if gw.get("monitor") != "~" else "",
                        default_gateway=str(gw.get("default_gw", "false")).lower() in ("true", "1"),
                        raw=gw,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"gateways": gateways, "count": len(gateways)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> AdapterResult:
        """Return list of NormalizedService."""
        try:
            raw = await self._api.get_services()
            services = []
            # OPNsense /api/core/service/search returns paginated {rows:[...]}
            items = (
                raw if isinstance(raw, list) else self._rows(raw) if isinstance(raw, dict) else []
            )
            for svc in items:
                if not isinstance(svc, dict):
                    continue
                running = str(svc.get("running", "0")) == "1" or svc.get("status") == "running"
                services.append(
                    NormalizedService(
                        name=svc.get("name", ""),
                        description=svc.get("description", ""),
                        status=ServiceStatus.RUNNING if running else ServiceStatus.STOPPED,
                        running=running,
                        pid=int(svc["pid"]) if svc.get("pid") else None,
                        raw=svc,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"services": services, "count": len(services)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def start_service(self, name: str) -> AdapterResult:
        try:
            from app.adapters.validation import validate_id

            validate_id(name, label="service_name")
            result = await self._api.start_service(name, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message=f"Service {name} started")
        except Exception as exc:
            logger.exception("OPNsense start_service failed")
            return AdapterResult.fail(type(exc).__name__)

    async def stop_service(self, name: str) -> AdapterResult:
        try:
            from app.adapters.validation import validate_id

            validate_id(name, label="service_name")
            result = await self._api.stop_service(name, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message=f"Service {name} stopped")
        except Exception as exc:
            logger.exception("OPNsense stop_service failed")
            return AdapterResult.fail(type(exc).__name__)

    async def restart_service(self, name: str) -> AdapterResult:
        try:
            from app.adapters.validation import validate_id

            validate_id(name, label="service_name")
            result = await self._api.restart_service(name, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message=f"Service {name} restarted")
        except Exception as exc:
            logger.exception("OPNsense restart_service failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # IDS / IPS — Suricata
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _parse_opnsense_multi_select(raw_val: Any) -> list[str]:
        """Parse OPNsense multi-select field.

        These come as either:
          - a comma-separated string: "wan,lan,opt1"
          - a dict of {key: {value: label, selected: 0|1}}
        Returns human-readable labels for selected items (or all if none selected).
        """
        if isinstance(raw_val, dict):
            selected = [
                v.get("value", k)
                for k, v in raw_val.items()
                if isinstance(v, dict) and str(v.get("selected", "0")) == "1"
            ]
            if selected:
                return selected
            # Nothing explicitly selected — return all labels
            return [v.get("value", k) for k, v in raw_val.items() if isinstance(v, dict)]
        if isinstance(raw_val, str) and raw_val:
            return [i.strip() for i in raw_val.split(",") if i.strip()]
        return []

    async def get_ids_settings(self) -> AdapterResult:
        """Return NormalizedIDSSettings."""
        try:
            raw = await self._api.get_ids_settings()
            ids_data = raw.get("ids", raw) if isinstance(raw, dict) else {}
            general = ids_data.get("general", ids_data)
            settings = NormalizedIDSSettings(
                enabled=str(general.get("enabled", "0")) == "1",
                ips_mode=str(general.get("ips", "0")) == "1",
                interfaces=self._parse_opnsense_multi_select(general.get("interfaces", "")),
                pattern_matcher=general.get("pattern_matcher", ""),
                promiscuous_mode=str(general.get("promiscmode", "0")) == "1",
                home_networks=self._parse_opnsense_multi_select(general.get("homenet", "")),
            )
            return AdapterResult.ok(data=settings.model_dump())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_ids_settings(self, settings: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.update_ids_settings(settings, force=self._direct_write_force)
            await self._api.apply_ids_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS settings updated")
        except Exception as exc:
            logger.exception("OPNsense update_ids_settings failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ids_alerts(self, limit: int = 500) -> AdapterResult:
        """Return list of NormalizedIDSAlert.

        ``limit`` clamped at 5000 — high-volume IDS deployments
        (ransomware burst, port scan storm) can produce 100k+ alerts
        and the uncapped path would pull all of them in one request.

        """
        bounded = max(1, min(int(limit), 5000))
        try:
            raw = await self._api.get_ids_alerts(bounded)
            alerts = []
            for row in self._rows(raw):
                sev_str = str(row.get("alert_severity", "medium")).lower()
                alerts.append(
                    NormalizedIDSAlert(
                        timestamp=row.get("timestamp", ""),
                        severity=IDSAlertSeverity(sev_str)
                        if sev_str in IDSAlertSeverity.__members__.values()
                        else IDSAlertSeverity.MEDIUM,
                        alert_sid=row.get("alert_sid", ""),
                        alert_msg=row.get("alert", row.get("alert_msg", "")),
                        alert_category=row.get("alert_category", ""),
                        source_ip=row.get("src_ip", ""),
                        source_port=int(row["src_port"]) if row.get("src_port") else None,
                        destination_ip=row.get("dest_ip", ""),
                        destination_port=int(row["dest_port"]) if row.get("dest_port") else None,
                        protocol=row.get("proto", ""),
                        interface=row.get("in_iface", ""),
                        action=row.get("action", ""),
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ids_rulesets(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_ids_rulesets())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ids_rules(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_ids_rules())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def toggle_ids_rule(self, sid: str, enabled: bool) -> AdapterResult:
        try:
            from app.adapters.validation import validate_id

            validate_id(sid, label="ids_sid")
            result = await self._api.toggle_ids_rule(sid, enabled, force=self._direct_write_force)
            return AdapterResult.ok(data=result)
        except Exception as exc:
            logger.exception("OPNsense toggle_ids_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def drop_ids_alert_log(self) -> AdapterResult:
        try:
            result = await self._api.drop_ids_alert_log(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS alert log cleared")
        except Exception as exc:
            logger.exception("OPNsense drop_ids_alert_log failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_ids_status(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_ids_status())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def start_ids(self) -> AdapterResult:
        try:
            result = await self._api.start_ids(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS started")
        except Exception as exc:
            logger.exception("OPNsense start_ids failed")
            return AdapterResult.fail(type(exc).__name__)

    async def stop_ids(self) -> AdapterResult:
        try:
            result = await self._api.stop_ids(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS stopped")
        except Exception as exc:
            logger.exception("OPNsense stop_ids failed")
            return AdapterResult.fail(type(exc).__name__)

    async def restart_ids(self) -> AdapterResult:
        try:
            result = await self._api.restart_ids(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS restarted")
        except Exception as exc:
            logger.exception("OPNsense restart_ids failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_ids_rules(self) -> AdapterResult:
        try:
            result = await self._api.update_ids_rules_download(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="IDS rules update started")
        except Exception as exc:
            logger.exception("OPNsense update_ids_rules failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Traffic Shaper (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_shaper_pipes(self) -> AdapterResult:
        """Return list of NormalizedTrafficPipe."""
        try:
            raw = await self._api.get_shaper_pipes()
            pipes = []
            for row in self._rows(raw):
                pipes.append(
                    NormalizedTrafficPipe(
                        uuid=row.get("uuid", ""),
                        description=row.get("description", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        bandwidth=int(row["bandwidth"]) if row.get("bandwidth") else None,
                        bandwidth_metric=row.get("bandwidth_Metric", "Kbit"),
                        queue_size=int(row["queue"]) if row.get("queue") else None,
                        mask=row.get("mask", ""),
                        delay_ms=int(row["delay"]) if row.get("delay") else None,
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"pipes": pipes, "count": len(pipes)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_shaper_pipe(self, pipe: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_shaper_pipe(pipe, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper pipe created")
        except Exception as exc:
            logger.exception("OPNsense create_shaper_pipe failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_shaper_pipe(self, uuid: str, pipe: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_shaper_pipe(uuid, pipe, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper pipe updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_shaper_pipe failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_shaper_pipe(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_shaper_pipe(uuid, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper pipe deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_shaper_pipe failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_shaper_queues(self) -> AdapterResult:
        """List traffic shaper queues."""
        try:
            raw = await self._api.get_shaper_queues()
            queues = []
            for row in self._rows(raw):
                queues.append(
                    NormalizedTrafficQueue(
                        uuid=row.get("uuid", ""),
                        description=row.get("description", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        pipe=row.get("pipe", ""),
                        weight=int(row["weight"]) if row.get("weight") else None,
                        mask=row.get("mask", ""),
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"queues": queues, "count": len(queues)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_shaper_queue(self, queue: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_shaper_queue(queue, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper queue created")
        except Exception as exc:
            logger.exception("OPNsense create_shaper_queue failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_shaper_queue(self, uuid: str, queue: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_shaper_queue(
                uuid, queue, force=self._direct_write_force
            )
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper queue updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_shaper_queue failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_shaper_queue(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_shaper_queue(uuid, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper queue deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_shaper_queue failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_shaper_rules(self) -> AdapterResult:
        """List traffic shaper rules."""
        try:
            raw = await self._api.get_shaper_rules()
            rules = []
            for row in self._rows(raw):
                rules.append(
                    NormalizedTrafficRule(
                        uuid=row.get("uuid", ""),
                        description=row.get("description", ""),
                        enabled=str(row.get("enabled", "1")) == "1",
                        interface=row.get("interface", ""),
                        protocol=row.get("protocol", ""),
                        source=row.get("source", ""),
                        source_port=row.get("src_port", ""),
                        destination=row.get("destination", ""),
                        destination_port=row.get("dst_port", ""),
                        target_pipe=row.get("target", ""),
                        sequence=int(row["sequence"]) if row.get("sequence") else None,
                        raw=row,
                    ).model_dump()
                )
            return AdapterResult.ok(data={"rules": rules, "count": len(rules)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_shaper_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_shaper_rule(rule, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper rule created")
        except Exception as exc:
            logger.exception("OPNsense create_shaper_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_shaper_rule(self, uuid: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.update_shaper_rule(uuid, rule, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper rule updated")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_shaper_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_shaper_rule(self, uuid: str) -> AdapterResult:
        try:
            self._validate_uuid(uuid)
            result = await self._api.delete_shaper_rule(uuid, force=self._direct_write_force)
            await self._api.apply_shaper_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Shaper rule deleted")
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_shaper_rule failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    async def run_ping(self, host: str, count: int = 3) -> AdapterResult:
        """
        Run a ping diagnostic against a target host.

        OPNsense executes the ping server-side and returns results.
        If the initial response contains a job UUID, polls until
        completion (max 30 s).
        """
        try:
            self._validate_host(host)
            count = max(1, min(count, 10))  # clamp 1-10
            data = await self._api.ping(host, count)

            # If OPNsense returned a job UUID, poll for completion
            if isinstance(data, dict) and data.get("uuid") and not data.get("output"):
                job_uuid = data["uuid"]
                data = await self._poll_diagnostic_job(
                    f"/api/diagnostics/interface/getPingStatus/{job_uuid}",
                )

            # Normalise into structured result
            return AdapterResult.ok(
                data=self._parse_ping_output(data, host),
            )
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except TimeoutError:
            return AdapterResult.fail(
                f"Ping to {host} timed out",
                error_code="DIAGNOSTIC_TIMEOUT",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(f"Ping operation failed: {exc}")

    async def run_traceroute(self, host: str) -> AdapterResult:
        """
        Run a traceroute diagnostic against a target host.

        OPNsense executes the traceroute server-side. If the initial
        response contains a job UUID, polls until completion (max 60 s).
        """
        try:
            self._validate_host(host)
            data = await self._api.traceroute(host)

            # If OPNsense returned a job UUID, poll for completion
            if isinstance(data, dict) and data.get("uuid") and not data.get("output"):
                job_uuid = data["uuid"]
                data = await self._poll_diagnostic_job(
                    f"/api/diagnostics/interface/getRouteStatus/{job_uuid}",
                    max_wait=60.0,
                )

            return AdapterResult.ok(data=data)
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except TimeoutError:
            return AdapterResult.fail(
                f"Traceroute to {host} timed out",
                error_code="DIAGNOSTIC_TIMEOUT",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(f"Traceroute operation failed: {exc}")

    async def _poll_diagnostic_job(
        self,
        status_url: str,
        *,
        max_wait: float = 30.0,
        poll_interval: float = 1.0,
    ) -> dict[str, Any]:
        """Poll an OPNsense diagnostic job until completion or timeout."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max_wait
        while loop.time() < deadline:
            result = await self._api.get(status_url)
            if isinstance(result, dict):
                status = result.get("status", "")
                if status in ("done", "completed", ""):
                    return result
                if status == "error":
                    return result
            await asyncio.sleep(poll_interval)
        raise TimeoutError(f"Diagnostic job timed out after {max_wait}s")

    @staticmethod
    def _parse_ping_output(
        data: dict[str, Any] | str,
        target: str,
    ) -> dict[str, Any]:
        """Parse raw ping output into a structured dict."""
        if isinstance(data, str):
            data = {"output": data}
        if not isinstance(data, dict):
            return {"target": target, "raw_output": str(data)}

        raw = data.get("output", "") or str(data)
        result: dict[str, Any] = {"target": target, "raw_output": raw}

        # Try to extract statistics from standard ping output
        # "3 packets transmitted, 3 packets received, 0% packet loss"
        import re

        m = re.search(
            r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?(\d+(?:\.\d+)?)% packet loss",
            raw,
        )
        if m:
            result["packets_sent"] = int(m.group(1))
            result["packets_received"] = int(m.group(2))
            result["loss_pct"] = float(m.group(3))

        # "min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms"
        m2 = re.search(
            r"min/avg/max/(?:std-dev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
            raw,
        )
        if m2:
            result["min_ms"] = float(m2.group(1))
            result["avg_ms"] = float(m2.group(2))
            result["max_ms"] = float(m2.group(3))
            result["stddev_ms"] = float(m2.group(4))

        return result

    async def run_dns_lookup(self, hostname: str) -> AdapterResult:
        try:
            self._validate_host(hostname)
            data = await self._api.dns_lookup(hostname)
            return AdapterResult.ok(data=data)
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception:
            return AdapterResult.fail("DNS lookup operation failed")

    async def get_connections(self) -> AdapterResult:
        """Active PF state table."""
        try:
            return AdapterResult.ok(data=await self._api.get_connections())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_pf_info(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_pf_info())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_pf_statistics(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_pf_statistics())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_temperature(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_temperature())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_disk_usage(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_disk_usage())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self, limit: int = 100) -> AdapterResult:
        # Clamp at 5000 to prevent uncapped log requests from blocking
        # the worker on a multi-minute controller query + 200MB parse.
        # Some OPNsense versions treat very large ``limit`` as
        # "no limit" — the cap here is enforced regardless of what the
        # caller passes.
        bounded = max(1, min(int(limit), 5000))
        try:
            return AdapterResult.ok(data=await self._api.get_system_log(bounded))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_firewall_log(self, limit: int = 100) -> AdapterResult:
        bounded = max(1, min(int(limit), 5000))
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_log(bounded))
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_traffic_stats(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_traffic_stats())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Cron (scheduled jobs)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cron_jobs(self) -> AdapterResult:
        """Return cron jobs from OPNsense."""
        try:
            raw = await self._api.get_cron_jobs()
            # OPNsense /api/cron/settings/searchJobs returns {rows: [...], rowCount: N}
            rows = (
                self._rows(raw) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
            )
            cron_jobs = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                # Build human-readable schedule or use %command as description
                cron_jobs.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "description": r.get("%command", r.get("description", "")),
                        "command": r.get("command", ""),
                        "origin": r.get("origin", ""),
                        "minutes": r.get("minutes", "*"),
                        "hours": r.get("hours", "*"),
                        "days": r.get("days", "*"),
                        "months": r.get("months", "*"),
                        "weekdays": r.get("weekdays", "*"),
                        "who": r.get("who", "root"),
                        "enabled": r.get("enabled", "0") == "1",
                    }
                )
            return AdapterResult.ok(data={"cron_jobs": cron_jobs, "count": len(cron_jobs)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Tailscale VPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_tailscale_status(self) -> AdapterResult:
        """Return Tailscale settings + service status."""
        try:
            import asyncio

            settings_raw, svc_status = await asyncio.gather(
                self._api.get("/api/tailscale/settings/get"),
                self._api.get("/api/tailscale/service/status"),
                return_exceptions=True,
            )
            settings = {}
            if isinstance(settings_raw, dict):
                s = settings_raw.get("settings", settings_raw)
                settings = {
                    "enabled": s.get("enabled", "0") == "1",
                    "listen_port": s.get("listenPort", ""),
                    "accept_dns": s.get("acceptDNS", "0") == "1",
                    "advertise_exit_node": s.get("advertiseExitNode", "0") == "1",
                    "accept_subnet_routes": s.get("acceptSubnetRoutes", "0") == "1",
                    "enable_ssh": s.get("enableSSH", "0") == "1",
                    "disable_snat": s.get("disableSNAT", "0") == "1",
                    "login_timeout": s.get("loginTimeout", ""),
                    "use_exit_node": self._parse_opnsense_multi_select(s.get("useExitNode")),
                }
            running = False
            if isinstance(svc_status, dict):
                running = svc_status.get("status") == "running"
            return AdapterResult.ok(
                data={
                    "tailscale": {"settings": settings, "running": running},
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN / LAGG / Virtual IP Devices
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlan_devices(self) -> AdapterResult:
        """Return VLAN device configurations from OPNsense."""
        try:
            raw = await self._api.post(
                "/api/interfaces/vlan_settings/searchItem",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            vlans = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                vlans.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "device": r.get("vlanif", ""),
                        "parent": r.get("if", ""),
                        "parent_label": r.get("%if", ""),
                        "tag": int(r["tag"]) if r.get("tag") else 0,
                        "priority": r.get("%pcp", r.get("pcp", "")),
                        "proto": r.get("proto", "802.1q"),
                        "description": r.get("descr", ""),
                    }
                )
            return AdapterResult.ok(data={"vlans": vlans, "count": len(vlans)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_lagg_devices(self) -> AdapterResult:
        """Return LAGG (link aggregation) configurations from OPNsense."""
        try:
            raw = await self._api.post(
                "/api/interfaces/lagg_settings/searchItem",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            laggs = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                laggs.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "device": r.get("laggif", ""),
                        "members": r.get("members", ""),
                        "members_label": r.get("%members", ""),
                        "protocol": r.get("proto", ""),
                        "primary_member": r.get("primary_member", ""),
                        "lacp_fast_timeout": r.get("lacp_fast_timeout", "0") == "1",
                        "description": r.get("descr", ""),
                    }
                )
            return AdapterResult.ok(data={"laggs": laggs, "count": len(laggs)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_virtual_ips(self) -> AdapterResult:
        """Return Virtual IP (CARP / IP Alias) configurations from OPNsense."""
        try:
            raw = await self._api.post(
                "/api/interfaces/vip_settings/searchItem",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            vips = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                vips.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "address": r.get("subnet", ""),
                        "subnet_bits": r.get("subnet_bits", ""),
                        "interface": r.get("%interface", r.get("interface", "")),
                        "mode": r.get("%mode", r.get("mode", "")),
                        "description": r.get("descr", r.get("description", "")),
                        "vhid": r.get("vhid", ""),
                        "gateway": r.get("gateway", ""),
                    }
                )
            return AdapterResult.ok(data={"virtual_ips": vips, "count": len(vips)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Dashboard / Aggregate
    # ═══════════════════════════════════════════════════════════════════════

    async def get_device_summary(self) -> AdapterResult:
        """
        NormalizedDeviceSummary — high-level overview suitable for the
        dashboard, cross-adapter inventory, and health-check polling.
        """
        try:
            import asyncio

            status, fw, gw_raw, ifaces_raw = await asyncio.gather(
                self._api.get_system_status(),
                self._api.get_firmware_status(),
                self._api.get_gateway_status(),
                self._api.get_interfaces(),
                return_exceptions=True,
            )

            # interfaces summary
            if isinstance(ifaces_raw, Exception) or not isinstance(ifaces_raw, dict):
                iface_count, ifaces_up = 0, 0
            else:
                iface_count = len(ifaces_raw)
                ifaces_up = sum(
                    1
                    for v in ifaces_raw.values()
                    if isinstance(v, dict) and str(v.get("status", "")).lower() == "up"
                )

            # gateway summary (first default)
            wan_status = GatewayStatus.UNKNOWN
            wan_ip = ""
            wan_loss = 0.0
            wan_delay = 0.0
            gw_items = (
                gw_raw.get("items", gw_raw)
                if isinstance(gw_raw, dict)
                else gw_raw
                if isinstance(gw_raw, list)
                else []
            )
            if isinstance(gw_items, dict):
                gw_items = list(gw_items.values())
            for gw in gw_items:
                if isinstance(gw, dict):
                    wan_ip = gw.get("address", gw.get("gateway", ""))
                    s = str(gw.get("status_translated", gw.get("status", "unknown"))).lower()
                    wan_status = (
                        GatewayStatus(s)
                        if s in GatewayStatus.__members__.values()
                        else GatewayStatus.UNKNOWN
                    )
                    try:
                        wan_loss = float(str(gw.get("loss", "0")).rstrip("%") or 0)
                    except ValueError:
                        wan_loss = 0.0
                    try:
                        wan_delay = float(str(gw.get("delay", "0")).rstrip("ms").strip() or 0)
                    except ValueError:
                        wan_delay = 0.0
                    break

            summary = NormalizedDeviceSummary(
                hostname=status.get("name", ""),
                version=fw.get("product_version", ""),
                uptime_text=status.get("uptime", ""),
                interface_count=iface_count,
                interfaces_up=ifaces_up,
                interfaces_down=iface_count - ifaces_up,
                wan_status=wan_status,
                wan_ip=wan_ip,
                wan_loss_pct=wan_loss,
                wan_delay_ms=wan_delay,
                firmware_update_available=fw.get("status_upgrade_action", "") != "",
            )
            return AdapterResult.ok(data=summary.model_dump())
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # HAProxy — Load Balancer
    # ═══════════════════════════════════════════════════════════════════════

    async def get_haproxy_servers(self) -> AdapterResult:
        """Return HAProxy real servers (backends pool members)."""
        try:
            raw = await self._api.post(
                "/api/haproxy/settings/searchServers",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            servers = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                servers.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "name": r.get("name", ""),
                        "address": r.get("address", ""),
                        "port": r.get("port", ""),
                        "mode": r.get("mode", ""),
                        "ssl": r.get("ssl", "0") == "1",
                        "ssl_verify": r.get("sslVerify", "0") == "1",
                        "weight": r.get("weight", ""),
                        "check_interval": r.get("checkInterval", ""),
                        "check_down_interval": r.get("checkDownInterval", ""),
                        "source": r.get("source", ""),
                        "linked_resolver": r.get("linkedResolver", ""),
                        "description": r.get("Description", r.get("description", "")),
                    }
                )
            return AdapterResult.ok(data={"servers": servers, "count": len(servers)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_haproxy_backends(self) -> AdapterResult:
        """Return HAProxy backend pools."""
        try:
            raw = await self._api.post(
                "/api/haproxy/settings/searchBackends",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            backends = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                backends.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "name": r.get("name", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "mode": r.get("mode", ""),
                        "algorithm": r.get("algorithm", ""),
                        "proxy_protocol": r.get("proxyProtocol", ""),
                        "linked_servers": r.get("linkedServers", ""),
                        "linked_resolver": r.get("linkedResolver", ""),
                        "health_check_enabled": r.get("healthCheckEnabled", "0") == "1",
                        "health_check": r.get("healthCheck", ""),
                        "health_check_fall": r.get("healthCheckFall", ""),
                        "health_check_rise": r.get("healthCheckRise", ""),
                        "persistence": r.get("persistence", ""),
                        "persistence_cookiename": r.get("persistence_cookiename", ""),
                        "stickiness_pattern": r.get("stickiness_pattern", ""),
                        "basic_auth_enabled": r.get("basicAuthEnabled", "0") == "1",
                        "tuning_timeout_connect": r.get("tuning_timeoutConnect", ""),
                        "tuning_timeout_server": r.get("tuning_timeoutServer", ""),
                        "description": r.get("Description", r.get("description", "")),
                    }
                )
            return AdapterResult.ok(data={"backends": backends, "count": len(backends)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_haproxy_frontends(self) -> AdapterResult:
        """Return HAProxy frontend listeners."""
        try:
            raw = await self._api.post(
                "/api/haproxy/settings/searchFrontends",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            frontends = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                frontends.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "name": r.get("name", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "bind": r.get("bind", ""),
                        "bind_options": r.get("bindOptions", ""),
                        "mode": r.get("mode", ""),
                        "default_backend": r.get("defaultBackend", ""),
                        "ssl_enabled": r.get("ssl_enabled", "0") == "1",
                        "ssl_certificates": r.get("ssl_certificates", ""),
                        "ssl_default_certificate": r.get("ssl_default_certificate", ""),
                        "ssl_bind_options": r.get("ssl_bindOptions", ""),
                        "linked_cpu_affinity_rules": r.get("linkedCpuAffinityRules", ""),
                        "linked_actions": r.get("linkedActions", ""),
                        "linked_errorfiles": r.get("linkedErrorfiles", ""),
                        "forwarded_for": r.get("forwardFor", "0") == "1",
                        "connection_behaviour": r.get("connectionBehaviour", ""),
                        "tuning_max_connections": r.get("tuning_maxConnections", ""),
                        "tuning_timeout_client": r.get("tuning_timeoutClient", ""),
                        "description": r.get("Description", r.get("description", "")),
                    }
                )
            return AdapterResult.ok(data={"frontends": frontends, "count": len(frontends)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_haproxy_acls(self) -> AdapterResult:
        """Return HAProxy ACL conditions."""
        try:
            raw = await self._api.post(
                "/api/haproxy/settings/searchAcls",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            acls = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                acls.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "name": r.get("name", ""),
                        "expression": r.get("expression", ""),
                        "negate": r.get("negate", "0") == "1",
                        "hdr_name": r.get("hdr_name", ""),
                        "hdr_beg": r.get("hdr_beg", ""),
                        "hdr_end": r.get("hdr_end", ""),
                        "hdr_sub": r.get("hdr_sub", ""),
                        "hdr_reg": r.get("hdr_reg", ""),
                        "hdr_dir": r.get("hdr_dir", ""),
                        "value": r.get("value", ""),
                        "query_backend": r.get("queryBackend", ""),
                        "allowed_users": r.get("allowedUsers", ""),
                        "allowed_groups": r.get("allowedGroups", ""),
                        "description": r.get("Description", r.get("description", "")),
                    }
                )
            return AdapterResult.ok(data={"acls": acls, "count": len(acls)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_haproxy_actions(self) -> AdapterResult:
        """Return HAProxy rule actions (use_backend, redirect, etc.)."""
        try:
            raw = await self._api.post(
                "/api/haproxy/settings/searchActions",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            actions = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                actions.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "name": r.get("name", ""),
                        "test_type": r.get("testType", ""),
                        "linked_acls": r.get("linkedAcls", ""),
                        "operator": r.get("operator", ""),
                        "type": r.get("type", ""),
                        "use_backend": r.get("useBackend", ""),
                        "use_server": r.get("useServer", ""),
                        "map_use_backend_file": r.get("map_use_backend_file", ""),
                        "http_request_auth": r.get("http_request_auth", ""),
                        "http_request_redirect": r.get("http_request_redirect", ""),
                        "http_request_lua": r.get("http_request_lua", ""),
                        "http_response_lua": r.get("http_response_lua", ""),
                        "description": r.get("Description", r.get("description", "")),
                    }
                )
            return AdapterResult.ok(data={"actions": actions, "count": len(actions)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_haproxy_status(self) -> AdapterResult:
        """Return aggregated HAProxy configuration overview."""
        try:
            import asyncio

            servers_r, backends_r, frontends_r, acls_r, actions_r = await asyncio.gather(
                self.get_haproxy_servers(),
                self.get_haproxy_backends(),
                self.get_haproxy_frontends(),
                self.get_haproxy_acls(),
                self.get_haproxy_actions(),
                return_exceptions=True,
            )

            def _extract(r, key):
                if isinstance(r, AdapterResult) and r.success and isinstance(r.data, dict):
                    return r.data.get(key, [])
                return []

            return AdapterResult.ok(
                data={
                    "haproxy": {
                        "servers": _extract(servers_r, "servers"),
                        "backends": _extract(backends_r, "backends"),
                        "frontends": _extract(frontends_r, "frontends"),
                        "acls": _extract(acls_r, "acls"),
                        "actions": _extract(actions_r, "actions"),
                        "server_count": len(_extract(servers_r, "servers")),
                        "backend_count": len(_extract(backends_r, "backends")),
                        "frontend_count": len(_extract(frontends_r, "frontends")),
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Certificate Management (Trust store)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_certificates(self) -> AdapterResult:
        """Return TLS/SSL certificates from the OPNsense trust store."""
        try:
            raw = await self._api.post(
                "/api/trust/cert/search",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            certs = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                certs.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "descr": r.get("descr", ""),
                        "caref": r.get("caref", ""),
                        "refid": r.get("refid", ""),
                        "serial": r.get("serial", ""),
                        "dn_commonname": r.get("dn_commonname", ""),
                        "dn_country": r.get("dn_country", ""),
                        "dn_state": r.get("dn_state", ""),
                        "dn_city": r.get("dn_city", ""),
                        "dn_organization": r.get("dn_organization", ""),
                        "dn_organizationalunit": r.get("dn_organizationalunit", ""),
                        "valid_from": r.get("valid_from", ""),
                        "valid_to": r.get("valid_to", ""),
                        "in_use": r.get("in_use", ""),
                        "rfc3280_purpose": r.get("rfc3280_purpose", ""),
                        "key_type": r.get("key_type", ""),
                        "key_size": r.get("key_size", ""),
                    }
                )
            return AdapterResult.ok(data={"certificates": certs, "count": len(certs)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_certificate_authorities(self) -> AdapterResult:
        """Return Certificate Authorities from the OPNsense trust store."""
        try:
            raw = await self._api.post(
                "/api/trust/ca/search",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            cas = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                cas.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "descr": r.get("descr", ""),
                        "refid": r.get("refid", ""),
                        "serial": r.get("serial", ""),
                        "dn_commonname": r.get("dn_commonname", ""),
                        "dn_country": r.get("dn_country", ""),
                        "dn_state": r.get("dn_state", ""),
                        "dn_city": r.get("dn_city", ""),
                        "dn_organization": r.get("dn_organization", ""),
                        "valid_from": r.get("valid_from", ""),
                        "valid_to": r.get("valid_to", ""),
                        "in_use": r.get("in_use", ""),
                        "key_type": r.get("key_type", ""),
                        "key_size": r.get("key_size", ""),
                    }
                )
            return AdapterResult.ok(data={"certificate_authorities": cas, "count": len(cas)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_certificate_revocation_lists(self) -> AdapterResult:
        """Return Certificate Revocation Lists from the OPNsense trust store."""
        try:
            raw = await self._api.post(
                "/api/trust/crl/search",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            crls = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                crls.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "descr": r.get("descr", ""),
                        "caref": r.get("caref", ""),
                        "serial": r.get("serial", ""),
                        "lifetime": r.get("lifetime", ""),
                        "certificates": r.get("certificates", ""),
                    }
                )
            return AdapterResult.ok(data={"crls": crls, "count": len(crls)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_trust_overview(self) -> AdapterResult:
        """Return full trust-store overview: CAs + certs + CRLs."""
        try:
            import asyncio

            cas_r, certs_r, crls_r = await asyncio.gather(
                self.get_certificate_authorities(),
                self.get_certificates(),
                self.get_certificate_revocation_lists(),
                return_exceptions=True,
            )

            def _extract(r, key):
                if isinstance(r, AdapterResult) and r.success and isinstance(r.data, dict):
                    return r.data.get(key, [])
                return []

            return AdapterResult.ok(
                data={
                    "trust": {
                        "certificate_authorities": _extract(cas_r, "certificate_authorities"),
                        "certificates": _extract(certs_r, "certificates"),
                        "crls": _extract(crls_r, "crls"),
                        "ca_count": len(_extract(cas_r, "certificate_authorities")),
                        "cert_count": len(_extract(certs_r, "certificates")),
                        "crl_count": len(_extract(crls_r, "crls")),
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # ACME / Let's Encrypt Client
    # ═══════════════════════════════════════════════════════════════════════

    async def get_acme_certificates(self) -> AdapterResult:
        """Return ACME-managed certificates."""
        try:
            raw = await self._api.post(
                "/api/acmeclient/certificates/searchCertificates",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            certs = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                certs.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "name": r.get("name", ""),
                        "description": r.get("description", ""),
                        "status_code": r.get("statusCode", ""),
                        "status_last_update": r.get("statusLastUpdate", ""),
                        "account": r.get("account", ""),
                        "validation_method": r.get("validationMethod", ""),
                        "restart_actions": r.get("restartActions", ""),
                        "renewal_interval": r.get("renewInterval", ""),
                        "cert_private_key": bool(r.get("certPrivateKey")),
                        "cert_refid": r.get("certRefId", ""),
                        "last_update": r.get("lastUpdate", ""),
                    }
                )
            return AdapterResult.ok(data={"acme_certificates": certs, "count": len(certs)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_acme_accounts(self) -> AdapterResult:
        """Return ACME registration accounts (e.g. Let's Encrypt accounts)."""
        try:
            raw = await self._api.post(
                "/api/acmeclient/accounts/searchAccounts",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            accounts = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                accounts.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "name": r.get("name", ""),
                        "description": r.get("description", ""),
                        "email": r.get("email", ""),
                        "ca": r.get("ca", ""),
                        "status_code": r.get("statusCode", ""),
                        "status_last_update": r.get("statusLastUpdate", ""),
                    }
                )
            return AdapterResult.ok(data={"acme_accounts": accounts, "count": len(accounts)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_acme_validations(self) -> AdapterResult:
        """Return ACME domain validation methods."""
        try:
            raw = await self._api.post(
                "/api/acmeclient/validations/searchValidations",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            validations = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                validations.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "name": r.get("name", ""),
                        "description": r.get("description", ""),
                        "method": r.get("method", ""),
                        "dns_service": r.get("dns_service", ""),
                        "dns_sleep": r.get("dns_sleep", ""),
                    }
                )
            return AdapterResult.ok(
                data={"acme_validations": validations, "count": len(validations)}
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_acme_actions(self) -> AdapterResult:
        """Return ACME automation actions (run after cert issuance)."""
        try:
            raw = await self._api.post(
                "/api/acmeclient/actions/searchActions",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            actions = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                actions.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "name": r.get("name", ""),
                        "description": r.get("description", ""),
                        "type": r.get("type", ""),
                        "linked_certificates": r.get("linkedCertificates", ""),
                    }
                )
            return AdapterResult.ok(data={"acme_actions": actions, "count": len(actions)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_acme_settings(self) -> AdapterResult:
        """Return ACME client global settings."""
        try:
            raw = await self._api.get("/api/acmeclient/settings/get")
            settings = {}
            if isinstance(raw, dict):
                s = raw.get("acmeclient", raw)
                settings = {
                    "enabled": s.get("enabled", "0") == "1",
                    "environment": s.get("environment", ""),
                    "log_level": s.get("logLevel", ""),
                    "auto_renewal": s.get("autoRenewal", "0") == "1",
                    "renew_interval": s.get("renewInterval", ""),
                    "challenge_port": s.get("challengePort", ""),
                    "tls_challenge_port": s.get("tlsChallengePort", ""),
                }
            return AdapterResult.ok(data={"acme_settings": settings})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_acme_overview(self) -> AdapterResult:
        """Return full ACME overview: settings + certs + accounts + validations + actions."""
        try:
            import asyncio

            settings_r, certs_r, accounts_r, validations_r, actions_r = await asyncio.gather(
                self.get_acme_settings(),
                self.get_acme_certificates(),
                self.get_acme_accounts(),
                self.get_acme_validations(),
                self.get_acme_actions(),
                return_exceptions=True,
            )

            def _extract(r, key):
                if isinstance(r, AdapterResult) and r.success and isinstance(r.data, dict):
                    return r.data.get(key, [])
                return []

            def _extract_dict(r, key):
                if isinstance(r, AdapterResult) and r.success and isinstance(r.data, dict):
                    return r.data.get(key, {})
                return {}

            return AdapterResult.ok(
                data={
                    "acme": {
                        "settings": _extract_dict(settings_r, "acme_settings"),
                        "certificates": _extract(certs_r, "acme_certificates"),
                        "accounts": _extract(accounts_r, "acme_accounts"),
                        "validations": _extract(validations_r, "acme_validations"),
                        "actions": _extract(actions_r, "acme_actions"),
                        "cert_count": len(_extract(certs_r, "acme_certificates")),
                        "account_count": len(_extract(accounts_r, "acme_accounts")),
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Syslog Forwarding
    # ═══════════════════════════════════════════════════════════════════════

    async def get_syslog_destinations(self) -> AdapterResult:
        """Return configured syslog remote destinations."""
        try:
            raw = await self._api.post(
                "/api/syslog/settings/searchDestinations",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            destinations = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                destinations.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "transport": r.get("transport", ""),
                        "program": r.get("program", ""),
                        "level": r.get("level", ""),
                        "facility": r.get("facility", ""),
                        "hostname": r.get("hostname", ""),
                        "certificate": r.get("certificate", ""),
                        "port": r.get("port", ""),
                        "rfc5424": r.get("rfc5424", "0") == "1",
                        "description": r.get("description", r.get("descr", "")),
                    }
                )
            return AdapterResult.ok(
                data={"syslog_destinations": destinations, "count": len(destinations)}
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_syslog_stats(self) -> AdapterResult:
        """Return syslog statistics."""
        try:
            raw = await self._api.get("/api/syslog/service/stats")
            return AdapterResult.ok(data={"syslog_stats": raw if isinstance(raw, dict) else {}})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Dynamic DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dyndns_accounts(self) -> AdapterResult:
        """Return Dynamic DNS provider accounts."""
        try:
            # OPNsense 24.7+ uses the dyndns module
            raw = await self._api.post(
                "/api/dyndns/accounts/searchAccount",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            accounts = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                accounts.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "service": r.get("service", ""),
                        "protocol": r.get("protocol", ""),
                        "server": r.get("server", ""),
                        "username": r.get("username", ""),
                        "hostname": r.get("hostnames", r.get("hostname", "")),
                        "interface": r.get("interface", ""),
                        "check_ip": r.get("checkip", ""),
                        "force_ssl": r.get("force_ssl", ""),
                        "current_ip": r.get("current_ip", ""),
                        "description": r.get("description", ""),
                    }
                )
            return AdapterResult.ok(data={"dyndns_accounts": accounts, "count": len(accounts)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Captive Portal
    # ═══════════════════════════════════════════════════════════════════════

    async def get_captive_portal_zones(self) -> AdapterResult:
        """Return captive portal zones."""
        try:
            raw = await self._api.post(
                "/api/captiveportal/settings/searchZones",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            zones = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                zones.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": r.get("enabled", "0") == "1",
                        "zoneid": r.get("zoneid", ""),
                        "interfaces": r.get("interfaces", ""),
                        "auth_servers": r.get("authservers", ""),
                        "idle_timeout": r.get("idletimeout", ""),
                        "hard_timeout": r.get("hardtimeout", ""),
                        "concurrent_logins": r.get("concurrentlogins", "0") == "1",
                        "certificate": r.get("certificate", ""),
                        "template": r.get("template", ""),
                        "description": r.get("description", ""),
                    }
                )
            return AdapterResult.ok(data={"captive_portal_zones": zones, "count": len(zones)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_captive_portal_sessions(self) -> AdapterResult:
        """Return active captive portal sessions."""
        try:
            raw = await self._api.post(
                "/api/captiveportal/session/list",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            sessions = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                sessions.append(
                    {
                        "session_id": r.get("sessionId", ""),
                        "username": r.get("userName", ""),
                        "ip_address": r.get("ipAddress", ""),
                        "mac_address": r.get("macAddress", ""),
                        "zone": r.get("zoneid", ""),
                        "start_time": r.get("startTime", ""),
                        "bytes_in": r.get("bytes_in", ""),
                        "bytes_out": r.get("bytes_out", ""),
                        "packets_in": r.get("packets_in", ""),
                        "packets_out": r.get("packets_out", ""),
                    }
                )
            return AdapterResult.ok(
                data={"captive_portal_sessions": sessions, "count": len(sessions)}
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # High Availability / Config Sync
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ha_status(self) -> AdapterResult:
        """Return high-availability / CARP failover status."""
        try:
            # hasync is a core OPNsense module for HA configuration
            raw = await self._api.get("/api/hasync/settings/get")
            settings = {}
            if isinstance(raw, dict):
                s = raw.get("hasync", raw)
                settings = {
                    "enabled": s.get("disablepreempt", "0") != "1",
                    "disable_preempt": s.get("disablepreempt", "0") == "1",
                    "disconnect_dialup": s.get("disconnectppps", "0") == "1",
                    "pfsync_enabled": s.get("pfsyncenabled", "0") == "1",
                    "pfsync_interface": s.get("pfsyncinterface", ""),
                    "pfsync_peer": s.get("pfsyncpeerip", ""),
                    "sync_interface": s.get("synchronizeinterface", ""),
                    "remote_system": s.get("remotesystem", ""),
                    "remote_user": s.get("remoteusername", ""),
                    "sync_config_to_ip": s.get("synchronizetoip", ""),
                    "sync_rules": s.get("synchronizerules", "0") == "1",
                    "sync_schedules": s.get("synchronizeschedules", "0") == "1",
                    "sync_aliases": s.get("synchronizealiases", "0") == "1",
                    "sync_nat": s.get("synchronizenat", "0") == "1",
                    "sync_dhcpd": s.get("synchronizedhcpd", "0") == "1",
                    "sync_openvpn": s.get("synchronizeopenvpn", "0") == "1",
                    "sync_ipsec": s.get("synchronizeipsec", "0") == "1",
                    "sync_static_routes": s.get("synchronizestaticroutes", "0") == "1",
                    "sync_users": s.get("synchronizeusers", "0") == "1",
                    "sync_auth_servers": s.get("synchronizeauthservers", "0") == "1",
                    "sync_vlans": s.get("synchronizevirtualip", "0") == "1",
                }
            return AdapterResult.ok(data={"ha_settings": settings})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Kea DHCP (DHCPv4 + DHCPv6 + Reservations)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_kea_dhcpv4_subnets(self) -> AdapterResult:
        """Return Kea DHCPv4 subnet configurations."""
        try:
            raw = await self._api.post(
                "/api/kea/dhcpv4/searchSubnet",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            subnets = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                subnets.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "subnet": r.get("subnet", ""),
                        "description": r.get("description", ""),
                        "next_server": r.get("next_server", ""),
                        "option_data_autocollect": r.get("option_data_autocollect", ""),
                        "pools": r.get("pools", ""),
                    }
                )
            return AdapterResult.ok(data={"kea_dhcpv4_subnets": subnets, "count": len(subnets)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_kea_dhcpv4_reservations(self) -> AdapterResult:
        """Return Kea DHCPv4 static reservations."""
        try:
            raw = await self._api.post(
                "/api/kea/dhcpv4/searchReservation",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            reservations = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                reservations.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "subnet": r.get("subnet", ""),
                        "ip_address": r.get("ip_address", ""),
                        "hw_address": r.get("hw_address", ""),
                        "hostname": r.get("hostname", ""),
                        "description": r.get("description", ""),
                    }
                )
            return AdapterResult.ok(
                data={"kea_reservations": reservations, "count": len(reservations)}
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_kea_dhcpv4_leases(self) -> AdapterResult:
        """Return Kea DHCPv4 active leases."""
        try:
            raw = await self._api.post(
                "/api/kea/leases4/search",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            leases = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                leases.append(
                    {
                        "address": r.get("address", ""),
                        "hwaddr": r.get("hwaddr", ""),
                        "hostname": r.get("hostname", ""),
                        "state": r.get("state", ""),
                        "subnet_id": r.get("subnet_id", ""),
                        "valid_lifetime": r.get("valid_lifetime", ""),
                        "expire": r.get("expire", ""),
                        "cltt": r.get("cltt", ""),
                    }
                )
            return AdapterResult.ok(data={"kea_leases": leases, "count": len(leases)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_kea_dhcpv6_subnets(self) -> AdapterResult:
        """Return Kea DHCPv6 subnet configurations."""
        try:
            raw = await self._api.post(
                "/api/kea/dhcpv6/searchSubnet6",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            subnets = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                subnets.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "subnet": r.get("subnet", ""),
                        "description": r.get("description", ""),
                        "interface": r.get("interface", ""),
                        "pools": r.get("pools", ""),
                        "pd_pools": r.get("pd_pools", ""),
                    }
                )
            return AdapterResult.ok(data={"kea_dhcpv6_subnets": subnets, "count": len(subnets)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # 1:1 NAT (Binat / OneToOne)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_onetoone_nat_rules(self) -> AdapterResult:
        """Return 1:1 NAT (binat) rules from OPNsense."""
        try:
            raw = await self._api.post(
                "/api/firewall/source_nat/searchRule",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            rules = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rules.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": self._safe(r, "enabled", False),
                        "interface": r.get("interface", ""),
                        "source_net": r.get("source_net", r.get("source", {}).get("net", "")),
                        "destination_net": r.get(
                            "destination_net", r.get("destination", {}).get("net", "")
                        ),
                        "target": r.get("target", ""),
                        "nat_reflection": r.get("natreflection", ""),
                        "description": r.get("description", ""),
                        "log": self._safe(r, "log", False),
                    }
                )
            return AdapterResult.ok(data={"onetoone_nat_rules": rules, "count": len(rules)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Network Bridges
    # ═══════════════════════════════════════════════════════════════════════

    async def get_bridges(self) -> AdapterResult:
        """Return bridge interface configurations."""
        try:
            raw = await self._api.post(
                "/api/interfaces/bridge_settings/searchBridge",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            bridges = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                bridges.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "device": r.get("device", r.get("bridgeif", "")),
                        "members": r.get("members", ""),
                        "description": r.get("descr", r.get("description", "")),
                        "stp": self._safe(r, "enablestp", False),
                        "maxaddr": r.get("maxaddr", ""),
                        "maxage": r.get("maxage", ""),
                        "fwdelay": r.get("fwdelay", ""),
                        "hellotime": r.get("hellotime", ""),
                        "priority": r.get("priority", ""),
                    }
                )
            return AdapterResult.ok(data={"bridges": bridges, "count": len(bridges)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Relay
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_relay_status(self) -> AdapterResult:
        """Return DHCP relay configuration."""
        try:
            raw = await self._api.get("/api/dhcrelay/settings/get")
            if not isinstance(raw, dict):
                return AdapterResult.ok(data={"dhcp_relay": None})
            settings = raw.get("dhcrelay", raw)
            destinations = []
            dest_raw = settings.get("destinations", {})
            if isinstance(dest_raw, dict):
                for k, v in dest_raw.items():
                    if isinstance(v, dict):
                        destinations.append(
                            {
                                "uuid": v.get("uuid", k),
                                "server": v.get("server", ""),
                                "interface": v.get("interface", ""),
                                "description": v.get("description", ""),
                            }
                        )
            return AdapterResult.ok(
                data={
                    "dhcp_relay": {
                        "enabled": self._safe(settings, "enabled", False),
                        "destinations": destinations,
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Web Proxy / Squid (os-squid)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_proxy_settings(self) -> AdapterResult:
        """Return web proxy (Squid) settings and status."""
        try:
            import asyncio

            settings_raw, status_raw = await asyncio.gather(
                self._api.get("/api/proxy/settings/get"),
                self._api.get("/api/proxy/service/status"),
                return_exceptions=True,
            )
            settings = {}
            if isinstance(settings_raw, dict):
                fwd = settings_raw.get("proxy", {}).get("forward", {})
                general = settings_raw.get("proxy", {}).get("general", {})
                settings = {
                    "enabled": self._safe(general, "enabled", False),
                    "port": general.get("port", "3128"),
                    "ssl_inspection": self._safe(fwd, "sslbump", False),
                    "transparent_mode": self._safe(fwd, "transparentMode", False),
                    "cache_enabled": self._safe(general, "cache", {}).get("enabled", False)
                    if isinstance(general.get("cache"), dict)
                    else False,
                    "logging": self._safe(general, "logging", {}).get("enable", False)
                    if isinstance(general.get("logging"), dict)
                    else False,
                }
            status = {}
            if isinstance(status_raw, dict):
                status = {"running": status_raw.get("status", "") == "running"}
            return AdapterResult.ok(data={"proxy": {**settings, **status}})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_proxy_blacklists(self) -> AdapterResult:
        """Return web proxy remote ACL/blacklist entries."""
        try:
            raw = await self._api.post(
                "/api/proxy/settings/searchRemoteBlacklists",
                {"current": 1, "rowCount": -1},
            )
            rows = self._rows(raw) if isinstance(raw, dict) else []
            lists = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                lists.append(
                    {
                        "uuid": r.get("uuid", ""),
                        "enabled": self._safe(r, "enabled", False),
                        "filename": r.get("filename", ""),
                        "url": r.get("url", ""),
                        "description": r.get("description", ""),
                    }
                )
            return AdapterResult.ok(data={"proxy_blacklists": lists, "count": len(lists)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CrowdSec (os-crowdsec)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_crowdsec_status(self) -> AdapterResult:
        """Return CrowdSec status and statistics."""
        try:
            import asyncio

            status_raw, alerts_raw, decisions_raw = await asyncio.gather(
                self._api.get("/api/crowdsec/service/status"),
                self._api.post("/api/crowdsec/alerts/searchAlert", {"current": 1, "rowCount": 50}),
                self._api.post(
                    "/api/crowdsec/decisions/searchDecision", {"current": 1, "rowCount": 50}
                ),
                return_exceptions=True,
            )
            status = {}
            if isinstance(status_raw, dict):
                status = {"running": status_raw.get("status", "") == "running"}
            alerts = self._rows(alerts_raw) if isinstance(alerts_raw, dict) else []
            decisions = self._rows(decisions_raw) if isinstance(decisions_raw, dict) else []
            return AdapterResult.ok(
                data={
                    "crowdsec": {
                        **status,
                        "alert_count": len(alerts),
                        "decision_count": len(decisions),
                        "alerts": [
                            {
                                "id": a.get("id", ""),
                                "value": a.get("value", ""),
                                "scenario": a.get("scenario", ""),
                                "scope": a.get("scope", ""),
                                "created_at": a.get("created_at", ""),
                            }
                            for a in alerts[:50]
                            if isinstance(a, dict)
                        ],
                        "decisions": [
                            {
                                "id": d.get("id", ""),
                                "value": d.get("value", ""),
                                "type": d.get("type", ""),
                                "scope": d.get("scope", ""),
                                "origin": d.get("origin", ""),
                                "duration": d.get("duration", ""),
                            }
                            for d in decisions[:50]
                            if isinstance(d, dict)
                        ],
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Telegraf (os-telegraf)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_telegraf_status(self) -> AdapterResult:
        """Return Telegraf metrics agent config and status."""
        try:
            import asyncio

            settings_raw, status_raw = await asyncio.gather(
                self._api.get("/api/telegraf/settings/get"),
                self._api.get("/api/telegraf/service/status"),
                return_exceptions=True,
            )
            settings = {}
            if isinstance(settings_raw, dict):
                general = settings_raw.get("telegraf", {}).get("general", {})
                settings = {
                    "enabled": self._safe(general, "enabled", False),
                    "output_influxdb": self._safe(general, "output_influxdb", False),
                    "output_graphite": self._safe(general, "output_graphite", False),
                    "output_prometheus": self._safe(general, "output_prometheus", False),
                    "influx_url": general.get("influx_url", ""),
                    "influx_database": general.get("influx_database", ""),
                }
            status = {}
            if isinstance(status_raw, dict):
                status = {"running": status_raw.get("status", "") == "running"}
            return AdapterResult.ok(data={"telegraf": {**settings, **status}})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Monit (os-monit)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_monit_status(self) -> AdapterResult:
        """Return Monit service monitoring configuration and status."""
        try:
            import asyncio

            services_raw, tests_raw, alerts_raw, status_raw = await asyncio.gather(
                self._api.post("/api/monit/settings/searchService", {"current": 1, "rowCount": -1}),
                self._api.post("/api/monit/settings/searchTest", {"current": 1, "rowCount": -1}),
                self._api.post("/api/monit/settings/searchAlert", {"current": 1, "rowCount": -1}),
                self._api.get("/api/monit/service/status"),
                return_exceptions=True,
            )
            services = self._rows(services_raw) if isinstance(services_raw, dict) else []
            tests = self._rows(tests_raw) if isinstance(tests_raw, dict) else []
            alerts = self._rows(alerts_raw) if isinstance(alerts_raw, dict) else []
            status = {}
            if isinstance(status_raw, dict):
                status = {"running": status_raw.get("status", "") == "running"}
            return AdapterResult.ok(
                data={
                    "monit": {
                        **status,
                        "service_count": len(services),
                        "test_count": len(tests),
                        "alert_count": len(alerts),
                        "services": [
                            {
                                "uuid": s.get("uuid", ""),
                                "name": s.get("name", ""),
                                "type": s.get("type", ""),
                                "address": s.get("address", ""),
                                "enabled": self._safe(s, "enabled", False),
                                "description": s.get("description", ""),
                            }
                            for s in services
                            if isinstance(s, dict)
                        ],
                        "tests": [
                            {
                                "uuid": t.get("uuid", ""),
                                "name": t.get("name", ""),
                                "condition": t.get("condition", ""),
                                "action": t.get("action", ""),
                            }
                            for t in tests
                            if isinstance(t, dict)
                        ],
                        "alerts": [
                            {
                                "uuid": a.get("uuid", ""),
                                "recipient": a.get("recipient", ""),
                                "events": a.get("events", ""),
                                "description": a.get("description", ""),
                                "enabled": self._safe(a, "enabled", False),
                            }
                            for a in alerts
                            if isinstance(a, dict)
                        ],
                    },
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # NetFlow / sFlow (built-in netflow module)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_netflow_status(self) -> AdapterResult:
        """Return NetFlow/sFlow collector configuration and status."""
        try:
            import asyncio

            settings_raw, status_raw = await asyncio.gather(
                self._api.get("/api/netflow/settings/get"),
                self._api.get("/api/netflow/service/status"),
                return_exceptions=True,
            )
            settings = {}
            if isinstance(settings_raw, dict):
                nf = settings_raw.get("netflow", {})
                capture = nf.get("capture", {})
                collect = nf.get("collect", {})
                settings = {
                    "enabled": self._safe(capture, "enabled", False),
                    "interfaces": capture.get("interfaces", ""),
                    "egress_only": self._safe(capture, "egress_only", False),
                    "version": capture.get("version", ""),
                    "collect_enabled": self._safe(collect, "enabled", False),
                }
            status = {}
            if isinstance(status_raw, dict):
                status = {"running": status_raw.get("status", "") == "running"}
            return AdapterResult.ok(data={"netflow": {**settings, **status}})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Health-check probe (used by poller / sync engine)
    # ═══════════════════════════════════════════════════════════════════════

    async def health_check(self) -> AdapterResult:
        """Quick reachability + basic health check for the polling loop."""
        try:
            import asyncio

            status, gw = await asyncio.gather(
                self._api.get_system_status(),
                self._api.get_gateway_status(),
            )
            return AdapterResult.ok(
                data={
                    "reachable": True,
                    "hostname": status.get("name", ""),
                    "uptime": status.get("uptime", ""),
                    "gateways": gw,
                }
            )
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN Interface CRUD  (Orchestration)
    # ═══════════════════════════════════════════════════════════════════════

    async def _resolve_parent_interface(self) -> str | None:
        """Auto-detect the parent interface for VLAN creation.

        Looks for the LAN interface device name.  Falls back to the
        first non-WAN physical interface.
        """
        try:
            result = await self.get_interfaces()
            if not result.success:
                return None
            interfaces = result.data if isinstance(result.data, list) else []
            # First pass: find LAN interface
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                if iface.get("is_lan") and iface.get("device"):
                    return iface["device"]
            # Second pass: first non-WAN physical interface
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                if (
                    iface.get("link_type") == "ethernet"
                    and not iface.get("is_wan")
                    and iface.get("device")
                ):
                    return iface["device"]
            return None
        except Exception:
            return None

    async def create_vlan_interface(
        self,
        vlan_id: int,
        name: str = "",
        subnet: str = "",
        gateway_ip: str = "",
        description: str = "",
        *,
        parent_if: str | None = None,
        proto: str = "802.1q",
        pcp: int = 0,
    ) -> AdapterResult:
        """
        Create a VLAN sub-interface on OPNsense.

        Called by the distribution engine (Tier 1) with canonical VLAN
        parameters.  Creates the 802.1Q VLAN device on the parent
        interface and applies the configuration.

        Parameters
        ----------
        vlan_id : int
            802.1Q VLAN tag (1-4094).
        name : str
            Human-readable VLAN name (from CanonicalVLAN).
        subnet : str
            IP subnet in CIDR notation (e.g. ``192.168.10.0/24``).
        gateway_ip : str
            Gateway IP address for this VLAN subnet.
        description : str
            Description tag (typically ``[FreeSdn:managed] ...``).
        parent_if : str, keyword-only
            Parent interface device name (e.g. ``igb0``).  If not
            provided, resolved from gateway settings or auto-detected
            from the LAN interface.
        proto : str, keyword-only
            Encapsulation protocol (``802.1q`` or ``802.1ad``).
        pcp : int, keyword-only
            Priority Code Point (0-7).

        Returns
        -------
        AdapterResult
            ``data`` dict with ``uuid``, ``tag``, ``parent``, ``device``,
            ``name``, ``subnet``, ``gateway_ip``.
        """
        try:
            if not 1 <= vlan_id <= 4094:
                return AdapterResult.fail(
                    f"VLAN tag {vlan_id} out of range 1-4094",
                    error_code="INVALID_VLAN_TAG",
                )

            # Resolve parent interface
            resolved_parent = parent_if or self.config.get("parent_interface")
            if not resolved_parent:
                resolved_parent = await self._resolve_parent_interface()
            if not resolved_parent:
                return AdapterResult.fail(
                    "Cannot determine parent interface for VLAN creation. "
                    "Set 'parent_interface' in gateway connection settings.",
                    error_code="NO_PARENT_INTERFACE",
                )

            # Check for existing VLAN with this tag to avoid duplicates
            existing = await self.get_vlan_devices()
            if existing.success and existing.data:
                for v in existing.data.get("vlans", []):
                    if v.get("tag") == vlan_id and v.get("parent") == resolved_parent:
                        return AdapterResult.ok(
                            data={
                                "uuid": v["uuid"],
                                "tag": vlan_id,
                                "parent": resolved_parent,
                                "device": v.get("device", f"vlan{vlan_id}"),
                                "name": name,
                                "subnet": subnet,
                                "gateway_ip": gateway_ip,
                                "already_existed": True,
                            },
                            message=f"VLAN {vlan_id} already exists on {resolved_parent}",
                        )

            descr = description or (f"[FreeSdn:managed] {name}" if name else "")
            payload = {
                "if": resolved_parent,
                "tag": str(vlan_id),
                "pcp": str(pcp),
                "proto": proto,
                "descr": descr,
            }
            result = await self._api.add_vlan_item(payload, force=self._direct_write_force)
            uuid = result.get("uuid", "")
            if not uuid:
                return AdapterResult.fail(
                    f"VLAN creation returned no UUID: {result}",
                    error_code="NO_UUID",
                )
            # Apply to make OPNsense create the vlanXXX device
            await self._api.apply_vlan_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data={
                    "uuid": uuid,
                    "tag": vlan_id,
                    "parent": resolved_parent,
                    "device": f"vlan{vlan_id}",
                    "name": name,
                    "subnet": subnet,
                    "gateway_ip": gateway_ip,
                },
                message=f"Created VLAN {vlan_id} on {resolved_parent}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def update_vlan_interface(
        self,
        uuid: str,
        *,
        parent_if: str | None = None,
        tag: int | None = None,
        description: str | None = None,
        proto: str | None = None,
        pcp: int | None = None,
    ) -> AdapterResult:
        """Update an existing VLAN sub-interface by its OPNsense UUID."""
        try:
            if tag is not None and not 1 <= tag <= 4094:
                return AdapterResult.fail(f"VLAN tag {tag} out of range 1-4094")
            # Build partial payload — only set fields that are provided
            payload: dict[str, str] = {}
            if parent_if is not None:
                payload["if"] = parent_if
            if tag is not None:
                payload["tag"] = str(tag)
            if description is not None:
                payload["descr"] = description
            if proto is not None:
                payload["proto"] = proto
            if pcp is not None:
                payload["pcp"] = str(pcp)
            if not payload:
                return AdapterResult.fail("No fields to update")
            self._validate_uuid(uuid)
            result = await self._api.update_vlan_item(uuid, payload, force=self._direct_write_force)
            await self._api.apply_vlan_changes(force=self._direct_write_force)
            return AdapterResult.ok(data={"uuid": uuid, "result": result})
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense update_vlan_interface failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_vlan_interface(
        self,
        vlan_id: int | None = None,
        *,
        uuid: str | None = None,
    ) -> AdapterResult:
        """
        Delete a VLAN sub-interface by VLAN tag or OPNsense UUID.

        The distribution engine calls with ``vlan_id``; direct callers
        may pass ``uuid`` for precision.

        Parameters
        ----------
        vlan_id : int, optional
            802.1Q VLAN tag — the device with this tag will be located
            and deleted.
        uuid : str, keyword-only, optional
            OPNsense UUID of the VLAN item for direct deletion.
        """
        try:
            target_uuid = uuid

            if not target_uuid and vlan_id is not None:
                # Look up the VLAN device by tag
                existing = await self.get_vlan_devices()
                if existing.success and existing.data:
                    for v in existing.data.get("vlans", []):
                        if v.get("tag") == vlan_id:
                            target_uuid = v.get("uuid")
                            break

            if not target_uuid:
                if vlan_id is not None:
                    # VLAN not found — treat as idempotent success
                    return AdapterResult.ok(
                        data={"vlan_id": vlan_id, "already_absent": True},
                        message=f"VLAN {vlan_id} not found — nothing to delete",
                    )
                return AdapterResult.fail(
                    "Either vlan_id or uuid must be provided",
                    error_code="MISSING_IDENTIFIER",
                )

            self._validate_uuid(target_uuid)
            result = await self._api.delete_vlan_item(target_uuid, force=self._direct_write_force)
            await self._api.apply_vlan_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data={
                    "uuid": target_uuid,
                    "vlan_id": vlan_id,
                    "result": result,
                },
                message=f"Deleted VLAN {vlan_id or target_uuid}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except ValueError as exc:
            return AdapterResult.fail(type(exc).__name__)
        except Exception as exc:
            logger.exception("OPNsense delete_vlan_interface failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Limb VLAN + DHCP Suppression  (Distribution Engine — Tier 3)
    # ═══════════════════════════════════════════════════════════════════════

    async def create_vlan(
        self,
        vlan_id: int,
        name: str = "",
        **kwargs: Any,
    ) -> AdapterResult:
        """
        Create an L2 VLAN on a limb device.

        On OPNsense this delegates to ``create_vlan_interface`` since
        the OPNsense VLAN model creates the sub-interface device.
        No IP assignment is performed (that is the brain's job).

        Called by the distribution engine Tier 3.
        """
        return await self.create_vlan_interface(
            vlan_id=vlan_id,
            name=name,
            description=f"[FreeSdn:limb] {name}" if name else "",
        )

    async def delete_vlan(self, vlan_id: int) -> AdapterResult:
        """
        Delete an L2 VLAN from a limb device.

        Called by the distribution engine for rollback / retraction.
        """
        return await self.delete_vlan_interface(vlan_id=vlan_id)

    async def suppress_dhcp(self, vlan_id: int) -> AdapterResult:
        """
        Suppress DHCP on a specific VLAN interface.

        On a limb device, DHCP must be disabled so that only the
        brain serves DHCP for this VLAN.  This prevents multiple
        DHCP servers on the same broadcast domain.

        Called by the distribution engine Tier 3.
        """
        try:
            interface = f"vlan{vlan_id}"
            return await self.delete_dhcp_scope(interface)
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(
                f"Failed to suppress DHCP on VLAN {vlan_id}: {exc}",
            )

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Scope / Subnet CRUD  (Orchestration)
    # ═══════════════════════════════════════════════════════════════════════

    async def _detect_dhcp_backend(self) -> str:
        """Detect whether ISC-DHCPD or KEA is the active DHCP server.

        Returns ``"kea"`` or ``"isc"``.  KEA is default on OPNsense 24.7+.
        Detection: try KEA subnet search first; if it succeeds the KEA
        plugin is installed and active.
        """
        try:
            result = await self._api.get_kea_dhcpv4_subnets()
            # If KEA endpoint works and returns data structure, KEA is active
            if isinstance(result, dict) and "rows" in result:
                return "kea"
        except Exception:
            pass
        return "isc"

    async def get_dhcp_scopes(self) -> AdapterResult:
        """
        Return all per-interface DHCP scopes (subnets).

        Reads the full DHCPv4 settings and extracts each interface's
        range, options, and enabled state.
        """
        try:
            raw = await self._api.get_dhcpv4_settings()
            dhcpd = raw.get("dhcpd", {}) if isinstance(raw, dict) else {}
            scopes: list[dict[str, Any]] = []
            for iface, cfg in dhcpd.items():
                if not isinstance(cfg, dict):
                    continue
                enabled = cfg.get("enable", "0") == "1"
                scopes.append(
                    {
                        "interface": iface,
                        "enabled": enabled,
                        "range_start": cfg.get("range", {}).get("from", ""),
                        "range_end": cfg.get("range", {}).get("to", ""),
                        "gateway": cfg.get("gateway", ""),
                        "domain_name": cfg.get("domain", ""),
                        "dns_servers": [
                            s
                            for s in [
                                cfg.get("dns1", ""),
                                cfg.get("dns2", ""),
                            ]
                            if s
                        ],
                        "ntp_servers": [
                            s
                            for s in [
                                cfg.get("ntp1", ""),
                                cfg.get("ntp2", ""),
                            ]
                            if s
                        ],
                        "default_lease_time": cfg.get("defaultleasetime", ""),
                        "max_lease_time": cfg.get("maxleasetime", ""),
                        "raw": cfg,
                    }
                )
            return AdapterResult.ok(data={"scopes": scopes, "count": len(scopes)})
        except Exception as exc:
            logger.exception("OPNsense adapter operation failed")
            return AdapterResult.fail(type(exc).__name__)

    async def create_dhcp_scope(
        self,
        interface: str,
        range_start: str,
        range_end: str,
        *,
        gateway: str = "",
        subnet: str = "",
        dns_servers: list[str] | None = None,
        ntp_servers: list[str] | None = None,
        domain_name: str = "",
        lease_time: int = 86400,
    ) -> AdapterResult:
        """
        Enable / create a DHCP scope on a specific interface.

        OPNsense DHCPv4 scopes are keyed by interface name (e.g.
        ``opt3``, ``lan``, ``igb0_vlan100``).

        Called by the distribution engine (Tier 2) with parameters
        from CanonicalVLAN.

        Parameters
        ----------
        interface : str
            Interface name (e.g. ``vlan10``, ``opt3``).
        range_start : str
            First IP in the DHCP pool.
        range_end : str
            Last IP in the DHCP pool.
        gateway : str, keyword-only
            Gateway IP address for DHCP clients.
        subnet : str, keyword-only
            Subnet in CIDR notation (e.g. ``192.168.10.0/24``).
            Accepted from the distribution engine for context; the
            OPNsense DHCP scope derives the subnet from the interface
            configuration.
        dns_servers : list[str], keyword-only
            Up to 2 DNS server IPs.
        ntp_servers : list[str], keyword-only
            Up to 2 NTP server IPs.
        domain_name : str, keyword-only
            Domain name for DHCP clients.
        lease_time : int, keyword-only
            Default/max lease time in seconds.
        """
        try:
            backend = await self._detect_dhcp_backend()

            if backend == "kea":
                return await self._create_dhcp_scope_kea(
                    interface,
                    range_start,
                    range_end,
                    gateway=gateway,
                    subnet=subnet,
                    dns_servers=dns_servers,
                    lease_time=lease_time,
                )

            # ISC-DHCPD (default / legacy)
            dns = dns_servers or []
            ntp = ntp_servers or []
            settings: dict[str, Any] = {
                "enable": "1",
                "range": {"from": range_start, "to": range_end},
                "defaultleasetime": str(lease_time),
                "maxleasetime": str(lease_time),
            }
            if gateway:
                settings["gateway"] = gateway
            if domain_name:
                settings["domain"] = domain_name
            if len(dns) >= 1:
                settings["dns1"] = dns[0]
            if len(dns) >= 2:
                settings["dns2"] = dns[1]
            if len(ntp) >= 1:
                settings["ntp1"] = ntp[0]
            if len(ntp) >= 2:
                settings["ntp2"] = ntp[1]
            result = await self._api.set_dhcpv4_interface(
                interface,
                settings,
                force=self._direct_write_force,
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data={
                    "interface": interface,
                    "range_start": range_start,
                    "range_end": range_end,
                    "subnet": subnet,
                    "backend": "isc",
                    "result": result,
                },
                message=f"Created DHCP scope on {interface} (ISC-DHCPD)",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.exception("OPNsense create DHCP scope (ISC) failed")
            return AdapterResult.fail(type(exc).__name__)

    async def _create_dhcp_scope_kea(
        self,
        interface: str,
        range_start: str,
        range_end: str,
        *,
        gateway: str = "",
        subnet: str = "",
        dns_servers: list[str] | None = None,
        lease_time: int = 86400,
    ) -> AdapterResult:
        """Create a DHCP scope using the KEA DHCP backend (OPNsense 24.7+)."""
        kea_subnet: dict[str, Any] = {
            "subnet": subnet or f"{range_start}/24",
            "description": f"[FreeSdn:managed] {interface}",
            "option_data_autocollect": "1",
        }
        # KEA pools use "start-end" format
        pool = f"{range_start}-{range_end}"
        kea_subnet["pools"] = pool

        if gateway:
            kea_subnet["option_data"] = {"routers": gateway}
        if dns_servers:
            opts = kea_subnet.get("option_data", {})
            opts["domain-name-servers"] = ",".join(dns_servers)
            kea_subnet["option_data"] = opts
        if lease_time:
            kea_subnet["valid_lifetime"] = str(lease_time)

        result = await self._api.add_kea_dhcpv4_subnet(
            kea_subnet,
            force=self._direct_write_force,
        )
        uuid = result.get("uuid", "")
        await self._api.apply_kea_changes(force=self._direct_write_force)

        return AdapterResult.ok(
            data={
                "interface": interface,
                "range_start": range_start,
                "range_end": range_end,
                "subnet": subnet,
                "backend": "kea",
                "uuid": uuid,
                "result": result,
            },
            message=f"Created DHCP scope on {interface} (KEA)",
        )

    async def update_dhcp_scope(
        self,
        interface: str,
        *,
        range_start: str | None = None,
        range_end: str | None = None,
        gateway: str | None = None,
        dns_servers: list[str] | None = None,
        ntp_servers: list[str] | None = None,
        domain_name: str | None = None,
        lease_time: int | None = None,
        enabled: bool | None = None,
    ) -> AdapterResult:
        """Update an existing DHCP scope on a specific interface."""
        try:
            settings: dict[str, Any] = {}
            if enabled is not None:
                settings["enable"] = "1" if enabled else "0"
            if range_start is not None and range_end is not None:
                settings["range"] = {"from": range_start, "to": range_end}
            if gateway is not None:
                settings["gateway"] = gateway
            if domain_name is not None:
                settings["domain"] = domain_name
            if lease_time is not None:
                settings["defaultleasetime"] = str(lease_time)
                settings["maxleasetime"] = str(lease_time)
            if dns_servers is not None:
                settings["dns1"] = dns_servers[0] if len(dns_servers) >= 1 else ""
                settings["dns2"] = dns_servers[1] if len(dns_servers) >= 2 else ""
            if ntp_servers is not None:
                settings["ntp1"] = ntp_servers[0] if len(ntp_servers) >= 1 else ""
                settings["ntp2"] = ntp_servers[1] if len(ntp_servers) >= 2 else ""
            if not settings:
                return AdapterResult.fail("No fields to update")
            result = await self._api.set_dhcpv4_interface(
                interface,
                settings,
                force=self._direct_write_force,
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(data={"interface": interface, "result": result})
        except Exception as exc:
            logger.exception("OPNsense update_dhcp_scope failed")
            return AdapterResult.fail(type(exc).__name__)

    async def delete_dhcp_scope(self, interface: str) -> AdapterResult:
        """
        Disable the DHCP scope on a specific interface.

        Called by the distribution engine for rollback or retraction.
        Detects the DHCP backend (ISC or KEA) and disables accordingly.
        """
        try:
            backend = await self._detect_dhcp_backend()

            if backend == "kea":
                # KEA: find subnet by description marker and delete it
                try:
                    raw = await self._api.get_kea_dhcpv4_subnets()
                    for row in self._rows(raw):
                        desc = row.get("description", "")
                        if interface in desc and "[FreeSdn" in desc:
                            uuid = row.get("uuid", "")
                            if uuid:
                                self._validate_uuid(uuid)
                                await self._api.del_kea_dhcpv4_subnet(
                                    uuid,
                                    force=self._direct_write_force,
                                )
                                await self._api.apply_kea_changes(force=self._direct_write_force)
                                return AdapterResult.ok(
                                    data={"interface": interface, "backend": "kea", "uuid": uuid},
                                    message=f"Deleted KEA DHCP scope for {interface}",
                                )
                except Exception as exc:
                    logger.warning("KEA delete failed, trying ISC: %s", exc)

            # ISC-DHCPD: disable the scope
            result = await self._api.set_dhcpv4_interface(
                interface,
                {"enable": "0"},
                force=self._direct_write_force,
            )
            await self._api.apply_dhcp_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data={"interface": interface, "backend": "isc", "result": result},
                message=f"Disabled DHCP scope on {interface}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            logger.exception("OPNsense delete_dhcp_scope failed")
            return AdapterResult.fail(type(exc).__name__)
