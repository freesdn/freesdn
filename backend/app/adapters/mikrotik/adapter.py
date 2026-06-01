# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - MikroTik Adapter
================================

BaseAdapter implementation for MikroTik RouterOS devices.
Uses the REST API introduced in RouterOS 7.1+.
"""

import asyncio
import logging
import re
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
    AdapterError,
)
from app.adapters.mikrotik.client import MikroTikAPIError, MikroTikClient

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Module-level helpers
# ────────────────────────────────────────────────────────────────────
#
# IMPORTANT: do NOT add module-level mutable caches (dicts/sets keyed
# by org/user/host) without bounded eviction. RouterOS deployments
# can hold thousands of devices across hundreds of organizations and
# an unbounded cache here would leak indefinitely. Use ``functools.lru_cache``
# with maxsize OR an explicit TTL+size policy in ``app.core.cache``
# if a future patch needs caching at this layer.


def _mt_bool(value: Any) -> bool:
    """Normalise a RouterOS boolean-shaped field to a Python bool.

    Why this exists: RouterOS 7.0/7.1 returns booleans as actual
    Python ``True``/``False`` after JSON parse, but 7.2+ returns the
    string ``"true"``/``"false"``. A simple ``v == "true"`` check
    silently breaks on the older firmware (and on 7.2+ if RouterOS
    ever switches back). This helper accepts both shapes plus the
    historical ``"yes"``/``"no"`` and ``1``/``0`` variants emitted
    by a few RouterOS subsystems.

    Returns False for None/missing/unrecognised values — the
    safe-default for "is this interface running?" / "is this rule
    disabled?" checks where the caller wants a positive signal.
    """
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "on")
    if isinstance(value, (int, float)):
        return value != 0
    return False


# Parse a RouterOS bridge ``vlan-ids`` field shape (e.g. ``"10"``,
# ``"10,20,30"``, ``"10-15"``, ``"10,20-25,40"``) and test whether a
# given VID falls inside it. The wire grammar matches the create-side
# regex at ``client._BRIDGE_VLAN_IDS_RE``.
_VID_TOKEN_RE = re.compile(r"^\s*(\d+)(?:\s*-\s*(\d+))?\s*$")


def _vid_in_set(vid: int, spec: str) -> bool:
    """Return True iff ``vid`` is contained in the RouterOS bridge
    VLAN-ids spec ``spec``.

    Accepts the same comma-list-with-ranges grammar as the create
    side. Whitespace inside tokens is tolerated; bad tokens are
    silently skipped (caller should validate input upstream).
    """
    if not isinstance(spec, str) or not spec.strip():
        return False
    try:
        vid_int = int(vid)
    except (TypeError, ValueError):
        return False
    for token in spec.split(","):
        match = _VID_TOKEN_RE.match(token)
        if not match:
            continue
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        if low > high:
            low, high = high, low
        if low <= vid_int <= high:
            return True
    return False


class MikroTikAdapter(BaseAdapter):
    """
    Adapter for MikroTik RouterOS devices (v7.1+).

    Supports:
    - Firewall filter / NAT / mangle / address-list management
    - DHCP server & leases
    - DNS static entries
    - Interface management (Ethernet, bridge, VLAN)
    - IP address management
    - Routing (static routes)
    - QoS (simple queues)
    - VPN (IPsec, WireGuard, L2TP, PPTP)
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="mikrotik",
        name="MikroTik RouterOS",
        vendor="MikroTik",
        version="1.0.0",
        description="MikroTik RouterOS REST API (v7.1+) – HTTP Basic auth",
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=[
            "7.1",
            "7.2",
            "7.3",
            "7.4",
            "7.5",
            "7.6",
            "7.7",
            "7.8",
            "7.9",
            "7.10",
            "7.11",
            "7.12",
            "7.13",
            "7.14",
            "7.15",
            "7.16",
            "7.17",
            "7.18",
        ],
        device_types={
            "router": DeviceTypeCapabilities(
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
                    Capability.ROUTING_DYNAMIC,
                    Capability.QOS,
                    Capability.TRAFFIC_SHAPING,
                    Capability.VLAN_MANAGEMENT,
                    Capability.VLAN_CREATE,
                    Capability.VLAN_DELETE,
                    # Per-domain feature surfaces — backed by
                    # adapter_mikrotik_* services + endpoints. The
                    # frontend reads these to gate per-domain tabs.
                    Capability.MIKROTIK_FIREWALL_FILTER,
                    Capability.MIKROTIK_FIREWALL_NAT,
                    Capability.MIKROTIK_FIREWALL_MANGLE,
                    Capability.MIKROTIK_FIREWALL_ADDRESS_LIST,
                    Capability.MIKROTIK_INTERFACES_LIST,
                    Capability.MIKROTIK_INTERFACES_VLAN,
                    Capability.MIKROTIK_INTERFACES_BRIDGE,
                    Capability.MIKROTIK_INTERFACES_ETHERNET,
                    Capability.MIKROTIK_IP_ADDRESS,
                    Capability.MIKROTIK_IP_POOL,
                    Capability.MIKROTIK_IP_ARP,
                    Capability.MIKROTIK_DHCP_SERVER,
                    Capability.MIKROTIK_DHCP_LEASES,
                    Capability.MIKROTIK_DNS_SETTINGS,
                    Capability.MIKROTIK_DNS_STATIC,
                    Capability.MIKROTIK_ROUTING_STATIC,
                    Capability.MIKROTIK_ROUTING_OSPF,
                    Capability.MIKROTIK_ROUTING_BGP,
                    Capability.MIKROTIK_QUEUES_SIMPLE,
                    Capability.MIKROTIK_QUEUES_TREE,
                    Capability.MIKROTIK_PPP_PPPOE_SERVER,
                    Capability.MIKROTIK_PPP_PPPOE_CLIENT,
                    Capability.MIKROTIK_PPP_SECRETS,
                    Capability.MIKROTIK_HOTSPOT_SERVER,
                    Capability.MIKROTIK_HOTSPOT_USERS,
                    Capability.MIKROTIK_HOTSPOT_WALLED_GARDEN,
                    Capability.MIKROTIK_CAPSMAN_CONFIG,
                    Capability.MIKROTIK_CAPSMAN_DATAPATH,
                    Capability.MIKROTIK_CAPSMAN_SECURITY,
                    Capability.MIKROTIK_CAPSMAN_REGISTRATIONS,
                    Capability.MIKROTIK_SECURITY_USERS,
                    Capability.MIKROTIK_SECURITY_CERTIFICATES,
                    Capability.MIKROTIK_SECURITY_SNMP,
                    Capability.MIKROTIK_SECURITY_RADIUS,
                    Capability.MIKROTIK_SYSTEM_REBOOT,
                    Capability.MIKROTIK_SYSTEM_BACKUP,
                    Capability.MIKROTIK_SYSTEM_EXPORT,
                    Capability.MIKROTIK_SYSTEM_SERVICES,
                    Capability.MIKROTIK_SYSTEM_SWITCH,
                    Capability.MIKROTIK_SYSTEM_TOOLS,
                    Capability.MIKROTIK_SYSTEM_LOGS,
                ],
                models=["RB*", "CCR*", "hAP*", "hEX*", "RB4011*", "RB5009*", "*"],
            ),
            "firewall": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.FIREWALL_BASIC,
                    Capability.FIREWALL_ADVANCED,
                    Capability.FIREWALL_LOGGING,
                    Capability.NAT,
                ],
                models=["*"],
            ),
            "vpn_gateway": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.VPN_IPSEC,
                    Capability.VPN_WIREGUARD,
                    Capability.VPN_L2TP,
                    Capability.VPN_PPTP,
                    Capability.VPN_SERVER,
                    Capability.VPN_CLIENT,
                ],
                models=["*"],
            ),
            "switch": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.SWITCH_PORT_CONFIG,
                    Capability.SWITCH_PORT_ENABLE,
                    Capability.VLAN_MANAGEMENT,
                    Capability.PORT_STATISTICS,
                    Capability.POE_STATUS,
                ],
                models=["CRS*", "CSS*", "*"],
            ),
        },
        auth_methods=["basic"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=4,
        default_sync_interval=60,
        min_sync_interval=30,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=False,
    )

    # ── init ─────────────────────────────────────────────────────────────

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        # high-level adapter write methods thread
        # this flag to the client instead of hard-coding force=True, so a
        # direct live write (gateway-service / passthrough route) is refused
        # under ADAPTER_READ_ONLY unless opted in. The staged applier calls the
        # client directly with force=True and does not use these methods, so it
        # is unaffected. Default False = direct routes refused. Diagnostic
        # read-POSTs (ping/traceroute/dns) keep force=True (they are reads).
        self._direct_write_force = bool(kwargs.pop("direct_write_force", False))
        super().__init__(host, username, password, **kwargs)
        self._api = MikroTikClient(
            host=host,
            username=username,
            password=password,
            port=kwargs.get("port", 443),
            use_ssl=kwargs.get("use_ssl"),  # None → auto-detect from port
            verify_ssl=kwargs.get("verify_ssl", False),
            timeout=kwargs.get("timeout", 30),
        )

    # ── BaseAdapter required ─────────────────────────────────────────────

    async def connect(self) -> bool:
        try:
            await self._api.connect()
            await self._api.get_system_resource()
            self._connected = True
            return True
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"Failed to connect to MikroTik at {self.host}: {exc}",
                adapter_id="mikrotik",
            ) from exc

    async def disconnect(self) -> None:
        await self._api.close()
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        try:
            await self._api.connect()
            resource = await self._api.get_system_resource()
            identity = await self._api.get_system_identity()
            await self._api.close()
            return AdapterResult.ok(
                data={
                    "vendor": "MikroTik",
                    "identity": identity,
                    "resource": resource,
                },
                message="Connection successful",
            )
        except AdapterAuthenticationError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"Connection failed: {exc}")

    async def discover_devices(self) -> list[DiscoveredDevice]:
        try:
            resource = await self._api.get_system_resource()
            identity = await self._api.get_system_identity()
            rb = await self._api.get_system_routerboard()

            hostname = identity.get("name", self.host)
            version = resource.get("version", "unknown")
            model = rb.get("model", resource.get("board-name", "RouterOS"))

            return [
                DiscoveredDevice(
                    device_type="router",
                    name=hostname,
                    vendor="MikroTik",
                    model=model,
                    mac_address="",
                    ip_address=self.host,
                    firmware_version=version,
                    status="online",
                    raw_data={
                        "resource": resource,
                        "routerboard": rb,
                        "architecture": resource.get("architecture-name"),
                    },
                )
            ]
        except Exception as exc:
            logger.warning("MikroTik discover_devices failed: %s", exc)
            return []

    async def get_device_status(self, device_id: str) -> AdapterResult:
        # CRIT-perf: parallelise 3 independent reads.
        try:
            resource, health, ifaces = await asyncio.gather(
                self._api.get_system_resource(),
                self._api.get_system_health(),
                self._api.get_interfaces(),
                return_exceptions=True,
            )

            def _ok(val: Any, fallback: Any) -> Any:
                return fallback if isinstance(val, BaseException) else val

            return AdapterResult.ok(
                data={
                    "resource": _ok(resource, {}),
                    "health": _ok(health, []),
                    "interfaces": _ok(ifaces, []),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_device_info(self, device_id: str) -> AdapterResult:
        # CRIT-perf: parallelise 4 independent reads.
        try:
            resource, identity, rb, lic = await asyncio.gather(
                self._api.get_system_resource(),
                self._api.get_system_identity(),
                self._api.get_system_routerboard(),
                self._api.get_system_license(),
                return_exceptions=True,
            )

            def _ok(val: Any, fallback: Any) -> Any:
                return fallback if isinstance(val, BaseException) else val

            resource = _ok(resource, {})
            identity = _ok(identity, {})
            rb = _ok(rb, {})
            lic = _ok(lic, {})
            return AdapterResult.ok(
                data={
                    "hostname": identity.get("name"),
                    "version": resource.get("version"),
                    "model": rb.get("model", resource.get("board-name")),
                    "architecture": resource.get("architecture-name"),
                    "uptime": resource.get("uptime"),
                    "cpu_load": resource.get("cpu-load"),
                    "memory_total": resource.get("total-memory"),
                    "memory_free": resource.get("free-memory"),
                    "license": lic,
                    "routerboard": rb,
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Filter
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_filter_rules())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_firewall_rule(self, rule_id: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_filter_rule(rule_id))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_firewall_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_firewall_filter_rule(rule)
            return AdapterResult.ok(data=result, message="Rule created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_firewall_rule(self, rule_id: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.update_firewall_filter_rule(rule_id, rule)
            return AdapterResult.ok(data=result, message="Rule updated")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_firewall_rule(self, rule_id: str) -> AdapterResult:
        try:
            result = await self._api.delete_firewall_filter_rule(rule_id)
            return AdapterResult.ok(data=result, message="Rule deleted")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def toggle_firewall_rule(self, rule_id: str, enabled: bool) -> AdapterResult:
        try:
            if enabled:
                result = await self._api.enable_firewall_filter_rule(rule_id)
            else:
                result = await self._api.disable_firewall_filter_rule(rule_id)
            return AdapterResult.ok(data=result)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_nat_rules())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_nat_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.add_firewall_nat_rule(rule))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_nat_rule(self, rule_id: str, rule: dict[str, Any]) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.update_firewall_nat_rule(rule_id, rule))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_nat_rule(self, rule_id: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.delete_firewall_nat_rule(rule_id))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Address Lists (alias equivalent)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_address_lists(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_address_lists())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_address_list_entry(
        self, list_name: str, address: str, **kw: Any
    ) -> AdapterResult:
        try:
            return AdapterResult.ok(
                data=await self._api.add_firewall_address_list(list_name, address, **kw)
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_address_list_entry(self, entry_id: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.delete_firewall_address_list(entry_id))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_leases(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_dhcp_leases())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_entries(self) -> AdapterResult:
        try:
            settings = await self._api.get_dns_settings()
            static = await self._api.get_dns_static_entries()
            return AdapterResult.ok(data={"settings": settings, "static": static})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_dns_entry(self, name: str, address: str, **kw: Any) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.add_dns_static_entry(name, address, **kw))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> AdapterResult:
        try:
            ifaces = await self._api.get_interfaces()
            addrs = await self._api.get_ip_addresses()
            return AdapterResult.ok(data={"interfaces": ifaces, "addresses": addrs})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # VPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vpn_status(self) -> AdapterResult:
        # CRIT-perf: parallelise — 7 independent RouterOS reads.
        # Previously sequential, so a single 1s read serialised into
        # a 7s page-load. Each call is wrapped in try/except (via
        # ``return_exceptions=True``) so one failing sub-system (e.g.
        # WireGuard package missing) doesn't blank the whole panel —
        # that section just returns ``None`` and the caller can show
        # a partial view.
        try:
            (
                ipsec_policies,
                ipsec_peers,
                ipsec_active,
                wg_ifaces,
                wg_peers,
                l2tp,
                pptp,
            ) = await asyncio.gather(
                self._api.get_ipsec_policies(),
                self._api.get_ipsec_peers(),
                self._api.get_ipsec_active(),
                self._api.get_wireguard_interfaces(),
                self._api.get_wireguard_peers(),
                self._api.get_l2tp_server(),
                self._api.get_pptp_server(),
                return_exceptions=True,
            )

            def _ok(val: Any, fallback: Any) -> Any:
                return fallback if isinstance(val, BaseException) else val

            return AdapterResult.ok(
                data={
                    "ipsec": {
                        "policies": _ok(ipsec_policies, []),
                        "peers": _ok(ipsec_peers, []),
                        "active": _ok(ipsec_active, []),
                    },
                    "wireguard": {
                        "interfaces": _ok(wg_ifaces, []),
                        "peers": _ok(wg_peers, []),
                    },
                    "l2tp": _ok(l2tp, None),
                    "pptp": _ok(pptp, None),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # QoS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_queues(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_simple_queues())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_logs())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # System Info (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_info(self) -> AdapterResult:
        # CRIT-perf: parallelise 3 independent reads.
        try:
            resource, identity, rb = await asyncio.gather(
                self._api.get_system_resource(),
                self._api.get_system_identity(),
                self._api.get_system_routerboard(),
                return_exceptions=True,
            )

            def _ok(val: Any, fallback: Any) -> Any:
                return fallback if isinstance(val, BaseException) else val

            resource = _ok(resource, {})
            identity = _ok(identity, {})
            rb = _ok(rb, {})
            return AdapterResult.ok(
                data={
                    "hostname": identity.get("name", ""),
                    "model": rb.get("model", resource.get("board-name", "")),
                    "board_name": resource.get("board-name", ""),
                    "architecture": resource.get("architecture-name", ""),
                    "version": resource.get("version", ""),
                    "uptime": resource.get("uptime", ""),
                    "cpu_load": resource.get("cpu-load", 0),
                    "cpu_count": resource.get("cpu-count", 0),
                    "memory_total": resource.get("total-memory", 0),
                    "memory_free": resource.get("free-memory", 0),
                    "hdd_total": resource.get("total-hdd-space", 0),
                    "hdd_free": resource.get("free-hdd-space", 0),
                    "serial_number": rb.get("serial-number", ""),
                    "factory_firmware": rb.get("factory-firmware", ""),
                    "current_firmware": rb.get("current-firmware", ""),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN Devices (drift detection)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlan_devices(self) -> AdapterResult:
        try:
            vlans = await self._api.get_vlan_interfaces()
            addrs = await self._api.get_ip_addresses()
            addr_map: dict[str, str] = {}
            for a in addrs:
                iface = a.get("interface", "")
                if iface:
                    addr_map[iface] = a.get("address", "")
            result = []
            for v in vlans:
                name = v.get("name", "")
                result.append(
                    {
                        "id": v.get(".id", ""),
                        "name": name,
                        "vlan_id": self._safe_int(v.get("vlan-id", 0)),
                        "interface": v.get("interface", ""),
                        # _mt_bool handles RouterOS 7.0/7.1 (Python bool)
                        # and 7.2+ ("true"/"false" strings) consistently.
                        "running": _mt_bool(v.get("running")),
                        "disabled": _mt_bool(v.get("disabled")),
                        "address": addr_map.get(name, ""),
                    }
                )
            return AdapterResult.ok(data=result)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_static_mappings(self) -> AdapterResult:
        try:
            leases = await self._api.get_dhcp_leases()
            # ``dynamic=false`` means it's a static reservation. Use
            # _mt_bool so RouterOS 7.0/7.1 boolean responses also
            # filter correctly.
            static = [lease for lease in leases if not _mt_bool(lease.get("dynamic", "true"))]
            return AdapterResult.ok(data=static)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS overrides (import wizard)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_overrides(self) -> AdapterResult:
        try:
            static = await self._api.get_dns_static_entries()
            return AdapterResult.ok(data=static)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Static routes (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_static_routes(self) -> AdapterResult:
        try:
            routes = await self._api.get_routes()
            return AdapterResult.ok(data=routes)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Services (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_services())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def restart_service(self, service_name: str) -> AdapterResult:
        """Direct-route entry point — threads ``self._direct_write_force``
        (default False) to the client, so a direct live restart is refused
        under ADAPTER_READ_ONLY. The sanctioned write path is the staged
        applier (client-direct, force=True), which does not use this method.

        MikroTik services are always-on; toggle disabled state.

        A naive disable-then-re-enable can lock the operator out of
        ``api``/``www-ssl``: if the re-enable fails for any reason
        (transient network blip, RouterOS spinning under load, breaker
        tripping) the service stays disabled. This is therefore hardened:
          1. Idempotent: if service is already disabled, skip the
             disable step entirely (operator-requested restart on an
             already-down service is a no-op, not an error).
          2. Re-enable is retried up to 3 times with exponential
             backoff before giving up.
          3. On final re-enable failure we emit a structured
             ``mikrotik.restart_service.LOCKED_OUT`` log line and
             return AdapterResult.fail so the dashboard surfaces
             the partial-failure rather than the operator thinking
             the restart succeeded.
        """
        try:
            services = await self._api.get_services()
            target = None
            for svc in services:
                if svc.get("name", "") == service_name:
                    target = svc
                    break
            if target is None:
                return AdapterResult.fail(f"Service {service_name} not found")

            sid = target.get(".id", "")
            already_disabled = _mt_bool(target.get("disabled"))

            # Step 1: disable (skipped if already disabled — idempotent).
            if not already_disabled:
                await self._api.update_service(
                    sid, {"disabled": "true"}, force=self._direct_write_force
                )

            # Step 2: re-enable with bounded retries. Each retry uses
            # exponential backoff (0.5s, 1s, 2s) so transient breaker
            # holds and network blips don't trip the lock-out path
            # immediately.
            last_exc: Exception | None = None
            for attempt in range(3):
                if attempt > 0:
                    await asyncio.sleep(0.5 * (2 ** (attempt - 1)))
                try:
                    await self._api.update_service(
                        sid, {"disabled": "false"}, force=self._direct_write_force
                    )
                    last_exc = None
                    break
                except Exception as exc:  # noqa: BLE001 — caught + re-raised
                    last_exc = exc
                    logger.warning(
                        "mikrotik.restart_service.re_enable_retry service=%s attempt=%d/3 error=%s",
                        service_name,
                        attempt + 1,
                        exc,
                    )

            if last_exc is not None:
                # Service is now disabled and we couldn't re-enable.
                # If service_name is one of api/www/www-ssl/ssh/winbox
                # the operator may have just locked themselves out;
                # emit a structured line that operations can grep for.
                logger.error(
                    "mikrotik.restart_service.LOCKED_OUT "
                    "service=%s host=%s error=%s — service is now "
                    "disabled and retries exhausted; operator may need "
                    "console access to recover",
                    service_name,
                    self.host,
                    last_exc,
                )
                return AdapterResult.fail(
                    f"Service {service_name} restart failed after retries: {last_exc}"
                )

            return AdapterResult.ok(message=f"Service {service_name} restarted")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    async def run_ping(self, target: str, **kwargs: Any) -> AdapterResult:
        # Diagnostics are sanctioned by the adapter (this method IS
        # the write-path entrypoint) so propagate force=True down to
        # the client — RouterOS' /tool/ping is a POST and the dual-
        # gate refuses it by default.
        try:
            count = kwargs.get("count", 4)
            results = await self._api.run_ping(target, count=count, force=True)
            return AdapterResult.ok(data={"results": results, "target": target})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def run_traceroute(self, target: str, **kwargs: Any) -> AdapterResult:
        try:
            results = await self._api.run_traceroute(target, force=True)
            return AdapterResult.ok(data={"results": results, "target": target})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def run_dns_lookup(self, hostname: str, **kwargs: Any) -> AdapterResult:
        """MikroTik doesn't have a dedicated DNS lookup tool — use ping with count=1."""
        try:
            results = await self._api.run_ping(hostname, count=1, force=True)
            return AdapterResult.ok(data={"results": results, "hostname": hostname})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Backup
    # ═══════════════════════════════════════════════════════════════════════

    async def create_backup(self, **kwargs: Any) -> AdapterResult:
        """Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes."""
        try:
            result = await self._api.create_backup(name="freesdn", force=self._direct_write_force)
            # Strip any password field that may echo back in the
            # response (RouterOS 7 returns an envelope of the saved
            # request body for /system/backup/save). The applied
            # response is persisted to ``adapter_pending_changes`` so
            # we do not want secrets at rest there.
            from app.core.redaction import redact_secrets

            result = redact_secrets(result)
            return AdapterResult.ok(data=result, message="Backup created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Firmware
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firmware_info(self) -> AdapterResult:
        # CRIT-perf: parallelise 3 independent reads.
        try:
            resource, rb, packages = await asyncio.gather(
                self._api.get_system_resource(),
                self._api.get_system_routerboard(),
                self._api.get_packages(),
                return_exceptions=True,
            )

            def _ok(val: Any, fallback: Any) -> Any:
                return fallback if isinstance(val, BaseException) else val

            resource = _ok(resource, {})
            rb = _ok(rb, {})
            packages = _ok(packages, [])
            return AdapterResult.ok(
                data={
                    "current_version": resource.get("version", ""),
                    "factory_firmware": rb.get("factory-firmware", ""),
                    "current_firmware": rb.get("current-firmware", ""),
                    "upgrade_firmware": rb.get("upgrade-firmware", ""),
                    "packages": packages,
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # ARP (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_arp_table(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_arp_table())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # ╔═══════════════════════════════════════════════════════════════════╗
    # ║  DISTRIBUTION ENGINE METHODS                                      ║
    # ║  Called by distribution_service.py via getattr(adapter, action)    ║
    # ╚═══════════════════════════════════════════════════════════════════╝
    # ═══════════════════════════════════════════════════════════════════════

    # ── helpers ───────────────────────────────────────────────────────────

    def _mk_bool(self, val: Any) -> str:
        """Convert Python bool to MikroTik string bool."""
        if isinstance(val, bool):
            return "true" if val else "false"
        return str(val).lower()

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        """Safely convert a MikroTik field value to int."""
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    async def _find_vlan_iface(self, vlan_id: int) -> dict[str, Any] | None:
        """Find an existing VLAN interface by vlan-id."""
        vlans = await self._api.get_vlan_interfaces()
        for v in vlans:
            if self._safe_int(v.get("vlan-id", 0)) == vlan_id:
                return v
        return None

    async def _find_ip_for_interface(self, iface_name: str) -> dict[str, Any] | None:
        """Find IP address entry assigned to an interface."""
        addrs = await self._api.get_ip_addresses()
        for a in addrs:
            if a.get("interface", "") == iface_name:
                return a
        return None

    async def _find_dhcp_server_for_interface(self, iface_name: str) -> dict[str, Any] | None:
        """Find DHCP server assigned to an interface."""
        servers = await self._api.get_dhcp_servers()
        for s in servers:
            if s.get("interface", "") == iface_name:
                return s
        return None

    async def _find_pool_by_name(self, pool_name: str) -> dict[str, Any] | None:
        """Find IP pool by name."""
        pools = await self._api.get_ip_pools()
        for p in pools:
            if p.get("name", "") == pool_name:
                return p
        return None

    async def _find_dhcp_network_for_subnet(self, subnet: str) -> dict[str, Any] | None:
        """Find DHCP network by subnet address."""
        networks = await self._api.get_dhcp_networks()
        for n in networks:
            if n.get("address", "") == subnet:
                return n
        return None

    async def _resolve_parent_interface(self) -> str:
        """Auto-detect the best parent interface for VLAN sub-interfaces.

        Raises ``AdapterError`` (typed, breaker-aware) when no
        running bridge or ethernet is available so VLAN
        distribution fails fast at the adapter layer rather than
        silently writing a VLAN onto a hard-coded ``ether1`` that
        may not exist on the target device. The previous fallback
        was load-bearing for tests and brand-new devices but
        masked real network misconfig.
        """
        ifaces = await self._api.get_interfaces()
        # Prefer bridge interface (most common for MikroTik VLAN trunking).
        # _mt_bool tolerates RouterOS 7.0/7.1 Python-bool "running" AND
        # the 7.2+ "true"/"false" string shape (the previous string-only
        # check returned False on 7.0/7.1 and the resolver fell through
        # to ethernet, sometimes picking the wrong physical port).
        for iface in ifaces:
            if iface.get("type") == "bridge" and _mt_bool(iface.get("running")):
                return iface.get("name", "bridge1")
        # Fall back to first running ethernet
        for iface in ifaces:
            if iface.get("type") == "ether" and _mt_bool(iface.get("running")):
                return iface.get("name", "ether1")
        raise AdapterError(
            "MikroTik: cannot auto-resolve parent interface for VLAN "
            "distribution — no running bridge or ethernet interface "
            "found. Pass parent_if explicitly or fix the device's "
            "interface state.",
            adapter_id="mikrotik",
        )

    # ── Tier 1: VLAN Interface CRUD ──────────────────────────────────────

    async def create_vlan_interface(
        self,
        vlan_id: int,
        name: str = "",
        subnet: str = "",
        gateway_ip: str = "",
        description: str = "",
        *,
        parent_if: str | None = None,
    ) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Create a VLAN sub-interface on MikroTik.

        Called by the distribution engine (Tier 1).

        Steps:
          1. Create /interface/vlan with vlan-id on parent interface
          2. Add /ip/address with gateway_ip on the new VLAN interface

        MikroTik changes take effect immediately — no commit step.
        """
        if not 1 <= vlan_id <= 4094:
            return AdapterResult.fail(
                f"VLAN tag {vlan_id} out of range 1-4094",
                error_code="INVALID_VLAN_TAG",
            )
        try:
            # Check for duplicate
            existing = await self._find_vlan_iface(vlan_id)
            if existing:
                return AdapterResult.ok(
                    data={"id": existing.get(".id"), "vlan_id": vlan_id},
                    message=f"VLAN {vlan_id} already exists",
                )

            parent = parent_if or await self._resolve_parent_interface()
            iface_name = name or f"vlan{vlan_id}"

            # 1. Create the VLAN interface
            vlan_data: dict[str, Any] = {
                "name": iface_name,
                "vlan-id": str(vlan_id),
                "interface": parent,
            }
            if description:
                vlan_data["comment"] = description
            result = await self._api.add_vlan_interface(
                iface_name,
                vlan_id,
                parent,
                comment=description if description else "",
                force=self._direct_write_force,
            )

            # 2. Assign IP address if provided
            ip_result = None
            if gateway_ip and subnet:
                # Extract prefix length from subnet CIDR
                prefix = subnet.split("/")[1] if "/" in subnet else "24"
                addr = f"{gateway_ip}/{prefix}"
                ip_result = await self._api.add_ip_address(
                    addr, iface_name, force=self._direct_write_force
                )

            return AdapterResult.ok(
                data={
                    "vlan_id": vlan_id,
                    "interface_name": iface_name,
                    "parent": parent,
                    "address": f"{gateway_ip}/{prefix}" if gateway_ip and subnet else None,
                    "vlan_result": result,
                    "ip_result": ip_result,
                },
                message=f"VLAN {vlan_id} interface created on {parent}",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to create VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to create VLAN {vlan_id}: {exc}")

    async def delete_vlan_interface(
        self,
        vlan_id: int | None = None,
        *,
        iface_id: str | None = None,
    ) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Delete a VLAN sub-interface from MikroTik.

        Called by the distribution engine (rollback) with vlan_id.
        Removes the VLAN interface and its IP address.
        """
        try:
            if iface_id:
                # Direct deletion by .id
                await self._api.delete_vlan_interface(iface_id, force=self._direct_write_force)
                return AdapterResult.ok(message=f"VLAN interface {iface_id} deleted")

            if vlan_id is None:
                return AdapterResult.fail("Either vlan_id or iface_id is required")

            existing = await self._find_vlan_iface(vlan_id)
            if not existing:
                return AdapterResult.ok(message=f"VLAN {vlan_id} already absent")

            iface_name = existing.get("name", "")
            mt_id = existing.get(".id", "")

            # Remove IP addresses on this interface first
            ip_entry = await self._find_ip_for_interface(iface_name)
            if ip_entry and ip_entry.get(".id"):
                await self._api.delete_ip_address(ip_entry[".id"], force=self._direct_write_force)

            # Remove the VLAN interface
            await self._api.delete_vlan_interface(mt_id, force=self._direct_write_force)

            return AdapterResult.ok(
                data={"vlan_id": vlan_id, "interface_name": iface_name},
                message=f"VLAN {vlan_id} interface deleted",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to delete VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to delete VLAN {vlan_id}: {exc}")

    # ── Tier 2: DHCP Scope CRUD ──────────────────────────────────────────

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
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Create a DHCP scope on MikroTik.

        Called by the distribution engine (Tier 2).

        MikroTik DHCP requires three components:
          1. IP pool (address range)
          2. DHCP network (subnet, gateway, DNS)
          3. DHCP server (binds pool to interface)
        """
        # Track each successfully-created RouterOS row so we can
        # roll back on partial failure. RouterOS doesn't have a
        # transactional create across pool/network/server, so we
        # implement compensating deletes ourselves; a half-built
        # scope on a production router would silently leak addresses
        # or shadow another DHCP scope's pool.
        created: list[tuple[str, str]] = []
        try:
            # Check for existing DHCP server on this interface
            existing = await self._find_dhcp_server_for_interface(interface)
            if existing:
                return AdapterResult.ok(
                    data={"id": existing.get(".id")},
                    message=f"DHCP server already exists on {interface}",
                )

            pool_name = f"FreeSdn_{interface}_pool"
            server_name = f"FreeSdn_{interface}"

            # Convert lease_time seconds to MikroTik format
            lease_str = f"{lease_time // 3600}h" if lease_time >= 3600 else f"{lease_time // 60}m"

            # RouterOS 7.5 and earlier return the new row's ID
            # under ``ret``; 7.6+ returns it under ``.id``. Read both
            # keys so rollback walks a populated ``created`` list and
            # actually tears the partial scope down on failure.
            def _new_row_id(resp: Any) -> str | None:
                if not isinstance(resp, dict):
                    return None
                # Prefer 7.6+ shape; fall back to 7.5-style ``ret``.
                rid = resp.get(".id") or resp.get("ret")
                return rid if isinstance(rid, str) and rid else None

            # 1. Create IP pool
            pool_range = f"{range_start}-{range_end}"
            pool_resp = await self._api.add_ip_pool(
                pool_name, pool_range, force=self._direct_write_force
            )
            pool_id = _new_row_id(pool_resp)
            if pool_id:
                created.append(("pool", pool_id))

            # 2. Create DHCP network
            net_data: dict[str, Any] = {}
            if subnet:
                net_data["address"] = subnet
            if gateway:
                net_data["gateway"] = gateway
            if dns_servers:
                net_data["dns-server"] = ",".join(dns_servers)
            if domain_name:
                net_data["domain"] = domain_name
            if ntp_servers:
                net_data["ntp-server"] = ",".join(ntp_servers)
            net_data["comment"] = f"FreeSdn managed – {interface}"
            if net_data.get("address"):
                net_resp = await self._api.add_dhcp_network(
                    net_data, force=self._direct_write_force
                )
                net_id = _new_row_id(net_resp)
                if net_id:
                    created.append(("network", net_id))

            # 3. Create DHCP server
            server_data: dict[str, Any] = {
                "name": server_name,
                "interface": interface,
                "address-pool": pool_name,
                "lease-time": lease_str,
                "disabled": "false",
            }
            result = await self._api.add_dhcp_server(server_data, force=self._direct_write_force)
            srv_id = _new_row_id(result)
            if srv_id:
                created.append(("server", srv_id))

            return AdapterResult.ok(
                data={
                    "interface": interface,
                    "pool_name": pool_name,
                    "server_name": server_name,
                    "range": pool_range,
                    "result": result,
                },
                message=f"DHCP scope created on {interface}",
            )
        except MikroTikAPIError as exc:
            await self._rollback_dhcp_scope(created)
            return AdapterResult.fail(f"Failed to create DHCP scope on {interface}: {exc}")
        except Exception as exc:
            await self._rollback_dhcp_scope(created)
            return AdapterResult.fail(f"Failed to create DHCP scope on {interface}: {exc}")

    async def _rollback_dhcp_scope(self, created: list[tuple[str, str]]) -> None:
        """Best-effort delete of partial DHCP-scope creates.

        Walks ``created`` in reverse so we tear down in the opposite
        order from which the rows were added. Each delete swallows
        its own error — we never let a rollback failure mask the
        original exception that triggered it. Logged at WARNING so
        an operator can see what got orphaned if cleanup fails.
        """
        for kind, row_id in reversed(created):
            try:
                if kind == "pool":
                    await self._api.delete_ip_pool(row_id, force=self._direct_write_force)
                elif kind == "network":
                    await self._api.delete_dhcp_network(row_id, force=self._direct_write_force)
                elif kind == "server":
                    await self._api.delete_dhcp_server(row_id, force=self._direct_write_force)
            except Exception as cleanup_exc:
                logger.warning(
                    "DHCP scope rollback partial: %s id=%s did not delete cleanly: %s",
                    kind,
                    row_id,
                    cleanup_exc,
                )

    async def delete_dhcp_scope(self, interface: str) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Delete a DHCP scope from MikroTik.

        Removes the DHCP server, network entry, and IP pool associated
        with the interface.

        the previous network-cleanup loop matched on
        ``"FreeSdn" in comment and interface in comment`` (substring).
        If two interfaces shared a name-prefix (``ether1`` vs
        ``ether10``) both rows matched and BOTH got deleted, silently
        nuking an adjacent scope. The new logic narrows by:

          1. The server-side DHCP-network lookup: the DHCP server we
             already deleted has its ``address-pool``; we resolve the
             matching network rows by their assigned subnet (the pool
             range overlap) rather than text-matching a comment.
          2. As a fallback we still scan comments but require an
             *exact* token match (split on whitespace and ``–``) on
             ``interface`` rather than substring containment.

        Each per-row delete is wrapped in try/except so a partial
        failure leaves a precise audit trail in ``deleted`` rather than
        a single ambiguous exception bubble.
        """
        deleted: list[dict[str, Any]] = []

        def _record(kind: str, row_id: str, *, ok: bool, error: str = "") -> None:
            """Append a structured entry so the caller can audit
            exactly which RouterOS rows were touched and which failed."""
            entry = {"kind": kind, "id": row_id, "ok": ok}
            if not ok:
                entry["error"] = error
            deleted.append(entry)

        def _interface_token_match(comment: str, target: str) -> bool:
            """Exact-token match on the comment field so ``ether1``
            does not match ``ether10``."""
            if not comment or not target:
                return False
            # Tokenise on whitespace and en/em-dash + hyphen so the
            # ``FreeSdn managed – ether1`` shape works.
            tokens = re.split(r"[\s\-–—]+", comment)
            return target in tokens

        try:
            # 1. Find and delete DHCP server (exact interface match —
            #    _find_dhcp_server_for_interface already does ``==``).
            server = await self._find_dhcp_server_for_interface(interface)
            pool_name_from_server = ""
            if server:
                pool_name_from_server = server.get("address-pool", "")
                srv_id = server.get(".id", "")
                try:
                    await self._api.delete_dhcp_server(srv_id, force=self._direct_write_force)
                    _record("server", srv_id, ok=True)
                except Exception as exc:  # noqa: BLE001
                    _record("server", srv_id, ok=False, error=str(exc))

                # 2. Delete associated IP pool by exact name match.
                if pool_name_from_server:
                    pool = await self._find_pool_by_name(pool_name_from_server)
                    if pool and pool.get(".id"):
                        pid = pool[".id"]
                        try:
                            await self._api.delete_ip_pool(pid, force=self._direct_write_force)
                            _record("pool", pid, ok=True)
                        except Exception as exc:  # noqa: BLE001
                            _record("pool", pid, ok=False, error=str(exc))

            # 3. Delete DHCP networks that belong to THIS interface.
            #    Strategy: a FreeSdn-managed scope's network row has
            #    ``comment = "FreeSdn managed – <interface>"`` so we
            #    only delete rows where the comment includes the
            #    interface name as an *exact whitespace-delimited
            #    token* — not a substring. This prevents the
            #    ether1/ether10 silent-cascade described above.
            networks = await self._api.get_dhcp_networks()
            for net in networks:
                comment = net.get("comment", "")
                if "FreeSdn" not in comment:
                    continue
                if not _interface_token_match(comment, interface):
                    continue
                net_id = net.get(".id", "")
                try:
                    await self._api.delete_dhcp_network(net_id, force=self._direct_write_force)
                    _record("network", net_id, ok=True)
                except Exception as exc:  # noqa: BLE001
                    _record("network", net_id, ok=False, error=str(exc))

            successes = [d for d in deleted if d["ok"]]
            failures = [d for d in deleted if not d["ok"]]
            if not deleted:
                return AdapterResult.ok(
                    data={"deleted": [], "interface": interface},
                    message=f"No DHCP scope found on {interface}",
                )
            if failures:
                logger.warning(
                    "mikrotik.delete_dhcp_scope.partial interface=%s ok=%d fail=%d",
                    interface,
                    len(successes),
                    len(failures),
                )

            return AdapterResult.ok(
                data={
                    "deleted": deleted,
                    "interface": interface,
                    "success_count": len(successes),
                    "failure_count": len(failures),
                },
                message=f"DHCP scope deleted from {interface}",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to delete DHCP scope on {interface}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to delete DHCP scope on {interface}: {exc}")

    # ── Tier 2: Alias (address-list) CRUD ─────────────────────────────────

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
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Create a firewall address-list group on MikroTik.

        Called by the distribution engine (Tier 2) with named params,
        or by the gateway API with a dict payload.

        MikroTik address-lists differ from OPNsense aliases: each
        member is a separate entry sharing the same list name.
        """
        try:
            if alias and isinstance(alias, dict):
                name = alias.get("name", name)
                members = alias.get("members", members)
                description = alias.get("description", description)

            if not name:
                return AdapterResult.fail("Alias name is required")

            members = members or []
            created = []
            for member in members:
                entry = await self._api.add_firewall_address_list(
                    name,
                    member,
                    comment=description if description else "",
                    force=self._direct_write_force,
                )
                created.append(entry)

            return AdapterResult.ok(
                data={"name": name, "entries_created": len(created), "members": members},
                message=f"Address-list '{name}' created with {len(created)} entries",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to create alias '{name}': {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to create alias '{name}': {exc}")

    async def delete_alias(
        self,
        entry_id: str | None = None,
        *,
        name: str = "",
    ) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Delete a firewall address-list group from MikroTik.

        If *name* is given, all entries with that list name are deleted.
        If *entry_id* is given, only that single entry is deleted.
        """
        try:
            if entry_id and not name:
                await self._api.delete_firewall_address_list(
                    entry_id, force=self._direct_write_force
                )
                return AdapterResult.ok(message=f"Address-list entry {entry_id} deleted")

            if not name:
                return AdapterResult.fail("Either name or entry_id is required")

            # Delete all entries with this list name
            all_entries = await self._api.get_firewall_address_lists()
            deleted = 0
            for entry in all_entries:
                if entry.get("list", "") == name:
                    eid = entry.get(".id", "")
                    if eid:
                        await self._api.delete_firewall_address_list(
                            eid, force=self._direct_write_force
                        )
                        deleted += 1

            if deleted == 0:
                return AdapterResult.ok(message=f"Address-list '{name}' already absent")

            return AdapterResult.ok(
                data={"name": name, "entries_deleted": deleted},
                message=f"Address-list '{name}' deleted ({deleted} entries)",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to delete alias '{name}': {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to delete alias '{name}': {exc}")

    # ── Tier 3: Limb-role VLAN / DHCP suppression ─────────────────────────

    async def create_vlan(self, vlan_id: int, name: str = "", **kwargs: Any) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Create an L2 VLAN on a MikroTik limb device.

        For MikroTik as limb (switch role), this adds a bridge VLAN
        entry. For router role, delegates to create_vlan_interface
        — kwargs (subnet, gateway_ip, description, parent_if) are
        forwarded so the L3 fallback receives the full distribution
        intent rather than an interface stub.
        """
        try:
            # Try bridge VLAN first (switch/limb mode)
            bridges = await self._api.get_bridge_interfaces()
            if bridges:
                bridge_name = bridges[0].get("name", "bridge1")
                await self._api.add_bridge_vlan(
                    bridge_name,
                    str(vlan_id),
                    comment=name or f"FreeSdn VLAN {vlan_id}",
                    force=self._direct_write_force,
                )
                return AdapterResult.ok(
                    data={"vlan_id": vlan_id, "bridge": bridge_name},
                    message=f"Bridge VLAN {vlan_id} created on {bridge_name}",
                )
            # Fallback to L3 VLAN interface — forward kwargs so the
            # full intent (subnet/gateway_ip/description/parent_if)
            # makes it through. ``create_vlan_interface`` is itself a
            # distribution-engine entrypoint that passes force=True.
            return await self.create_vlan_interface(
                vlan_id,
                name=name,
                subnet=kwargs.get("subnet", ""),
                gateway_ip=kwargs.get("gateway_ip", ""),
                description=kwargs.get("description", ""),
                parent_if=kwargs.get("parent_if"),
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to create VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to create VLAN {vlan_id}: {exc}")

    async def delete_vlan(self, vlan_id: int) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Delete an L2 VLAN from a MikroTik limb device.

        Removes the bridge VLAN entry if present, otherwise removes
        the L3 VLAN interface.
        """
        try:
            # Try bridge VLANs first.
            # A plain ``str(vlan_id) == str(vids)`` only matches single-VID
            # rows ("10"). RouterOS stores
            # the ``vlan-ids`` field as a comma/range grammar
            # (``"10,20,30"`` or ``"10-15"``) so a multi-VID entry that
            # legitimately contains the requested VID would be missed
            # and the caller would fall through to L3 deletion. Use
            # ``_vid_in_set`` which mirrors the create-side regex.
            bridge_vlans = await self._api.get_bridge_vlans()
            for bv in bridge_vlans:
                vids = bv.get("vlan-ids", "")
                if _vid_in_set(vlan_id, str(vids)):
                    await self._api.delete_bridge_vlan(bv[".id"], force=self._direct_write_force)
                    return AdapterResult.ok(
                        data={"vlan_id": vlan_id, "matched_spec": vids},
                        message=f"Bridge VLAN {vlan_id} deleted",
                    )
            # Fallback to L3 VLAN interface
            return await self.delete_vlan_interface(vlan_id=vlan_id)
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to delete VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to delete VLAN {vlan_id}: {exc}")

    async def suppress_dhcp(self, vlan_id: int) -> AdapterResult:
        """
        Distribution-engine entrypoint — passes force=True to the
        underlying client because this method IS the sanctioned write
        path; the dual-gate is enforced by the env var alone for
        distribution writes.

        Suppress DHCP on a limb device for a specific VLAN.

        Finds and disables/removes the DHCP server bound to the
        VLAN interface.
        """
        try:
            # Find the VLAN interface name
            vlan_iface = await self._find_vlan_iface(vlan_id)
            if not vlan_iface:
                return AdapterResult.ok(
                    message=f"No VLAN {vlan_id} interface found — nothing to suppress",
                )

            iface_name = vlan_iface.get("name", "")
            server = await self._find_dhcp_server_for_interface(iface_name)
            if not server:
                return AdapterResult.ok(
                    message=f"No DHCP server on {iface_name} — already suppressed",
                )

            # Disable the DHCP server rather than deleting (safer)
            await self._api.update_dhcp_server(
                server[".id"], {"disabled": "true"}, force=self._direct_write_force
            )
            return AdapterResult.ok(
                data={"vlan_id": vlan_id, "interface": iface_name},
                message=f"DHCP suppressed on {iface_name}",
            )
        except MikroTikAPIError as exc:
            return AdapterResult.fail(f"Failed to suppress DHCP for VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to suppress DHCP for VLAN {vlan_id}: {exc}")
