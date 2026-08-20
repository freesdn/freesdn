# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OpenWRT Enterprise Adapter
=========================================

Full BaseAdapter implementation for OpenWRT routers and firewalls.

Key architectural differences from OPNsense/pfSense:
  - Uses ubus JSON-RPC (not REST).
  - Config managed via UCI (not per-module APIs).
  - No native UUIDs — uses synthetic ID mapping.
  - Changes require ``uci commit`` + service restart.
  - Package-dependent capabilities (WireGuard, SQM, etc.).

Domains covered:
  System      — board info, resources, uptime, reboot
  Interfaces  — dump, status, VLAN management
  Firewall    — UCI rule CRUD + ipset/address groups
  NAT         — redirect/DNAT CRUD
  DHCP        — dnsmasq leases, static hosts, scope CRUD
  DNS         — dnsmasq host/domain overrides
  Routing     — static route CRUD, kernel table
  Services    — procd service list / restart
  VPN         — WireGuard, OpenVPN (package-dependent)
  Diagnostics — ping, traceroute (best-effort)
  Backup      — /etc/config/ tarball
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
import uuid as uuid_mod
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
from app.adapters.openwrt.client import OpenWRTAPIError, OpenWRTClient

logger = logging.getLogger(__name__)


def _stable_id(*parts: str) -> str:
    """Generate a deterministic UUID from content parts."""
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return str(uuid_mod.UUID(h))


class OpenWRTAdapter(BaseAdapter):
    """
    Enterprise adapter for OpenWRT routers and firewalls.

    Covers: system, interfaces, firewall rules, NAT, DHCP (dnsmasq),
    DNS, static routing, services, and package-dependent VPN.
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="openwrt",
        name="OpenWRT Router",
        vendor="OpenWrt Project",
        version="1.0.0",
        description="OpenWRT router/firewall — ubus JSON-RPC adapter",
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["21.02", "22.03", "23.05", "24.10"],
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
                    Capability.NAT,
                    Capability.DHCP_SERVER,
                    Capability.DNS,
                    Capability.ROUTING_STATIC,
                    Capability.GATEWAY_VLAN_INTERFACE,
                    Capability.GATEWAY_DHCP_MANAGE,
                    Capability.GATEWAY_DNS_MANAGE,
                    Capability.GATEWAY_ALIAS_MANAGE,
                    Capability.GATEWAY_PING,
                    Capability.GATEWAY_TRACEROUTE,
                    Capability.GATEWAY_DNS_LOOKUP,
                    Capability.GATEWAY_BACKUP,
                    Capability.GATEWAY_SERVICE_RESTART,
                ],
                models=["OpenWrt*", "*"],
            ),
        },
        auth_methods=["username_password"],
        rate_limit_calls_per_minute=60,
        rate_limit_concurrent=3,
        default_sync_interval=120,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=False,
    )

    # ── Initialisation ─────────────────────────────────────────────────────

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        super().__init__(host, username, password, **kwargs)
        self._api = OpenWRTClient(
            host=host,
            username=username,
            password=password,
            port=kwargs.get("port", 443),
            verify_ssl=kwargs.get("verify_ssl", False),
            timeout=kwargs.get("timeout", 30),
        )
        self._capabilities: dict[str, bool] = {}

    # ── Helpers ────────────────────────────────────────────────────────────

    def _uci_sections(
        self,
        data: dict[str, Any],
        section_type: str | None = None,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Extract UCI config sections from a ``uci get`` response.

        Returns list of ``(section_name, values_dict)`` tuples,
        optionally filtered by ``.type``.
        """
        values = data.get("values", data)
        if not isinstance(values, dict):
            return []
        result = []
        for name, section in values.items():
            if not isinstance(section, dict):
                continue
            if section_type and section.get(".type") != section_type:
                continue
            result.append((name, section))
        return result

    # ── Generic UCI helpers ───────────────────────────────────────────────

    def _find_uci_section(
        self,
        data: dict[str, Any],
        section_type: str,
        stable_id: str,
    ) -> str | None:
        """Resolve a synthetic stable UUID back to a UCI section name."""
        for name, _section in self._uci_sections(data, section_type):
            if _stable_id(section_type.replace(".", "_"), name) == stable_id:
                return name
            # Also check config-prefixed IDs used in firewall/dhcp
            for prefix in ("firewall", "dhcp", "network", "sqm", "openvpn"):
                if _stable_id(prefix, section_type, name) == stable_id:
                    return name
        return None

    async def _uci_update(
        self,
        config: str,
        section_type: str,
        stable_id: str,
        values: dict[str, Any],
        service: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        """Generic: find UCI section by stable ID → set values → commit → restart.

        ``uci_name`` (kw-only): if the caller has ALREADY resolved
        ``stable_id`` to a UCI section name (e.g., a service applier
        that just fetched the live list to verify ownership), pass it
        here to skip the redundant ``uci_get_all`` lookup. Saves one
        full-tree fetch per write — meaningful for bulk operations
        where N updates would otherwise mean 2N fetches (1 for the
        IDOR guard, 1 here).
        """
        try:
            if uci_name is None:
                raw = await self._api.uci_get_all(config)
                uci_name = self._find_uci_section(raw, section_type, stable_id)
            if not uci_name:
                return AdapterResult.fail(
                    f"{section_type} with id {stable_id} not found",
                    error_code="NOT_FOUND",
                )
            await self._api.uci_set(config, uci_name, values)
            await self._api.uci_commit(config)
            if service == "network":
                await self._api.reload_network()
            else:
                await self._api.restart_service(service)
            return AdapterResult.ok(
                data={"uci_name": uci_name},
                message=f"Updated {section_type} {uci_name}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            # Let middleware map transport/auth failures (conn → 502,
            # auth → 401) instead of flattening them into a 502 here.
            raise
        except OpenWRTAPIError as exc:
            # ubus argument/command errors are caller-input faults
            # (bad value syntax, malformed section) → surface as a
            # 4xx-class INVALID_CONFIG rather than an opaque 502.
            if exc.code in (1, 2):  # INVALID_COMMAND / INVALID_ARGUMENT
                return AdapterResult.fail(
                    f"invalid {section_type} configuration",
                    error_code="INVALID_CONFIG",
                )
            return AdapterResult.fail(str(exc), error_code="UCI_ERROR")
        except Exception:
            return AdapterResult.fail(
                f"failed to update {section_type}",
                error_code="UCI_UPDATE_FAILED",
            )

    async def _uci_delete_section(
        self,
        config: str,
        section_type: str,
        stable_id: str,
        service: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        """Generic: find UCI section by stable ID → delete → commit → restart.

        ``uci_name`` (kw-only): pre-resolved section name from the
        caller, skips the redundant fetch. See ``_uci_update`` docstring.
        """
        try:
            if uci_name is None:
                raw = await self._api.uci_get_all(config)
                uci_name = self._find_uci_section(raw, section_type, stable_id)
            if not uci_name:
                return AdapterResult.ok(
                    data={"id": stable_id, "already_absent": True},
                    message=f"{section_type} not found — nothing to delete",
                )
            await self._api.uci_delete(config, uci_name)
            await self._api.uci_commit(config)
            if service == "network":
                await self._api.reload_network()
            else:
                await self._api.restart_service(service)
            return AdapterResult.ok(
                data={"uci_name": uci_name},
                message=f"Deleted {section_type} {uci_name}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            # Let middleware map transport/auth failures (conn → 502,
            # auth → 401) instead of flattening them into a 502 here.
            raise
        except OpenWRTAPIError as exc:
            if exc.code == 4:  # NOT_FOUND — section already gone
                return AdapterResult.ok(
                    data={"id": stable_id, "already_absent": True},
                    message=f"{section_type} not found — nothing to delete",
                )
            if exc.code in (1, 2):  # INVALID_COMMAND / INVALID_ARGUMENT
                return AdapterResult.fail(
                    f"invalid {section_type} delete request",
                    error_code="INVALID_CONFIG",
                )
            return AdapterResult.fail(str(exc), error_code="UCI_ERROR")
        except Exception:
            return AdapterResult.fail(
                f"failed to delete {section_type}",
                error_code="UCI_DELETE_FAILED",
            )

    # ═══════════════════════════════════════════════════════════════════════
    # BaseAdapter — required methods
    # ═══════════════════════════════════════════════════════════════════════

    async def connect(self) -> bool:
        await self._api.connect()
        self._connected = True
        return True

    async def disconnect(self) -> None:
        await self._api.disconnect()
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        try:
            await self._api.connect()
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            hostname = board.get("hostname", "")
            model = board.get("model", "")
            release = board.get("release", {})
            version = release.get("version", "")

            # Detect installed packages / capabilities
            await self._detect_capabilities()

            # NOTE: deliberately do NOT call ``self._api.disconnect()`` here.
            # The ``async with adapter:`` context owns the session lifecycle
            # — tearing it down inside ``test_connection`` invalidates every
            # subsequent call in the same context block (get_interfaces,
            # get_firewall_rules, etc. all 404'd with no diagnostic). Caller
            # is responsible for ``adapter.__aexit__`` cleanup.
            return AdapterResult.ok(
                data={
                    "hostname": hostname,
                    "model": model,
                    "version": version,
                    "kernel": board.get("kernel", ""),
                    "uptime": info.get("uptime", 0),
                    "capabilities": self._capabilities,
                }
            )
        except AdapterAuthenticationError as exc:
            return AdapterResult.fail(str(exc))
        except AdapterConnectionError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"Connection failed: {exc}")

    async def _detect_capabilities(self) -> None:
        """Probe for installed packages to determine capabilities."""
        try:
            pkgs = await self._api.get_package_list()
            packages = pkgs.get("packages", {})
            if isinstance(packages, list):
                pkg_names = set(packages)
            elif isinstance(packages, dict):
                pkg_names = set(packages.keys())
            else:
                pkg_names = set()

            self._capabilities = {
                "wireguard": bool(pkg_names & {"wireguard-tools", "kmod-wireguard"}),
                "openvpn": bool(pkg_names & {"openvpn-openssl", "openvpn-mbedtls"}),
                "sqm": "sqm-scripts" in pkg_names,
                "ids": False,  # No standard IDS on OpenWRT
                "ipset": bool(pkg_names & {"ipset", "kmod-nft-set"}),
                "luci": "luci" in pkg_names or "luci-base" in pkg_names,
            }
        except Exception:
            self._capabilities = {}

    async def discover_devices(self) -> list[DiscoveredDevice]:
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            release = board.get("release", {})

            ifaces = await self._api.get_network_interfaces()
            # Find primary IP from first interface with IPv4
            ip = self.host
            mac = ""
            for iface in ifaces.get("interface", []):
                addrs = iface.get("ipv4-address", [])
                if addrs:
                    ip = addrs[0].get("address", ip)
                mac_addr = iface.get("macaddr", "")
                if mac_addr and not mac:
                    mac = mac_addr

            return [
                DiscoveredDevice(
                    mac_address=mac or "00:00:00:00:00:00",
                    ip_address=ip,
                    name=board.get("hostname", "openwrt"),
                    vendor="OpenWrt",
                    model=board.get("model", "Generic"),
                    firmware_version=release.get("version", ""),
                    device_type="firewall",
                    status="online",
                    raw_data={"board": board, "info": info},
                )
            ]
        except Exception as exc:
            logger.error("OpenWRT discovery failed: %s", exc)
            return []

    async def get_device_status(self, device_id: str) -> AdapterResult:
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            ifaces = await self._api.get_network_interfaces()
            return AdapterResult.ok(
                data={
                    "board": board,
                    "info": info,
                    "interfaces": ifaces.get("interface", []),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_device_info(self, device_id: str | None = None) -> AdapterResult:  # type: ignore[override]
        """Board + system info for THIS device.

        OpenWrt is a single-device adapter -- one adapter instance talks to one
        router -- so there is nothing to select and ``device_id`` is ignored. It
        is accepted anyway because BaseAdapter declares it: a vendor-neutral
        caller does ``adapter.get_device_info(device.id)``, and refusing that
        argument raised TypeError instead of returning information the adapter
        had readily available.
        """
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            release = board.get("release", {})
            return AdapterResult.ok(
                data={
                    "hostname": board.get("hostname", ""),
                    "model": board.get("model", ""),
                    "version": release.get("version", ""),
                    "kernel": board.get("kernel", ""),
                    "uptime": info.get("uptime", 0),
                    "memory": info.get("memory", {}),
                    "load": info.get("load", []),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> AdapterResult:
        try:
            raw = await self._api.get_network_interfaces()
            interfaces = []
            for iface in raw.get("interface", []):
                name = iface.get("interface", "")
                device = iface.get("device", iface.get("l3_device", ""))
                up = iface.get("up", False)

                # IPv4 info
                ipv4_addrs = iface.get("ipv4-address", [])
                ipv4 = ipv4_addrs[0].get("address", "") if ipv4_addrs else ""
                ipv4_mask = str(ipv4_addrs[0].get("mask", "")) if ipv4_addrs else ""

                # IPv6 info
                ipv6_addrs = iface.get("ipv6-address", [])
                ipv6 = ipv6_addrs[0].get("address", "") if ipv6_addrs else ""

                # Route / gateway
                routes = iface.get("route", [])
                gw = ""
                for r in routes:
                    if r.get("target") == "0.0.0.0" and r.get("nexthop"):
                        gw = r["nexthop"]
                        break

                # DNS
                dns = iface.get("dns-server", [])

                # Statistics
                data_block = iface.get("data", {})

                interfaces.append(
                    {
                        "name": name,
                        "device": device,
                        "status": "up" if up else "down",
                        "enabled": not iface.get("disabled", False),
                        "proto": iface.get("proto", ""),
                        "ipv4_address": ipv4 or None,
                        "ipv4_subnet": ipv4_mask,
                        "ipv4_gateway": gw or None,
                        "ipv6_address": ipv6 or None,
                        "mac_address": iface.get("macaddr"),
                        "mtu": iface.get("mtu"),
                        "is_wan": name.lower() in ("wan", "wan6"),
                        "is_lan": name.lower() == "lan",
                        "is_bridge": "br-" in device if device else False,
                        "dns_servers": dns,
                        "rx_bytes": data_block.get("rx_bytes", 0),
                        "tx_bytes": data_block.get("tx_bytes", 0),
                        "rx_packets": data_block.get("rx_packets", 0),
                        "tx_packets": data_block.get("tx_packets", 0),
                        "link_type": "bridge" if "br-" in device else "ethernet",
                        "raw": iface,
                    }
                )
            return AdapterResult.ok(data=interfaces)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN Devices (drift detection)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlan_devices(self) -> AdapterResult:
        """Return VLAN interfaces for drift detection."""
        try:
            result = await self.get_interfaces()
            if not result.success:
                return result
            vlans = []
            for iface in result.data or []:
                device = iface.get("device", "")
                # OpenWRT VLAN devices contain a dot (e.g., eth0.10)
                if "." in device:
                    parts = device.rsplit(".", 1)
                    try:
                        vid = int(parts[1])
                    except (ValueError, IndexError):
                        continue
                    vlans.append(
                        {
                            "name": iface.get("name", ""),
                            "device": device,
                            "vlan_id": vid,
                            "parent": parts[0],
                            "status": iface.get("status", "down"),
                            "ipv4_address": iface.get("ipv4_address"),
                            "ipv4_subnet": iface.get("ipv4_subnet", ""),
                        }
                    )
            return AdapterResult.ok(data=vlans)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Rules
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("firewall")
            rules = []
            for name, section in self._uci_sections(raw, "rule"):
                rules.append(
                    {
                        "id": _stable_id("firewall", "rule", name),
                        "uci_name": name,
                        "name": section.get("name", ""),
                        "enabled": section.get("enabled", "1") != "0",
                        "target": section.get("target", "DROP"),
                        "src": section.get("src", ""),
                        "dest": section.get("dest", ""),
                        "src_ip": section.get("src_ip", ""),
                        "dest_ip": section.get("dest_ip", ""),
                        "src_port": section.get("src_port", ""),
                        "dest_port": section.get("dest_port", ""),
                        "proto": section.get("proto", ""),
                        "family": section.get("family", ""),
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(data={"rules": rules, "count": len(rules)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_firewall_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            values = {k: v for k, v in rule.items() if k not in ("id", "uci_name")}
            result = await self._api.uci_add("firewall", "rule", values=values)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(data=result, message="Firewall rule created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_firewall_rule(
        self,
        uci_name: str,
        *,
        resolved_uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            # Accept either a UCI section name, a stable UUID, or a
            # caller-resolved UCI name (skips the lookup fetch).
            if resolved_uci_name:
                target = resolved_uci_name
                await self._api.uci_delete("firewall", target)
                await self._api.uci_commit("firewall")
                await self._api.restart_service("firewall")
                return AdapterResult.ok(message="Firewall rule deleted")
            raw = await self._api.uci_get_all("firewall")
            target = uci_name
            # If it looks like a UUID, resolve it
            if len(uci_name) == 36 and "-" in uci_name:
                resolved = self._find_uci_section(raw, "rule", uci_name)
                if resolved:
                    target = resolved
            await self._api.uci_delete("firewall", target)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(message="Firewall rule deleted")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_firewall_rule(
        self,
        uuid: str,
        rule: dict[str, Any],
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            values = {}
            _map = {
                "name": "name",
                "target": "target",
                "src": "src",
                "dest": "dest",
                "src_ip": "src_ip",
                "dest_ip": "dest_ip",
                "src_port": "src_port",
                "dest_port": "dest_port",
                "proto": "proto",
                "family": "family",
                "description": "name",
            }
            for key, uci_key in _map.items():
                if key in rule:
                    values[uci_key] = rule[key]
            if "enabled" in rule:
                values["enabled"] = "1" if rule["enabled"] else "0"
            return await self._uci_update(
                "firewall",
                "rule",
                uuid,
                values,
                "firewall",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def toggle_firewall_rule(
        self,
        uuid: str,
        enabled: bool,
    ) -> AdapterResult:
        try:
            return await self._uci_update(
                "firewall",
                "rule",
                uuid,
                {"enabled": "1" if enabled else "0"},
                "firewall",
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def apply_firewall_changes(self) -> AdapterResult:
        # OpenWRT applies on uci commit + service restart — no extra step
        return AdapterResult.ok(message="Firewall changes applied")

    # ═══════════════════════════════════════════════════════════════════════
    # Port Forwards (DNAT)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_port_forwards(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("firewall")
            forwards = []
            for name, section in self._uci_sections(raw, "redirect"):
                if section.get("target", "DNAT") != "DNAT":
                    continue
                forwards.append(
                    {
                        "id": _stable_id("firewall", "redirect", name),
                        "uci_name": name,
                        "name": section.get("name", ""),
                        "enabled": section.get("enabled", "1") != "0",
                        "interface": section.get("src", ""),
                        "protocol": section.get("proto", ""),
                        "source_port": section.get("src_dport", ""),
                        "destination_port": section.get("dest_port", ""),
                        "target_ip": section.get("dest_ip", ""),
                        "target_port": section.get("dest_port", ""),
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(
                data={"port_forwards": forwards, "count": len(forwards)},
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_port_forward(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            values: dict[str, Any] = {
                "target": "DNAT",
                "src": rule.get("interface", rule.get("src", "wan")),
                "dest": rule.get("dest", "lan"),
                "proto": rule.get("protocol", rule.get("proto", "tcp")),
                "src_dport": str(rule.get("source_port", rule.get("src_dport", ""))),
                "dest_ip": rule.get("target_ip", rule.get("dest_ip", "")),
                "dest_port": str(rule.get("destination_port", rule.get("dest_port", ""))),
            }
            if rule.get("name"):
                values["name"] = rule["name"]
            if "enabled" in rule:
                values["enabled"] = "1" if rule["enabled"] else "0"

            result = await self._api.uci_add("firewall", "redirect", values=values)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(data=result, message="Port forward created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_port_forward(
        self,
        uuid: str,
        rule: dict[str, Any],
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            if "name" in rule:
                values["name"] = rule["name"]
            if "protocol" in rule or "proto" in rule:
                values["proto"] = rule.get("protocol", rule.get("proto"))
            if "source_port" in rule or "src_dport" in rule:
                values["src_dport"] = str(rule.get("source_port", rule.get("src_dport")))
            if "target_ip" in rule or "dest_ip" in rule:
                values["dest_ip"] = rule.get("target_ip", rule.get("dest_ip"))
            if "destination_port" in rule or "dest_port" in rule:
                values["dest_port"] = str(rule.get("destination_port", rule.get("dest_port")))
            if "enabled" in rule:
                values["enabled"] = "1" if rule["enabled"] else "0"
            return await self._uci_update(
                "firewall",
                "redirect",
                uuid,
                values,
                "firewall",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_port_forward(
        self,
        uuid: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            return await self._uci_delete_section(
                "firewall",
                "redirect",
                uuid,
                "firewall",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Source NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_source_nat_rules(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("firewall")
            rules = []
            for name, section in self._uci_sections(raw, "redirect"):
                if section.get("target") != "SNAT":
                    continue
                rules.append(
                    {
                        "id": _stable_id("firewall", "redirect", name),
                        "uci_name": name,
                        "name": section.get("name", ""),
                        "enabled": section.get("enabled", "1") != "0",
                        "target": "SNAT",
                        "src": section.get("src", ""),
                        "dest": section.get("dest", ""),
                        "src_ip": section.get("src_ip", ""),
                        "dest_ip": section.get("dest_ip", ""),
                        "dest_port": section.get("dest_port", ""),
                        "proto": section.get("proto", ""),
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(data={"rules": rules, "count": len(rules)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_source_nat_rule(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            values: dict[str, Any] = {
                "target": "SNAT",
                "src": rule.get("src", "lan"),
                "dest": rule.get("dest", "wan"),
                "proto": rule.get("proto", "all"),
            }
            for key in ("name", "src_ip", "dest_ip", "dest_port", "src_dip"):
                if rule.get(key):
                    values[key] = rule[key]
            if "enabled" in rule:
                values["enabled"] = "1" if rule["enabled"] else "0"

            result = await self._api.uci_add("firewall", "redirect", values=values)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(data=result, message="Source NAT rule created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_source_nat_rule(
        self,
        uuid: str,
        rule: dict[str, Any],
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            for key in (
                "name",
                "src",
                "dest",
                "src_ip",
                "dest_ip",
                "dest_port",
                "proto",
                "src_dip",
            ):
                if key in rule:
                    values[key] = rule[key]
            if "enabled" in rule:
                values["enabled"] = "1" if rule["enabled"] else "0"
            return await self._uci_update(
                "firewall",
                "redirect",
                uuid,
                values,
                "firewall",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_source_nat_rule(
        self,
        uuid: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            return await self._uci_delete_section(
                "firewall",
                "redirect",
                uuid,
                "firewall",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # NAT Rules
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("firewall")
            rules = []
            for name, section in self._uci_sections(raw, "redirect"):
                rules.append(
                    {
                        "id": _stable_id("firewall", "redirect", name),
                        "uci_name": name,
                        "name": section.get("name", ""),
                        "enabled": section.get("enabled", "1") != "0",
                        "target": section.get("target", "DNAT"),
                        "src": section.get("src", ""),
                        "dest": section.get("dest", ""),
                        "src_dip": section.get("src_dip", ""),
                        "src_dport": section.get("src_dport", ""),
                        "dest_ip": section.get("dest_ip", ""),
                        "dest_port": section.get("dest_port", ""),
                        "proto": section.get("proto", ""),
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(data={"rules": rules, "count": len(rules)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_leases(self) -> AdapterResult:
        try:
            raw = await self._api.get_dhcp_leases()
            leases = []
            for entry in raw.get("dhcp_leases", raw.get("leases", [])):
                if isinstance(entry, dict):
                    leases.append(
                        {
                            "mac_address": entry.get("macaddr", entry.get("mac", "")),
                            "ip_address": entry.get("ipaddr", entry.get("ip", "")),
                            "hostname": entry.get("hostname", ""),
                            "expires": entry.get("expires", 0),
                            "status": "active",
                        }
                    )
            return AdapterResult.ok(data={"leases": leases, "count": len(leases)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_dhcp_static_mappings(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("dhcp")
            hosts = []
            for name, section in self._uci_sections(raw, "host"):
                hosts.append(
                    {
                        "id": _stable_id("dhcp", "host", name),
                        "uci_name": name,
                        "mac_address": section.get("mac", ""),
                        "ip_address": section.get("ip", ""),
                        "hostname": section.get("name", ""),
                        "dns": section.get("dns", "1") == "1",
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(data={"static_mappings": hosts, "count": len(hosts)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_dhcp_static_mapping(
        self,
        mapping: dict[str, Any],
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {
                "mac": mapping.get("mac_address", mapping.get("mac", "")),
                "ip": mapping.get("ip_address", mapping.get("ip", "")),
                "name": mapping.get("hostname", mapping.get("name", "")),
            }
            if "dns" in mapping:
                values["dns"] = "1" if mapping["dns"] else "0"

            result = await self._api.uci_add("dhcp", "host", values=values)
            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")
            return AdapterResult.ok(data=result, message="DHCP static mapping created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_dhcp_static_mapping(
        self,
        uuid: str,
        mapping: dict[str, Any],
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            if "mac_address" in mapping or "mac" in mapping:
                values["mac"] = mapping.get("mac_address", mapping.get("mac"))
            if "ip_address" in mapping or "ip" in mapping:
                values["ip"] = mapping.get("ip_address", mapping.get("ip"))
            if "hostname" in mapping or "name" in mapping:
                values["name"] = mapping.get("hostname", mapping.get("name"))
            if "dns" in mapping:
                values["dns"] = "1" if mapping["dns"] else "0"
            return await self._uci_update(
                "dhcp",
                "host",
                uuid,
                values,
                "dnsmasq",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_dhcp_static_mapping(
        self,
        uuid: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            return await self._uci_delete_section(
                "dhcp",
                "host",
                uuid,
                "dnsmasq",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_overrides(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("dhcp")
            overrides = []
            for name, section in self._uci_sections(raw, "domain"):
                overrides.append(
                    {
                        "id": _stable_id("dhcp", "domain", name),
                        "uci_name": name,
                        "hostname": section.get("name", ""),
                        "ip_address": section.get("ip", ""),
                        "description": section.get("name", ""),
                    }
                )
            return AdapterResult.ok(data={"overrides": overrides, "count": len(overrides)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_dns_override(
        self,
        override: dict[str, Any],
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {
                "name": override.get("hostname", override.get("name", "")),
                "ip": override.get("ip_address", override.get("ip", "")),
            }
            result = await self._api.uci_add("dhcp", "domain", values=values)
            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")
            return AdapterResult.ok(data=result, message="DNS override created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_dns_override(
        self,
        uuid: str,
        override: dict[str, Any],
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            if "hostname" in override or "name" in override:
                values["name"] = override.get("hostname", override.get("name"))
            if "ip_address" in override or "ip" in override:
                values["ip"] = override.get("ip_address", override.get("ip"))
            return await self._uci_update(
                "dhcp",
                "domain",
                uuid,
                values,
                "dnsmasq",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_dns_override(
        self,
        uuid: str,
        *,
        uci_name: str | None = None,
    ) -> AdapterResult:
        try:
            return await self._uci_delete_section(
                "dhcp",
                "domain",
                uuid,
                "dnsmasq",
                uci_name=uci_name,
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS Domain Overrides (conditional forwarding)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_domain_overrides(self) -> AdapterResult:
        """Parse dnsmasq server list entries (format: /{domain}/{ip})."""
        try:
            raw = await self._api.uci_get_all("dhcp")
            overrides = []
            # Find dnsmasq section and its server list
            for name, section in self._uci_sections(raw, "dnsmasq"):
                servers = section.get("server", [])
                if isinstance(servers, str):
                    servers = [servers]
                for idx, entry in enumerate(servers):
                    # Format: /{domain}/{ip} or just {ip}
                    if entry.startswith("/"):
                        parts = entry.strip("/").split("/")
                        if len(parts) >= 2:
                            domain, server = parts[0], parts[1]
                            overrides.append(
                                {
                                    "id": _stable_id("dhcp", "dnsmasq_server", name, str(idx)),
                                    "domain": domain,
                                    "server": server,
                                    "description": f"{domain} → {server}",
                                    "enabled": True,
                                }
                            )
                break  # typically one dnsmasq section
            return AdapterResult.ok(
                data={"domain_overrides": overrides, "count": len(overrides)},
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_dns_domain_override(
        self,
        override: dict[str, Any],
    ) -> AdapterResult:
        try:
            domain = override.get("domain", "")
            server = override.get("server", "")
            if not domain or not server:
                return AdapterResult.fail("domain and server are required")

            entry = f"/{domain}/{server}"
            raw = await self._api.uci_get_all("dhcp")
            for name, section in self._uci_sections(raw, "dnsmasq"):
                servers = section.get("server", [])
                if isinstance(servers, str):
                    servers = [servers]
                servers.append(entry)
                await self._api.uci_set("dhcp", name, {"server": servers})
                break

            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")
            return AdapterResult.ok(message=f"DNS domain override for {domain} created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_dns_domain_override(
        self,
        uuid: str,
        override: dict[str, Any],
    ) -> AdapterResult:
        try:
            domain = override.get("domain", "")
            server = override.get("server", "")
            if not domain or not server:
                return AdapterResult.fail("domain and server are required")

            raw = await self._api.uci_get_all("dhcp")
            for name, section in self._uci_sections(raw, "dnsmasq"):
                servers = section.get("server", [])
                if isinstance(servers, str):
                    servers = [servers]
                # Find and replace matching entry by UUID
                new_servers = []
                for idx, entry in enumerate(servers):
                    sid = _stable_id("dhcp", "dnsmasq_server", name, str(idx))
                    if sid == uuid:
                        new_servers.append(f"/{domain}/{server}")
                    else:
                        new_servers.append(entry)
                await self._api.uci_set("dhcp", name, {"server": new_servers})
                break

            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")
            return AdapterResult.ok(message="DNS domain override updated")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_dns_domain_override(self, uuid: str) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("dhcp")
            for name, section in self._uci_sections(raw, "dnsmasq"):
                servers = section.get("server", [])
                if isinstance(servers, str):
                    servers = [servers]
                new_servers = []
                for idx, entry in enumerate(servers):
                    sid = _stable_id("dhcp", "dnsmasq_server", name, str(idx))
                    if sid != uuid:
                        new_servers.append(entry)
                await self._api.uci_set("dhcp", name, {"server": new_servers})
                break

            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")
            return AdapterResult.ok(message="DNS domain override deleted")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Static Routes
    # ═══════════════════════════════════════════════════════════════════════

    async def get_static_routes(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("network")
            routes = []
            for name, section in self._uci_sections(raw, "route"):
                routes.append(
                    {
                        "id": _stable_id("network", "route", name),
                        "uci_name": name,
                        "interface": section.get("interface", ""),
                        "target": section.get("target", ""),
                        "netmask": section.get("netmask", ""),
                        "gateway": section.get("gateway", ""),
                        "metric": int(section.get("metric", 0) or 0),
                        "description": section.get("comment", ""),
                    }
                )
            return AdapterResult.ok(data={"routes": routes, "count": len(routes)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_static_route(self, route: dict[str, Any]) -> AdapterResult:
        try:
            values: dict[str, Any] = {
                "interface": route.get("interface", "lan"),
                "target": route.get("target", route.get("destination", "")),
                "gateway": route.get("gateway", ""),
            }
            if route.get("netmask"):
                values["netmask"] = route["netmask"]
            if route.get("metric"):
                values["metric"] = str(route["metric"])
            if route.get("description") or route.get("comment"):
                values["comment"] = route.get("description", route.get("comment", ""))

            result = await self._api.uci_add("network", "route", values=values)
            await self._api.uci_commit("network")
            await self._api.reload_network()
            return AdapterResult.ok(data=result, message="Static route created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_static_route(
        self,
        uuid: str,
        route: dict[str, Any],
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            for key in ("interface", "target", "netmask", "gateway"):
                if key in route:
                    values[key] = route[key]
            if "destination" in route:
                values["target"] = route["destination"]
            if "metric" in route:
                values["metric"] = str(route["metric"])
            if "description" in route or "comment" in route:
                values["comment"] = route.get("description", route.get("comment", ""))
            return await self._uci_update("network", "route", uuid, values, "network")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_static_route(self, uuid: str) -> AdapterResult:
        try:
            return await self._uci_delete_section("network", "route", uuid, "network")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_routing_table(self) -> AdapterResult:
        """Return kernel routing table entries."""
        try:
            ifaces = await self._api.get_network_interfaces()
            entries = []
            for iface in ifaces.get("interface", []):
                for route in iface.get("route", []):
                    entries.append(
                        {
                            "destination": route.get("target", ""),
                            "gateway": route.get("nexthop", "0.0.0.0"),
                            "flags": "UG" if route.get("nexthop") else "U",
                            "interface": iface.get("interface", ""),
                            "metric": route.get("metric", 0),
                        }
                    )
            return AdapterResult.ok(data={"entries": entries, "count": len(entries)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> AdapterResult:
        try:
            raw = await self._api.get_services()
            services = []
            for svc_name, svc_data in raw.items():
                if not isinstance(svc_data, dict):
                    continue
                instances = svc_data.get("instances", {})
                running = (
                    any(
                        inst.get("running", False)
                        for inst in instances.values()
                        if isinstance(inst, dict)
                    )
                    if instances
                    else False
                )
                services.append(
                    {
                        "name": svc_name,
                        "status": "running" if running else "stopped",
                        "running": running,
                        "instances": len(instances),
                    }
                )
            return AdapterResult.ok(data={"services": services, "count": len(services)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def restart_service(self, service_name: str) -> AdapterResult:
        _ALLOWED_SERVICES = {
            "network",
            "firewall",
            "dnsmasq",
            "odhcpd",
            "uhttpd",
            "dropbear",
            "cron",
            "sysntpd",
            "wireguard",
            "openvpn",
            "sqm",
        }
        if service_name not in _ALLOWED_SERVICES:
            return AdapterResult.fail(
                f"Service '{service_name}' not in allowed list",
                error_code="SERVICE_NOT_ALLOWED",
            )
        try:
            result = await self._api.restart_service(service_name)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

        # ``client.restart_service`` SWALLOWS ubus failures and returns a
        # ``{"reload_skipped": True, "reason": ...}`` sentinel instead of
        # raising. That is deliberate and right for the reload that follows a
        # UCI write: the config was already committed, so a refused reload
        # should not 503 a write that landed.
        #
        # It is wrong here. This method is the operator pressing "Restart" on a
        # service, and there is no committed write behind it -- the restart IS
        # the whole action. Inheriting the swallow meant ubus answering
        # "Access denied" (the common case: OpenWrt 24.10+ needs an explicit
        # ``rc.exec`` ACL grant, which the docs call out) produced HTTP 200
        # "Restarted dnsmasq" while nothing had restarted.
        if isinstance(result, dict) and result.get("reload_skipped"):
            reason = result.get("reason") or "ubus refused the request"
            return AdapterResult.fail(
                f"Could not restart {service_name}: {reason}",
                error_code="SERVICE_RESTART_REFUSED",
            )
        return AdapterResult.ok(message=f"Restarted {service_name}")

    async def start_service(self, service_name: str) -> AdapterResult:
        _ALLOWED_SERVICES = {
            "network",
            "firewall",
            "dnsmasq",
            "odhcpd",
            "uhttpd",
            "dropbear",
            "cron",
            "sysntpd",
            "wireguard",
            "openvpn",
            "sqm",
        }
        if service_name not in _ALLOWED_SERVICES:
            return AdapterResult.fail(
                f"Service '{service_name}' not in allowed list",
                error_code="SERVICE_NOT_ALLOWED",
            )
        try:
            await self._api.start_service(service_name)
            return AdapterResult.ok(message=f"Started {service_name}")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def stop_service(self, service_name: str) -> AdapterResult:
        _ALLOWED_SERVICES = {
            "network",
            "firewall",
            "dnsmasq",
            "odhcpd",
            "uhttpd",
            "dropbear",
            "cron",
            "sysntpd",
            "wireguard",
            "openvpn",
            "sqm",
        }
        if service_name not in _ALLOWED_SERVICES:
            return AdapterResult.fail(
                f"Service '{service_name}' not in allowed list",
                error_code="SERVICE_NOT_ALLOWED",
            )
        try:
            await self._api.stop_service(service_name)
            return AdapterResult.ok(message=f"Stopped {service_name}")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # System & Monitoring
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_info(self) -> AdapterResult:
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            release = board.get("release", {})
            memory = info.get("memory", {})
            load = info.get("load", [0, 0, 0])
            return AdapterResult.ok(
                data={
                    "hostname": board.get("hostname", ""),
                    "model": board.get("model", ""),
                    "board_name": board.get("board_name", ""),
                    "kernel": board.get("kernel", ""),
                    "release_distribution": release.get("distribution", "OpenWrt"),
                    "release_version": release.get("version", ""),
                    "release_revision": release.get("revision", ""),
                    "release_description": release.get("description", ""),
                    "uptime": info.get("uptime", 0),
                    "localtime": info.get("localtime", 0),
                    "load_1m": load[0] if len(load) > 0 else 0,
                    "load_5m": load[1] if len(load) > 1 else 0,
                    "load_15m": load[2] if len(load) > 2 else 0,
                    "memory_total": memory.get("total", 0),
                    "memory_free": memory.get("free", 0),
                    "memory_buffered": memory.get("buffered", 0),
                    "memory_shared": memory.get("shared", 0),
                    "swap_total": memory.get("swap_total", info.get("swap", {}).get("total", 0)),
                    "swap_free": memory.get("swap_free", info.get("swap", {}).get("free", 0)),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_system_resources(self) -> AdapterResult:
        try:
            info = await self._api.get_system_info()
            memory = info.get("memory", {})
            load = info.get("load", [0, 0, 0])
            mem_total = memory.get("total", 0)
            mem_free = memory.get("free", 0)
            mem_used = mem_total - mem_free if mem_total else 0
            return AdapterResult.ok(
                data={
                    "cpu_usage": None,  # Not available via ubus
                    "memory_total": mem_total,
                    "memory_used": mem_used,
                    "memory_free": mem_free,
                    "memory_usage_percent": round(mem_used / mem_total * 100, 1)
                    if mem_total
                    else 0,
                    "swap_total": memory.get("swap_total", info.get("swap", {}).get("total", 0)),
                    "swap_used": None,
                    "uptime": info.get("uptime", 0),
                    "load_average": load,
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def reboot_device(self, device_id: str = "") -> AdapterResult:
        try:
            await self._api.reboot()
            return AdapterResult.ok(message="Device rebooting")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def halt_device(self, device_id: str = "") -> AdapterResult:
        try:
            await self._api.halt()
            return AdapterResult.ok(message="Device shutting down")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_system_log(self, limit: int = 100) -> AdapterResult:
        try:
            raw = await self._api.get_system_log(lines=limit)
            entries = []
            log_data = raw.get("log", raw.get("data", []))
            if isinstance(log_data, str):
                # Parse syslog text lines
                for line in log_data.strip().splitlines()[-limit:]:
                    entries.append(
                        {
                            "timestamp": "",
                            "priority": "",
                            "facility": "",
                            "message": line,
                        }
                    )
            elif isinstance(log_data, list):
                for entry in log_data[-limit:]:
                    if isinstance(entry, dict):
                        entries.append(
                            {
                                "timestamp": str(entry.get("time", entry.get("timestamp", ""))),
                                "priority": str(entry.get("priority", "")),
                                "facility": str(entry.get("facility", "")),
                                "message": entry.get("msg", entry.get("message", "")),
                            }
                        )
                    elif isinstance(entry, str):
                        entries.append(
                            {
                                "timestamp": "",
                                "priority": "",
                                "facility": "",
                                "message": entry,
                            }
                        )
            return AdapterResult.ok(data={"logs": entries, "count": len(entries)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_firewall_log(self, limit: int = 100) -> AdapterResult:
        try:
            result = await self.get_system_log(limit=500)
            if not result.success:
                return result
            logs = result.data.get("logs", []) if result.data else []
            fw_logs = []
            for entry in logs:
                msg = entry.get("message", "")
                if any(kw in msg for kw in ("DROP", "REJECT", "ACCEPT", "fw3", "nft", "iptables")):
                    fw_logs.append(entry)
                    if len(fw_logs) >= limit:
                        break
            return AdapterResult.ok(data={"logs": fw_logs, "count": len(fw_logs)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_firmware_info(self) -> AdapterResult:
        try:
            board = await self._api.get_board_info()
            release = board.get("release", {})
            return AdapterResult.ok(
                data={
                    "product_name": board.get("model", ""),
                    "product_version": release.get("version", ""),
                    "product_series": release.get("distribution", "OpenWrt"),
                    "product_revision": release.get("revision", ""),
                    "product_id": board.get("board_name", ""),
                    "description": release.get("description", ""),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_installed_packages(self) -> AdapterResult:
        try:
            raw = await self._api.get_package_list()
            packages = raw.get("packages", {})
            pkg_list = []
            if isinstance(packages, dict):
                for name, version in packages.items():
                    pkg_list.append({"name": name, "version": version})
            elif isinstance(packages, list):
                for pkg in packages:
                    if isinstance(pkg, dict):
                        pkg_list.append(pkg)
                    else:
                        pkg_list.append({"name": str(pkg), "version": ""})
            return AdapterResult.ok(
                data={"packages": pkg_list, "count": len(pkg_list)},
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_backup_list(self) -> AdapterResult:
        # OpenWRT doesn't maintain a backup history
        return AdapterResult.ok(data={"backups": [], "count": 0})

    async def download_config(self) -> AdapterResult:
        try:
            return await self.create_backup()
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_backup(self, filename: str) -> AdapterResult:
        return AdapterResult.fail(
            "OpenWRT does not support backup deletion",
            error_code="NOT_SUPPORTED",
        )

    async def revert_backup(self, filename: str) -> AdapterResult:
        return AdapterResult.fail(
            "OpenWRT does not support backup restore via API",
            error_code="NOT_SUPPORTED",
        )

    async def get_cron_jobs(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("system")
            crons = []
            for name, section in self._uci_sections(raw, "crontab"):
                crons.append(
                    {
                        "id": _stable_id("system", "crontab", name),
                        "command": section.get("command", ""),
                        "schedule": section.get("schedule", ""),
                        "enabled": section.get("enabled", "1") != "0",
                    }
                )
            return AdapterResult.ok(data={"cron_jobs": crons, "count": len(crons)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_disk_usage(self) -> AdapterResult:
        try:
            raw = await self._api.get_filesystem_usage()
            return AdapterResult.ok(data=raw if raw else {"note": "Disk usage not available"})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def health_check(self) -> AdapterResult:
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            return AdapterResult.ok(
                data={
                    "status": "healthy",
                    "hostname": board.get("hostname", ""),
                    "uptime": info.get("uptime", 0),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(f"Health check failed: {exc}")

    async def get_gateway_status(self) -> AdapterResult:
        try:
            ifaces = await self._api.get_network_interfaces()
            gateways = []
            for iface in ifaces.get("interface", []):
                name = iface.get("interface", "")
                if name.lower() not in ("wan", "wan6"):
                    continue
                up = iface.get("up", False)
                routes = iface.get("route", [])
                gw_addr = ""
                for r in routes:
                    if r.get("target") == "0.0.0.0" and r.get("nexthop"):
                        gw_addr = r["nexthop"]
                        break
                ipv4_addrs = iface.get("ipv4-address", [])
                addr = ipv4_addrs[0].get("address", "") if ipv4_addrs else ""
                gateways.append(
                    {
                        "name": name,
                        "address": gw_addr or addr,
                        "status": "online" if up else "offline",
                        "interface": iface.get("device", iface.get("l3_device", "")),
                        "default_gateway": bool(gw_addr),
                    }
                )
            return AdapterResult.ok(
                data={"gateways": gateways, "count": len(gateways)},
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — WireGuard
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vpn_status(self) -> AdapterResult:
        tunnels: dict[str, Any] = {"wireguard": [], "openvpn": []}
        try:
            if self._capabilities.get("wireguard"):
                raw = await self._api.uci_get_all("network")
                for name, section in self._uci_sections(raw, "interface"):
                    if section.get("proto") == "wireguard":
                        tunnels["wireguard"].append(
                            {
                                "name": name,
                                "private_key": "***",
                                "listen_port": section.get("listen_port", ""),
                                "addresses": section.get("addresses", []),
                            }
                        )
        except Exception as exc:
            logger.debug("WireGuard status failed: %s", exc)

        try:
            if self._capabilities.get("openvpn"):
                raw = await self._api.uci_get_all("openvpn")
                for name, section in self._uci_sections(raw, "openvpn"):
                    tunnels["openvpn"].append(
                        {
                            "name": name,
                            "enabled": section.get("enabled", "1") != "0",
                            "proto": section.get("proto", ""),
                            "dev": section.get("dev", ""),
                        }
                    )
        except Exception as exc:
            logger.debug("OpenVPN status failed: %s", exc)

        return AdapterResult.ok(data={"tunnels": tunnels})

    async def get_wireguard_servers(self) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.ok(data={"servers": [], "count": 0})
        try:
            raw = await self._api.uci_get_all("network")
            servers = []
            for name, section in self._uci_sections(raw, "interface"):
                if section.get("proto") != "wireguard":
                    continue
                addrs = section.get("addresses", [])
                if isinstance(addrs, str):
                    addrs = [addrs]
                servers.append(
                    {
                        "id": _stable_id("network", "wireguard", name),
                        "uci_name": name,
                        "name": name,
                        "enabled": not section.get("disabled", False),
                        "listen_port": int(section.get("listen_port", 0) or 0),
                        "addresses": addrs,
                        "public_key": "***",  # private key present, public derived
                    }
                )
            return AdapterResult.ok(data={"servers": servers, "count": len(servers)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_wireguard_peers(self) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.ok(data={"peers": [], "count": 0})
        try:
            raw = await self._api.uci_get_all("network")
            peers = []
            for name, section in self._uci_sections(raw):
                stype = section.get(".type", "")
                if not stype.startswith("wireguard_"):
                    continue
                allowed = section.get("allowed_ips", [])
                if isinstance(allowed, str):
                    allowed = [allowed]
                peers.append(
                    {
                        "id": _stable_id("network", "wireguard_peer", name),
                        "uci_name": name,
                        "name": section.get("description", name),
                        "enabled": not section.get("disabled", False),
                        "public_key": section.get("public_key", ""),
                        "endpoint_host": section.get("endpoint_host", ""),
                        "endpoint_port": int(section.get("endpoint_port", 0) or 0),
                        "allowed_ips": allowed,
                        "persistent_keepalive": int(section.get("persistent_keepalive", 0) or 0),
                    }
                )
            return AdapterResult.ok(data={"peers": peers, "count": len(peers)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_wireguard_server(
        self,
        server: dict[str, Any],
    ) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
        try:
            iface_name = server.get("name", "wg0")
            values: dict[str, Any] = {
                "proto": "wireguard",
                "private_key": server.get("private_key", ""),
                "listen_port": str(server.get("listen_port", 51820)),
            }
            addrs = server.get("addresses", [])
            if addrs:
                values["addresses"] = addrs

            await self._api.uci_set("network", iface_name, values)
            await self._api.uci_commit("network")
            await self._api.reload_network()
            return AdapterResult.ok(
                data={"name": iface_name},
                message=f"WireGuard interface {iface_name} created",
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_wireguard_server(
        self,
        uuid: str,
        server: dict[str, Any],
    ) -> AdapterResult:
        try:
            if not self._capabilities.get("wireguard"):
                return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
            values: dict[str, Any] = {}
            if "listen_port" in server:
                values["listen_port"] = str(server["listen_port"])
            if "addresses" in server:
                values["addresses"] = server["addresses"]
            if "private_key" in server:
                values["private_key"] = server["private_key"]
            return await self._uci_update("network", "interface", uuid, values, "network")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_wireguard_server(self, uuid: str) -> AdapterResult:
        try:
            if not self._capabilities.get("wireguard"):
                return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
            return await self._uci_delete_section("network", "interface", uuid, "network")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_wireguard_peer(
        self,
        peer: dict[str, Any],
    ) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
        try:
            iface = peer.get("interface", "wg0")
            values: dict[str, Any] = {
                "public_key": peer.get("public_key", ""),
            }
            if peer.get("endpoint_host"):
                values["endpoint_host"] = peer["endpoint_host"]
            if peer.get("endpoint_port"):
                values["endpoint_port"] = str(peer["endpoint_port"])
            if peer.get("allowed_ips"):
                values["allowed_ips"] = peer["allowed_ips"]
            if peer.get("persistent_keepalive"):
                values["persistent_keepalive"] = str(peer["persistent_keepalive"])
            if peer.get("description") or peer.get("name"):
                values["description"] = peer.get("description", peer.get("name", ""))

            result = await self._api.uci_add(
                "network",
                f"wireguard_{iface}",
                values=values,
            )
            await self._api.uci_commit("network")
            await self._api.reload_network()
            return AdapterResult.ok(data=result, message="WireGuard peer created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_wireguard_peer(
        self,
        uuid: str,
        peer: dict[str, Any],
    ) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
        values: dict[str, Any] = {}
        for key in ("public_key", "endpoint_host", "description"):
            if key in peer:
                values[key] = peer[key]
        if "endpoint_port" in peer:
            values["endpoint_port"] = str(peer["endpoint_port"])
        if "allowed_ips" in peer:
            values["allowed_ips"] = peer["allowed_ips"]
        if "persistent_keepalive" in peer:
            values["persistent_keepalive"] = str(peer["persistent_keepalive"])
        # Find the matching wireguard_ section type
        try:
            raw = await self._api.uci_get_all("network")
            for name, section in self._uci_sections(raw):
                stype = section.get(".type", "")
                if stype.startswith("wireguard_"):
                    sid = _stable_id("network", "wireguard_peer", name)
                    if sid == uuid:
                        await self._api.uci_set("network", name, values)
                        await self._api.uci_commit("network")
                        await self._api.reload_network()
                        return AdapterResult.ok(message=f"WireGuard peer {name} updated")
            return AdapterResult.fail("Peer not found", error_code="NOT_FOUND")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_wireguard_peer(self, uuid: str) -> AdapterResult:
        if not self._capabilities.get("wireguard"):
            return AdapterResult.fail("WireGuard not installed", error_code="NOT_SUPPORTED")
        try:
            raw = await self._api.uci_get_all("network")
            for name, section in self._uci_sections(raw):
                stype = section.get(".type", "")
                if stype.startswith("wireguard_"):
                    sid = _stable_id("network", "wireguard_peer", name)
                    if sid == uuid:
                        await self._api.uci_delete("network", name)
                        await self._api.uci_commit("network")
                        await self._api.reload_network()
                        return AdapterResult.ok(message=f"WireGuard peer {name} deleted")
            return AdapterResult.ok(
                data={"id": uuid, "already_absent": True},
                message="Peer not found — nothing to delete",
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_wireguard_handshakes(self) -> AdapterResult:
        # Not available via ubus
        return AdapterResult.ok(data={"handshakes": [], "count": 0})

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — OpenVPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_openvpn_status(self) -> AdapterResult:
        if not self._capabilities.get("openvpn"):
            return AdapterResult.ok(data={"instances": [], "count": 0})
        try:
            raw = await self._api.uci_get_all("openvpn")
            instances = []
            for name, section in self._uci_sections(raw, "openvpn"):
                instances.append(
                    {
                        "id": _stable_id("openvpn", "openvpn", name),
                        "uci_name": name,
                        "name": name,
                        "enabled": section.get("enabled", "1") != "0",
                        "proto": section.get("proto", ""),
                        "dev": section.get("dev", ""),
                        "port": section.get("port", ""),
                        "mode": section.get("mode", ""),
                    }
                )
            return AdapterResult.ok(
                data={"instances": instances, "count": len(instances)},
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_openvpn_instance(
        self,
        config: dict[str, Any],
    ) -> AdapterResult:
        if not self._capabilities.get("openvpn"):
            return AdapterResult.fail("OpenVPN not installed", error_code="NOT_SUPPORTED")
        try:
            name = config.pop("name", None)
            values = {k: v for k, v in config.items() if k not in ("id", "uci_name")}
            result = await self._api.uci_add("openvpn", "openvpn", name=name, values=values)
            await self._api.uci_commit("openvpn")
            await self._api.restart_service("openvpn")
            return AdapterResult.ok(data=result, message="OpenVPN instance created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_openvpn_instance(
        self,
        uuid: str,
        config: dict[str, Any],
    ) -> AdapterResult:
        try:
            if not self._capabilities.get("openvpn"):
                return AdapterResult.fail("OpenVPN not installed", error_code="NOT_SUPPORTED")
            values = {k: v for k, v in config.items() if k not in ("id", "uci_name", "name")}
            return await self._uci_update("openvpn", "openvpn", uuid, values, "openvpn")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_openvpn_instance(self, uuid: str) -> AdapterResult:
        try:
            if not self._capabilities.get("openvpn"):
                return AdapterResult.fail("OpenVPN not installed", error_code="NOT_SUPPORTED")
            return await self._uci_delete_section("openvpn", "openvpn", uuid, "openvpn")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_openvpn_sessions(self) -> AdapterResult:
        # Not easily available via ubus
        return AdapterResult.ok(data={"sessions": [], "count": 0})

    async def kill_openvpn_session(self, session_id: str) -> AdapterResult:
        return AdapterResult.fail(
            "OpenVPN session kill not supported via ubus",
            error_code="NOT_SUPPORTED",
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Aliases / Address Groups (ipset)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_aliases(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("firewall")
            groups = []
            for name, section in self._uci_sections(raw, "ipset"):
                entries = section.get("entry", [])
                if isinstance(entries, str):
                    entries = [entries]
                groups.append(
                    {
                        "id": _stable_id("firewall", "ipset", name),
                        "uci_name": name,
                        "name": section.get("name", name),
                        "match": section.get("match", "src_net"),
                        "storage": section.get("storage", "hash"),
                        "enabled": section.get("enabled", "1") != "0",
                        "entries": entries,
                        "description": section.get("comment", ""),
                    }
                )
            return AdapterResult.ok(data={"aliases": groups, "count": len(groups)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_alias(
        self,
        alias: dict[str, Any] | None = None,
        *,
        name: str = "",
        type: str = "",
        members: list[str] | None = None,
        description: str = "",
    ) -> AdapterResult:
        try:
            if alias is None:
                alias_name = name
                entries = members or []
            else:
                alias_name = alias.get("name", "")
                entries = alias.get("members", alias.get("entry", []))
                if isinstance(entries, str):
                    entries = entries.split("\n")

            values: dict[str, Any] = {
                "name": alias_name,
                "match": "src_net",
                "storage": "hash",
                "enabled": "1",
            }
            if entries:
                values["entry"] = entries
            if description:
                values["comment"] = description

            result = await self._api.uci_add("firewall", "ipset", values=values)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(data=result, message=f"ipset '{alias_name}' created")
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_alias(
        self,
        uuid: str,
        alias: dict[str, Any],
    ) -> AdapterResult:
        try:
            values: dict[str, Any] = {}
            if "name" in alias:
                values["name"] = alias["name"]
            if "entries" in alias or "members" in alias:
                entries = alias.get("entries", alias.get("members", []))
                if isinstance(entries, str):
                    entries = entries.split("\n")
                values["entry"] = entries
            if "match" in alias:
                values["match"] = alias["match"]
            if "enabled" in alias:
                values["enabled"] = "1" if alias["enabled"] else "0"
            if "description" in alias:
                values["comment"] = alias["description"]
            return await self._uci_update("firewall", "ipset", uuid, values, "firewall")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_alias(
        self,
        uuid: str | None = None,
        *,
        name: str = "",
    ) -> AdapterResult:
        try:
            target_section = None
            # ``uuid`` was declared, accepted, and READ BY NOTHING. Deleting an
            # alias by id therefore fell through to the failure below and told
            # the caller "Either uuid or name required" -- while holding the
            # uuid they had just supplied. Delete-by-id was impossible, and the
            # error blamed the caller for the adapter's own gap.
            #
            # ``update_alias`` directly above resolves the same identifier with
            # ``_find_uci_section``; use it here so the two agree on what an
            # alias id means.
            if uuid:
                raw = await self._api.uci_get_all("firewall")
                target_section = self._find_uci_section(raw, "ipset", uuid)
            if not target_section and name:
                raw = await self._api.uci_get_all("firewall")
                for sec_name, section in self._uci_sections(raw, "ipset"):
                    if section.get("name", sec_name) == name:
                        target_section = sec_name
                        break
            if not target_section:
                if name or uuid:
                    # Idempotent delete: already gone is the desired state.
                    return AdapterResult.ok(
                        data={"name": name, "uuid": uuid, "already_absent": True},
                        message=f"ipset {name or uuid!r} not found",
                    )
                return AdapterResult.fail("Either uuid or name required")

            await self._api.uci_delete("firewall", target_section)
            await self._api.uci_commit("firewall")
            await self._api.restart_service("firewall")
            return AdapterResult.ok(message=f"ipset {name or uuid!r} deleted")
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Network Tables
    # ═══════════════════════════════════════════════════════════════════════

    async def get_arp_table(self) -> AdapterResult:
        try:
            raw = await self._api.get_arp_table()
            entries = []
            arp_data = raw.get("entries", raw.get("arp_table", []))
            if isinstance(arp_data, list):
                for entry in arp_data:
                    if isinstance(entry, dict):
                        entries.append(
                            {
                                "ip_address": entry.get("ipaddr", entry.get("IP address", "")),
                                "mac_address": entry.get("macaddr", entry.get("HW address", "")),
                                "hostname": entry.get("hostname", ""),
                                "interface": entry.get("device", entry.get("Device", "")),
                                "permanent": entry.get("permanent", False),
                            }
                        )
            return AdapterResult.ok(data={"entries": entries, "count": len(entries)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_ndp_table(self) -> AdapterResult:
        # IPv6 neighbor discovery — best effort
        try:
            ifaces = await self._api.get_network_interfaces()
            entries = []
            for iface in ifaces.get("interface", []):
                for neighbor in iface.get("ipv6-prefix-assignment", []):
                    if isinstance(neighbor, dict) and neighbor.get("address"):
                        entries.append(
                            {
                                "ip_address": neighbor.get("address", ""),
                                "mac_address": "",
                                "interface": iface.get("interface", ""),
                            }
                        )
            return AdapterResult.ok(data={"entries": entries, "count": len(entries)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def flush_arp(self) -> AdapterResult:
        return AdapterResult.fail(
            "ARP flush not supported via ubus",
            error_code="NOT_SUPPORTED",
        )

    async def get_bridges(self) -> AdapterResult:
        try:
            raw = await self._api.uci_get_all("network")
            bridges = []
            for name, section in self._uci_sections(raw, "device"):
                if section.get("type") == "bridge":
                    ports = section.get("ports", [])
                    if isinstance(ports, str):
                        ports = [ports]
                    bridges.append(
                        {
                            "name": section.get("name", name),
                            "members": ports,
                            "stp": section.get("stp", "0") == "1",
                        }
                    )
            # Also check interfaces for br- devices
            result = await self.get_interfaces()
            if result.success and result.data:
                for iface in result.data:
                    if isinstance(iface, dict) and iface.get("is_bridge"):
                        already = any(b["name"] == iface.get("device", "") for b in bridges)
                        if not already:
                            bridges.append(
                                {
                                    "name": iface.get("device", ""),
                                    "members": [],
                                    "stp": False,
                                }
                            )
            return AdapterResult.ok(data={"bridges": bridges, "count": len(bridges)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_connections(self) -> AdapterResult:
        try:
            raw = await self._api.get_conntrack_count()
            return AdapterResult.ok(
                data={
                    "count": raw.get("count", 0),
                    "max": raw.get("limit", 0),
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Backup
    # ═══════════════════════════════════════════════════════════════════════

    async def create_backup(self) -> AdapterResult:
        try:
            data = await self._api.create_backup()
            return AdapterResult.ok(
                data={
                    "backup_data": data,
                    "format": "tar.gz",
                    "scope": "/etc/config/",
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    _SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._:-]+$")

    def _validate_host(self, host: str) -> str:
        if not host or len(host) > 253 or not self._SAFE_HOST_RE.match(host):
            raise ValueError("Invalid diagnostic target")
        return host

    async def run_ping(self, host: str, count: int = 3) -> AdapterResult:
        try:
            self._validate_host(host)
            # OpenWRT doesn't have a standard ping ubus API —
            # use luci2.network.ping or fall back to system call
            try:
                result = await self._api.call(
                    "luci2.network",
                    "ping",
                    {"host": host, "count": min(count, 10)},
                )
                return AdapterResult.ok(data=result)
            except OpenWRTAPIError:
                return AdapterResult.ok(
                    data={
                        "target": host,
                        "note": "Ping not available via ubus — use SSH diagnostic",
                    }
                )
        except ValueError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"Ping failed: {exc}")

    async def run_traceroute(self, host: str) -> AdapterResult:
        try:
            self._validate_host(host)
            try:
                result = await self._api.call(
                    "luci2.network",
                    "traceroute",
                    {"host": host},
                )
                return AdapterResult.ok(data=result)
            except OpenWRTAPIError:
                return AdapterResult.ok(
                    data={
                        "target": host,
                        "note": "Traceroute not available via ubus",
                    }
                )
        except ValueError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"Traceroute failed: {exc}")

    async def run_dns_lookup(self, hostname: str) -> AdapterResult:
        try:
            self._validate_host(hostname)
            return AdapterResult.ok(
                data={
                    "hostname": hostname,
                    "note": "DNS lookup not available via ubus",
                }
            )
        except ValueError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"DNS lookup failed: {exc}")

    # ═══════════════════════════════════════════════════════════════════════
    # Dashboard / Summary
    # ═══════════════════════════════════════════════════════════════════════

    async def get_device_summary(self) -> AdapterResult:
        try:
            board = await self._api.get_board_info()
            info = await self._api.get_system_info()
            ifaces_raw = await self._api.get_network_interfaces()
            services = await self._api.get_services()

            iface_list = ifaces_raw.get("interface", [])
            iface_up = sum(1 for i in iface_list if i.get("up"))
            memory = info.get("memory", {})

            return AdapterResult.ok(
                data={
                    "hostname": board.get("hostname", ""),
                    "model": board.get("model", ""),
                    "version": board.get("release", {}).get("version", ""),
                    "uptime": info.get("uptime", 0),
                    "interfaces_total": len(iface_list),
                    "interfaces_up": iface_up,
                    "memory_total": memory.get("total", 0),
                    "memory_free": memory.get("free", 0),
                    "services_total": len(services),
                    "capabilities": self._capabilities,
                }
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # QoS / SQM (capability-gated)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_shaper_pipes(self) -> AdapterResult:
        """SQM queues mapped to OPNsense 'pipes' format."""
        if not self._capabilities.get("sqm"):
            return AdapterResult.ok(data={"pipes": [], "count": 0})
        try:
            raw = await self._api.uci_get_all("sqm")
            pipes = []
            for name, section in self._uci_sections(raw, "queue"):
                pipes.append(
                    {
                        "id": _stable_id("sqm", "queue", name),
                        "uci_name": name,
                        "interface": section.get("interface", ""),
                        "enabled": section.get("enabled", "1") != "0",
                        "download": int(section.get("download", 0) or 0),
                        "upload": int(section.get("upload", 0) or 0),
                        "qdisc": section.get("qdisc", "fq_codel"),
                        "script": section.get("script", "simple.qos"),
                        "bandwidth": int(section.get("download", 0) or 0),
                        "description": section.get("comment", ""),
                    }
                )
            return AdapterResult.ok(data={"pipes": pipes, "count": len(pipes)})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_shaper_pipe(self, pipe: dict[str, Any]) -> AdapterResult:
        if not self._capabilities.get("sqm"):
            return AdapterResult.fail("SQM not installed", error_code="NOT_SUPPORTED")
        try:
            values: dict[str, Any] = {
                "interface": pipe.get("interface", ""),
                "download": str(pipe.get("download", pipe.get("bandwidth", 0))),
                "upload": str(pipe.get("upload", pipe.get("bandwidth", 0))),
                "qdisc": pipe.get("qdisc", "fq_codel"),
                "script": pipe.get("script", "simple.qos"),
                "enabled": "1" if pipe.get("enabled", True) else "0",
            }
            if pipe.get("comment") or pipe.get("description"):
                values["comment"] = pipe.get("comment", pipe.get("description", ""))

            result = await self._api.uci_add("sqm", "queue", values=values)
            await self._api.uci_commit("sqm")
            await self._api.restart_service("sqm")
            return AdapterResult.ok(data=result, message="SQM queue created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_shaper_pipe(
        self,
        uuid: str,
        pipe: dict[str, Any],
    ) -> AdapterResult:
        try:
            if not self._capabilities.get("sqm"):
                return AdapterResult.fail("SQM not installed", error_code="NOT_SUPPORTED")
            values: dict[str, Any] = {}
            if "interface" in pipe:
                values["interface"] = pipe["interface"]
            if "download" in pipe:
                values["download"] = str(pipe["download"])
            if "upload" in pipe:
                values["upload"] = str(pipe["upload"])
            if "bandwidth" in pipe and "download" not in pipe:
                values["download"] = str(pipe["bandwidth"])
                values["upload"] = str(pipe["bandwidth"])
            if "qdisc" in pipe:
                values["qdisc"] = pipe["qdisc"]
            if "script" in pipe:
                values["script"] = pipe["script"]
            if "enabled" in pipe:
                values["enabled"] = "1" if pipe["enabled"] else "0"
            return await self._uci_update("sqm", "queue", uuid, values, "sqm")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_shaper_pipe(self, uuid: str) -> AdapterResult:
        try:
            if not self._capabilities.get("sqm"):
                return AdapterResult.fail("SQM not installed", error_code="NOT_SUPPORTED")
            return await self._uci_delete_section("sqm", "queue", uuid, "sqm")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_shaper_queues(self) -> AdapterResult:
        # SQM is per-interface, no separate queue objects
        return AdapterResult.ok(data={"queues": [], "count": 0})

    async def get_shaper_rules(self) -> AdapterResult:
        # SQM doesn't have separate rules
        return AdapterResult.ok(data={"rules": [], "count": 0})

    async def create_shaper_queue(self, queue: dict[str, Any]) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    async def update_shaper_queue(self, uuid: str, queue: dict[str, Any]) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    async def delete_shaper_queue(self, uuid: str) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    async def create_shaper_rule(self, rule: dict[str, Any]) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    async def update_shaper_rule(self, uuid: str, rule: dict[str, Any]) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    async def delete_shaper_rule(self, uuid: str) -> AdapterResult:
        return AdapterResult.fail("SQM uses per-interface pipes", error_code="NOT_SUPPORTED")

    # ═══════════════════════════════════════════════════════════════════════
    # Distribution Engine — VLAN Interface CRUD
    # ═══════════════════════════════════════════════════════════════════════

    async def _resolve_parent_interface(self) -> str | None:
        """Find the LAN bridge or first non-WAN interface device."""
        try:
            result = await self.get_interfaces()
            if not result.success:
                return None
            interfaces = result.data if isinstance(result.data, list) else []
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                if iface.get("is_lan") and iface.get("device"):
                    return iface["device"]
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                if not iface.get("is_wan") and iface.get("device"):
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
        Create a VLAN interface on OpenWRT.

        Creates both a VLAN device (bridge-vlan or 802.1q) and a
        network interface with static IP configuration.
        """
        try:
            if not 1 <= vlan_id <= 4094:
                return AdapterResult.fail(
                    f"VLAN tag {vlan_id} out of range 1-4094",
                    error_code="INVALID_VLAN_TAG",
                )

            resolved_parent = parent_if or self.config.get("parent_interface")
            if not resolved_parent:
                resolved_parent = await self._resolve_parent_interface()
            if not resolved_parent:
                return AdapterResult.fail(
                    "Cannot determine parent interface",
                    error_code="NO_PARENT_INTERFACE",
                )

            iface_name = f"vlan{vlan_id}"
            device_name = f"{resolved_parent}.{vlan_id}"

            # Create VLAN device section
            await self._api.uci_set(
                "network",
                iface_name,
                {
                    "proto": "static",
                    "device": device_name,
                },
            )

            # Set IP if provided
            if gateway_ip and subnet:
                import ipaddress as _ipaddress

                try:
                    net = _ipaddress.IPv4Network(subnet, strict=False)
                    netmask = str(net.netmask)
                except (ValueError, TypeError):
                    return AdapterResult.fail(
                        f"Invalid subnet CIDR: {subnet}",
                        error_code="INVALID_SUBNET",
                    )
                await self._api.uci_set(
                    "network",
                    iface_name,
                    {
                        "ipaddr": gateway_ip,
                        "netmask": netmask,
                    },
                )

            await self._api.uci_commit("network")
            await self._api.reload_network()

            return AdapterResult.ok(
                data={
                    "tag": vlan_id,
                    "parent": resolved_parent,
                    "device": device_name,
                    "interface": iface_name,
                    "name": name,
                    "subnet": subnet,
                    "gateway_ip": gateway_ip,
                },
                message=f"Created VLAN {vlan_id} on {resolved_parent}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            # Revert on failure
            with contextlib.suppress(Exception):
                await self._api.uci_revert("network")
            return AdapterResult.fail(str(exc))

    async def delete_vlan_interface(
        self,
        vlan_id: int | None = None,
        *,
        uuid: str | None = None,
    ) -> AdapterResult:
        try:
            if vlan_id is None:
                return AdapterResult.fail("vlan_id is required")

            iface_name = f"vlan{vlan_id}"

            try:
                await self._api.uci_delete("network", iface_name)
                await self._api.uci_commit("network")
                await self._api.reload_network()
            except OpenWRTAPIError as exc:
                if "NOT_FOUND" in str(exc) or exc.code == 4:
                    return AdapterResult.ok(
                        data={"vlan_id": vlan_id, "already_absent": True},
                        message=f"VLAN {vlan_id} not found — nothing to delete",
                    )
                raise

            return AdapterResult.ok(
                data={"vlan_id": vlan_id, "interface": iface_name},
                message=f"Deleted VLAN {vlan_id}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Distribution Engine — DHCP Scope CRUD
    # ═══════════════════════════════════════════════════════════════════════

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
        Create a DHCP scope on OpenWRT via dnsmasq UCI config.

        OpenWRT dnsmasq uses ``start`` (offset) and ``limit`` (count)
        rather than explicit start/end IPs.  We calculate the offset
        from the subnet.
        """
        try:
            # Calculate start offset and limit from IP range
            start_offset, limit = self._ip_range_to_offset(
                range_start,
                range_end,
                subnet,
            )

            # Convert lease_time seconds to dnsmasq format
            leasetime_str = f"{lease_time // 3600}h" if lease_time >= 3600 else f"{lease_time}s"

            section_name = interface.replace("vlan", "dhcp_vlan")

            values: dict[str, Any] = {
                "interface": interface,
                "start": str(start_offset),
                "limit": str(limit),
                "leasetime": leasetime_str,
            }

            await self._api.uci_add("dhcp", "dhcp", name=section_name, values=values)
            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")

            return AdapterResult.ok(
                data={
                    "interface": interface,
                    "range_start": range_start,
                    "range_end": range_end,
                    "subnet": subnet,
                    "backend": "dnsmasq",
                },
                message=f"Created DHCP scope on {interface}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            with contextlib.suppress(Exception):
                await self._api.uci_revert("dhcp")
            return AdapterResult.fail(str(exc))

    async def delete_dhcp_scope(self, interface: str) -> AdapterResult:
        try:
            # Find the DHCP section for this interface
            raw = await self._api.uci_get_all("dhcp")
            target = None
            for name, section in self._uci_sections(raw, "dhcp"):
                if section.get("interface") == interface:
                    target = name
                    break

            if not target:
                return AdapterResult.ok(
                    data={"interface": interface, "already_absent": True},
                    message=f"No DHCP scope found for {interface}",
                )

            await self._api.uci_delete("dhcp", target)
            await self._api.uci_commit("dhcp")
            await self._api.restart_service("dnsmasq")

            return AdapterResult.ok(
                data={"interface": interface},
                message=f"Deleted DHCP scope for {interface}",
            )
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Distribution Engine — Limb VLAN + DHCP Suppression
    # ═══════════════════════════════════════════════════════════════════════

    async def create_vlan(
        self,
        vlan_id: int,
        name: str = "",
        **kwargs: Any,
    ) -> AdapterResult:
        return await self.create_vlan_interface(
            vlan_id=vlan_id,
            name=name,
            description=f"[FreeSdn:limb] {name}" if name else "",
        )

    async def delete_vlan(self, vlan_id: int) -> AdapterResult:
        return await self.delete_vlan_interface(vlan_id=vlan_id)

    async def suppress_dhcp(self, vlan_id: int) -> AdapterResult:
        try:
            interface = f"vlan{vlan_id}"
            return await self.delete_dhcp_scope(interface)
        except Exception as exc:
            return AdapterResult.fail(f"Failed to suppress DHCP on VLAN {vlan_id}: {exc}")

    # ═══════════════════════════════════════════════════════════════════════
    # Utility methods
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _prefix_to_netmask(prefix: int) -> str:
        """Convert CIDR prefix length to dotted-decimal netmask."""
        bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"

    @staticmethod
    def _ip_range_to_offset(
        start: str,
        end: str,
        subnet: str,
    ) -> tuple[int, int]:
        """Convert IP range to dnsmasq offset + limit.

        Returns ``(start_offset, limit)`` where ``start_offset``
        is the offset from the network address.
        """
        import ipaddress

        try:
            start_ip = ipaddress.IPv4Address(start)
            end_ip = ipaddress.IPv4Address(end)

            if subnet and "/" in subnet:
                net = ipaddress.IPv4Network(subnet, strict=False)
                net_addr = int(net.network_address)
            else:
                # Guess /24 network from start IP
                net_addr = int(start_ip) & 0xFFFFFF00

            offset = int(start_ip) - net_addr
            limit = int(end_ip) - int(start_ip) + 1
            return max(offset, 2), max(limit, 1)
        except Exception:
            return 100, 150  # sensible defaults
