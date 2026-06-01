# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - pfSense Adapter
===============================

BaseAdapter implementation for pfSense firewalls/routers.
"""

import asyncio
import logging
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
from app.adapters.pfsense.client import PfSenseAPIError, PfSenseClient
from app.adapters.validation import validate_id
from app.core.redaction import redact_secrets

logger = logging.getLogger(__name__)


# Maximum recursion depth tolerated when walking arbitrary controller
# responses (interface dicts, VLAN lists, etc.) inside the adapter
# helpers. Bounded so a malformed / hostile pfSense reply cannot blow
# the Python stack.
_MAX_WALK_DEPTH = 8


# pfSense alias types per the firewall_alias schema. Reject anything
# else at the adapter edge — passing an unknown type lets pfSense
# coerce silently or 500 with a confusing message.
_PFSENSE_ALIAS_TYPES: frozenset[str] = frozenset(
    {
        "host",
        "network",
        "port",
        "url",
        "urltable",
        "urltable_ports",
        "geoip",
    }
)


# Per-(controller, vlan_tag) idempotency lock cache. A second
# concurrent ``create_vlan_interface`` for the same tag waits for the
# first to complete, then sees the now-existing VLAN via the
# ``_find_vlan_by_tag`` short-circuit. Without this the two calls race
# the existence check and BOTH issue ``add_vlan``, producing a
# duplicate-tag 500 from pfSense on the loser.
_VLAN_CREATE_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}
_VLAN_CREATE_LOCKS_GUARD = asyncio.Lock()


async def _get_vlan_create_lock(controller_id: str, vlan_id: int) -> asyncio.Lock:
    """Return (creating if needed) the per-(controller, vlan) lock."""
    key = (controller_id, vlan_id)
    async with _VLAN_CREATE_LOCKS_GUARD:
        lock = _VLAN_CREATE_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _VLAN_CREATE_LOCKS[key] = lock
        return lock


class PfSenseAdapter(BaseAdapter):
    """
    Adapter for pfSense firewalls and routers.

    Supports:
    - Firewall rule management (filter, NAT, aliases)
    - VPN management (WireGuard, OpenVPN, IPsec)
    - DHCP lease management
    - DNS overrides (Unbound)
    - Interface monitoring
    - Gateway health monitoring
    - Service control
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="pfsense",
        name="pfSense Firewall",
        vendor="Netgate",
        version="1.0.0",
        description="pfSense CE/Plus firewall – API key/secret auth over HTTPS",
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["2.6.0", "2.7.0", "2.7.1", "2.7.2", "23.09", "24.03"],
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
                    # Per-domain feature surfaces — backed by
                    # adapter_pfsense_* services + endpoints.
                    Capability.PFSENSE_FIREWALL_RULES,
                    Capability.PFSENSE_FIREWALL_ALIASES,
                    Capability.PFSENSE_NAT_PORT_FORWARD,
                    Capability.PFSENSE_NAT_OUTBOUND,
                    Capability.PFSENSE_DHCP_LEASES,
                    Capability.PFSENSE_DHCP_STATIC_MAPPINGS,
                    Capability.PFSENSE_DNS_OVERRIDES,
                    Capability.PFSENSE_ROUTING_GATEWAYS,
                    Capability.PFSENSE_ROUTING_STATIC,
                    Capability.PFSENSE_SERVICES_CONTROL,
                    Capability.PFSENSE_SYSTEM_INFO,
                    Capability.PFSENSE_SYSTEM_REBOOT,
                    Capability.PFSENSE_DIAG_LOGS,
                    Capability.PFSENSE_DIAG_PING,
                    Capability.PFSENSE_DIAG_TRACEROUTE,
                    Capability.PFSENSE_DIAG_DNS_LOOKUP,
                    Capability.PFSENSE_INTERFACES_LIST,
                    Capability.PFSENSE_INTERFACES_VLAN,
                    Capability.PFSENSE_INTERFACES_ARP,
                ],
                models=["pfSense*", "Netgate*", "*"],
            ),
            "vpn_gateway": DeviceTypeCapabilities(
                module="firewall",
                capabilities=[
                    Capability.VPN_IPSEC,
                    Capability.VPN_OPENVPN,
                    Capability.VPN_WIREGUARD,
                    Capability.VPN_SERVER,
                    Capability.VPN_CLIENT,
                    Capability.PFSENSE_VPN_OPENVPN,
                    Capability.PFSENSE_VPN_WIREGUARD,
                    Capability.PFSENSE_VPN_IPSEC,
                ],
                models=["pfSense*", "Netgate*", "*"],
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

    # ── init ─────────────────────────────────────────────────────────────

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        # high-level adapter write methods thread
        # this flag to the client instead of hard-coding force=True, so a
        # direct live write (gateway-service / device-control route) is refused
        # under ADAPTER_READ_ONLY unless opted in. The staged applier calls the
        # client directly with force=True and does not use these methods, so it
        # is unaffected. Default False = direct routes refused. Diagnostic
        # read-POSTs (ping/traceroute/dns) keep force=True (they are reads).
        self._direct_write_force = bool(kwargs.pop("direct_write_force", False))
        super().__init__(host, username, password, **kwargs)
        self._api = PfSenseClient(
            host=host,
            api_key=username,
            api_secret=password,
            port=kwargs.get("port", 443),
            use_ssl=kwargs.get("use_ssl", True),
            verify_ssl=kwargs.get("verify_ssl", False),
            timeout=kwargs.get("timeout", 30),
            api_version=kwargs.get("api_version", "v2"),
        )

    # ── BaseAdapter required ─────────────────────────────────────────────

    async def connect(self) -> bool:
        try:
            await self._api.connect()
            await self._api.get_system_version()
            self._connected = True
            return True
        except (AdapterConnectionError, AdapterAuthenticationError):
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"Failed to connect to pfSense at {self.host}: {exc}",
                adapter_id="pfsense",
            ) from exc

    async def disconnect(self) -> None:
        # ``close()`` can raise (httpx mid-flight, network reset, etc.).
        # Disconnect is best-effort cleanup — don't let a transport
        # error abort whatever the caller was doing next.
        try:
            await self._api.close()
        except Exception:
            logger.exception("pfsense disconnect close() raised")
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        try:
            await self._api.connect()
            ver = await self._api.get_system_version()
            await self._api.close()
            return AdapterResult.ok(
                data={"vendor": "pfSense", "version": ver},
                message="Connection successful",
            )
        except AdapterAuthenticationError as exc:
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(f"Connection failed: {exc}")

    async def discover_devices(self) -> list[DiscoveredDevice]:
        try:
            ver = await self._api.get_system_version()
            info = await self._api.get_system_info()
            hostname = info.get("hostname", self.host) if isinstance(info, dict) else self.host
            version = ver.get("version", "unknown") if isinstance(ver, dict) else str(ver)
            return [
                DiscoveredDevice(
                    device_type="firewall",
                    name=hostname,
                    vendor="pfSense",
                    model=f"pfSense {version}",
                    mac_address="",
                    ip_address=self.host,
                    firmware_version=version,
                    status="online",
                    raw_data={"version_info": ver},
                )
            ]
        except Exception:
            # Generic catch — surface only the exception type to the
            # operator and log full repr+traceback server-side. Mirrors
            # the OPNsense adapter pattern: don't leak controller
            # response bodies (which can carry hostnames / paths) into
            # API error fields.
            logger.exception("pfSense discover_devices failed")
            return []

    async def get_device_status(self, device_id: str) -> AdapterResult:
        try:
            status = await self._api.get_system_status()
            ifaces = await self._api.get_interface_stats()
            gw = await self._api.get_gateway_status()
            return AdapterResult.ok(
                data={
                    "system": status,
                    "interfaces": ifaces,
                    "gateways": gw,
                }
            )
        except Exception as exc:
            logger.exception("pfSense get_device_status failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_device_info(self, device_id: str) -> AdapterResult:
        try:
            ver = await self._api.get_system_version()
            info = await self._api.get_system_info()
            return AdapterResult.ok(
                data={
                    "hostname": info.get("hostname") if isinstance(info, dict) else None,
                    "version": ver,
                    "system_info": info,
                }
            )
        except Exception as exc:
            logger.exception("pfSense get_device_info failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self, interface: str | None = None) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_rules(interface))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_firewall_rule(self, rule_id: int) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_rule(rule_id))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_firewall_rule(self, rule: dict[str, Any]) -> AdapterResult:
        # Direct-route entry point: threads ``self._direct_write_force``
        # (default False) to the client, so a direct live write is refused
        # under ADAPTER_READ_ONLY. The sanctioned write path is the staged
        # applier (client-direct, force=True), which does not use this method.
        try:
            result = await self._api.add_firewall_rule(rule, force=self._direct_write_force)
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule created and applied")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_firewall_rule(self, rule_id: int, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.update_firewall_rule(
                rule_id, rule, force=self._direct_write_force
            )
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule updated and applied")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_firewall_rule(self, rule_id: int) -> AdapterResult:
        try:
            result = await self._api.delete_firewall_rule(rule_id, force=self._direct_write_force)
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result, message="Rule deleted and applied")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Aliases
    # ═══════════════════════════════════════════════════════════════════════

    async def get_aliases(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_aliases())
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
        """
        Create a firewall alias on pfSense.

        Called by the distribution engine (Tier 2) with named params,
        or by the gateway API with a dict payload.
        """
        try:
            if alias and isinstance(alias, dict):
                # Validate ``type`` on the dict path too — the gateway
                # API is the other entrypoint and we can't trust its
                # body to have been pre-validated upstream.
                t = alias.get("type")
                if t is not None and t not in _PFSENSE_ALIAS_TYPES:
                    return AdapterResult.fail(
                        f"Invalid alias type {t!r}; must be one of {sorted(_PFSENSE_ALIAS_TYPES)}",
                        error_code="INVALID_ALIAS_TYPE",
                    )
                result = await self._api.add_alias(alias, force=self._direct_write_force)
                # Stage + apply: a created alias is invisible to the
                # filter ruleset until the firewall config is applied.
                await self._api.apply_firewall_changes(force=self._direct_write_force)
                return AdapterResult.ok(data=result)

            # Build payload from named params (distribution engine)
            alias_type = type or "network"
            if alias_type not in _PFSENSE_ALIAS_TYPES:
                return AdapterResult.fail(
                    f"Invalid alias type {alias_type!r}; must be one of "
                    f"{sorted(_PFSENSE_ALIAS_TYPES)}",
                    error_code="INVALID_ALIAS_TYPE",
                )
            payload: dict[str, Any] = {
                "name": name,
                "type": alias_type,
                "address": members or [],
                "descr": description,
            }
            result = await self._api.add_alias(payload, force=self._direct_write_force)
            # Apply so the new alias is usable in subsequent rule writes.
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data=result,
                message=f"Alias '{name}' created",
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def update_alias(self, name: str, alias: dict[str, Any]) -> AdapterResult:
        try:
            validate_id(name, label="alias_name")
            return AdapterResult.ok(
                data=await self._api.update_alias(name, alias, force=self._direct_write_force)
            )
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def delete_alias(
        self,
        alias_name: str | None = None,
        *,
        name: str = "",
    ) -> AdapterResult:
        """
        Delete a firewall alias from pfSense.

        Accepts alias name as positional arg or keyword 'name'
        (distribution engine uses keyword).
        """
        try:
            target = alias_name or name
            if not target:
                return AdapterResult.fail("Alias name is required")
            # Validate at the adapter edge — even though the underlying
            # client will re-validate, we want the failure to surface as
            # an ``AdapterResult.fail`` (not an HTTPException) so the
            # distribution engine handles it uniformly.
            validate_id(target, label="alias_name")
            result = await self._api.delete_alias(target, force=self._direct_write_force)
            return AdapterResult.ok(data=result, message=f"Alias '{target}' deleted")
        except PfSenseAPIError as exc:
            if exc.status_code == 404:
                return AdapterResult.ok(message=f"Alias '{alias_name or name}' already absent")
            return AdapterResult.fail(str(exc))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_nat_rules())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_port_forwards(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_port_forwards())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_port_forward(self, rule: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_port_forward(rule, force=self._direct_write_force)
            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result)
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

    async def get_dhcp_static_mappings(self, interface: str = "lan") -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_dhcp_static_mappings(interface))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_overrides(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_dns_host_overrides())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def create_dns_override(self, override: dict[str, Any]) -> AdapterResult:
        try:
            result = await self._api.add_dns_host_override(override, force=self._direct_write_force)
            await self._api.apply_dns_changes(force=self._direct_write_force)
            return AdapterResult.ok(data=result)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # VPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vpn_status(self) -> AdapterResult:
        try:
            ovpn = await self._api.get_openvpn_status()
            wg = await self._api.get_wireguard_tunnels()
            wg_peers = await self._api.get_wireguard_peers()
            ipsec = await self._api.get_ipsec_status()
            # OpenVPN / WireGuard / IPsec status carries peer pubkeys,
            # PSK fragments, and client cert CNs in some pfSense
            # builds. Strip every sensitive key shape before the
            # response leaves the adapter.
            return AdapterResult.ok(
                data=redact_secrets(
                    {
                        "openvpn": ovpn,
                        "wireguard": {"tunnels": wg, "peers": wg_peers},
                        "ipsec": ipsec,
                    }
                )
            )
        except Exception as exc:
            logger.exception("pfSense get_vpn_status failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces / Gateway
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> AdapterResult:
        try:
            data = await self._api.get_interfaces()
            stats = await self._api.get_interface_stats()
            return AdapterResult.ok(data={"interfaces": data, "statistics": stats})
        except Exception as exc:
            logger.exception("pfSense get_interfaces failed")
            return AdapterResult.fail(type(exc).__name__)

    async def get_gateway_status(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_gateway_status())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_services())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def restart_service(self, name: str) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.restart_service(name))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self, limit: int = 100) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_system_log(limit))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def get_firewall_log(self, limit: int = 100) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firewall_log(limit))
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # System Info (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_info(self) -> AdapterResult:
        try:
            ver = await self._api.get_system_version()
            info = await self._api.get_system_info()
            status = await self._api.get_system_status()
            return AdapterResult.ok(
                data={
                    "hostname": info.get("hostname") if isinstance(info, dict) else "",
                    "version": ver,
                    "system_status": status,
                }
            )
        except Exception as exc:
            logger.exception("pfSense get_system_info failed")
            return AdapterResult.fail(type(exc).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN Devices (drift detection)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlan_devices(self) -> AdapterResult:
        try:
            vlans = await self._api.get_vlans()
            if not isinstance(vlans, list):
                vlans = [vlans] if vlans else []
            return AdapterResult.ok(data=vlans)
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Static routes (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_static_routes(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_static_routes())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # ARP table (gateway API)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_arp_table(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_arp_table())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    async def run_ping(self, target: str, **kwargs: Any) -> AdapterResult:
        try:
            count = kwargs.get("count", 4)
            # Diagnostic POSTs are non-mutating; pass ``force=True`` so
            # the universal ``ADAPTER_READ_ONLY`` gate doesn't refuse the
            # probe when the operator only wants a ping.
            result = await self._api.run_ping(target, count=count, force=True)
            return AdapterResult.ok(data={"result": result, "target": target})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def run_traceroute(self, target: str, **kwargs: Any) -> AdapterResult:
        try:
            # Non-mutating diagnostic POST — pass ``force=True``.
            result = await self._api.run_traceroute(target, force=True)
            return AdapterResult.ok(data={"result": result, "target": target})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    async def run_dns_lookup(self, hostname: str, **kwargs: Any) -> AdapterResult:
        try:
            # Non-mutating diagnostic POST — pass ``force=True``.
            result = await self._api.run_dns_lookup(hostname, force=True)
            return AdapterResult.ok(data={"result": result, "hostname": hostname})
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Backup
    # ═══════════════════════════════════════════════════════════════════════

    async def create_backup(self, **kwargs: Any) -> AdapterResult:
        try:
            result = await self._api.create_backup()
            # pfSense ``config_history/backup`` returns the running
            # config which embeds hashed admin passwords, OpenVPN keys,
            # IPsec PSKs, WireGuard private keys, and SNMP communities.
            # Strip every sensitive-looking key before the payload
            # leaves the adapter — the operator can still see structure
            # and counts; the secrets are masked as ``***``.
            return AdapterResult.ok(data=redact_secrets(result), message="Backup created")
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # Firmware
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firmware_info(self) -> AdapterResult:
        try:
            return AdapterResult.ok(data=await self._api.get_firmware_info())
        except Exception as exc:
            return AdapterResult.fail(str(exc))

    # ═══════════════════════════════════════════════════════════════════════
    # ╔═══════════════════════════════════════════════════════════════════╗
    # ║  DISTRIBUTION ENGINE METHODS                                      ║
    # ║  Called by distribution_service.py via getattr(adapter, action)    ║
    # ╚═══════════════════════════════════════════════════════════════════╝
    # ═══════════════════════════════════════════════════════════════════════

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _check_walk_depth(depth: int, label: str) -> None:
        """Raise if a controller response nests deeper than allowed.

        Bounded so a malformed / hostile pfSense reply (recursive
        ``data`` envelopes, deeply nested interface dicts, …) cannot
        push the Python stack into recursion. The walk in each helper
        is shallow by design (1–2 levels for real responses), so 8 is
        already a generous ceiling.
        """
        if depth > _MAX_WALK_DEPTH:
            raise PfSenseAPIError(
                f"pfSense {label} response nested past max depth "
                f"({_MAX_WALK_DEPTH}); refusing to walk further",
            )

    async def _find_vlan_by_tag(self, vlan_id: int) -> dict[str, Any] | None:
        """Find existing VLAN by tag number."""
        vlans = await self._api.get_vlans()
        if not isinstance(vlans, list):
            vlans = [vlans] if vlans else []
        for v in vlans:
            # Each entry must be a dict — reject non-dict shapes rather
            # than crashing on .get(). Bound implicit depth via the
            # outer guard.
            if not isinstance(v, dict):
                continue
            self._check_walk_depth(1, "vlans")
            try:
                if int(v.get("tag", 0)) == vlan_id:
                    return v
            except (TypeError, ValueError):
                continue
        return None

    async def _find_interface_by_descr(self, descr: str) -> dict[str, Any] | None:
        """Find interface assignment by description."""
        ifaces = await self._api.get_interfaces()
        if isinstance(ifaces, dict):
            for key, iface in ifaces.items():
                self._check_walk_depth(1, "interfaces")
                if isinstance(iface, dict) and iface.get("descr", "") == descr:
                    iface["_key"] = key
                    return iface
        elif isinstance(ifaces, list):
            for iface in ifaces:
                self._check_walk_depth(1, "interfaces")
                if isinstance(iface, dict) and iface.get("descr", "") == descr:
                    return iface
        return None

    async def _resolve_parent_interface(self) -> str:
        """Auto-detect parent interface for VLAN sub-interfaces."""
        ifaces = await self._api.get_interfaces()
        if isinstance(ifaces, dict):
            self._check_walk_depth(1, "interfaces")
            # Check for LAN interface first
            if "lan" in ifaces:
                lan = ifaces["lan"]
                return lan.get("if", "igb0") if isinstance(lan, dict) else "igb0"
            # First WAN-excluded interface
            for key, iface in ifaces.items():
                self._check_walk_depth(2, "interfaces")
                if key != "wan" and isinstance(iface, dict):
                    return iface.get("if", "igb0")
        return "igb0"

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
        Create a VLAN sub-interface on pfSense.

        Called by the distribution engine (Tier 1).

        Steps:
          1. Create the 802.1Q VLAN on parent interface
          2. Assign it as a logical interface (OPTx)
          3. Configure IP address and enable
          4. Apply firewall changes
        """
        if not 1 <= vlan_id <= 4094:
            return AdapterResult.fail(
                f"VLAN tag {vlan_id} out of range 1-4094",
                error_code="INVALID_VLAN_TAG",
            )
        # Idempotency lock: a second concurrent caller for the same
        # ``(host, vlan_id)`` waits here, then sees the now-existing
        # VLAN via the duplicate check below. Without this both
        # callers race past ``_find_vlan_by_tag`` and BOTH issue
        # ``add_vlan``, producing a duplicate-tag 500 from pfSense.
        lock = await _get_vlan_create_lock(self.host, vlan_id)
        async with lock:
            try:
                # Check for duplicate (now under lock — safe).
                existing = await self._find_vlan_by_tag(vlan_id)
                if existing:
                    return AdapterResult.ok(
                        data={"vlan_id": vlan_id, "existing": existing},
                        message=f"VLAN {vlan_id} already exists",
                    )

                parent = parent_if or await self._resolve_parent_interface()
                descr = name or f"VLAN{vlan_id}"

                # 1. Create the VLAN
                #
                # Distribution-engine entrypoint: this is the SANCTIONED
                # write path for VLAN provisioning. Pass ``force=True``
                # on every client call so the universal
                # ``ADAPTER_READ_ONLY`` gate at the bottom of the stack
                # lets the writes through. Without this the engine
                # silently fails in default-safe mode.
                vlan_payload = {
                    "if": parent,
                    "tag": vlan_id,
                    "descr": description or descr,
                }
                vlan_result = await self._api.add_vlan(vlan_payload, force=self._direct_write_force)

                # 2. Assign interface
                vlan_if = f"{parent}.{vlan_id}"  # e.g., igb0.100
                await self._api.assign_interface(
                    {
                        "if": vlan_if,
                        "descr": descr,
                        "enable": True,
                    },
                    force=self._direct_write_force,
                )

                # 3. Configure IP if provided
                ip_result = None
                if gateway_ip and subnet:
                    prefix = subnet.split("/")[1] if "/" in subnet else "24"
                    # Find the assigned interface name (OPTx)
                    assigned = await self._find_interface_by_descr(descr)
                    if assigned:
                        iface_key = assigned.get("_key", "")
                        ip_result = await self._api.update_interface(
                            iface_key,
                            {
                                "ipaddr": gateway_ip,
                                "subnet": prefix,
                                "enable": True,
                                "type": "staticv4",
                            },
                            force=self._direct_write_force,
                        )

                # 4. Apply
                await self._api.apply_firewall_changes(force=self._direct_write_force)

                return AdapterResult.ok(
                    data={
                        "vlan_id": vlan_id,
                        "parent": parent,
                        "vlan_if": vlan_if,
                        "descr": descr,
                        "vlan_result": vlan_result,
                        "ip_result": ip_result,
                    },
                    message=f"VLAN {vlan_id} interface created on {parent}",
                )
            except PfSenseAPIError as exc:
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
        Delete a VLAN sub-interface from pfSense.

        Removes the interface assignment and the VLAN.
        """
        try:
            if vlan_id is None and not iface_id:
                return AdapterResult.fail("Either vlan_id or iface_id is required")

            if vlan_id is not None:
                existing = await self._find_vlan_by_tag(vlan_id)
                if not existing:
                    return AdapterResult.ok(message=f"VLAN {vlan_id} already absent")

                # Find and remove the interface assignment.
                # Sanctioned write path — pass ``force=True`` so the
                # client's ``ADAPTER_READ_ONLY`` gate releases the
                # write. Same dispatch shape as create_vlan_interface.
                vlan_if = f"{existing.get('if', '')}.{vlan_id}"
                ifaces = await self._api.get_interfaces()
                if isinstance(ifaces, dict):
                    for key, iface in ifaces.items():
                        self._check_walk_depth(1, "interfaces")
                        if isinstance(iface, dict) and iface.get("if", "") == vlan_if:
                            await self._api.delete_interface(key, force=self._direct_write_force)
                            break

                # Delete the VLAN entry
                vlan_idx = existing.get("id", existing.get("vlanif", ""))
                if isinstance(vlan_idx, int) or (isinstance(vlan_idx, str) and vlan_idx.isdigit()):
                    await self._api.delete_vlan(int(vlan_idx), force=self._direct_write_force)

            elif iface_id:
                await self._api.delete_interface(iface_id, force=self._direct_write_force)

            await self._api.apply_firewall_changes(force=self._direct_write_force)
            return AdapterResult.ok(
                data={"vlan_id": vlan_id},
                message=f"VLAN {vlan_id} interface deleted",
            )
        except PfSenseAPIError as exc:
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
        Create/enable a DHCP scope on pfSense.

        Called by the distribution engine (Tier 2).

        pfSense DHCP scopes are configured per interface via
        /services/dhcpd — we enable the scope and set the range.
        """
        try:
            config: dict[str, Any] = {
                "enable": True,
                "range_from": range_start,
                "range_to": range_end,
                "defaultleasetime": lease_time,
                "maxleasetime": lease_time * 2,
            }
            if gateway:
                config["gateway"] = gateway
            if dns_servers:
                config["dnsserver"] = dns_servers
            if ntp_servers:
                config["ntpserver"] = ntp_servers
            if domain_name:
                config["domain"] = domain_name

            # Sanctioned write path (Tier 2 distribution engine).
            # Both calls pass ``force=True`` so the universal
            # ``ADAPTER_READ_ONLY`` gate releases the write.
            result = await self._api.update_dhcp_server(
                interface, config, force=self._direct_write_force
            )
            await self._api.restart_service("dhcpd", force=self._direct_write_force)

            return AdapterResult.ok(
                data={
                    "interface": interface,
                    "range": f"{range_start}-{range_end}",
                    "result": result,
                },
                message=f"DHCP scope created on {interface}",
            )
        except PfSenseAPIError as exc:
            return AdapterResult.fail(f"Failed to create DHCP scope on {interface}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to create DHCP scope on {interface}: {exc}")

    async def delete_dhcp_scope(self, interface: str) -> AdapterResult:
        """
        Disable DHCP scope on pfSense for a given interface.

        pfSense doesn't delete DHCP configs — we disable them.
        """
        try:
            # Sanctioned write path — force=True on both calls.
            result = await self._api.update_dhcp_server(
                interface, {"enable": False}, force=self._direct_write_force
            )
            await self._api.restart_service("dhcpd", force=self._direct_write_force)
            return AdapterResult.ok(
                data={"interface": interface, "result": result},
                message=f"DHCP scope disabled on {interface}",
            )
        except PfSenseAPIError as exc:
            return AdapterResult.fail(f"Failed to delete DHCP scope on {interface}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to delete DHCP scope on {interface}: {exc}")

    # ── Tier 3: Limb-role VLAN / DHCP suppression ─────────────────────────

    async def create_vlan(self, vlan_id: int, name: str = "", **kwargs: Any) -> AdapterResult:
        """
        Create an L2 VLAN on a pfSense limb device.

        pfSense doesn't have a separate L2-only VLAN concept;
        delegates to create_vlan_interface with no IP.
        """
        return await self.create_vlan_interface(vlan_id, name=name)

    async def delete_vlan(self, vlan_id: int) -> AdapterResult:
        """Delete an L2 VLAN from a pfSense limb device."""
        return await self.delete_vlan_interface(vlan_id=vlan_id)

    async def suppress_dhcp(self, vlan_id: int) -> AdapterResult:
        """
        Suppress DHCP on a limb pfSense for a specific VLAN.

        Finds the interface assigned to the VLAN and disables its
        DHCP server.
        """
        try:
            vlan = await self._find_vlan_by_tag(vlan_id)
            if not vlan:
                return AdapterResult.ok(
                    message=f"No VLAN {vlan_id} found — nothing to suppress",
                )

            vlan_if = f"{vlan.get('if', '')}.{vlan_id}"
            # Find the interface key for this VLAN
            ifaces = await self._api.get_interfaces()
            iface_key = None
            if isinstance(ifaces, dict):
                for key, iface in ifaces.items():
                    self._check_walk_depth(1, "interfaces")
                    if isinstance(iface, dict) and iface.get("if", "") == vlan_if:
                        iface_key = key
                        break

            if not iface_key:
                return AdapterResult.ok(
                    message=f"No interface assignment for VLAN {vlan_id} — already suppressed",
                )

            # Sanctioned write path (Tier 3 limb-role suppression).
            await self._api.update_dhcp_server(
                iface_key, {"enable": False}, force=self._direct_write_force
            )
            await self._api.restart_service("dhcpd", force=self._direct_write_force)
            return AdapterResult.ok(
                data={"vlan_id": vlan_id, "interface": iface_key},
                message=f"DHCP suppressed on {iface_key}",
            )
        except PfSenseAPIError as exc:
            return AdapterResult.fail(f"Failed to suppress DHCP for VLAN {vlan_id}: {exc}")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to suppress DHCP for VLAN {vlan_id}: {exc}")
