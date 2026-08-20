# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Brain VPN Service
================================

Connects FreeSDN to a site's brain (OPNsense, pfSense, MikroTik, OpenWrt)
via the brain's built-in VPN server. The brain already knows all site subnets
and already has VPN capabilities — this service leverages that.

Supported flows:
  1. Discover VPN servers running on a brain controller
  2. Import VPN config from a brain into SiteVPNConfiguration
  3. Sync subnets from brain's routing table → Site.subnets
  4. Import arbitrary OpenVPN .ovpn config (manual flow)
"""

import contextlib
import ipaddress
import logging
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import get_adapter
from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.core import Controller, Site
from app.models.vpn import SiteVPNConfiguration, VPNSource, VPNStatus, VPNType
from app.schemas.vpn import (
    _DANGEROUS_OPENVPN_DIRECTIVES,
    _OPENVPN_FILE_REF_DIRECTIVES,
    _OPENVPN_SAFE_FILE_REF_ARGS,
)

logger = logging.getLogger(__name__)

# Controller types that can act as brain VPN gateways
BRAIN_CAPABLE_TYPES = {"opnsense", "pfsense", "mikrotik", "openwrt"}

# Maximum subnets per site (prevents unbounded JSONB growth)
MAX_SITE_SUBNETS = 500

# Allowlist for fields that can be set during brain import (prevents mass-assignment)
_BRAIN_IMPORT_FIELDS = {
    "openvpn_protocol",
    "openvpn_mode",
    "vpn_endpoint",
    "vpn_port",
    "health_check_ip",
    "remote_subnets",
    "wireguard_interface",
    "wireguard_endpoint",
    "wireguard_peer_public_key",
}

# Regex for VPN server ID from brain adapter — alphanumeric + hyphens/underscores
_VPN_SERVER_ID_RE = re.compile(r"^[\w\-]{1,128}$")


def _decrypt(val: str | None) -> str:
    if not val:
        return ""
    return decrypt_credential(val) if is_encrypted(val) else val


def _request_can_access_site(site_id: UUID | None) -> bool:
    """Whether the request caller may access ``site_id``.

    Reads the request-scoped current user (published by the auth dependency) and
    returns ``True`` (allow) for super_admin / org_admin / grant-less users, in
    background context (no request user), or for a ``None`` site. Used by
    ``get_brain_controller`` to gate the brain VPN flows at a single chokepoint.
    """
    from app.core.site_access import current_user_var

    user = current_user_var.get()
    if user is None or site_id is None:
        return True
    return bool(user.can_access_site(site_id))


async def _get_adapter_for_controller(ctrl: Controller) -> Any:
    """Create and connect an adapter for the given controller."""
    cloud_kwargs: dict[str, Any] = {}
    if ctrl.connection_mode == "cloud":
        cloud_kwargs = {
            "client_id": ctrl.client_id or "",
            "client_secret": _decrypt(ctrl.client_secret),
            "omada_id": ctrl.omada_id or "",
            "cloud_region": ctrl.cloud_region or "us",
        }
    return await get_adapter(
        adapter_type=ctrl.controller_type,
        host=ctrl.host,
        username=ctrl.username or "",
        password=_decrypt(ctrl.password),
        port=ctrl.port,
        use_ssl=ctrl.use_ssl,
        verify_ssl=ctrl.verify_ssl,
        mode=ctrl.connection_mode or "local",
        **cloud_kwargs,
    )


class BrainVPNService:
    """
    Service for discovering and importing VPN configs from brain controllers.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # ── Controller helpers ──────────────────────────────────────

    async def get_brain_controller(
        self,
        controller_id: UUID,
        org_id: UUID,
    ) -> Controller:
        """Fetch a brain-capable controller with org-scoping."""
        ctrl = (
            await self.session.execute(
                select(Controller)
                .join(Site, Controller.site_id == Site.id)
                .where(
                    Controller.id == controller_id,
                    Controller.deleted_at.is_(None),
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()

        if not ctrl:
            raise ValueError("Controller not found")

        # Site-grant chokepoint: a brain controller
        # belongs to exactly one site, so enforce the request caller's per-user
        # site grant here — the single resolver shared by discover_vpn_servers,
        # import_from_brain and sync_subnets_from_brain. This arms the gate for
        # the discover/sync endpoints (which never thread current_user) without
        # editing them. Reads the request-scoped contextvar; no-op for
        # super_admin / org_admin / grant-less callers and in background context.
        # Raise the SAME "Controller not found" ValueError used for a missing /
        # unowned controller (→ identical 400 at the endpoint) so a site-limited
        # caller gets no existence oracle for a sibling-site controller.
        if not _request_can_access_site(ctrl.site_id):
            raise ValueError("Controller not found")

        if ctrl.controller_type not in BRAIN_CAPABLE_TYPES:
            raise ValueError("Controller does not support VPN gateway capability")
        return ctrl

    # ── VPN Discovery ───────────────────────────────────────────

    async def discover_vpn_servers(
        self,
        controller_id: UUID,
        org_id: UUID,
    ) -> dict[str, Any]:
        """
        Query a brain controller for its available VPN servers.

        Returns a normalized dict with keys:
          openvpn: list of OpenVPN server instances
          wireguard: list of WireGuard server interfaces
          ipsec: list of IPsec tunnels
        """
        ctrl = await self.get_brain_controller(controller_id, org_id)
        adapter = await _get_adapter_for_controller(ctrl)

        try:
            result = await adapter.get_vpn_status()
            if not result.success:
                raise ValueError(f"Failed to query VPN: {result.message}")

            data = result.data or {}
            servers: dict[str, Any] = {
                "controller_id": str(ctrl.id),
                "controller_name": ctrl.name,
                "controller_type": ctrl.controller_type,
                "site_id": str(ctrl.site_id),
                "openvpn": [],
                "wireguard": [],
                "ipsec": [],
            }

            # Normalize OpenVPN instances (filter to servers)
            ovpn_data = data.get("openvpn", {})
            instances = ovpn_data if isinstance(ovpn_data, list) else ovpn_data.get("instances", [])
            for inst in instances if isinstance(instances, list) else []:
                if isinstance(inst, dict):
                    role = inst.get("role", inst.get("mode", ""))
                    # Include servers (and dual-mode/any, but not pure clients)
                    if role in ("server", "", "p2p") or "server" in str(role).lower():
                        servers["openvpn"].append(
                            {
                                "id": inst.get("uuid", inst.get("id", "")),
                                "description": inst.get(
                                    "description", inst.get("name", "OpenVPN Server")
                                ),
                                "protocol": inst.get("proto", inst.get("protocol", "udp")),
                                "port": inst.get("port", inst.get("local_port", "1194")),
                                "mode": role or "server",
                                "status": inst.get("status_text", inst.get("status", "unknown")),
                                "dev_type": inst.get("dev_type", "tun"),
                            }
                        )

            # Normalize WireGuard servers
            wg_data = data.get("wireguard", {})
            wg_servers = wg_data if isinstance(wg_data, list) else wg_data.get("servers", [])
            for srv in wg_servers if isinstance(wg_servers, list) else []:
                if isinstance(srv, dict):
                    servers["wireguard"].append(
                        {
                            "id": srv.get("uuid", srv.get("id", "")),
                            "name": srv.get("name", "WireGuard"),
                            "listen_port": srv.get("port", srv.get("listen_port", "51820")),
                            "public_key": srv.get("pubkey", srv.get("public_key", "")),
                            "peers": srv.get("peers", []),
                            "address": srv.get("tunneladdress", srv.get("address", "")),
                        }
                    )

            # Normalize IPsec tunnels
            ipsec_data = data.get("ipsec", {})
            # Various formats: list of tunnels, or dict with phase1/sad/spd
            ipsec_tunnels = (
                ipsec_data
                if isinstance(ipsec_data, list)
                else ipsec_data.get("phase1", ipsec_data.get("sad", []))
            )
            for tun in ipsec_tunnels if isinstance(ipsec_tunnels, list) else []:
                if isinstance(tun, dict):
                    servers["ipsec"].append(
                        {
                            "id": tun.get("uuid", tun.get("id", "")),
                            "description": tun.get("description", tun.get("descr", "IPsec Tunnel")),
                            "remote_gateway": tun.get(
                                "remote_gateway", tun.get("remote-addrs", "")
                            ),
                            "status": tun.get("status_text", tun.get("status", "unknown")),
                        }
                    )

            return servers
        finally:
            if hasattr(adapter, "close"):
                await adapter.close()

    # ── VPN Import ──────────────────────────────────────────────

    async def import_from_brain(
        self,
        controller_id: UUID,
        org_id: UUID,
        vpn_type: str,
        vpn_server_id: str,
        site_id: UUID | None = None,
    ) -> SiteVPNConfiguration:
        """
        Import a VPN config from a brain controller into SiteVPNConfiguration.

        Args:
            controller_id: The brain controller UUID
            org_id: Caller's organization ID
            vpn_type: 'openvpn', 'wireguard', or 'ipsec'
            vpn_server_id: ID of the VPN server on the brain
            site_id: Override site (defaults to controller's site)
        """
        ctrl = await self.get_brain_controller(controller_id, org_id)
        target_site_id = site_id or ctrl.site_id

        # Validate vpn_server_id format (prevent path traversal on adapter API)
        if not _VPN_SERVER_ID_RE.match(vpn_server_id):
            raise ValueError("Invalid VPN server ID format")

        # Verify site access
        site = (
            await self.session.execute(
                select(Site).where(
                    Site.id == target_site_id,
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if not site:
            raise ValueError("Site not found")

        adapter = await _get_adapter_for_controller(ctrl)
        try:
            config_data = await self._fetch_vpn_server_config(
                adapter, vpn_type, vpn_server_id, ctrl
            )
        finally:
            if hasattr(adapter, "close"):
                await adapter.close()

        # Upsert SiteVPNConfiguration (FOR UPDATE prevents race on concurrent imports)
        vpn_config = (
            await self.session.execute(
                select(SiteVPNConfiguration)
                .where(
                    SiteVPNConfiguration.site_id == target_site_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()

        if not vpn_config:
            # organization_id is required by every org-scoped read of this
            # table (endpoints/vpn.py, vpn_cert_lifecycle.py); a row created
            # without it is invisible to all of them.
            _site = (
                await self.db.execute(
                    select(Site.organization_id).where(
                        Site.id == target_site_id, Site.deleted_at.is_(None)
                    )
                )
            ).scalar_one_or_none()
            vpn_config = SiteVPNConfiguration(
                site_id=target_site_id,
                organization_id=_site,
                vpn_type=vpn_type,
                enabled=True,
                vpn_source=VPNSource.BRAIN_IMPORT,
                controller_id=controller_id,
                brain_vpn_server_id=vpn_server_id,
                status=VPNStatus.DISCONNECTED,
                last_config_sync=datetime.now(UTC),
            )
            self.session.add(vpn_config)
        else:
            vpn_config.vpn_type = vpn_type
            vpn_config.vpn_source = VPNSource.BRAIN_IMPORT
            vpn_config.controller_id = controller_id
            vpn_config.brain_vpn_server_id = vpn_server_id
            vpn_config.last_config_sync = datetime.now(UTC)

        # Apply provider-specific fields (allowlist prevents mass-assignment)
        for key, value in config_data.items():
            if key in _BRAIN_IMPORT_FIELDS:
                setattr(vpn_config, key, value)

        await self.session.flush()
        await self.session.refresh(vpn_config)
        return vpn_config

    async def _fetch_vpn_server_config(
        self,
        adapter: Any,
        vpn_type: str,
        server_id: str,
        ctrl: Controller,
    ) -> dict[str, Any]:
        """Fetch config for a specific VPN server from the brain adapter."""
        if vpn_type == VPNType.OPENVPN:
            result = await adapter.get_openvpn_instance(server_id)
            if not result.success:
                raise ValueError(f"Failed to fetch OpenVPN instance: {result.message}")
            inst = result.data or {}
            return {
                "openvpn_protocol": inst.get("proto", inst.get("protocol", "udp")),
                "openvpn_mode": "client",
                "vpn_endpoint": ctrl.host,
                "vpn_port": int(inst.get("port", inst.get("local_port", 1194))),
                "health_check_ip": ctrl.host,
                "remote_subnets": self._extract_subnets(inst),
            }

        elif vpn_type == VPNType.WIREGUARD:
            result = await adapter.get_wireguard_server(server_id)
            if not result.success:
                raise ValueError(f"Failed to fetch WireGuard server: {result.message}")
            srv = result.data or {}
            return {
                "wireguard_interface": srv.get("name", "wg0"),
                "wireguard_endpoint": f"{ctrl.host}:{srv.get('port', srv.get('listen_port', 51820))}",
                "wireguard_peer_public_key": srv.get("pubkey", srv.get("public_key", "")),
                "vpn_endpoint": ctrl.host,
                "vpn_port": int(srv.get("port", srv.get("listen_port", 51820))),
                "health_check_ip": ctrl.host,
                "remote_subnets": self._extract_wg_allowed_ips(srv),
            }

        elif vpn_type == VPNType.IPSEC:
            # IPsec import is informational — actual config is complex
            return {
                "vpn_endpoint": ctrl.host,
                "health_check_ip": ctrl.host,
            }

        else:
            raise ValueError(f"Unsupported VPN type for brain import: {vpn_type}")

    @staticmethod
    def _extract_subnets(ovpn_inst: dict[str, Any]) -> list[str]:
        """Extract remote subnets from an OpenVPN instance config."""
        subnets: list[str] = []
        # OPNsense: local_network field contains pushed routes
        for field in ("local_network", "server_push", "push_routes"):
            val = ovpn_inst.get(field, "")
            if isinstance(val, str) and val:
                for part in val.replace(",", " ").split():
                    part = part.strip()
                    if part:
                        try:
                            ipaddress.ip_network(part, strict=False)
                            subnets.append(part)
                        except ValueError:
                            pass
            elif isinstance(val, list):
                for item in val:
                    try:
                        ipaddress.ip_network(str(item).strip(), strict=False)
                        subnets.append(str(item).strip())
                    except ValueError:
                        pass
        return subnets

    @staticmethod
    def _extract_wg_allowed_ips(wg_server: dict[str, Any]) -> list[str]:
        """Extract subnets from WireGuard server tunnel address / allowed IPs."""
        subnets: list[str] = []
        for field in ("tunneladdress", "address", "allowed_ips"):
            val = wg_server.get(field, "")
            if isinstance(val, str) and val:
                for part in val.replace(",", " ").split():
                    part = part.strip()
                    if part:
                        try:
                            ipaddress.ip_network(part, strict=False)
                            subnets.append(part)
                        except ValueError:
                            pass
        return subnets

    # ── Subnet Sync ─────────────────────────────────────────────

    async def sync_subnets_from_brain(
        self,
        controller_id: UUID,
        org_id: UUID,
        current_user: Any = None,
    ) -> dict[str, Any]:
        """
                Pull interface subnets from brain's routing table → merge into Site.subnets.

                This is more reliable than agent-based discovery because the brain IS the router
                and knows every subnet it routes to.

                ``current_user`` (optional) is used to enforce the per-user site grant
        : a site-limited caller must not mutate ``Site.subnets``
                for a sibling site they lack a grant for.
        """
        ctrl = await self.get_brain_controller(controller_id, org_id)

        # site-grant gate before any mutation of the site's
        # subnet list. No-op for super_admin / org_admin / grant-less callers.
        if current_user is not None:
            from app.core.site_access import assert_can_access_site

            assert_can_access_site(current_user, ctrl.site_id, detail="Controller not found")

        # Get site (with row lock for merge safety)
        site = (
            await self.session.execute(
                select(Site)
                .where(
                    Site.id == ctrl.site_id,
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if not site:
            raise ValueError("Site not found")

        adapter = await _get_adapter_for_controller(ctrl)
        try:
            discovered = await self._discover_subnets_from_adapter(adapter, ctrl.controller_type)
        finally:
            if hasattr(adapter, "close"):
                await adapter.close()

        # Merge into site.subnets
        existing_cidrs = {s.get("cidr") for s in (site.subnets or []) if isinstance(s, dict)}
        merged = list(site.subnets or [])
        added = 0
        for cidr in discovered:
            if cidr not in existing_cidrs:
                merged.append(
                    {
                        "cidr": cidr,
                        "name": f"Brain ({ctrl.name})",
                        "vlan_id": None,
                        "description": f"Discovered from {ctrl.controller_type} routing table",
                    }
                )
                existing_cidrs.add(cidr)
                added += 1

        if len(merged) > MAX_SITE_SUBNETS:
            raise ValueError(f"Too many subnets ({len(merged)}); maximum is {MAX_SITE_SUBNETS}")

        if added > 0:
            site.subnets = merged
            await self.session.flush()

        return {
            "discovered": discovered,
            "added": added,
            "total": len(merged),
            "controller": ctrl.name,
        }

    async def _discover_subnets_from_adapter(
        self,
        adapter: Any,
        controller_type: str,
    ) -> list[str]:
        """
        Pull network interfaces / routing data from the brain to discover site subnets.
        """
        subnets: set[str] = set()

        # Try different methods depending on what the adapter supports
        methods = [
            ("get_interfaces", self._parse_interfaces),
            ("get_vpn_status", self._parse_vpn_subnets),
        ]

        for method_name, parser in methods:
            if not hasattr(adapter, method_name):
                continue
            try:
                result = await getattr(adapter, method_name)()
                if result.success and result.data:
                    found = parser(result.data)
                    subnets.update(found)
            except Exception as exc:
                logger.warning("Brain subnet discovery via %s failed: %s", method_name, exc)

        # Filter out non-routable / meta networks
        filtered: list[str] = []
        for cidr in sorted(subnets):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Skip loopback, link-local, multicast, and very large ranges
                if (
                    net.is_loopback
                    or net.is_link_local
                    or net.is_multicast
                    or net.prefixlen < 8  # /8 or larger — too broad
                    or str(net) == "0.0.0.0/0"
                ):
                    continue
                filtered.append(str(net))
            except ValueError:
                pass

        return filtered

    @staticmethod
    def _parse_interfaces(data: Any) -> set[str]:
        """Extract CIDRs from interface data."""
        subnets: set[str] = set()
        if isinstance(data, list):
            for iface in data:
                if isinstance(iface, dict):
                    for field in ("address", "subnet", "ipaddr", "network"):
                        val = iface.get(field, "")
                        if isinstance(val, str) and "/" in val:
                            try:
                                net = ipaddress.ip_network(val, strict=False)
                                subnets.add(str(net))
                            except ValueError:
                                pass
        elif isinstance(data, dict):
            for _name, iface in data.items():
                if isinstance(iface, dict):
                    for field in ("address", "subnet", "ipaddr", "network"):
                        val = iface.get(field, "")
                        if isinstance(val, str) and "/" in val:
                            try:
                                net = ipaddress.ip_network(val, strict=False)
                                subnets.add(str(net))
                            except ValueError:
                                pass
        return subnets

    @staticmethod
    def _parse_vpn_subnets(data: Any) -> set[str]:
        """Extract subnets advertised through VPN servers."""
        subnets: set[str] = set()
        if not isinstance(data, dict):
            return subnets
        # Check OpenVPN local_network / push routes
        for section in ("openvpn", "wireguard", "ipsec"):
            section_data = data.get(section, {})
            if isinstance(section_data, dict):
                for _key, items in section_data.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                for field in (
                                    "local_network",
                                    "tunneladdress",
                                    "local_subnet",
                                    "allowed_ips",
                                ):
                                    val = item.get(field, "")
                                    if isinstance(val, str):
                                        for part in val.replace(",", " ").split():
                                            try:
                                                net = ipaddress.ip_network(
                                                    part.strip(), strict=False
                                                )
                                                subnets.add(str(net))
                                            except ValueError:
                                                pass
        return subnets

    # ── OpenVPN Config Import ───────────────────────────────────

    @staticmethod
    def validate_openvpn_config(content: str) -> dict[str, Any]:
        """
        Parse and validate an OpenVPN .ovpn config file content.

        Returns extracted metadata (protocol, port, remote, etc.).
        Raises ValueError if the config is invalid or dangerous.
        """
        if not content or not content.strip():
            raise ValueError("Empty OpenVPN config")

        # Safety: reject excessively large configs (100KB max — generous for .ovpn with embedded certs)
        if len(content) > 102400:
            raise ValueError("OpenVPN config too large (max 100KB)")

        lines = content.strip().splitlines()
        meta: dict[str, Any] = {
            "protocol": "udp",
            "port": 1194,
            "remote": None,
            "dev_type": "tun",
            "has_ca": False,
            "has_cert": False,
            "has_key": False,
            "has_tls_auth": False,
        }

        # Detect dangerous directives — single source of truth shared with the
        # connection-config schema validator so the two ingest paths can't drift.
        DANGEROUS_DIRECTIVES = _DANGEROUS_OPENVPN_DIRECTIVES

        in_inline = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue

            # Track inline blocks (<ca>, <cert>, <key>, <tls-auth>)
            if stripped.startswith("<"):
                tag = stripped.strip("<>/ ")
                if stripped.startswith("</"):
                    in_inline = False
                else:
                    in_inline = True
                    if tag == "ca":
                        meta["has_ca"] = True
                    elif tag == "cert":
                        meta["has_cert"] = True
                    elif tag in ("key", "secret"):
                        meta["has_key"] = True
                    elif tag == "tls-auth":
                        meta["has_tls_auth"] = True
                continue

            if in_inline:
                continue

            parts = stripped.split(None, 1)
            # strip a leading `--` (OpenVPN accepts it in config files) so e.g.
            # `--up /script` can't slip past the dangerous-directive check — mirrors
            # the schema validator (_assert_openvpn_config_safe)
            directive = parts[0].lstrip("-").lower()

            # Safety: reject configs with script execution
            if directive in DANGEROUS_DIRECTIVES:
                raise ValueError(
                    f"OpenVPN config contains dangerous directive: '{directive}'. "
                    "Remove script-execution directives before importing."
                )
            # Reject file-PATH references to cert/credential material (arbitrary-
            # file read/exfil via the root daemon); require inline blocks instead.
            if directive in _OPENVPN_FILE_REF_DIRECTIVES:
                arg = ""
                if len(parts) > 1:
                    arg = parts[1].split()[0].strip("\"'").lower() if parts[1].split() else ""
                if arg and arg not in _OPENVPN_SAFE_FILE_REF_ARGS:
                    raise ValueError(
                        f"OpenVPN '{directive}' must be supplied inline, not as a file path."
                    )

            if directive == "remote" and len(parts) > 1:
                remote_parts = parts[1].split()
                meta["remote"] = remote_parts[0]
                if len(remote_parts) > 1:
                    with contextlib.suppress(ValueError):
                        meta["port"] = int(remote_parts[1])
                if len(remote_parts) > 2:
                    meta["protocol"] = remote_parts[2]

            elif directive == "proto" and len(parts) > 1:
                meta["protocol"] = parts[1].strip().lower()

            elif directive == "port" and len(parts) > 1:
                with contextlib.suppress(ValueError):
                    meta["port"] = int(parts[1].strip())

            elif directive == "dev" and len(parts) > 1:
                meta["dev_type"] = parts[1].strip()

        return meta

    async def import_openvpn_config(
        self,
        site_id: UUID,
        org_id: UUID,
        config_content: str,
    ) -> SiteVPNConfiguration:
        """
        Import an OpenVPN .ovpn config for a site.
        Validates the config, stores it, and creates/updates SiteVPNConfiguration.
        """
        # Validate
        meta = self.validate_openvpn_config(config_content)

        # Verify site access
        site = (
            await self.session.execute(
                select(Site).where(
                    Site.id == site_id,
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if not site:
            raise ValueError("Site not found")

        # Upsert config (FOR UPDATE prevents race on concurrent imports)
        vpn_config = (
            await self.session.execute(
                select(SiteVPNConfiguration)
                .where(
                    SiteVPNConfiguration.site_id == site_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()

        if not vpn_config:
            # See the note on the sibling construction above: without
            # organization_id this row is invisible to every org-scoped read.
            _site = (
                await self.db.execute(
                    select(Site.organization_id).where(
                        Site.id == site_id, Site.deleted_at.is_(None)
                    )
                )
            ).scalar_one_or_none()
            vpn_config = SiteVPNConfiguration(
                site_id=site_id,
                organization_id=_site,
                vpn_type=VPNType.OPENVPN,
                enabled=True,
                vpn_source=VPNSource.MANUAL,
                # Encrypted at rest, like every other write of this column.
                #
                # ``POST /vpn/connections`` stores it as
                # ``encrypt_credential(data.openvpn_config_content)``; this
                # site-import path stored the raw text. An .ovpn file is not
                # config, it is a CREDENTIAL: it carries the CA cert, the client
                # cert and, inline, the client private key. So importing a
                # site's OpenVPN profile wrote a complete VPN identity into the
                # database in plaintext, on a column the backup module already
                # lists as per-field encrypted.
                #
                # It also split the two readers: adapter_overlay_vpn does
                # ``_safe_decrypt(rec.openvpn_config_content)``, which quietly
                # returned None for these rows, so "connect this site's OpenVPN
                # overlay" handed the manager no config at all.
                openvpn_config_content=encrypt_credential(config_content),
                openvpn_protocol=meta["protocol"],
                openvpn_mode="client",
                vpn_endpoint=meta["remote"],
                vpn_port=meta["port"],
                health_check_ip=meta["remote"],
                status=VPNStatus.DISCONNECTED,
            )
            self.session.add(vpn_config)
        else:
            vpn_config.vpn_type = VPNType.OPENVPN
            vpn_config.openvpn_config_content = encrypt_credential(config_content)
            vpn_config.openvpn_protocol = meta["protocol"]
            vpn_config.openvpn_mode = "client"
            vpn_config.vpn_endpoint = meta["remote"]
            vpn_config.vpn_port = meta["port"]
            vpn_config.health_check_ip = meta["remote"]

        await self.session.flush()
        await self.session.refresh(vpn_config)
        return vpn_config
