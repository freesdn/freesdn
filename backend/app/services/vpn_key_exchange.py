# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Key Exchange Service
=============================================

Automated WireGuard key exchange for site-to-site tunnels.

Handles zero-touch S2S WireGuard tunnel setup between two sites:
1. Generate WireGuard keypair for each side
2. Build WireGuard config for both gateways
3. Store configs in the tunnel's config_a / config_b JSONB fields
4. Optionally push configs to gateway devices via adapters (if available)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.core import Site
from app.models.devices import Device
from app.models.vpn import SiteToSiteTunnel

logger = logging.getLogger(__name__)


def _safe_decrypt(val: str | None) -> str:
    """Decrypt a credential value if encrypted, otherwise return as-is."""
    if not val:
        return ""
    return decrypt_credential(val) if is_encrypted(val) else val


class VPNKeyExchangeService:
    """
    Automates WireGuard keypair generation and config provisioning
    for site-to-site tunnels.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    async def generate_s2s_wireguard_config(
        self,
        tunnel_id: UUID,
        org_id: UUID,
        site_a_endpoint: str | None = None,
        site_b_endpoint: str | None = None,
        site_a_port: int = 51820,
        site_b_port: int = 51821,
        site_a_subnets: list[str] | None = None,
        site_b_subnets: list[str] | None = None,
        mtu: int | None = None,
    ) -> dict:
        """
        Generate WireGuard keypairs and configs for both sides of a S2S tunnel.

        Steps:
            1. Load SiteToSiteTunnel by id + org_id
            2. Generate keypair A (private_key_a, public_key_a)
            3. Generate keypair B (private_key_b, public_key_b)
            4. Build config_a dict with private_key, peer info, listen_port, etc.
            5. Build config_b dict (swapped keys)
            6. Encrypt private keys via encrypt_credential() before storing
            7. Update tunnel.config_a, tunnel.config_b, tunnel.status = 'provisioning'
            8. Return summary dict

        Returns:
            Summary dict with public keys, endpoints, and status.

        Raises:
            ValueError: If the tunnel is not found or not owned by the org.
        """
        # 1. Load tunnel
        tunnel = await self._load_tunnel(tunnel_id, org_id)

        # 2–3. Generate keypairs for both sides
        private_key_a, public_key_a = await self._generate_keypair()
        private_key_b, public_key_b = await self._generate_keypair()

        # Resolve subnets from Site records if not explicitly provided
        if site_a_subnets is None:
            site_a_subnets = await self._resolve_site_subnets(tunnel.site_a_id)
        if site_b_subnets is None:
            site_b_subnets = await self._resolve_site_subnets(tunnel.site_b_id)

        # 4. Build config for side A
        config_a = self._build_wg_config(
            private_key=encrypt_credential(private_key_a),
            listen_port=site_a_port,
            peer_public_key=public_key_b,
            peer_endpoint=site_b_endpoint,
            peer_port=site_b_port,
            allowed_ips=site_b_subnets or ["0.0.0.0/0"],
            mtu=mtu,
        )

        # 5. Build config for side B (swapped)
        config_b = self._build_wg_config(
            private_key=encrypt_credential(private_key_b),
            listen_port=site_b_port,
            peer_public_key=public_key_a,
            peer_endpoint=site_a_endpoint,
            peer_port=site_a_port,
            allowed_ips=site_a_subnets or ["0.0.0.0/0"],
            mtu=mtu,
        )

        # 6–7. Store configs and update status
        tunnel.config_a = config_a
        tunnel.config_b = config_b
        tunnel.status = "provisioning"
        tunnel.error_message = None

        await self.db.flush()

        logger.info(
            "Generated WireGuard config for tunnel %s (org %s): side_a_port=%d, side_b_port=%d",
            tunnel_id,
            org_id,
            site_a_port,
            site_b_port,
        )

        # 8. Return summary (never expose private keys)
        return {
            "tunnel_id": str(tunnel_id),
            "status": "provisioning",
            "site_a": {
                "public_key": public_key_a,
                "endpoint": site_a_endpoint,
                "listen_port": site_a_port,
                "allowed_ips": config_a["allowed_ips"],
            },
            "site_b": {
                "public_key": public_key_b,
                "endpoint": site_b_endpoint,
                "listen_port": site_b_port,
                "allowed_ips": config_b["allowed_ips"],
            },
            "mtu": mtu,
        }

    async def push_config_to_gateway(
        self,
        tunnel_id: UUID,
        org_id: UUID,
        side: str,
    ) -> dict:
        """
        Push WireGuard config to the gateway device for one side of the tunnel.

        Args:
            tunnel_id: The S2S tunnel UUID.
            org_id: Organization UUID for tenant scoping.
            side: Which side to push — ``"a"`` or ``"b"``.

        Returns:
            Dict with ``success``, ``message``, and ``device_id``.
        """
        if side not in ("a", "b"):
            raise ValueError(f"Invalid side '{side}': must be 'a' or 'b'")

        tunnel = await self._load_tunnel(tunnel_id, org_id)

        # Resolve device ID and config for the requested side
        device_id: UUID | None = (
            tunnel.gateway_a_device_id if side == "a" else tunnel.gateway_b_device_id
        )
        config: dict = tunnel.config_a if side == "a" else tunnel.config_b

        if not device_id:
            return {
                "success": False,
                "message": f"No gateway device assigned for side {side}",
                "device_id": None,
            }

        if not config:
            return {
                "success": False,
                "message": f"No WireGuard config generated for side {side}",
                "device_id": str(device_id),
            }

        # Load the device and its controller
        device = (
            await self.db.execute(
                select(Device)
                .options(selectinload(Device.controller))
                .where(Device.id == device_id)
            )
        ).scalar_one_or_none()

        if not device:
            return {
                "success": False,
                "message": f"Gateway device {device_id} not found",
                "device_id": str(device_id),
            }

        if not device.controller:
            return {
                "success": False,
                "message": f"Device {device_id} has no associated controller",
                "device_id": str(device_id),
            }

        # Get adapter for the controller
        try:
            from app.adapters import get_adapter

            ctrl = device.controller
            cloud_kwargs: dict = {}
            if getattr(ctrl, "connection_mode", None) == "cloud":
                cloud_kwargs = {
                    "client_id": ctrl.client_id or "",
                    "client_secret": _safe_decrypt(ctrl.client_secret),
                    "omada_id": ctrl.omada_id or "",
                    "cloud_region": ctrl.cloud_region or "us",
                }

            adapter = await get_adapter(
                adapter_type=ctrl.controller_type,
                host=ctrl.host,
                username=ctrl.username or "",
                password=_safe_decrypt(ctrl.password),
                port=ctrl.port,
                use_ssl=getattr(ctrl, "use_ssl", True),
                verify_ssl=getattr(ctrl, "verify_ssl", False),
                **cloud_kwargs,
            )
        except Exception:
            logger.exception(
                "Failed to create adapter for device %s (controller %s)",
                device_id,
                device.controller_id,
            )
            return {
                "success": False,
                "message": "Failed to connect to gateway controller",
                "device_id": str(device_id),
            }

        # Attempt to push WireGuard config via adapter
        try:
            if not hasattr(adapter, "configure_wireguard"):
                return {
                    "success": False,
                    "message": (
                        f"Adapter {ctrl.controller_type} does not support configure_wireguard()"
                    ),
                    "device_id": str(device_id),
                }

            # Decrypt private key before pushing to the device
            push_config = dict(config)
            if push_config.get("private_key"):
                push_config["private_key"] = _safe_decrypt(push_config["private_key"])

            result = await adapter.configure_wireguard(push_config)

            if getattr(result, "success", True):
                logger.info(
                    "Pushed WireGuard config to device %s (side %s) for tunnel %s",
                    device_id,
                    side,
                    tunnel_id,
                )
                return {
                    "success": True,
                    "message": f"WireGuard config pushed to device {device.name}",
                    "device_id": str(device_id),
                }
            else:
                msg = getattr(result, "message", "Unknown adapter error")
                return {
                    "success": False,
                    "message": msg,
                    "device_id": str(device_id),
                }
        except Exception:
            logger.exception(
                "Error pushing WireGuard config to device %s",
                device_id,
            )
            return {
                "success": False,
                "message": "Error pushing config to gateway device",
                "device_id": str(device_id),
            }
        finally:
            if hasattr(adapter, "close"):
                try:
                    await adapter.close()
                except Exception:
                    logger.debug("Failed to close adapter during cleanup", exc_info=True)

    # ─────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────

    async def _load_tunnel(self, tunnel_id: UUID, org_id: UUID) -> SiteToSiteTunnel:
        """Load a SiteToSiteTunnel by ID, scoped to the organization.

        After the org fetch, enforce the request caller's per-user site grant on
        *both* tunnel endpoints. A site-to-site tunnel
        spans two sites, so a site-limited operator may only act on a tunnel when
        they hold a grant for both ``site_a_id`` and ``site_b_id``. Enforced at
        this single chokepoint via the request-scoped contextvar so every caller
        — including ``vpn.py``'s ``generate-keys`` / ``push-config`` endpoints,
        which do not thread ``current_user`` — is covered. No-op for
        super_admin / org_admin / grant-less users and in background context.
        """
        tunnel = (
            await self.db.execute(
                select(SiteToSiteTunnel).where(
                    SiteToSiteTunnel.id == tunnel_id,
                    SiteToSiteTunnel.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()

        if not tunnel:
            raise ValueError(f"Tunnel {tunnel_id} not found (or not in org {org_id})")

        from app.core.site_access import assert_site_access_for_request

        assert_site_access_for_request(tunnel.site_a_id, detail="Tunnel not found")
        assert_site_access_for_request(tunnel.site_b_id, detail="Tunnel not found")
        return tunnel

    async def _resolve_site_subnets(self, site_id: UUID) -> list[str]:
        """
        Load subnets from the Site model's ``subnets`` JSONB field.
        Returns an empty list if the site has no subnets configured.
        """
        site = (await self.db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()

        if site and hasattr(site, "subnets") and site.subnets:
            return list(site.subnets)
        return []

    async def _generate_keypair(self) -> tuple[str, str]:
        """
        Generate a WireGuard keypair.

        Tries the ``wg`` CLI tool first (``wg genkey`` / ``wg pubkey``).
        Falls back to the ``cryptography`` library's X25519 if the ``wg``
        command is not available.

        Returns:
            Tuple of (private_key, public_key) as base64-encoded strings.
        """
        try:
            # Try wg command first
            proc = await asyncio.create_subprocess_exec(
                "wg",
                "genkey",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            private_key = stdout.decode().strip()

            proc2 = await asyncio.create_subprocess_exec(
                "wg",
                "pubkey",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
            stdout2, _ = await asyncio.wait_for(
                proc2.communicate(input=private_key.encode()),
                timeout=10,
            )
            public_key = stdout2.decode().strip()
            return private_key, public_key
        except Exception:
            # Fallback: use cryptography X25519
            import base64

            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )

            key = X25519PrivateKey.generate()
            priv = base64.b64encode(
                key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode()
            pub = base64.b64encode(
                key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode()
            return priv, pub

    def _build_wg_config(
        self,
        private_key: str,
        listen_port: int,
        peer_public_key: str,
        peer_endpoint: str | None,
        peer_port: int,
        allowed_ips: list[str],
        mtu: int | None = None,
    ) -> dict:
        """
        Build a WireGuard config dict for one side of the tunnel.

        The ``private_key`` should already be encrypted via
        ``encrypt_credential()`` before being passed here.

        Returns:
            Dict with interface and peer configuration.
        """
        config: dict = {
            "private_key": private_key,
            "listen_port": listen_port,
            "peer_public_key": peer_public_key,
            "allowed_ips": allowed_ips,
            "persistent_keepalive": 25,
        }

        if peer_endpoint:
            config["peer_endpoint"] = f"{peer_endpoint}:{peer_port}"
        else:
            config["peer_endpoint"] = None

        if mtu is not None:
            config["mtu"] = mtu

        config["generated_at"] = datetime.now(UTC).isoformat()

        return config
