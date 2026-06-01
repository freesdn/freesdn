# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense VPN service
=======================================

Read-and-stage for pfSense VPN config (OpenVPN, WireGuard, IPsec).

Status of write surface today:
    - The pfSense client only exposes *read* methods for VPN
      (``get_openvpn_servers``/``get_openvpn_clients``,
      ``get_wireguard_tunnels``/``get_wireguard_peers``,
      ``get_ipsec_tunnels``).
    - There is no ``add_openvpn_*`` / ``add_wireguard_*`` / ``add_ipsec_*``
      verb on the client. Until those land, this service exposes
      reads only and the ``_APPLY`` map is intentionally empty.

The shape still matches ``adapter_opnsense_vpn.py``: GatewayServiceBase,
``SUPPORTED_CONTROLLER_TYPE = "pfsense"``, and a ``build_applier`` that
refuses every feature with a clear 501. When the pfSense adapter grows
the write methods, populate ``_APPLY`` and add the dispatch branches.

Supported features:: (none yet — reads only)

The applier still passes ``force=True`` if/when populated, so the
sanctioned write path stays consistent with OPNsense.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

# (feature, operation) → bound client method name.
#
# Empty until the pfSense adapter grows OpenVPN / WireGuard / IPsec
# write methods. Keeping the map present (rather than deleting the
# applier) so the eventual diff is a one-line addition per feature.
_APPLY: dict[tuple[str, str], str] = {}


class GatewayPfsenseVpnService(GatewayServiceBase):
    """Live reads (writes deferred until adapter grows VPN write verbs)."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ─ OpenVPN ──────────────────────────────────────────

    async def list_openvpn_servers(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_openvpn_servers()
        # OpenVPN servers ship TLS keys, CA private material, and
        # static keys in many pfSense responses. Redact every
        # sensitive field before the payload leaves the service.
        return {
            "controller_id": controller_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def list_openvpn_clients(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_openvpn_clients()
        return {
            "controller_id": controller_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_openvpn_status(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.get_openvpn_status()
        return {
            "controller_id": controller_id,
            "item": redact_secrets(item),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ WireGuard ────────────────────────────────────────

    async def list_wireguard_tunnels(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_wireguard_tunnels()
        # WireGuard tunnels carry the interface's PRIVATE key in plain
        # text. Redact before exposing.
        return {
            "controller_id": controller_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def list_wireguard_peers(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_wireguard_peers()
        # WireGuard peers expose pre-shared keys and peer pubkeys —
        # the latter are technically public, but PSKs are not.
        return {
            "controller_id": controller_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ IPsec ────────────────────────────────────────────

    async def list_ipsec_tunnels(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_ipsec_tunnels()
        # IPsec phase-1 entries embed PSKs / pre_shared_key fields.
        return {
            "controller_id": controller_id,
            "items": redact_list(items) if isinstance(items, list) else redact_secrets(items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_ipsec_status(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.get_ipsec_status()
        return {
            "controller_id": controller_id,
            "item": redact_secrets(item),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Today every VPN feature lands in the empty-_APPLY branch and
        gets a 501. When the pfSense adapter grows write methods, fill
        in ``_APPLY`` and add the per-feature dispatch (mirror
        ``adapter_opnsense_vpn.py``).
        """

        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense VPN write surface is not yet implemented "
                        f"(feature={c.feature!r}, operation={c.operation!r}). "
                        "The adapter exposes reads only — add the "
                        "corresponding ``add_*``/``delete_*`` method to "
                        "``app/adapters/pfsense/client.py`` first."
                    ),
                )
            # Unreachable today — kept so the diff to enable a feature
            # is a single addition to ``_APPLY`` plus the dispatch
            # branch below. Mirror ``adapter_opnsense_vpn.py`` when
            # filling these in.
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense adapter has no method {method_name!r}; missing implementation"
                    ),
                )
            payload = c.payload or {}
            target_id = c.target_id
            # Default shape: create(payload), delete(target_id) — adjust
            # per-feature when the adapter side is ready.
            if c.operation == "create":
                return await method(payload, force=True)
            if c.operation == "delete":
                return await method(target_id, force=True)
            raise HTTPException(
                400,
                detail=(f"unhandled operation={c.operation!r} for feature={c.feature!r}"),
            )

        return _apply
