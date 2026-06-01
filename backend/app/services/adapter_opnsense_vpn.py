# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense VPN service
========================================

Read-and-stage for OPNsense VPN config across all three protocols
(WireGuard, OpenVPN, IPsec). Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX
applies. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.vpn.wireguard.server      create | update | delete
    opnsense.vpn.wireguard.peer        create | update | delete
    opnsense.vpn.wireguard.apply       create
    opnsense.vpn.openvpn.instance      create | update | delete
    opnsense.vpn.openvpn.apply         create
    opnsense.vpn.ipsec.connect         create  (target_id = tunnel uuid)
    opnsense.vpn.ipsec.disconnect      create  (target_id = tunnel uuid)
    opnsense.vpn.ipsec.apply           create

The applier passes ``force=True`` to the OPNsense client so the
write actually reaches the controller — every write outside the
applier is refused at the client layer by the
``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada services use.
_APPLY: dict[tuple[str, str], str] = {
    # WireGuard server CRUD.
    ("opnsense.vpn.wireguard.server", "create"): "add_wireguard_server",
    ("opnsense.vpn.wireguard.server", "update"): "update_wireguard_server",
    ("opnsense.vpn.wireguard.server", "delete"): "delete_wireguard_server",
    # WireGuard peer (client) CRUD.
    ("opnsense.vpn.wireguard.peer", "create"): "add_wireguard_peer",
    ("opnsense.vpn.wireguard.peer", "update"): "update_wireguard_peer",
    ("opnsense.vpn.wireguard.peer", "delete"): "delete_wireguard_peer",
    # Apply commits the staged WireGuard config (server + peers) by
    # reconfiguring the service.
    ("opnsense.vpn.wireguard.apply", "create"): "apply_wireguard_changes",
    # OpenVPN instance CRUD (the new instances API; covers both
    # server and client roles via the instance ``role`` field).
    ("opnsense.vpn.openvpn.instance", "create"): "add_openvpn_instance",
    ("opnsense.vpn.openvpn.instance", "update"): "update_openvpn_instance",
    ("opnsense.vpn.openvpn.instance", "delete"): "delete_openvpn_instance",
    ("opnsense.vpn.openvpn.apply", "create"): "apply_openvpn_changes",
    # IPsec session control. ``connect`` / ``disconnect`` operate on
    # an existing phase-1 tunnel UUID — no payload, just target_id.
    ("opnsense.vpn.ipsec.connect", "create"): "connect_ipsec_tunnel",
    ("opnsense.vpn.ipsec.disconnect", "create"): "disconnect_ipsec_tunnel",
    ("opnsense.vpn.ipsec.apply", "create"): "apply_ipsec_changes",
}

# Features whose applier passes only the payload (creates of objects
# whose UUID is server-assigned).
_PAYLOAD_ONLY_CREATE = frozenset(
    {
        "opnsense.vpn.wireguard.server",
        "opnsense.vpn.wireguard.peer",
        "opnsense.vpn.openvpn.instance",
    }
)

# Features whose applier passes target_id + payload (updates).
_TARGET_AND_PAYLOAD_UPDATE = frozenset(
    {
        "opnsense.vpn.wireguard.server",
        "opnsense.vpn.wireguard.peer",
        "opnsense.vpn.openvpn.instance",
    }
)

# Features whose delete applier passes only the target_id.
_TARGET_ONLY_DELETE = frozenset(
    {
        "opnsense.vpn.wireguard.server",
        "opnsense.vpn.wireguard.peer",
        "opnsense.vpn.openvpn.instance",
    }
)

# Features that take only target_id on ``create`` (IPsec session
# control — connect/disconnect by tunnel uuid, no body).
_IPSEC_SESSION_FEATURES = frozenset(
    {
        "opnsense.vpn.ipsec.connect",
        "opnsense.vpn.ipsec.disconnect",
    }
)

# Features that are pure ``apply`` commits (no args).
_APPLY_ONLY_FEATURES = frozenset(
    {
        "opnsense.vpn.wireguard.apply",
        "opnsense.vpn.openvpn.apply",
        "opnsense.vpn.ipsec.apply",
    }
)


class GatewayOpnsenseVpnService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense VPN config (WG/OVPN/IPsec)."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ─ WireGuard ────────────────────────────────────────

    async def list_wireguard_servers(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            servers = await client.get_wireguard_servers()
        finally:
            await client.close()
        # OPNsense ships server-side ``privkey`` and ``psk`` on every
        # row. Strip them before they cross the API boundary.
        return {
            "controller_id": controller_id,
            "items": redact_secrets(servers),
            "fetched_at": datetime.now(UTC),
        }

    async def list_wireguard_peers(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            peers = await client.get_wireguard_peers()
        finally:
            await client.close()
        # OPNsense peer rows carry ``psk`` and (rarely) embed key
        # material. Redact before returning to ``firewall:read``.
        return {
            "controller_id": controller_id,
            "items": redact_secrets(peers),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ OpenVPN ──────────────────────────────────────────

    async def list_openvpn_instances(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            instances = await client.get_openvpn_instances()
        finally:
            await client.close()
        # OPNsense instance rows leak ``tls_key``/``tls_auth``/``cert``/
        # ``key``/``auth_user_pass`` — strip before they reach the API.
        return {
            "controller_id": controller_id,
            "items": redact_secrets(instances),
            "fetched_at": datetime.now(UTC),
        }

    async def get_openvpn_status(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            # The client exposes session search as the active-status view.
            sessions = await client.get_openvpn_sessions()
        finally:
            await client.close()
        return {
            "controller_id": controller_id,
            "sessions": redact_secrets(sessions),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ IPsec ────────────────────────────────────────────

    async def list_ipsec_tunnels(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            tunnels = await client.get_ipsec_tunnels()
        finally:
            await client.close()
        # IPsec rows can carry ``psk`` / pre-shared keys.
        return {
            "controller_id": controller_id,
            "items": redact_secrets(tunnels),
            "fetched_at": datetime.now(UTC),
        }

    async def get_ipsec_status(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            sad = await client.get_ipsec_status()
        finally:
            await client.close()
        return {
            "controller_id": controller_id,
            "sad": redact_secrets(sad),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the OPNsense client so it
        satisfies the client-layer read-only check — that gate
        is the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the
        gate via ``AdapterStagingService.apply_change``'s dual-gate
        check.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            try:
                payload = c.payload or {}
                target_id = c.target_id

                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                    )
                method = getattr(client, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"OPNsense adapter has no method {method_name!r}; "
                            "missing implementation"
                        ),
                    )

                # Dispatch by feature/operation. Each call gets force=True
                # so the read-only gate lets the write through — the
                # operator already passed force=true at the apply
                # endpoint, which is the high-level dual-gate.
                if c.feature in _APPLY_ONLY_FEATURES:
                    # No payload, no target — just commit.
                    return await method(force=True)
                if c.feature in _IPSEC_SESSION_FEATURES:
                    # connect/disconnect by tunnel uuid, no body.
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                f"feature={c.feature!r} requires target_id (the IPsec tunnel UUID)"
                            ),
                        )
                    return await method(target_id, force=True)
                if c.operation == "create" and c.feature in _PAYLOAD_ONLY_CREATE:
                    return await method(payload, force=True)
                if c.operation == "update" and c.feature in _TARGET_AND_PAYLOAD_UPDATE:
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"update on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, payload, force=True)
                if c.operation == "delete" and c.feature in _TARGET_ONLY_DELETE:
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"delete on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, force=True)
                raise HTTPException(
                    400,
                    detail=(f"unhandled feature/operation: {c.feature!r}/{c.operation!r}"),
                )
            finally:
                await client.close()  # Item 14

        return _apply
