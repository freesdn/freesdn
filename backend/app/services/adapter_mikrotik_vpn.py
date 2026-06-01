# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik VPN service
=========================================

Read-and-stage for MikroTik RouterOS VPN config across all four
protocols the platform supports natively (IPsec, WireGuard, L2TP, PPTP).
Mirrors the shape of ``adapter_opnsense_firewall.py`` so the same
Pending Changes UX applies to MikroTik. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.vpn.ipsec.peer            create | update | delete
    mikrotik.vpn.ipsec.identity        create | update | delete
    mikrotik.vpn.ipsec.policy          create | update | delete
    mikrotik.vpn.ipsec.profile         create | update | delete
    mikrotik.vpn.wireguard.interface   create | update | delete
    mikrotik.vpn.wireguard.peer        create | update | delete
    mikrotik.vpn.l2tp_server           update         (singleton settings)
    mikrotik.vpn.pptp_server           update         (singleton settings)

Production safety: a managed MikroTik may be carrying production
traffic. Nothing here writes to the live device — every write is staged. The applier passes
``force=True`` so the universal ``ADAPTER_READ_ONLY`` gate at the
client layer lets the sanctioned write through; every write outside
this applier is refused at the bottom of the stack.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# the shared ``redact_secrets`` helper now
# normalises hyphens and covers the bulk of these names. We keep
# only RouterOS-specific entries the shared allowlist does not yet
# include.
#
# ``public-key`` is intentionally NOT in this VPN service's mask
# set: WireGuard public keys are public artefacts (the entire
# protocol is built on the assumption they're shared), and the UI
# uses them as the stable peer identifier in the peers tab. We keep
# ``private-key`` masked (which is what actually matters via the
# shared list) and let the public key flow through this layer. Note:
# the shared helper still masks ``public_key`` globally — the
# contract there is conservative and applies across all adapters,
# so a follow-up to that helper would be needed to fully expose
# public keys in WireGuard read responses.
_ROUTEROS_VPN_SENSITIVE: frozenset[str] = frozenset(
    {
        "shared-secret",  # IPsec / xAuth shared secret
        "auth-secret",  # IPsec / routing auth secret
    }
)


def _mask_routeros(payload: Any, depth: int = 0) -> Any:
    if depth >= 16:
        return payload
    if isinstance(payload, dict):
        return {
            k: (
                "***"
                if isinstance(k, str) and k.lower() in _ROUTEROS_VPN_SENSITIVE
                else _mask_routeros(v, depth + 1)
            )
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [_mask_routeros(i, depth + 1) for i in payload]
    return payload


def _redact_items(items: list[Any]) -> list[Any]:
    return [_mask_routeros(redact_secrets(i)) for i in items]


def _redact_item(item: Any) -> Any:
    return _mask_routeros(redact_secrets(item))


# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern OPNsense / pfSense services use.
_APPLY: dict[tuple[str, str], str] = {
    # IPsec — peers
    ("mikrotik.vpn.ipsec.peer", "create"): "add_ipsec_peer",
    ("mikrotik.vpn.ipsec.peer", "update"): "update_ipsec_peer",
    ("mikrotik.vpn.ipsec.peer", "delete"): "delete_ipsec_peer",
    # IPsec — identities
    ("mikrotik.vpn.ipsec.identity", "create"): "add_ipsec_identity",
    ("mikrotik.vpn.ipsec.identity", "update"): "update_ipsec_identity",
    ("mikrotik.vpn.ipsec.identity", "delete"): "delete_ipsec_identity",
    # IPsec — policies
    ("mikrotik.vpn.ipsec.policy", "create"): "add_ipsec_policy",
    ("mikrotik.vpn.ipsec.policy", "update"): "update_ipsec_policy",
    ("mikrotik.vpn.ipsec.policy", "delete"): "delete_ipsec_policy",
    # IPsec — profiles
    ("mikrotik.vpn.ipsec.profile", "create"): "add_ipsec_profile",
    ("mikrotik.vpn.ipsec.profile", "update"): "update_ipsec_profile",
    ("mikrotik.vpn.ipsec.profile", "delete"): "delete_ipsec_profile",
    # WireGuard — interfaces
    ("mikrotik.vpn.wireguard.interface", "create"): "add_wireguard_interface",
    ("mikrotik.vpn.wireguard.interface", "update"): "update_wireguard_interface",
    ("mikrotik.vpn.wireguard.interface", "delete"): "delete_wireguard_interface",
    # WireGuard — peers
    ("mikrotik.vpn.wireguard.peer", "create"): "add_wireguard_peer",
    ("mikrotik.vpn.wireguard.peer", "update"): "update_wireguard_peer",
    ("mikrotik.vpn.wireguard.peer", "delete"): "delete_wireguard_peer",
    # L2TP / PPTP — singleton server settings (no target_id, no create/delete)
    ("mikrotik.vpn.l2tp_server", "update"): "update_l2tp_server",
    ("mikrotik.vpn.pptp_server", "update"): "update_pptp_server",
}


# Features whose target identifier is per-row and required on update/delete.
_ROW_SCOPED_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.vpn.ipsec.peer",
        "mikrotik.vpn.ipsec.identity",
        "mikrotik.vpn.ipsec.policy",
        "mikrotik.vpn.ipsec.profile",
        "mikrotik.vpn.wireguard.interface",
        "mikrotik.vpn.wireguard.peer",
    }
)

# Singleton-config features (whole-resource update, no id).
_SINGLETON_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.vpn.l2tp_server",
        "mikrotik.vpn.pptp_server",
    }
)


class GatewayMikrotikVpnService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik VPN config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ─ IPsec ────────────────────────────────────────────

    async def list_ipsec_peers(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_peers()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ipsec_identities(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_identities()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ipsec_policies(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_policies()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ipsec_profiles(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_profiles()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ipsec_proposals(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_proposals()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_ipsec_active(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_ipsec_active()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ WireGuard ────────────────────────────────────────

    async def list_wireguard_interfaces(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_wireguard_interfaces()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_wireguard_peers(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_wireguard_peers()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Live reads ─ L2TP / PPTP ──────────────────────────────────────

    async def get_l2tp_server(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "item": _redact_item(await client.get_l2tp_server()),
            "fetched_at": datetime.now(UTC),
        }

    async def get_pptp_server(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "item": _redact_item(await client.get_pptp_server()),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the MikroTik client so it
        satisfies the client-layer read-only check — that gate is
        the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the gate
        via ``AdapterStagingService.apply_change``'s dual-gate check.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
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
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # Singleton features: PATCH the whole resource. No id.
            if c.feature in _SINGLETON_FEATURES:
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                return await method(payload, force=True)

            # Row-scoped features: create(payload), update(id, payload),
            # delete(id).
            if c.feature in _ROW_SCOPED_FEATURES:
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation == "update":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"update on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"delete on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, force=True)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply
