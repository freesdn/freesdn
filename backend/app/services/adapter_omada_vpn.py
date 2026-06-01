# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-VPN service
==============================

Reads run live against the Omada controller. Writes flow through
:class:`AdapterStagingService` and never touch the live device until an
operator explicitly applies them.

Naming: ``gateway_vpn`` (Omada gateway VPN configuration) is distinct
from the existing :mod:`app.services.vpn` (FreeSDN's own agent /
Tailscale overlay). They are independent products that share the
acronym.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.models.core import Controller, Site  # noqa: F401  (build_applier annotates Controller)
from app.services.adapter_base import GatewayServiceBase, _decrypt  # noqa: F401
from app.services.adapter_redaction import redact_list, redact_secrets


class GatewayVPNService(GatewayServiceBase):
    """Read live VPN config from the controller; stage every write."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    # ── Helpers ─────────────────────────────────────────────────────────
    # ``_get_controller``, ``_get_client``, ``_resolve_omada_site_id``
    # all inherit from GatewayServiceBase. The base implementation does
    # a single-query JOIN and runs the SSRF host gate before building
    # the adapter, both of which the local copies skipped.

    @staticmethod
    def _envelope(
        controller_id: UUID,
        site_id: UUID | None,
        omada_site_id: str | None,
        items: list[dict[str, Any]] | dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "omada_site_id": omada_site_id,
            "items": items if isinstance(items, list) else [items],
            "fetched_at": datetime.now(UTC),
        }

    @staticmethod
    def _detail_envelope(
        controller_id: UUID,
        site_id: UUID | None,
        omada_site_id: str | None,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "omada_site_id": omada_site_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    # ── Status normalization ────────────────────────────────────────────
    # The Omada ``/insight/vpn/*/status`` endpoints return controller-shaped
    # payloads (camelCase / short keys like ``tx``/``rx``). The frontend
    # status table reads the snake_case ``VPNStatusEntry`` shape
    # (peer/state/bytes_rx/bytes_tx/last_handshake). Without a mapper, live
    # tunnels render as ``0 / 0`` and ``—`` because the keys never match.
    # Precedent: adapters/omada/adapter.py:1014 maps raw ``tx``→bytes_tx.

    @staticmethod
    def _pick(raw: dict[str, Any], *candidates: str) -> Any:
        """Return the first present, non-None value among ``candidates``."""
        for key in candidates:
            if key in raw and raw[key] is not None:
                return raw[key]
        return None

    @classmethod
    def _normalize_status_entry(cls, raw: Any) -> dict[str, Any]:
        """Map one Omada VPN-status row to the snake_case ``VPNStatusEntry``
        shape the frontend reads. Unrecognised keys are preserved under
        ``extra`` so nothing is silently lost. Non-dict rows pass through
        wrapped so the caller always gets a uniform shape."""
        if not isinstance(raw, dict):
            return {"extra": {"value": raw}}

        # Known mappings (Omada uses several spellings across protocols).
        known = {
            "name": ("name", "vpnName", "tunnelName", "policyName"),
            "peer": ("peer", "peerAddress", "remoteGateway", "remoteAddress", "clientIp", "ip"),
            "state": ("state", "status", "connState", "phase", "tunnelStatus"),
            "bytes_rx": ("bytes_rx", "rx", "rxBytes", "bytesRx", "rxByte"),
            "bytes_tx": ("bytes_tx", "tx", "txBytes", "bytesTx", "txByte"),
            "last_handshake": (
                "last_handshake",
                "lastHandshake",
                "latestHandshake",
                "since",
                "uptime",
                "establishedAt",
            ),
        }
        entry: dict[str, Any] = {}
        for target, candidates in known.items():
            value = cls._pick(raw, *candidates)
            if value is not None:
                entry[target] = value

        # State on Omada is often a numeric enum (1=up/connected). Stringify
        # so the FE renders something meaningful rather than a bare int.
        if isinstance(entry.get("state"), int):
            entry["state"] = {1: "connected", 0: "disconnected"}.get(
                entry["state"], str(entry["state"])
            )

        # Preserve any non-mapped keys so we never lose controller data.
        consumed = {c for cands in known.values() for c in cands}
        extra = {k: v for k, v in raw.items() if k not in consumed}
        if extra:
            entry["extra"] = extra
        return entry

    @classmethod
    def _normalize_status_items(cls, items: Any) -> list[dict[str, Any]]:
        if isinstance(items, list):
            return [cls._normalize_status_entry(it) for it in items]
        if items is None:
            return []
        return [cls._normalize_status_entry(items)]

    # ── IPsec — live reads ──────────────────────────────────────────────

    async def get_ipsec_config(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        config = await client.get_ipsec_config(omada_site_id)
        return self._detail_envelope(controller_id, site_id, omada_site_id, redact_secrets(config))

    async def list_ipsec_policies(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_ipsec_policies(omada_site_id)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            redact_list(items) if isinstance(items, list) else redact_secrets(items),
        )

    async def get_ipsec_status(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.get_ipsec_status(omada_site_id)
        redacted = redact_list(items) if isinstance(items, list) else redact_secrets(items)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            self._normalize_status_items(redacted),
        )

    # ── WireGuard — live reads ──────────────────────────────────────────

    async def get_wireguard_config(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        config = await client.get_wireguard_config(omada_site_id)
        return self._detail_envelope(controller_id, site_id, omada_site_id, redact_secrets(config))

    async def list_wireguard_peers(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_wireguard_peers(omada_site_id)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            redact_list(items) if isinstance(items, list) else redact_secrets(items),
        )

    async def get_wireguard_status(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.get_wireguard_status(omada_site_id)
        redacted = redact_list(items) if isinstance(items, list) else redact_secrets(items)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            self._normalize_status_items(redacted),
        )

    # ── L2TP / PPTP / OpenVPN / SSL-VPN — uniform reads ─────────────────

    async def list_protocol_users(
        self,
        protocol: str,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
    ) -> dict[str, Any]:
        method_name = {
            "openvpn": "list_openvpn_users",
            "l2tp": "list_l2tp_users",
            "pptp": "list_pptp_users",
            "sslvpn": "list_sslvpn_users",
        }.get(protocol)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(
                    f"protocol={protocol!r} has no users list; expected openvpn|l2tp|pptp|sslvpn"
                ),
            )
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await getattr(client, method_name)(omada_site_id)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            redact_list(items) if isinstance(items, list) else redact_secrets(items),
        )

    async def get_protocol_status(
        self,
        protocol: str,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
    ) -> dict[str, Any]:
        method_name = {
            "ipsec": "get_ipsec_status",
            "openvpn": "get_openvpn_status",
            "l2tp": "get_l2tp_status",
            "pptp": "get_pptp_status",
            "wireguard": "get_wireguard_status",
            "sslvpn": "get_sslvpn_status",
            "gre": "get_gre_status",
        }.get(protocol)
        if method_name is None:
            raise HTTPException(
                400,
                detail=f"protocol={protocol!r} not recognised",
            )
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await getattr(client, method_name)(omada_site_id)
        redacted = redact_list(items) if isinstance(items, list) else redact_secrets(items)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            self._normalize_status_items(redacted),
        )

    async def get_protocol_config(
        self,
        protocol: str,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
    ) -> dict[str, Any]:
        method_name = {
            "ipsec": "get_ipsec_config",
            "openvpn": "get_openvpn_config",
            "l2tp": "get_l2tp_config",
            "pptp": "get_pptp_config",
            "wireguard": "get_wireguard_config",
            "sslvpn": "get_sslvpn_config",
        }.get(protocol)
        if method_name is None:
            raise HTTPException(
                400,
                detail=f"protocol={protocol!r} has no global config endpoint",
            )
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        config = await getattr(client, method_name)(omada_site_id)
        return self._detail_envelope(controller_id, site_id, omada_site_id, redact_secrets(config))

    async def list_gre_tunnels(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        ctrl, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_gre_tunnels(omada_site_id)
        return self._envelope(
            controller_id,
            site_id,
            omada_site_id,
            redact_list(items) if isinstance(items, list) else redact_secrets(items),
        )

    # ── Stage writes (always safe — never touches Omada) ────────────────

    async def stage_change(
        self,
        *,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID | None,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> Any:
        """Stage a VPN-related change. Reads are unrestricted; writes
        always come through here and never reach the controller without
        an explicit apply."""
        ctrl = await self._get_controller(controller_id, organization_id)
        omada_site_id = None
        if site_id is not None:
            site = await self.db.get(Site, site_id)
            # Match base service: org-scope every site_id we accept.
            if (
                site is None
                or site.organization_id != organization_id
                or site.deleted_at is not None
            ):
                raise HTTPException(404, detail="site not found")
            omada_site_id = self._resolve_omada_site_id(ctrl, site)

        return await self.staging.stage_change(
            organization_id=organization_id,
            controller_id=ctrl.id,
            site_id=site_id,
            omada_site_id=omada_site_id,
            feature=feature,
            operation=operation,
            payload=payload,
            target_id=target_id,
            notes=notes,
            actor_id=actor_id,
        )

    # ── Build the per-feature applier (used only when force-apply runs) ─

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that knows how to push ``change`` to the
        controller. Used by :meth:`AdapterStagingService.apply_change`.

        Refused unless OMADA_READ_ONLY=false AND force=true at the call
        site — see ``AdapterStagingService.apply_change`` for the gate.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""

            feature = c.feature
            operation = c.operation
            payload = c.payload or {}
            target_id = c.target_id

            # Map (feature, operation) → client method name.
            method_map: dict[tuple[str, str], str] = {
                # IPsec
                ("vpn.ipsec.config", "update"): "update_ipsec_config",
                ("vpn.ipsec.policy", "create"): "create_ipsec_policy",
                ("vpn.ipsec.policy", "update"): "update_ipsec_policy",
                ("vpn.ipsec.policy", "delete"): "delete_ipsec_policy",
                # OpenVPN
                ("vpn.openvpn.config", "update"): "update_openvpn_config",
                ("vpn.openvpn.user", "create"): "create_openvpn_user",
                ("vpn.openvpn.user", "update"): "update_openvpn_user",
                ("vpn.openvpn.user", "delete"): "delete_openvpn_user",
                # L2TP
                ("vpn.l2tp.config", "update"): "update_l2tp_config",
                ("vpn.l2tp.user", "create"): "create_l2tp_user",
                ("vpn.l2tp.user", "update"): "update_l2tp_user",
                ("vpn.l2tp.user", "delete"): "delete_l2tp_user",
                # PPTP
                ("vpn.pptp.config", "update"): "update_pptp_config",
                ("vpn.pptp.user", "create"): "create_pptp_user",
                ("vpn.pptp.user", "update"): "update_pptp_user",
                ("vpn.pptp.user", "delete"): "delete_pptp_user",
                # WireGuard
                ("vpn.wireguard.config", "update"): "update_wireguard_config",
                ("vpn.wireguard.peer", "create"): "create_wireguard_peer",
                ("vpn.wireguard.peer", "update"): "update_wireguard_peer",
                ("vpn.wireguard.peer", "delete"): "delete_wireguard_peer",
                # SSL-VPN
                ("vpn.sslvpn.config", "update"): "update_sslvpn_config",
                ("vpn.sslvpn.user", "create"): "create_sslvpn_user",
                ("vpn.sslvpn.user", "update"): "update_sslvpn_user",
                ("vpn.sslvpn.user", "delete"): "delete_sslvpn_user",
                # GRE
                ("vpn.gre.tunnel", "create"): "create_gre_tunnel",
                ("vpn.gre.tunnel", "update"): "update_gre_tunnel",
                ("vpn.gre.tunnel", "delete"): "delete_gre_tunnel",
            }
            method_name = method_map.get((feature, operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier mapped for feature={feature!r} operation={operation!r}"),
                )

            method = getattr(client, method_name)

            # Argument shape varies by operation.
            if operation == "create":
                return await method(omada_site_id, payload)
            if operation == "update":
                if target_id is None:
                    # Some "update" endpoints set a global config (no target_id).
                    return await method(omada_site_id, payload)
                return await method(omada_site_id, target_id, payload)
            if operation == "delete":
                if target_id is None:
                    raise HTTPException(
                        400,
                        detail="delete requires target_id",
                    )
                return await method(omada_site_id, target_id)
            raise HTTPException(400, detail=f"bad operation={operation!r}")

        return _apply
