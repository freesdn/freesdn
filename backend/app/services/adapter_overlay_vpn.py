# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Overlay (daemon) VPN apply service.

Applies staged ``overlay.*`` VPN writes — appliance-local daemon actions
(WireGuard/OpenVPN/NetBird/Tailscale connect/disconnect). Unlike every other
gateway apply service, these have NO vendor controller and NO adapter client: the
write is a local daemon operation enacted through the VPN manager. This service is
therefore deliberately client-LESS — it never calls ``_resolve_controller_or_gateway``
or ``_get_client`` (there is nothing to resolve), which is also why a NULL
``controller_id`` on the staged row is correct here.

Safety: reached only via ``AdapterStagingService.apply_change``, so the dual-gate
(``ADAPTER_READ_ONLY=false`` + ``force=true``) and operator sign-off already
governed this call. The applier re-reads + decrypts the connection's config from
the ``VPNConnectionRecord`` (secrets are NEVER carried in the staged payload), and
surfaces a daemon failure as an HTTP 502 so the change is recorded ``failed``,
never ``applied`` against a tunnel that did not come up.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import select

from app.services.adapter_base import GatewayServiceBase

# Only the REVERSIBLE overlay ops are exposed: connect/disconnect (and tailscale
# reconnect). The irreversible Tailscale ``up`` (--reset, re-enrolls) and
# ``logout`` (deauthorizes the node) are deliberately NOT Fabric ops.
#
# Connection-bound ops resolve a stored VPNConnectionRecord (by the staged
# target_id) to read+decrypt its config; singleton daemon ops act on the one
# node-local daemon and take no connection.
_CONNECTION_BOUND_FEATURES = frozenset(
    {
        "overlay.wireguard.connect",
        "overlay.wireguard.disconnect",
        "overlay.openvpn.connect",
        "overlay.openvpn.disconnect",
        "overlay.netbird.connect",
    }
)
_SINGLETON_FEATURES = frozenset(
    {
        "overlay.netbird.disconnect",
        "overlay.tailscale.disconnect",
        "overlay.tailscale.reconnect",
    }
)
_SUPPORTED_FEATURES = _CONNECTION_BOUND_FEATURES | _SINGLETON_FEATURES


class OverlayVPNApplierService(GatewayServiceBase):
    """Apply service for staged ``overlay.*`` daemon VPN writes (no controller)."""

    async def _get_record(self, target_id: Any, organization_id: Any) -> Any:
        """Org-scoped fetch of the staged change's VPN connection record (404 on
        miss / cross-org — re-validates tenancy at apply time)."""
        from app.models.vpn import VPNConnectionRecord

        rec = (
            await self.db.execute(
                select(VPNConnectionRecord).where(
                    VPNConnectionRecord.id == target_id,
                    VPNConnectionRecord.organization_id == organization_id,
                )
            )
        ).scalar_one_or_none()
        if rec is None:
            raise HTTPException(404, detail="VPN connection not found")
        return rec

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that enacts ``change`` on the local VPN daemon.

        Mirrors the gateway applier contract (``apply_change`` calls ``await
        applier(change)``), but routes to ``VPNManagerService`` daemon methods
        instead of an adapter client, and never touches a controller.
        """

        async def _apply(c: Any) -> Any:
            # Reuse the exact materialize/decrypt/name helpers the REST path uses
            # (lazy import avoids an endpoint↔service import cycle at module load).
            from app.api.v1.endpoints.vpn import (
                _openvpn_conn_name,
                _safe_decrypt,
                _wireguard_iface_name,
            )
            from app.services.vpn_integration import TailscaleSetupService, get_vpn_manager

            feature = c.feature
            if feature not in _SUPPORTED_FEATURES:
                raise HTTPException(400, detail=f"no overlay applier for feature={feature!r}")

            manager = get_vpn_manager()

            # Singleton daemon ops — act on the one node-local daemon, no record.
            if feature == "overlay.tailscale.disconnect":
                result = await TailscaleSetupService().disconnect()
            elif feature == "overlay.tailscale.reconnect":
                result = await TailscaleSetupService().reconnect()
            elif feature == "overlay.netbird.disconnect":
                result = await manager.netbird.disconnect()
            else:
                # Connection-bound ops — resolve + decrypt the stored record.
                if not c.target_id:
                    raise HTTPException(400, detail=f"{feature} requires a connection_id")
                rec = await self._get_record(c.target_id, c.organization_id)
                if feature == "overlay.wireguard.connect":
                    result = await manager.wireguard.connect(
                        _wireguard_iface_name(rec),
                        config_content=_safe_decrypt(rec.wireguard_config_content),
                    )
                elif feature == "overlay.wireguard.disconnect":
                    result = await manager.wireguard.disconnect(_wireguard_iface_name(rec))
                elif feature == "overlay.openvpn.connect":
                    result = await manager.openvpn.connect(
                        _openvpn_conn_name(rec),
                        config_content=_safe_decrypt(rec.openvpn_config_content),
                    )
                elif feature == "overlay.openvpn.disconnect":
                    result = await manager.openvpn.disconnect(_openvpn_conn_name(rec))
                elif feature == "overlay.netbird.connect":
                    result = await manager.netbird.connect(
                        setup_key=_safe_decrypt(rec.netbird_setup_key),
                        management_url=rec.netbird_management_url,
                    )
                else:  # pragma: no cover - guarded by _SUPPORTED_FEATURES above
                    raise HTTPException(400, detail=f"no overlay applier for feature={feature!r}")

            # The daemon methods return a plain dict (not an AdapterResult), so
            # apply_change's ``getattr(resp, "success") is False`` failure check
            # cannot see a failed dict — surface daemon failure as 502 HERE so the
            # change is recorded ``failed``, never a false ``applied``.
            if not (isinstance(result, dict) and result.get("success")):
                detail = (
                    (result.get("message") or result.get("error"))
                    if isinstance(result, dict)
                    else None
                ) or f"{feature} did not succeed"
                raise HTTPException(502, detail=detail)
            return result

        return _apply
