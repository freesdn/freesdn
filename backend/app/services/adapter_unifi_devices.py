# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Devices service
========================================

Live reads + staged writes for UniFi device (AP / switch / gateway)
management.

Supported features::

    unifi.devices.restart         update  target_id=mac
    unifi.devices.disable         update  target_id=mac
    unifi.devices.port_override   update  target_id=mac
    unifi.devices.set_port_poe    update  target_id=mac

``port_override`` payload carries ``{port_idx, overrides}``;
``set_port_poe`` carries ``{port_idx, mode}``; ``disable`` carries
``{disabled: bool}``; ``restart`` carries no extra payload (just the
site).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets
from app.services.adapter_unifi_common import enforce_unifi_site_grant

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.devices.restart", "update"): "restart_device",
    ("unifi.devices.disable", "update"): "disable_device",
    ("unifi.devices.port_override", "update"): "update_switch_port",
    ("unifi.devices.set_port_poe", "update"): "set_port_poe",
    ("unifi.devices.adopt", "update"): "adopt_device",
    ("unifi.devices.upgrade", "update"): "upgrade_device",
    ("unifi.devices.force_provision", "update"): "force_provision_device",
    ("unifi.devices.locate", "update"): "locate_device",
}


class GatewayUniFiDevicesService(GatewayServiceBase):
    """Live reads + staged writes for UniFi devices."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"

    # ── IDOR guard ───────────────────────────────────────────────────

    async def _verify_unifi_site_owned(
        self,
        ctrl: Any,
        client: Any,
        site: str,
    ) -> None:
        """Verify ``site`` is reachable on this controller.

        ``ctrl.site_mappings`` (operator-configured allowlist of UniFi
        site → FreeSDN site) is the strict allowlist. If populated and
        ``site`` is in it, we're done — no extra network call.
        Otherwise fall through to a live ``get_sites()`` check so we
        don't break controllers that haven't been onboarded with
        explicit mappings yet. Either path failing → 404.
        """
        mappings = getattr(ctrl, "site_mappings", None) or {}
        if mappings and site in mappings:
            return
        try:
            resp = await client.get_sites()
        except Exception as exc:
            raise HTTPException(
                502,
                detail=(f"could not list UniFi sites to verify site={site!r}: {exc}"),
            ) from exc
        # /api/self/sites returns ``{meta, data: [{name, ...}, ...]}``
        sites_data = resp.get("data") if isinstance(resp, dict) else None
        site_names = (
            {s.get("name") for s in sites_data if isinstance(s, dict)}
            if isinstance(sites_data, list)
            else set()
        )
        if site not in site_names:
            raise HTTPException(
                404,
                detail=(f"site={site!r} not found on this controller"),
            )

    # ── Live reads ───────────────────────────────────────────────────

    async def list_devices(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        items = await client.list_devices(site)
        # Device rows expose SSH keys, RADIUS secrets, and the
        # adoption credentials inline on UniFi controllers.
        return {
            "controller_id": controller_id,
            "site": site,
            "items": ([redact_secrets(d) for d in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_one(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        mac: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any] | None:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        return await client.get_device(site, mac)

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site")
            mac = c.target_id

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
                    detail=(f"UniFi adapter has no method {method_name!r}"),
                )
            if not site:
                raise HTTPException(
                    400,
                    detail=f"feature {c.feature!r} requires payload.site",
                )
            if not mac:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires target_id (device MAC)"),
                )

            # IDOR guard: verify ``site`` lives on this
            # controller before we let payload.site flow into a URL path
            # segment. ``_resolve_controller_or_gateway`` already binds
            # the request to the operator's org-scoped controller, but
            # ``site`` is opaque FE input that the adapter interpolates
            # straight into ``/api/s/{site}/...``. A controller whose
            # creds happen to see other tenants' sites (multi-tenant
            # UniFi deployments) would let an operator enumerate +
            # restart/disable devices on those sites otherwise.
            #
            # We check ``controller.site_mappings`` first (operator-
            # configured allowlist of UniFi sites that map to FreeSDN
            # sites); if empty, fall through to a live ``get_sites()``
            # check. 404 not 403 — don't leak "exists elsewhere".
            await self._verify_unifi_site_owned(ctrl, client, site)

            # restart_device(site, mac, *, force=True) — no extra args
            if c.feature == "unifi.devices.restart":
                return await method(site, mac, force=True)

            # disable_device(site, mac, disabled: bool, *, force=True)
            if c.feature == "unifi.devices.disable":
                disabled = payload.get("disabled")
                if disabled is None:
                    raise HTTPException(
                        400,
                        detail=("unifi.devices.disable requires payload.disabled (bool)"),
                    )
                return await method(
                    site,
                    mac,
                    bool(disabled),
                    force=True,
                )

            # port_override carries an arbitrary settings DICT ({port_idx,
            # overrides}); route it to update_switch_port (settings-merge), NOT
            # update_port_override (which takes a profile_id and would reject a
            # dict via validate_object_id). A bare port-PROFILE assignment uses
            # unifi.switch.port_profile instead. (audit #2 F3)
            if c.feature == "unifi.devices.port_override":
                port_idx = payload.get("port_idx")
                overrides = payload.get("overrides")
                if port_idx is None or not isinstance(overrides, dict) or not overrides:
                    raise HTTPException(
                        400,
                        detail=(
                            "unifi.devices.port_override requires payload.port_idx "
                            "+ payload.overrides (a non-empty settings dict)"
                        ),
                    )
                return await method(
                    site,
                    mac,
                    int(port_idx),
                    overrides,
                    force=True,
                )

            # set_port_poe(site, mac, port_idx, mode, *, force=True)
            if c.feature == "unifi.devices.set_port_poe":
                port_idx = payload.get("port_idx")
                mode = payload.get("mode")
                if port_idx is None or not mode:
                    raise HTTPException(
                        400,
                        detail=(
                            "unifi.devices.set_port_poe requires payload.port_idx + payload.mode"
                        ),
                    )
                return await method(
                    site,
                    mac,
                    int(port_idx),
                    mode,
                    force=True,
                )

            # adopt / upgrade / force-provision (site, mac, *, force=True)
            if c.feature in (
                "unifi.devices.adopt",
                "unifi.devices.upgrade",
                "unifi.devices.force_provision",
            ):
                return await method(site, mac, force=True)

            # locate_device(mac, enabled, *, site=, force=True) — BaseAdapter
            # override keeps the (mac, enabled) signature but takes site as a kwarg
            # so locate targets the device's ACTUAL site (not _default_site) on a
            # multi-site controller. The site was IDOR-verified above.
            if c.feature == "unifi.devices.locate":
                enabled = payload.get("enabled", True)
                return await method(mac, bool(enabled), site=site, force=True)

            raise HTTPException(
                400,
                detail=f"unhandled feature={c.feature!r}",
            )

        return _apply
