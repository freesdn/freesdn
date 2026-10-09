# SPDX-License-Identifier: AGPL-3.0-only
"""Staged, readback-verified administrative state and PoE changes for Omada."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Literal
from uuid import UUID

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select

from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.omada.utils import normalize_mac
from app.core.adapter_result import raise_for_adapter_result
from app.core.site_access import assert_site_access_for_request, current_user_var
from app.core.tenancy import tenant_filter
from app.models.core import Site
from app.models.devices import Device, DevicePort, DeviceType, PortStatus
from app.models.staging import AdapterPendingChange
from app.services.adapter_base import GatewayServiceBase


class PortStatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: UUID
    port_index: int = Field(ge=0, le=127)
    enabled: StrictBool


class GatewaySwitchPortsService(GatewayServiceBase):
    SUPPORTED_CONTROLLER_TYPE = "omada"
    FEATURES = {"switch.port.enabled", "switch.port.poe"}

    async def stage_state(
        self,
        device: Device,
        port_index: int,
        enabled: bool,
        kind: Literal["enabled", "poe"],
        organization_id: UUID,
        actor_id: UUID,
    ) -> AdapterPendingChange:
        if device.controller_id is None or device.site_id is None:
            raise HTTPException(409, detail="Port changes require a controller and mapped site")
        ctrl = await self._get_controller(device.controller_id, organization_id)
        if str(ctrl.controller_type) != "omada":
            raise HTTPException(
                501, detail="Verified port-state changes require an Omada controller"
            )
        site = await self.db.get(Site, device.site_id)
        if site is None or site.organization_id != organization_id or site.deleted_at is not None:
            raise HTTPException(404, detail="site not found")
        assert_site_access_for_request(site.id, detail="site not found")
        native_site = self._resolve_omada_site_id(ctrl, site)
        device_site = (device.device_metadata or {}).get("_omada_site_id")
        if not native_site or (device_site and str(device_site) != native_site):
            raise HTTPException(409, detail="Reconcile the controller/device site mapping first")
        if not device.mac_address:
            raise HTTPException(409, detail="The switch has no controller MAC address")
        port = (
            await self.db.execute(
                select(DevicePort).where(
                    DevicePort.device_id == device.id,
                    DevicePort.port_number == port_index,
                )
            )
        ).scalar_one_or_none()
        if port is None:
            raise HTTPException(404, detail="Port not found")
        payload = PortStatePayload(device_id=device.id, port_index=port_index, enabled=enabled)
        return await self.staging.stage_change(
            organization_id=organization_id,
            controller_id=ctrl.id,
            site_id=site.id,
            omada_site_id=native_site,
            feature=f"switch.port.{kind}",
            operation="update",
            target_id=normalize_mac(device.mac_address),
            payload=payload.model_dump(mode="json"),
            actor_id=actor_id,
        )

    def build_applier(
        self,
        _change: Any,
    ) -> Callable[[AdapterPendingChange], Awaitable[dict[str, Any]]]:
        async def apply(c: AdapterPendingChange) -> dict[str, Any]:
            if c.feature not in self.FEATURES or c.operation != "update":
                raise HTTPException(400, detail="Unsupported switch port state operation")
            if c.controller_id is None or c.site_id is None:
                raise HTTPException(400, detail="A staged port requires a controller and site")
            payload = PortStatePayload.model_validate(c.payload)
            query = (
                select(Device)
                .join(Site)
                .where(
                    Device.id == payload.device_id,
                    Device.controller_id == c.controller_id,
                    Device.site_id == c.site_id,
                    Device.device_type == DeviceType.SWITCH,
                    Device.deleted_at.is_(None),
                    Site.deleted_at.is_(None),
                    Site.organization_id == c.organization_id,
                )
            )
            principal = current_user_var.get()
            if principal is not None:
                query = query.where(tenant_filter(Device, principal))
            device = (await self.db.execute(query)).scalar_one_or_none()
            if device is None or not device.mac_address:
                raise HTTPException(
                    404, detail="Staged switch target no longer exists in this site"
                )
            if normalize_mac(device.mac_address) != c.target_id:
                raise HTTPException(409, detail="Staged switch identity changed; reconcile first")
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            if str(ctrl.controller_type) != "omada":
                raise HTTPException(409, detail="Staged controller type changed")
            site = await self.db.get(Site, c.site_id)
            native_site = self._resolve_omada_site_id(ctrl, site)
            device_site = (device.device_metadata or {}).get("_omada_site_id")
            if (
                not native_site
                or native_site != c.omada_site_id
                or (device_site and str(device_site) != native_site)
            ):
                raise HTTPException(409, detail="Staged controller/device site mapping changed")
            port = (
                await self.db.execute(
                    select(DevicePort).where(
                        DevicePort.device_id == device.id,
                        DevicePort.port_number == payload.port_index,
                    )
                )
            ).scalar_one_or_none()
            if port is None:
                raise HTTPException(404, detail="Staged port no longer exists")
            client = await self._get_client(ctrl)
            config = (
                {"enable": payload.enabled}
                if c.feature == "switch.port.enabled"
                else {"poe": {"enable": payload.enabled}}
            )
            response = await client.update_switch_port(
                native_site,
                c.target_id,
                payload.port_index,
                config,
            )
            raise_for_adapter_result(response)
            observed = None
            for attempt in range(3):
                if attempt:
                    await asyncio.sleep(0.5)
                try:
                    raw = await client.get_switch_port_overrides(
                        native_site,
                        c.target_id,
                        payload.port_index,
                        fresh=True,
                    )
                except Exception as exc:
                    raise AdapterOutcomeUnknownError("Port readback failed after write") from exc
                if isinstance(raw, dict):
                    value = (
                        raw.get("enable")
                        if c.feature == "switch.port.enabled"
                        else (
                            raw.get("poe", {}).get("enable")
                            if isinstance(raw.get("poe"), dict)
                            else None
                        )
                    )
                    # Missing/vendor-unknown values must not default to enabled.
                    if isinstance(value, bool) or type(value) is int and value in (0, 1):
                        observed = bool(value)
                    if observed is payload.enabled:
                        break
            if observed is not payload.enabled:
                raise AdapterOutcomeUnknownError("Port readback did not confirm requested state")
            if c.feature == "switch.port.enabled":
                port.is_enabled = observed
                # Administrative enablement alone does not establish a live link.
                port.status = PortStatus.UNKNOWN if observed else PortStatus.DISABLED
            else:
                port.is_poe_enabled = observed
            return {
                "success": True,
                "readback_verified": True,
                "enabled": observed,
                "port_index": payload.port_index,
            }

        return apply
