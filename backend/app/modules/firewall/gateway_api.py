# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Gateway Integration API Endpoints
=================================================

REST API for managing external firewall / router gateway connections
(OPNsense, pfSense, MikroTik).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user, require_permissions
from app.db import get_session
from app.modules.firewall.gateway_service import (
    GatewayNotFoundError,
    GatewayService,
)
from app.modules.firewall.schemas import (
    AliasRequest,
    DHCPStaticMappingRequest,
    DiagnosticDNSLookupRequest,
    DiagnosticPingRequest,
    DiagnosticTracerouteRequest,
    DNSDomainOverrideRequest,
    DNSOverrideRequest,
    GatewayConfigDownloadResponse,
    GatewayConnectionCreate,
    GatewayConnectionListResponse,
    GatewayConnectionResponse,
    GatewayConnectionsResponse,
    GatewayConnectionUpdate,
    GatewayCronJobsResponse,
    GatewayDiskUsageResponse,
    GatewayFirmwareChangelogResponse,
    GatewayFirmwareCheckResponse,
    GatewayFirmwareUpgradeStatusResponse,
    GatewayHealthCheckResponse,
    GatewayIDSRulesetsResponse,
    GatewayIDSRulesResponse,
    GatewayIDSStatusResponse,
    GatewayIPsecStatusResponse,
    GatewayNDPResponse,
    GatewayOpenVPNSessionsResponse,
    GatewayPackagesResponse,
    GatewayPFInfoResponse,
    GatewayPFStatisticsResponse,
    GatewayPluginsResponse,
    GatewayPreflightRequest,
    GatewayPreflightResponse,
    GatewayRulePushRequest,
    GatewayRulePushResponse,
    GatewaySummaryResponse,
    GatewaySyncLogResponse,
    GatewaySyncRequest,
    GatewayTemperatureResponse,
    GatewayTestOverride,
    GatewayTestRequest,
    GatewayTestResponse,
    GatewayTrafficStatsResponse,
    GatewayUnboundStatusResponse,
    GatewayVIPResponse,
    GatewayWireGuardHandshakesResponse,
    GatewayWriteResponse,
    IDSControlRequest,
    IDSSettingsUpdateRequest,
    OpenVPNInstanceRequest,
    PortForwardRequest,
    ServiceControlRequest,
    ShaperPipeRequest,
    ShaperQueueRequest,
    ShaperRuleRequest,
    SourceNATRuleRequest,
    StaticRouteRequest,
    WireGuardPeerRequest,
    WireGuardServerRequest,
)

router = APIRouter(prefix="/gateways", tags=["Firewall Gateways"])


def get_gateway_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> GatewayService:
    # bind per-user site grants so gateway connection reads/
    # actions are confined to granted sites (the route's own require_permissions
    # still gates access). No-op for super/org-admin + grant-less users.
    return GatewayService(
        db=session,
        accessible_site_ids=(
            current_user.accessible_site_ids if current_user.is_site_limited else None
        ),
    )


def _gw_to_response(gw) -> GatewayConnectionResponse:
    return GatewayConnectionResponse(
        id=gw.id,
        org_id=gw.org_id,
        site_id=gw.site_id,
        device_id=gw.device_id,
        name=gw.name,
        description=gw.description,
        vendor=gw.vendor,
        host=gw.host,
        port=gw.port,
        verify_ssl=gw.verify_ssl,
        has_credentials=bool(gw.credentials),
        sync_enabled=gw.sync_enabled,
        sync_interval_seconds=gw.sync_interval_seconds,
        sync_status=gw.sync_status,
        last_sync_at=gw.last_sync_at,
        last_sync_error=gw.last_sync_error,
        last_sync_duration_ms=gw.last_sync_duration_ms,
        is_online=gw.is_online,
        last_seen_at=gw.last_seen_at,
        detected_version=gw.detected_version,
        detected_hostname=gw.detected_hostname,
        detected_model=gw.detected_model,
        capabilities=gw.capabilities or [],
        settings=gw.settings or {},
        created_at=gw.created_at,
        updated_at=gw.updated_at,
    )


# ═════════════════════════════════════════════════════════════════════════════
# CRUD
# ═════════════════════════════════════════════════════════════════════════════


@router.get("", response_model=GatewayConnectionListResponse)
async def list_gateways(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    site_id: UUID | None = None,
    vendor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List all gateway connections for the current organisation."""
    items, total = await svc.list_gateways(
        org_id=current_user.organization_id,
        site_id=site_id,
        vendor=vendor,
        limit=limit,
        offset=offset,
    )
    return GatewayConnectionListResponse(
        items=[_gw_to_response(g) for g in items],
        total=total,
    )


@router.get("/summary", response_model=GatewaySummaryResponse)
async def get_gateway_summary(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    site_id: UUID | None = None,
):
    """Aggregate stats across all gateways."""
    try:
        return await svc.get_summary(current_user.organization_id, site_id=site_id)
    except GatewayNotFoundError:
        # a site-limited caller asked for a site they do not
        # hold a grant on — return the same opaque 404 the per-gateway reads
        # use rather than leaking that the site exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}", response_model=GatewayConnectionResponse)
async def get_gateway(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get a single gateway connection."""
    try:
        gw = await svc.get_gateway(gateway_id, current_user.organization_id)
        return _gw_to_response(gw)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("", response_model=GatewayConnectionResponse, status_code=status.HTTP_201_CREATED)
async def create_gateway(
    body: GatewayConnectionCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Add a new gateway connection."""
    gw = await svc.create_gateway(
        org_id=current_user.organization_id,
        name=body.name,
        description=body.description,
        vendor=body.vendor,
        host=body.host,
        port=body.port,
        verify_ssl=body.verify_ssl,
        site_id=body.site_id,
        api_key=body.api_key,
        api_secret=body.api_secret,
        username=body.username,
        password=body.password,
        sync_enabled=body.sync_enabled,
        sync_interval_seconds=body.sync_interval_seconds,
        settings=body.settings,
    )
    from app.services.device_sync import trigger_device_registry_sync

    trigger_device_registry_sync("firewall")
    return _gw_to_response(gw)


@router.patch("/{gateway_id}", response_model=GatewayConnectionResponse)
async def update_gateway(
    gateway_id: UUID,
    body: GatewayConnectionUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a gateway connection."""
    try:
        gw = await svc.update_gateway(
            gateway_id,
            current_user.organization_id,
            **body.model_dump(exclude_unset=True),
        )
        from app.services.device_sync import trigger_device_registry_sync

        trigger_device_registry_sync("firewall")

        # Pool eviction: any cached
        # adapter for this gateway may now be pointing at stale
        # host / port / credentials. Mirrors the same hook on the
        # ``PATCH /controllers/{id}`` path. Wrapped in try/except so
        # a pool-internal hiccup never breaks the update API.
        try:
            from app.adapters.pool import adapter_pool

            adapter_pool.invalidate_controller(str(gateway_id))
        except Exception:
            pass

        return _gw_to_response(gw)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_gateway(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete (soft) a gateway connection."""
    try:
        from app.services.device_sync import DeviceSyncService

        await DeviceSyncService.remove_device(
            svc.db,
            external_id_prefix="gateway",
            source_id=gateway_id,
        )
        await svc.delete_gateway(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Connection Test
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/test", response_model=GatewayTestResponse)
async def test_gateway_connection(
    body: GatewayTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Test connectivity to a gateway without saving anything."""
    result = await svc.test_connection(
        vendor=body.vendor,
        host=body.host,
        port=body.port,
        verify_ssl=body.verify_ssl,
        api_key=body.api_key,
        api_secret=body.api_secret,
        username=body.username,
        password=body.password,
    )
    return GatewayTestResponse(**result)


@router.post("/{gateway_id}/test", response_model=GatewayTestResponse)
async def test_existing_gateway(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    body: GatewayTestOverride | None = None,
):
    """Test connectivity of an already-saved gateway against its STORED host.

    An optional body may toggle ``verify_ssl`` only. Host/port are NOT
    overridable here (replaying the stored credentials to a
    caller-chosen host would leak the firewall's admin secrets); to test an
    edited host/port before saving, use the unsaved POST /gateways/test
    endpoint, which is firewall.manage_rules-gated and takes fresh credentials.
    """
    try:
        result = await svc.test_existing_gateway(
            gateway_id,
            current_user.organization_id,
            verify_ssl=(body.verify_ssl if body else None),
        )
        return GatewayTestResponse(**result)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/preflight", response_model=GatewayPreflightResponse)
async def preflight_gateway_change(
    gateway_id: UUID,
    body: GatewayPreflightRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Dry-run a prospective staged change: preview its risk class and whether it
    will require ``confirmed=true`` at apply time, WITHOUT staging anything or
    touching the device. Read-only; gated to the same role that stages writes."""
    try:
        result = await svc.preflight_preview(
            gateway_id,
            current_user.organization_id,
            body.feature,
            body.operation,
            body.payload,
        )
        return GatewayPreflightResponse(**result)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Sync
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/sync")
async def trigger_sync(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    body: GatewaySyncRequest | None = None,
):
    """Trigger a manual sync for a gateway."""
    try:
        result = await svc.trigger_sync(
            gateway_id,
            current_user.organization_id,
            full=body.full_sync if body else False,
        )
        return result
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/sync-logs", response_model=list[GatewaySyncLogResponse])
async def get_sync_logs(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    limit: int = Query(20, ge=1, le=100),
):
    """Get sync logs for a gateway."""
    try:
        logs = await svc.get_sync_logs(gateway_id, current_user.organization_id, limit=limit)
        return [GatewaySyncLogResponse.model_validate(l) for l in logs]
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Live Data (proxied from remote gateway)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/status")
async def get_gateway_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live system status from the gateway."""
    try:
        return await svc.get_live_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/firewall-rules")
async def get_gateway_firewall_rules(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live firewall rules from the gateway."""
    try:
        return await svc.get_live_firewall_rules(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/nat-rules")
async def get_gateway_nat_rules(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live NAT rules from the gateway."""
    try:
        return await svc.get_live_nat_rules(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/vpn")
async def get_gateway_vpn_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live VPN status from the gateway."""
    try:
        return await svc.get_live_vpn_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/interfaces")
async def get_gateway_interfaces(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live interface data from the gateway."""
    try:
        return await svc.get_live_interfaces(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/dhcp")
async def get_gateway_dhcp(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live DHCP leases from the gateway."""
    try:
        return await svc.get_live_dhcp_leases(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/services")
async def get_gateway_services(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get live services from the gateway."""
    try:
        return await svc.get_live_services(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Rule Push (Tier A)
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/firewall-rules", response_model=GatewayRulePushResponse)
async def push_firewall_rule(
    gateway_id: UUID,
    body: GatewayRulePushRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Push a firewall rule to the remote gateway."""
    try:
        result = await svc.push_firewall_rule(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
        return GatewayRulePushResponse(**result)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/firewall-rules/{vendor_rule_id}")
async def delete_vendor_rule(
    gateway_id: UUID,
    vendor_rule_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a firewall rule on the remote gateway by vendor ID."""
    try:
        return await svc.delete_vendor_rule(
            gateway_id,
            current_user.organization_id,
            vendor_rule_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — DNS Host Overrides
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dns/overrides")
async def get_dns_overrides(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get DNS host overrides from the gateway."""
    try:
        return await svc.get_live_dns_overrides(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/dns/overrides", response_model=GatewayWriteResponse)
async def create_dns_override(
    gateway_id: UUID,
    body: DNSOverrideRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a DNS host override on the gateway."""
    try:
        return await svc.create_live_dns_override(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/dns/overrides/{vendor_id}", response_model=GatewayWriteResponse)
async def update_dns_override(
    gateway_id: UUID,
    vendor_id: str,
    body: DNSOverrideRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a DNS host override on the gateway."""
    try:
        return await svc.update_live_dns_override(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/dns/overrides/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_dns_override(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a DNS host override on the gateway."""
    try:
        return await svc.delete_live_dns_override(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — DNS Domain Overrides
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dns/domain-overrides")
async def get_dns_domain_overrides(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get DNS domain overrides from the gateway."""
    try:
        return await svc.get_live_dns_domain_overrides(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/dns/domain-overrides", response_model=GatewayWriteResponse)
async def create_dns_domain_override(
    gateway_id: UUID,
    body: DNSDomainOverrideRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a DNS domain override on the gateway."""
    try:
        return await svc.create_live_dns_domain_override(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/dns/domain-overrides/{vendor_id}", response_model=GatewayWriteResponse)
async def update_dns_domain_override(
    gateway_id: UUID,
    vendor_id: str,
    body: DNSDomainOverrideRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a DNS domain override on the gateway."""
    try:
        return await svc.update_live_dns_domain_override(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete(
    "/{gateway_id}/dns/domain-overrides/{vendor_id}", response_model=GatewayWriteResponse
)
async def delete_dns_domain_override(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a DNS domain override on the gateway."""
    try:
        return await svc.delete_live_dns_domain_override(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — DHCP Static Mappings
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dhcp/static-mappings")
async def get_dhcp_static_mappings(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get DHCP static mappings from the gateway."""
    try:
        return await svc.get_live_dhcp_static_mappings(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/dhcp/static-mappings", response_model=GatewayWriteResponse)
async def create_dhcp_static_mapping(
    gateway_id: UUID,
    body: DHCPStaticMappingRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a DHCP static mapping on the gateway."""
    try:
        return await svc.create_live_dhcp_static_mapping(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/dhcp/static-mappings/{vendor_id}", response_model=GatewayWriteResponse)
async def update_dhcp_static_mapping(
    gateway_id: UUID,
    vendor_id: str,
    body: DHCPStaticMappingRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a DHCP static mapping on the gateway."""
    try:
        return await svc.update_live_dhcp_static_mapping(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete(
    "/{gateway_id}/dhcp/static-mappings/{vendor_id}", response_model=GatewayWriteResponse
)
async def delete_dhcp_static_mapping(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a DHCP static mapping on the gateway."""
    try:
        return await svc.delete_live_dhcp_static_mapping(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Port Forwards (DNAT)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/port-forwards")
async def get_port_forwards(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get port forward rules from the gateway."""
    try:
        return await svc.get_live_port_forwards(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/port-forwards", response_model=GatewayWriteResponse)
async def create_port_forward(
    gateway_id: UUID,
    body: PortForwardRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a port forward rule on the gateway."""
    try:
        return await svc.create_live_port_forward(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/port-forwards/{vendor_id}", response_model=GatewayWriteResponse)
async def update_port_forward(
    gateway_id: UUID,
    vendor_id: str,
    body: PortForwardRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a port forward rule on the gateway."""
    try:
        return await svc.update_live_port_forward(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/port-forwards/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_port_forward(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a port forward rule on the gateway."""
    try:
        return await svc.delete_live_port_forward(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Source NAT
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/source-nat", response_model=GatewayWriteResponse)
async def create_source_nat_rule(
    gateway_id: UUID,
    body: SourceNATRuleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a source NAT rule on the gateway."""
    try:
        return await svc.create_live_source_nat_rule(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/source-nat/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_source_nat_rule(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a source NAT rule on the gateway."""
    try:
        return await svc.delete_live_source_nat_rule(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Aliases
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/aliases")
async def get_aliases(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get firewall aliases from the gateway."""
    try:
        return await svc.get_live_aliases(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/aliases", response_model=GatewayWriteResponse)
async def create_alias(
    gateway_id: UUID,
    body: AliasRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a firewall alias on the gateway."""
    try:
        return await svc.create_live_alias(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/aliases/{vendor_id}", response_model=GatewayWriteResponse)
async def update_alias(
    gateway_id: UUID,
    vendor_id: str,
    body: AliasRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a firewall alias on the gateway."""
    try:
        return await svc.update_live_alias(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/aliases/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_alias(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a firewall alias on the gateway."""
    try:
        return await svc.delete_live_alias(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — WireGuard VPN
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/wireguard")
async def get_wireguard(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get WireGuard servers, peers, and handshakes."""
    try:
        return await svc.get_live_wireguard(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/wireguard/servers", response_model=GatewayWriteResponse)
async def create_wireguard_server(
    gateway_id: UUID,
    body: WireGuardServerRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a WireGuard server instance."""
    try:
        return await svc.create_live_wireguard_server(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/wireguard/servers/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_wireguard_server(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a WireGuard server instance."""
    try:
        return await svc.delete_live_wireguard_server(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/wireguard/peers", response_model=GatewayWriteResponse)
async def create_wireguard_peer(
    gateway_id: UUID,
    body: WireGuardPeerRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a WireGuard peer."""
    try:
        return await svc.create_live_wireguard_peer(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/wireguard/peers/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_wireguard_peer(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a WireGuard peer."""
    try:
        return await svc.delete_live_wireguard_peer(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — OpenVPN
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/openvpn")
async def get_openvpn(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get OpenVPN instances and sessions."""
    try:
        return await svc.get_live_openvpn(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/openvpn/instances", response_model=GatewayWriteResponse)
async def create_openvpn_instance(
    gateway_id: UUID,
    body: OpenVPNInstanceRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create an OpenVPN instance on the gateway."""
    try:
        return await svc.create_live_openvpn_instance(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/openvpn/instances/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_openvpn_instance(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete an OpenVPN instance."""
    try:
        return await svc.delete_live_openvpn_instance(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post(
    "/{gateway_id}/openvpn/sessions/{session_id}/kill", response_model=GatewayWriteResponse
)
async def kill_openvpn_session(
    gateway_id: UUID,
    session_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Kill an active OpenVPN session."""
    try:
        return await svc.kill_live_openvpn_session(
            gateway_id,
            current_user.organization_id,
            session_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — IPsec
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ipsec")
async def get_ipsec(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get IPsec tunnels and status."""
    try:
        return await svc.get_live_ipsec(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/ipsec/{vendor_id}/connect", response_model=GatewayWriteResponse)
async def connect_ipsec_tunnel(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Connect / bring up an IPsec tunnel."""
    try:
        return await svc.connect_live_ipsec_tunnel(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/ipsec/{vendor_id}/disconnect", response_model=GatewayWriteResponse)
async def disconnect_ipsec_tunnel(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Disconnect / tear down an IPsec tunnel."""
    try:
        return await svc.disconnect_live_ipsec_tunnel(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Routing
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/routes/static")
async def get_static_routes(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get static routes from the gateway."""
    try:
        return await svc.get_live_static_routes(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/routes/static", response_model=GatewayWriteResponse)
async def create_static_route(
    gateway_id: UUID,
    body: StaticRouteRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a static route on the gateway."""
    try:
        return await svc.create_live_static_route(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/routes/static/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_static_route(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a static route on the gateway."""
    try:
        return await svc.delete_live_static_route(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/routes/table")
async def get_routing_table(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get the full routing table from the gateway."""
    try:
        return await svc.get_live_routing_table(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — ARP
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/arp")
async def get_arp_table(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get ARP table from the gateway."""
    try:
        return await svc.get_live_arp_table(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Gateway Health (WAN monitoring)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/health")
async def get_gateway_health(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get WAN gateway health and monitoring data."""
    try:
        return await svc.get_live_gateway_health(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — IDS / IPS
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ids/settings")
async def get_ids_settings(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get IDS/IPS settings from the gateway."""
    try:
        return await svc.get_live_ids_settings(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/ids/settings", response_model=GatewayWriteResponse)
async def update_ids_settings(
    gateway_id: UUID,
    body: IDSSettingsUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update IDS/IPS settings on the gateway."""
    try:
        return await svc.update_live_ids_settings(
            gateway_id,
            current_user.organization_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/ids/alerts")
async def get_ids_alerts(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    limit: int = Query(500, ge=1, le=5000),
):
    """Get IDS/IPS alerts from the gateway."""
    try:
        return await svc.get_live_ids_alerts(gateway_id, current_user.organization_id, limit=limit)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Traffic Shaper
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/shaper/pipes")
async def get_shaper_pipes(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get traffic shaper pipes from the gateway."""
    try:
        return await svc.get_live_shaper_pipes(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/shaper/pipes", response_model=GatewayWriteResponse)
async def create_shaper_pipe(
    gateway_id: UUID,
    body: ShaperPipeRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a traffic shaper pipe on the gateway."""
    try:
        return await svc.create_live_shaper_pipe(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/shaper/pipes/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_shaper_pipe(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a traffic shaper pipe."""
    try:
        return await svc.delete_live_shaper_pipe(
            gateway_id,
            current_user.organization_id,
            vendor_id,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/shaper/queues")
async def get_shaper_queues(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get traffic shaper queues from the gateway."""
    try:
        return await svc.get_live_shaper_queues(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/shaper/rules")
async def get_shaper_rules(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get traffic shaper rules from the gateway."""
    try:
        return await svc.get_live_shaper_rules(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Backups
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/backups")
async def get_backups(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """List configuration backups on the gateway."""
    try:
        return await svc.get_live_backups(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/backups", response_model=GatewayWriteResponse)
async def create_backup(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a new configuration backup on the gateway."""
    try:
        return await svc.create_live_backup(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/backups/{filename}/revert", response_model=GatewayWriteResponse)
async def revert_backup(
    gateway_id: UUID,
    filename: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Revert gateway configuration to a backup."""
    import re

    if not re.match(r"^[a-zA-Z0-9._\-]+$", filename):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid backup filename")
    try:
        return await svc.revert_live_backup(gateway_id, current_user.organization_id, filename)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Firmware
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/firmware")
async def get_firmware(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get firmware info and update status."""
    try:
        return await svc.get_live_firmware(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Diagnostics
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/diagnostics/ping")
async def run_ping(
    gateway_id: UUID,
    body: DiagnosticPingRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Run a ping from the gateway to a target host."""
    try:
        return await svc.run_live_ping(
            gateway_id,
            current_user.organization_id,
            host=body.host,
            count=body.count,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/diagnostics/traceroute")
async def run_traceroute(
    gateway_id: UUID,
    body: DiagnosticTracerouteRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Run a traceroute from the gateway to a target host."""
    try:
        return await svc.run_live_traceroute(
            gateway_id,
            current_user.organization_id,
            host=body.host,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/diagnostics/dns-lookup")
async def run_dns_lookup(
    gateway_id: UUID,
    body: DiagnosticDNSLookupRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Run a DNS lookup from the gateway."""
    try:
        return await svc.run_live_dns_lookup(
            gateway_id,
            current_user.organization_id,
            hostname=body.hostname,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Logs
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/logs/system")
async def get_system_log(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    limit: int = Query(100, ge=1, le=5000),
):
    """Get system logs from the gateway."""
    try:
        return await svc.get_live_system_log(gateway_id, current_user.organization_id, limit=limit)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/logs/firewall")
async def get_firewall_log(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    limit: int = Query(100, ge=1, le=5000),
):
    """Get firewall filter logs from the gateway."""
    try:
        return await svc.get_live_firewall_log(
            gateway_id, current_user.organization_id, limit=limit
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Device Summary / Dashboard
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/device-summary")
async def get_device_summary(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get full device summary (CPU, RAM, disk, uptime, versions)."""
    try:
        return await svc.get_live_device_summary(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Service Control
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/services/{service_name}/control", response_model=GatewayWriteResponse)
async def control_service(
    gateway_id: UUID,
    service_name: str,
    body: ServiceControlRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Start, stop, or restart a service on the gateway."""
    # service_name flows directly to vendor control-plane calls. The
    # path was previously unbounded — a 100 KB service_name would
    # reach the adapter. Vendor service IDs are short slug-style
    # strings (unbound, dpinger, ntpd, etc.); 128 chars with a
    # conservative charset rejects shell-injection shapes outright.
    import re as _re

    if (
        not service_name
        or len(service_name) > 128
        or not _re.match(r"^[A-Za-z0-9._-]+$", service_name)
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "service_name must be 1-128 chars matching [A-Za-z0-9._-]",
        )
    try:
        return await svc.control_live_service(
            gateway_id,
            current_user.organization_id,
            service_name=service_name,
            action=body.action,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Deep Integration — Reboot
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/reboot", response_model=GatewayWriteResponse)
async def reboot_gateway(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.admin"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    confirm: bool = Query(
        False, description="Must be true — rebooting the gateway disrupts the site."
    ),
):
    """Reboot the gateway device. Requires admin permission + explicit confirm."""
    # FSDN-DW-GW-SYSTEM: a gateway reboot is a site-disrupting live op; require an
    # explicit confirmation second factor (mirrors the staged catastrophic gate)
    # so a single click / compromised admin session can't outage the site.
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Rebooting the gateway is disruptive; pass confirm=true to proceed.",
        )
    try:
        return await svc.reboot_live_gateway(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Halt
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/halt", response_model=GatewayWriteResponse)
async def halt_gateway(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.admin"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    confirm: bool = Query(False, description="Must be true — halting powers the gateway OFF."),
):
    """Halt (power off) the gateway device. Requires admin permission + confirm."""
    # FSDN-DW-GW-SYSTEM: halt powers the device OFF (needs out-of-band recovery) —
    # the most catastrophic gateway op. Require explicit confirmation.
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Halt powers the gateway OFF and needs out-of-band recovery; pass confirm=true.",
        )
    try:
        return await svc.halt_live_gateway(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Firmware extras
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/firmware/changelog", response_model=GatewayFirmwareChangelogResponse)
async def get_firmware_changelog(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get firmware changelog."""
    try:
        return await svc.get_live_firmware_changelog(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/firmware/check", response_model=GatewayFirmwareCheckResponse)
async def firmware_check(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Check for available firmware updates."""
    try:
        return await svc.firmware_check(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/firmware/update", response_model=GatewayWriteResponse)
async def firmware_update(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firmware:upgrade"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    confirm: bool = Query(
        False, description="Must be true — a firmware flash can brick the gateway."
    ),
):
    """Trigger firmware update on the gateway.

    FSDN-DW-GW-SYSTEM: gated on the super_admin-only ``firmware:upgrade`` (matches
    device/controller/AP firmware paths — org/site admins are deliberately
    excluded; a bad flash can brick the gateway) AND requires explicit confirm.
    """
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A firmware flash can brick the gateway; pass confirm=true to proceed.",
        )
    try:
        return await svc.firmware_update(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get(
    "/{gateway_id}/firmware/upgrade-status", response_model=GatewayFirmwareUpgradeStatusResponse
)
async def firmware_upgrade_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get firmware upgrade progress."""
    try:
        return await svc.firmware_upgrade_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/packages", response_model=GatewayPackagesResponse)
async def get_installed_packages(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """List installed packages on the gateway."""
    try:
        return await svc.get_live_installed_packages(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/plugins", response_model=GatewayPluginsResponse)
async def get_installed_plugins(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """List installed plugins on the gateway."""
    try:
        return await svc.get_live_installed_plugins(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Config Download + Backup Delete
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/config/download", response_model=GatewayConfigDownloadResponse)
async def download_config(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Download the full running configuration from the gateway.

    SECURITY: this endpoint returns the complete OPNsense / pfSense
    ``config.xml`` (or vendor equivalent), which contains the WHOLE
    secret estate of the firewall — CA private keys, IPsec PSKs,
    OpenVPN PKI material, password hashes for every user, API
    secrets, RADIUS shared secrets. Gating it requires:

    * ``controller:write`` permission (was ``firewall.manage_rules``;
      raised because rule-management is a much narrower right than
      lifting every secret on the box).
    * ``super_admin`` minimum role.
    * An audit-log entry written BEFORE the controller round-trip.

    The new per-domain ``/gateway-opnsense-system/config-download``
    endpoint enforces the same gates; this legacy route now matches.
    """
    if not current_user.has_min_role("super_admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "config download requires super_admin role — it returns "
            "the full secret estate of the gateway",
        )
    # Structured-log the download BEFORE the round-trip so the
    # action is on the wire even if the controller call fails. This
    # ships through the existing freesdn JSON logger and lands in
    # whichever sink the deployment forwards `WARNING`-level lines
    # to. Full audit-table integration can layer on later.
    import logging

    _logger = logging.getLogger("freesdn.security.config_download")
    _logger.warning(
        "firewall config download requested",
        extra={
            "actor_id": str(current_user.id),
            "organization_id": str(current_user.organization_id)
            if current_user.organization_id
            else None,
            "gateway_id": str(gateway_id),
            "endpoint": "/firewall/gateways/{gw}/config/download",
        },
    )
    try:
        return await svc.download_live_config(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/backups/{filename}", response_model=GatewayWriteResponse)
async def delete_backup(
    gateway_id: UUID,
    filename: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a specific backup on the gateway."""
    # Sanitise filename — block path traversal
    import re as _re

    if not _re.match(r"^[a-zA-Z0-9._\-]+$", filename) or ".." in filename:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid filename")
    try:
        return await svc.delete_live_backup(gateway_id, current_user.organization_id, filename)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Interfaces extras (NDP, ARP flush, VIPs)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ndp", response_model=GatewayNDPResponse)
async def get_ndp_table(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get IPv6 NDP (Neighbour Discovery Protocol) table."""
    try:
        return await svc.get_live_ndp_table(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/arp/flush", response_model=GatewayWriteResponse)
async def flush_arp_table(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Flush the ARP table on the gateway."""
    try:
        return await svc.flush_live_arp(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/vips", response_model=GatewayVIPResponse)
async def get_vip_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get virtual IP addresses (CARP, IP Alias, Proxy ARP) status."""
    try:
        return await svc.get_live_vip_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Firewall extras (toggle, update rule)
# ═════════════════════════════════════════════════════════════════════════════


@router.post(
    "/{gateway_id}/firewall-rules/{vendor_rule_id}/toggle", response_model=GatewayWriteResponse
)
async def toggle_firewall_rule(
    gateway_id: UUID,
    vendor_rule_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    enabled: bool = Query(True, description="Set rule enabled (true) or disabled (false)"),
):
    """Toggle (enable/disable) a firewall rule by vendor ID."""
    try:
        return await svc.toggle_live_firewall_rule(
            gateway_id, current_user.organization_id, vendor_rule_id, enabled=enabled
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/firewall-rules/{vendor_rule_id}", response_model=GatewayWriteResponse)
async def update_firewall_rule(
    gateway_id: UUID,
    vendor_rule_id: str,
    body: GatewayRulePushRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a firewall rule by vendor ID."""
    try:
        return await svc.update_live_firewall_rule(
            gateway_id,
            current_user.organization_id,
            vendor_rule_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Source NAT update
# ═════════════════════════════════════════════════════════════════════════════


@router.put("/{gateway_id}/source-nat/{vendor_id}", response_model=GatewayWriteResponse)
async def update_source_nat_rule(
    gateway_id: UUID,
    vendor_id: str,
    body: SourceNATRuleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a source NAT (outbound NAT) rule."""
    try:
        return await svc.update_live_source_nat_rule(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — DNS extras (Unbound status)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dns/unbound-status", response_model=GatewayUnboundStatusResponse)
async def get_unbound_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Unbound DNS resolver status."""
    try:
        return await svc.get_live_unbound_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — WireGuard update + handshakes
# ═════════════════════════════════════════════════════════════════════════════


@router.put("/{gateway_id}/wireguard/servers/{vendor_id}", response_model=GatewayWriteResponse)
async def update_wireguard_server(
    gateway_id: UUID,
    vendor_id: str,
    body: WireGuardServerRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a WireGuard server instance."""
    try:
        return await svc.update_live_wireguard_server(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/wireguard/peers/{vendor_id}", response_model=GatewayWriteResponse)
async def update_wireguard_peer(
    gateway_id: UUID,
    vendor_id: str,
    body: WireGuardPeerRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a WireGuard peer."""
    try:
        return await svc.update_live_wireguard_peer(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/wireguard/handshakes", response_model=GatewayWireGuardHandshakesResponse)
async def get_wireguard_handshakes(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get WireGuard peer handshake status."""
    try:
        return await svc.get_live_wireguard_handshakes(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — OpenVPN update + sessions
# ═════════════════════════════════════════════════════════════════════════════


@router.put("/{gateway_id}/openvpn/instances/{vendor_id}", response_model=GatewayWriteResponse)
async def update_openvpn_instance(
    gateway_id: UUID,
    vendor_id: str,
    body: OpenVPNInstanceRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update an OpenVPN instance."""
    try:
        return await svc.update_live_openvpn_instance(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/openvpn/sessions", response_model=GatewayOpenVPNSessionsResponse)
async def get_openvpn_sessions(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get active OpenVPN sessions."""
    try:
        return await svc.get_live_openvpn_sessions(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — IPsec extras (status, apply)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ipsec/status", response_model=GatewayIPsecStatusResponse)
async def get_ipsec_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get IPsec service status (SA/SPD details)."""
    try:
        return await svc.get_live_ipsec_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/ipsec/apply", response_model=GatewayWriteResponse)
async def apply_ipsec_changes(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Apply pending IPsec configuration changes."""
    try:
        return await svc.apply_live_ipsec_changes(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Static Route update
# ═════════════════════════════════════════════════════════════════════════════


@router.put("/{gateway_id}/routes/static/{vendor_id}", response_model=GatewayWriteResponse)
async def update_static_route(
    gateway_id: UUID,
    vendor_id: str,
    body: StaticRouteRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a static route."""
    try:
        return await svc.update_live_static_route(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — IDS/IPS full CRUD (rulesets, rules, status, control)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ids/rulesets", response_model=GatewayIDSRulesetsResponse)
async def get_ids_rulesets(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """List IDS rulesets."""
    try:
        return await svc.get_live_ids_rulesets(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/ids/rules", response_model=GatewayIDSRulesResponse)
async def get_ids_rules(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """List individual IDS rules."""
    try:
        return await svc.get_live_ids_rules(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/ids/rules/{sid}/toggle", response_model=GatewayWriteResponse)
async def toggle_ids_rule(
    gateway_id: UUID,
    sid: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Toggle an IDS rule by SID."""
    try:
        return await svc.toggle_live_ids_rule(gateway_id, current_user.organization_id, sid)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/ids/alerts", response_model=GatewayWriteResponse)
async def drop_ids_alert_log(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Clear the IDS alert log."""
    try:
        return await svc.drop_live_ids_alert_log(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/ids/status", response_model=GatewayIDSStatusResponse)
async def get_ids_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get IDS/IPS service status."""
    try:
        return await svc.get_live_ids_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/ids/control", response_model=GatewayWriteResponse)
async def control_ids(
    gateway_id: UUID,
    body: IDSControlRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Control IDS service: start, stop, restart, or update-rules."""
    try:
        return await svc.control_live_ids(gateway_id, current_user.organization_id, body.action)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Shaper full CRUD (pipe update, queue CRUD, rule CRUD)
# ═════════════════════════════════════════════════════════════════════════════


@router.put("/{gateway_id}/shaper/pipes/{vendor_id}", response_model=GatewayWriteResponse)
async def update_shaper_pipe(
    gateway_id: UUID,
    vendor_id: str,
    body: ShaperPipeRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a traffic shaper pipe."""
    try:
        return await svc.update_live_shaper_pipe(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/shaper/queues", response_model=GatewayWriteResponse)
async def create_shaper_queue(
    gateway_id: UUID,
    body: ShaperQueueRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a traffic shaper queue."""
    try:
        return await svc.create_live_shaper_queue(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/shaper/queues/{vendor_id}", response_model=GatewayWriteResponse)
async def update_shaper_queue(
    gateway_id: UUID,
    vendor_id: str,
    body: ShaperQueueRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a traffic shaper queue."""
    try:
        return await svc.update_live_shaper_queue(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/shaper/queues/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_shaper_queue(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a traffic shaper queue."""
    try:
        return await svc.delete_live_shaper_queue(
            gateway_id, current_user.organization_id, vendor_id
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.post("/{gateway_id}/shaper/rules", response_model=GatewayWriteResponse)
async def create_shaper_rule(
    gateway_id: UUID,
    body: ShaperRuleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Create a traffic shaper rule."""
    try:
        return await svc.create_live_shaper_rule(
            gateway_id,
            current_user.organization_id,
            body.model_dump(),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.put("/{gateway_id}/shaper/rules/{vendor_id}", response_model=GatewayWriteResponse)
async def update_shaper_rule(
    gateway_id: UUID,
    vendor_id: str,
    body: ShaperRuleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Update a traffic shaper rule."""
    try:
        return await svc.update_live_shaper_rule(
            gateway_id,
            current_user.organization_id,
            vendor_id,
            body.model_dump(exclude_unset=True),
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.delete("/{gateway_id}/shaper/rules/{vendor_id}", response_model=GatewayWriteResponse)
async def delete_shaper_rule(
    gateway_id: UUID,
    vendor_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Delete a traffic shaper rule."""
    try:
        return await svc.delete_live_shaper_rule(
            gateway_id, current_user.organization_id, vendor_id
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Diagnostics extras (connections, PF, temperature, disk, traffic)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/diagnostics/connections", response_model=GatewayConnectionsResponse)
async def get_connections(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get active PF state / connection tracking table."""
    try:
        return await svc.get_live_connections(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/diagnostics/pf-info", response_model=GatewayPFInfoResponse)
async def get_pf_info(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get PF filter info."""
    try:
        return await svc.get_live_pf_info(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/diagnostics/pf-statistics", response_model=GatewayPFStatisticsResponse)
async def get_pf_statistics(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get PF statistics."""
    try:
        return await svc.get_live_pf_statistics(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/monitoring/temperature", response_model=GatewayTemperatureResponse)
async def get_temperature(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get hardware temperature readings."""
    try:
        return await svc.get_live_temperature(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/monitoring/disk-usage", response_model=GatewayDiskUsageResponse)
async def get_disk_usage(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get disk usage information."""
    try:
        return await svc.get_live_disk_usage(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/monitoring/traffic", response_model=GatewayTrafficStatsResponse)
async def get_traffic_stats(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get traffic statistics."""
    try:
        return await svc.get_live_traffic_stats(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — System extras (cron jobs, health check)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/cron-jobs", response_model=GatewayCronJobsResponse)
async def get_cron_jobs(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get scheduled cron jobs on the gateway."""
    try:
        return await svc.get_live_cron_jobs(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/health-check", response_model=GatewayHealthCheckResponse)
async def health_check(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Run deep health check aggregating multiple subsystems."""
    try:
        return await svc.health_check_live(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Tailscale VPN
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/tailscale")
async def get_tailscale_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Tailscale VPN settings and status."""
    try:
        return await svc.get_live_tailscale_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — VLAN / LAGG / Virtual IP Devices
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/vlans")
async def get_vlan_devices(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get VLAN device configurations."""
    try:
        return await svc.get_live_vlan_devices(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/laggs")
async def get_lagg_devices(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get LAGG (link aggregation) configurations."""
    try:
        return await svc.get_live_lagg_devices(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/virtual-ips")
async def get_virtual_ips(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Virtual IP (CARP / IP Alias) configurations."""
    try:
        return await svc.get_live_virtual_ips(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — HAProxy (Load Balancer)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/haproxy")
async def get_haproxy_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get HAProxy load balancer overview (servers, backends, frontends)."""
    try:
        return await svc.get_live_haproxy_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/haproxy/servers")
async def get_haproxy_servers(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get HAProxy real servers."""
    try:
        return await svc.get_live_haproxy_servers(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/haproxy/backends")
async def get_haproxy_backends(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get HAProxy backend pools."""
    try:
        return await svc.get_live_haproxy_backends(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/haproxy/frontends")
async def get_haproxy_frontends(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get HAProxy frontend listeners."""
    try:
        return await svc.get_live_haproxy_frontends(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Certificate Management (Trust Store)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/certificates")
async def get_trust_overview(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get trust store overview (CAs, certificates, CRLs)."""
    try:
        return await svc.get_live_trust_overview(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/certificates/certs")
async def get_certificates(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get TLS/SSL certificates from trust store."""
    try:
        return await svc.get_live_certificates(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/certificates/cas")
async def get_certificate_authorities(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Certificate Authorities from trust store."""
    try:
        return await svc.get_live_certificate_authorities(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — ACME / Let's Encrypt
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/acme")
async def get_acme_overview(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get ACME/Let's Encrypt overview (settings, certs, accounts, validations, actions)."""
    try:
        return await svc.get_live_acme_overview(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/acme/certificates")
async def get_acme_certificates(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get ACME-managed certificates."""
    try:
        return await svc.get_live_acme_certificates(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Syslog Forwarding
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/syslog")
async def get_syslog_destinations(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get remote syslog forwarding destinations."""
    try:
        return await svc.get_live_syslog_destinations(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Dynamic DNS
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dyndns")
async def get_dyndns_accounts(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Dynamic DNS provider accounts."""
    try:
        return await svc.get_live_dyndns_accounts(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Captive Portal
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/captive-portal")
async def get_captive_portal_zones(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get captive portal zones."""
    try:
        return await svc.get_live_captive_portal_zones(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/captive-portal/sessions")
async def get_captive_portal_sessions(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get active captive portal sessions."""
    try:
        return await svc.get_live_captive_portal_sessions(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — High Availability / Config Sync
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/ha-status")
async def get_ha_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get high-availability / CARP failover status and sync configuration."""
    try:
        return await svc.get_live_ha_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═════════════════════════════════════════════════════════════════════════════
# Enterprise — Kea DHCP (DHCPv4 + DHCPv6 + Reservations)
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/kea/dhcpv4/subnets")
async def get_kea_dhcpv4_subnets(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Kea DHCPv4 subnet configurations."""
    try:
        return await svc.get_live_kea_dhcpv4_subnets(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/kea/dhcpv4/reservations")
async def get_kea_dhcpv4_reservations(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Kea DHCPv4 static reservations."""
    try:
        return await svc.get_live_kea_dhcpv4_reservations(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/kea/dhcpv4/leases")
async def get_kea_dhcpv4_leases(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Kea DHCPv4 active leases."""
    try:
        return await svc.get_live_kea_dhcpv4_leases(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/kea/dhcpv6/subnets")
async def get_kea_dhcpv6_subnets(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Kea DHCPv6 subnet configurations."""
    try:
        return await svc.get_live_kea_dhcpv6_subnets(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# 1:1 NAT (Binat)
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/nat/onetoone")
async def get_onetoone_nat_rules(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get 1:1 NAT (binat) rules."""
    try:
        return await svc.get_live_onetoone_nat_rules(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# Network Bridges
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/bridges")
async def get_bridges(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get network bridge configurations."""
    try:
        return await svc.get_live_bridges(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# DHCP Relay
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/dhcp-relay")
async def get_dhcp_relay(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get DHCP relay configuration."""
    try:
        return await svc.get_live_dhcp_relay(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# Web Proxy / Squid
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/proxy")
async def get_proxy_settings(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get web proxy (Squid) settings and status."""
    try:
        return await svc.get_live_proxy_settings(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


@router.get("/{gateway_id}/proxy/blacklists")
async def get_proxy_blacklists(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get web proxy remote blacklists/ACLs."""
    try:
        return await svc.get_live_proxy_blacklists(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# CrowdSec
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/crowdsec")
async def get_crowdsec_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get CrowdSec IPS status, alerts, and decisions."""
    try:
        return await svc.get_live_crowdsec_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# Telegraf
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/telegraf")
async def get_telegraf_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Telegraf metrics agent configuration and status."""
    try:
        return await svc.get_live_telegraf_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# Monit
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/monit")
async def get_monit_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get Monit service monitoring status."""
    try:
        return await svc.get_live_monit_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# NetFlow / sFlow
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/netflow")
async def get_netflow_status(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Get NetFlow/sFlow collector configuration and status."""
    try:
        return await svc.get_live_netflow_status(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CUTTING: Real-time Log Streaming (SSE)
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/logs/stream")
async def stream_firewall_logs(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    limit: int = Query(50, ge=1, le=500),
    interval: float = Query(3.0, ge=1.0, le=30.0),
):
    """
    Server-Sent Events stream of firewall logs.
    Polls the gateway every `interval` seconds and pushes new log entries.
    """
    import asyncio
    import json
    from collections import OrderedDict

    async def _event_generator():
        seen_digests: OrderedDict[str, None] = OrderedDict()
        MAX_SEEN = 1000
        try:
            while True:
                try:
                    result = await svc.get_live_firewall_log(
                        gateway_id, current_user.organization_id, limit=limit
                    )
                    logs = []
                    if isinstance(result, dict):
                        logs = result.get("data", {}).get("logs", [])
                    elif hasattr(result, "data"):
                        logs = (result.data or {}).get("logs", [])

                    new_entries = []
                    for entry in logs:
                        digest = json.dumps(entry, sort_keys=True, default=str)
                        if digest not in seen_digests:
                            seen_digests[digest] = None
                            new_entries.append(entry)
                            # Evict oldest entries when over limit
                            while len(seen_digests) > MAX_SEEN:
                                seen_digests.popitem(last=False)

                    if new_entries:
                        payload = json.dumps(new_entries, default=str)
                        yield f"data: {payload}\n\n"
                    else:
                        yield ": keepalive\n\n"

                except Exception:
                    yield f"data: {json.dumps({'error': 'Failed to fetch logs'})}\n\n"

                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CUTTING: Bulk Firewall Rule Operations
# ═══════════════════════════════════════════════════════════════════════════

from typing import Literal

from pydantic import BaseModel, Field


class BulkRuleAction(BaseModel):
    action: Literal["enable", "disable", "delete"]
    rule_uuids: list[str] = Field(..., min_length=1, max_length=200)
    confirm: bool = False


@router.post("/{gateway_id}/rules/bulk")
async def bulk_rule_operations(
    gateway_id: UUID,
    body: BulkRuleAction,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """
    Perform bulk operations on firewall rules.
    Supports enable, disable, and delete across multiple rule UUIDs.
    """
    # FSDN-DW-FW-BULK: a bulk DELETE can remove up to 200 live firewall rules in
    # one request (policy loss / operator lockout). Require explicit confirmation.
    # enable/disable are reversible, so they don't need the second factor.
    if body.action == "delete" and not body.confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Bulk rule delete removes live firewall policy; set confirm=true to proceed.",
        )
    try:
        return await svc.bulk_rule_operation(
            gateway_id,
            current_user.organization_id,
            body.action,
            body.rule_uuids,
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CUTTING: Config Diff Visualization
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/config/diff")
async def get_config_diff(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """
    Get a diff between the current running config and the last saved backup.
    Returns unified diff format suitable for frontend rendering.

    SECURITY: the diff is computed from the full running ``config.xml`` (via
    ``adapter.download_config()``), so the rendered diff can expose the SAME
    complete secret estate the ``config/download`` endpoint returns — CA
    private keys, IPsec PSKs, OpenVPN PKI, user password hashes, API/RADIUS
    secrets. It is therefore gated identically to ``config/download``:

    * ``controller:write`` permission (not the narrow ``firewall.view``).
    * ``super_admin`` minimum role.
    * An audit/security log line written BEFORE the controller round-trip.
    """
    if not current_user.has_min_role("super_admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "config diff requires super_admin role — it can expose "
            "the full secret estate of the gateway",
        )
    import logging

    _logger = logging.getLogger("freesdn.security.config_download")
    _logger.warning(
        "firewall config diff requested",
        extra={
            "actor_id": str(current_user.id),
            "organization_id": str(current_user.organization_id)
            if current_user.organization_id
            else None,
            "gateway_id": str(gateway_id),
            "endpoint": "/firewall/gateways/{gw}/config/diff",
        },
    )
    try:
        return await svc.get_config_diff(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CUTTING: Scheduled Backup Trigger
# ═══════════════════════════════════════════════════════════════════════════


@router.post("/{gateway_id}/backup/trigger")
async def trigger_config_backup(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
):
    """Trigger an immediate config backup for this gateway."""
    try:
        return await svc.trigger_config_backup(gateway_id, current_user.organization_id)
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CUTTING: Certificate Lifecycle
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/{gateway_id}/certificates/expiry")
async def get_certificate_expiry(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    svc: Annotated[GatewayService, Depends(get_gateway_service)],
    days_threshold: int = Query(30, ge=1, le=365),
):
    """
    Check certificate expiry across all gateway certificates.
    Returns certificates expiring within `days_threshold` days.
    """
    try:
        return await svc.get_certificate_expiry(
            gateway_id, current_user.organization_id, days_threshold
        )
    except GatewayNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")
