# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firewall Module API Endpoints
===========================================

REST API endpoints for firewall and security management.
"""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db import get_session
from app.modules.firewall.schemas import (
    FirewallLogListResponse,
    FirewallLogResponse,
    FirewallRuleCreate,
    FirewallRuleListResponse,
    FirewallRuleResponse,
    FirewallRuleUpdate,
    IDSAlertListResponse,
    IDSAlertResponse,
    IDSAlertStatsResponse,
    NATRuleCreate,
    NATRuleListResponse,
    NATRuleResponse,
    NATRuleUpdate,
    VPNTunnelCreate,
    VPNTunnelListResponse,
    VPNTunnelResponse,
    VPNTunnelUpdate,
)
from app.modules.firewall.service import (
    FirewallError,
    FirewallService,
    NATNotFoundError,
    RuleNotFoundError,
    VPNNotFoundError,
)

router = APIRouter(tags=["Firewall"])


def _org_id(user: CurrentUser) -> UUID:
    """Extract organization_id from the current user, or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(status_code=400, detail="Organization context required")
    return oid  # type: ignore[no-any-return]


def _get_service(session: AsyncSession, user: CurrentUser) -> FirewallService:
    """Build an organization-scoped FirewallService (+ per-user site grants)."""
    return FirewallService(
        db=session,
        organization_id=_org_id(user),
        accessible_site_ids=(
            user.accessible_site_ids if getattr(user, "is_site_limited", False) else None
        ),
    )


# =============================================================================
# Firewall Rules Endpoints
# =============================================================================


@router.get("/rules", response_model=FirewallRuleListResponse)
async def list_rules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = None,
    is_enabled: bool | None = None,
    action: str | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List firewall rules."""
    service = _get_service(session, current_user)
    rules, total = await service.list_rules(
        device_id=device_id,
        is_enabled=is_enabled,
        action=action,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [FirewallRuleResponse.model_validate(r) for r in rules]
    return FirewallRuleListResponse(items=items, total=total)


@router.get("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def get_rule(
    rule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a firewall rule by ID."""
    try:
        service = _get_service(session, current_user)
        rule = await service.get_rule(rule_id)
        return FirewallRuleResponse.model_validate(rule)
    except RuleNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Firewall rule not found",
        )


@router.post("/rules", response_model=FirewallRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: FirewallRuleCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a new firewall rule."""
    service = _get_service(session, current_user)
    rule = await service.create_rule(body.model_dump())
    return FirewallRuleResponse.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def update_rule(
    rule_id: UUID,
    body: FirewallRuleUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a firewall rule."""
    try:
        service = _get_service(session, current_user)
        rule = await service.update_rule(rule_id, body.model_dump(exclude_unset=True))
        return FirewallRuleResponse.model_validate(rule)
    except RuleNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Firewall rule not found",
        )


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a firewall rule."""
    try:
        service = _get_service(session, current_user)
        await service.delete_rule(rule_id)
    except RuleNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Firewall rule not found",
        )


@router.post("/rules/reorder")
async def reorder_rules(
    rule_ids: Annotated[list[UUID], Body()],
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID = Query(...),
) -> Any:
    """Reorder firewall rules."""
    service = _get_service(session, current_user)
    rules = await service.reorder_rules(device_id, rule_ids)
    items = [FirewallRuleResponse.model_validate(r) for r in rules]
    return {"items": items}


# =============================================================================
# NAT Rules Endpoints
# =============================================================================


@router.get("/nat", response_model=NATRuleListResponse)
async def list_nat_rules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = None,
    nat_type: str | None = None,
    is_enabled: bool | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List NAT rules."""
    service = _get_service(session, current_user)
    rules, total = await service.list_nat_rules(
        device_id=device_id,
        nat_type=nat_type,
        is_enabled=is_enabled,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [NATRuleResponse.model_validate(r) for r in rules]
    return NATRuleListResponse(items=items, total=total)


@router.get("/nat/{nat_id}", response_model=NATRuleResponse)
async def get_nat_rule(
    nat_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a NAT rule by ID."""
    try:
        service = _get_service(session, current_user)
        rule = await service.get_nat_rule(nat_id)
        return NATRuleResponse.model_validate(rule)
    except NATNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NAT rule not found",
        )


@router.post("/nat", response_model=NATRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_nat_rule(
    body: NATRuleCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_nat"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a NAT rule."""
    service = _get_service(session, current_user)
    rule = await service.create_nat_rule(body.model_dump())
    return NATRuleResponse.model_validate(rule)


@router.patch("/nat/{nat_id}", response_model=NATRuleResponse)
async def update_nat_rule(
    nat_id: UUID,
    body: NATRuleUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_nat"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a NAT rule."""
    try:
        service = _get_service(session, current_user)
        rule = await service.update_nat_rule(nat_id, body.model_dump(exclude_unset=True))
        return NATRuleResponse.model_validate(rule)
    except NATNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NAT rule not found",
        )


@router.delete("/nat/{nat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_nat_rule(
    nat_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_nat"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a NAT rule."""
    try:
        service = _get_service(session, current_user)
        await service.delete_nat_rule(nat_id)
    except NATNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NAT rule not found",
        )


# =============================================================================
# VPN Endpoints
# =============================================================================


@router.get("/vpn", response_model=VPNTunnelListResponse)
async def list_vpn_tunnels(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = None,
    vpn_type: str | None = None,
    vpn_status: str | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List VPN tunnels."""
    service = _get_service(session, current_user)
    tunnels, total = await service.list_vpn_tunnels(
        device_id=device_id,
        vpn_type=vpn_type,
        status=vpn_status,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [VPNTunnelResponse.model_validate(t) for t in tunnels]
    return VPNTunnelListResponse(items=items, total=total)


@router.get("/vpn/stats")
async def get_vpn_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
) -> Any:
    """Get VPN statistics."""
    service = _get_service(session, current_user)
    return await service.get_vpn_stats(site_id=site_id)


@router.get("/vpn/{vpn_id}", response_model=VPNTunnelResponse)
async def get_vpn_tunnel(
    vpn_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a VPN tunnel by ID."""
    try:
        service = _get_service(session, current_user)
        tunnel = await service.get_vpn_tunnel(vpn_id)
        return VPNTunnelResponse.model_validate(tunnel)
    except VPNNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN tunnel not found",
        )


@router.post("/vpn", response_model=VPNTunnelResponse, status_code=status.HTTP_201_CREATED)
async def create_vpn_tunnel(
    body: VPNTunnelCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_vpn"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a VPN tunnel."""
    service = _get_service(session, current_user)
    tunnel = await service.create_vpn_tunnel(body.model_dump())
    return VPNTunnelResponse.model_validate(tunnel)


@router.patch("/vpn/{vpn_id}", response_model=VPNTunnelResponse)
async def update_vpn_tunnel(
    vpn_id: UUID,
    body: VPNTunnelUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_vpn"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a VPN tunnel."""
    try:
        service = _get_service(session, current_user)
        tunnel = await service.update_vpn_tunnel(vpn_id, body.model_dump(exclude_unset=True))
        return VPNTunnelResponse.model_validate(tunnel)
    except VPNNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN tunnel not found",
        )


@router.delete("/vpn/{vpn_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vpn_tunnel(
    vpn_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_vpn"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a VPN tunnel."""
    try:
        service = _get_service(session, current_user)
        await service.delete_vpn_tunnel(vpn_id)
    except VPNNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN tunnel not found",
        )


# =============================================================================
# IDS/IPS Endpoints
# =============================================================================


@router.get("/ids/alerts", response_model=IDSAlertListResponse)
async def search_alerts(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = None,
    severity: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    is_acknowledged: bool | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Any:
    """Search IDS/IPS alerts."""
    service = _get_service(session, current_user)
    alerts, total = await service.search_alerts(
        device_id=device_id,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        is_acknowledged=is_acknowledged,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [IDSAlertResponse.model_validate(a) for a in alerts]
    return IDSAlertListResponse(items=items, total=total)


@router.get("/ids/alerts/stats", response_model=IDSAlertStatsResponse)
async def get_alert_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    site_id: UUID | None = None,
) -> Any:
    """Get IDS alert statistics."""
    service = _get_service(session, current_user)
    stats = await service.get_alert_stats(
        start_time=start_time,
        end_time=end_time,
        site_id=site_id,
    )
    return IDSAlertStatsResponse(**stats)


@router.post("/ids/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_ids"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Acknowledge an IDS alert."""
    try:
        service = _get_service(session, current_user)
        await service.acknowledge_alert(alert_id, current_user.id)
        return {"status": "ok", "alert_id": str(alert_id)}
    except FirewallError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )


# =============================================================================
# Firewall Logs Endpoints
# =============================================================================


@router.get("/logs", response_model=FirewallLogListResponse)
async def search_logs(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view_logs"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = None,
    action: str | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    site_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Any:
    """Search firewall logs."""
    service = _get_service(session, current_user)
    logs, total = await service.search_logs(
        device_id=device_id,
        action=action,
        source_ip=source_ip,
        dest_ip=dest_ip,
        start_time=start_time,
        end_time=end_time,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [FirewallLogResponse.model_validate(l) for l in logs]
    return FirewallLogListResponse(items=items, total=total)
