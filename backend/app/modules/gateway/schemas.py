# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Gateway Module Schemas
=====================================

Pydantic v2 request / response schemas for the Gateway module API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, ValidationInfo, field_validator

# ═══════════════════════════════════════════════════════════════════════════════
# Shared
# ═══════════════════════════════════════════════════════════════════════════════


class PaginatedResponse(BaseModel):
    total: int
    limit: int
    offset: int


# ═══════════════════════════════════════════════════════════════════════════════
# Site Role Map
# ═══════════════════════════════════════════════════════════════════════════════


class RoleAssignmentData(BaseModel):
    gateway_id: UUID | None = None
    controller_id: UUID | None = None
    device_type: str = Field("gateway", pattern=r"^(gateway|controller)$")
    role: str = Field(..., pattern=r"^(brain|brain_standby|limb|observer)$")
    priority: int = 0
    suppress_dhcp: bool = False

    @field_validator("controller_id", mode="after")
    @classmethod
    def validate_one_device(cls, v: UUID | None, info: ValidationInfo) -> UUID | None:
        gw = info.data.get("gateway_id")
        if v and gw:
            raise ValueError("Set either gateway_id or controller_id, not both")
        if not v and not gw:
            raise ValueError("One of gateway_id or controller_id is required")
        return v


class SiteRoleMapUpdate(BaseModel):
    """Update role assignments for a site."""

    assignments: list[RoleAssignmentData]
    authority_map: dict[str, str] | None = None

    @field_validator("assignments")
    @classmethod
    def validate_single_brain(cls, v: list[RoleAssignmentData]) -> list[RoleAssignmentData]:
        brains = [a for a in v if a.role == "brain"]
        if len(brains) > 1:
            raise ValueError("Only one brain device allowed per site")
        standby = [a for a in v if a.role == "brain_standby"]
        if len(standby) > 1:
            raise ValueError("Only one brain_standby device allowed per site")
        return v


class SiteRoleAssignmentResponse(BaseModel):
    id: UUID
    gateway_id: UUID | None = None
    controller_id: UUID | None = None
    device_type: str
    role: str
    priority: int
    capabilities: dict[str, Any]
    suppress_dhcp: bool

    model_config = {"from_attributes": True}


class SiteRoleMapResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    is_active: bool
    last_reconciled_at: datetime | None
    authority_map: dict[str, str]
    assignments: list[SiteRoleAssignmentResponse]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ValidationResult(BaseModel):
    is_valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Canonical VLAN
# ═══════════════════════════════════════════════════════════════════════════════


class CanonicalVLANCreate(BaseModel):
    site_id: UUID
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str = Field(..., min_length=1, max_length=64)
    description: str | None = None
    subnet: str = Field(..., min_length=7, max_length=18)
    gateway_ip: str = Field(..., min_length=7, max_length=45)
    dhcp_enabled: bool = True
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None
    dhcp_lease_time: int = Field(default=86400, ge=60, le=604800)
    dhcp_dns_servers: list[str] = Field(default_factory=list)
    dhcp_domain: str | None = None
    purpose: str = Field(
        default="general",
        pattern=r"^(general|management|guest|iot|voip|cameras|servers|dmz)$",
    )
    distribute: bool = True
    template_id: UUID | None = None

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR subnet: {v}")
        return v

    @field_validator("gateway_ip", "dhcp_range_start", "dhcp_range_end")
    @classmethod
    def validate_ip_address(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import ipaddress

        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("dhcp_dns_servers")
    @classmethod
    def validate_dns_servers(cls, v: list[str]) -> list[str]:
        import ipaddress

        for addr in v:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                raise ValueError(f"Invalid DNS server IP: {addr}")
        return v


class CanonicalVLANUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = None
    subnet: str | None = None
    gateway_ip: str | None = None
    dhcp_enabled: bool | None = None
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None
    dhcp_lease_time: int | None = Field(default=None, ge=60, le=604800)
    dhcp_dns_servers: list[str] | None = None
    dhcp_domain: str | None = None
    purpose: str | None = None


class CanonicalVLANResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    vlan_id: int
    name: str
    description: str | None
    subnet: str
    gateway_ip: str
    dhcp_enabled: bool
    dhcp_range_start: str | None
    dhcp_range_end: str | None
    dhcp_lease_time: int
    dhcp_dns_servers: list[str]
    dhcp_domain: str | None
    purpose: str
    management_state: str
    source_device_id: UUID | None
    template_id: UUID | None
    external_ids: dict[str, str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CanonicalVLANDetailResponse(CanonicalVLANResponse):
    dhcp_scope: DHCPScopeResponse | None = None
    dhcp_reservations: list[DHCPReservationResponse] = Field(default_factory=list)
    distribution_status: dict[str, str] | None = None


class CanonicalVLANListResponse(PaginatedResponse):
    items: list[CanonicalVLANResponse]


# ═══════════════════════════════════════════════════════════════════════════════
# DHCP
# ═══════════════════════════════════════════════════════════════════════════════


class DHCPScopeCreate(BaseModel):
    vlan_id: UUID
    range_start: str
    range_end: str
    subnet_mask: str
    gateway: str
    lease_time: int = Field(default=86400, ge=60, le=604800)
    dns_servers: list[str] = Field(default_factory=list)
    ntp_servers: list[str] = Field(default_factory=list)
    domain_name: str | None = None
    custom_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("range_start", "range_end", "gateway", "subnet_mask")
    @classmethod
    def validate_ip_fields(cls, v: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("dns_servers", "ntp_servers")
    @classmethod
    def validate_server_list(cls, v: list[str]) -> list[str]:
        import ipaddress

        for addr in v:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                raise ValueError(f"Invalid server IP: {addr}")
        return v


class DHCPScopeResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    vlan_id: UUID
    range_start: str
    range_end: str
    subnet_mask: str
    gateway: str
    lease_time: int
    dns_servers: list[str]
    ntp_servers: list[str]
    domain_name: str | None
    custom_options: dict[str, str]
    management_state: str
    external_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DHCPScopeListResponse(PaginatedResponse):
    items: list[DHCPScopeResponse]


class DHCPReservationCreate(BaseModel):
    vlan_id: UUID
    mac_address: str = Field(..., pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    ip_address: str
    hostname: str | None = None
    description: str | None = None


class DHCPReservationResponse(BaseModel):
    id: UUID
    organization_id: UUID
    vlan_id: UUID
    mac_address: str
    ip_address: str
    hostname: str | None
    description: str | None
    management_state: str
    external_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DHCPLeaseResponse(BaseModel):
    id: UUID
    ip_address: str
    mac_address: str
    hostname: str | None
    interface: str | None
    starts: datetime | None
    ends: datetime | None
    status: str | None

    model_config = {"from_attributes": True}


class DHCPLeaseListResponse(PaginatedResponse):
    items: list[DHCPLeaseResponse]


# ═══════════════════════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════════════════════


class DNSRecordCreate(BaseModel):
    site_id: UUID
    record_type: str = Field(..., pattern=r"^(A|AAAA|CNAME|PTR|MX|TXT|SRV)$")
    hostname: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1, max_length=255)
    ttl: int = Field(default=3600, ge=60, le=86400)
    priority: int | None = None
    description: str | None = None


class DNSRecordUpdate(BaseModel):
    value: str | None = None
    ttl: int | None = Field(default=None, ge=60, le=86400)
    priority: int | None = None
    description: str | None = None


class DNSRecordResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    record_type: str
    hostname: str
    value: str
    ttl: int
    priority: int | None
    description: str | None
    management_state: str
    external_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DNSRecordListResponse(PaginatedResponse):
    items: list[DNSRecordResponse]


# ═══════════════════════════════════════════════════════════════════════════════
# Distribution
# ═══════════════════════════════════════════════════════════════════════════════


class DistributionRequest(BaseModel):
    """Manually trigger a distribution."""

    site_id: UUID
    resource_type: str
    resource_id: UUID
    action: str = "create"


class DistributionStepResult(BaseModel):
    tier: int
    device_id: str
    action: str
    status: str
    external_id: str | None = None
    duration_ms: int | None = None
    error: str | None = None


class DistributionResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    resource_type: str
    resource_id: UUID
    action: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DistributionDetailResponse(DistributionResponse):
    plan: dict[str, Any]
    step_results: list[DistributionStepResult]
    rollback_plan: dict[str, Any] | None
    rollback_executed: bool
    error_device_id: UUID | None
    error_tier: int | None


class DistributionListResponse(PaginatedResponse):
    items: list[DistributionResponse]


class DistributionTriggerRequest(BaseModel):
    """Request to trigger a VLAN distribution."""

    vlan_id: UUID
    site_id: UUID


# ═══════════════════════════════════════════════════════════════════════════════
# Drift
# ═══════════════════════════════════════════════════════════════════════════════


class DriftEventResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    device_id: UUID
    drift_type: str
    resource_type: str
    resource_id: UUID | None
    expected_value: dict[str, Any] | None
    actual_value: dict[str, Any] | None
    severity: str
    message: str
    resolution: str
    resolved_at: datetime | None
    resolved_by: UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DriftEventListResponse(PaginatedResponse):
    items: list[DriftEventResponse]


class DriftResolveRequest(BaseModel):
    """Request body for resolving a drift event."""

    resolution: str = Field(..., pattern=r"^(reapply|accept|ignore)$")


class DriftCheckResponse(BaseModel):
    site_id: UUID
    task_id: str
    message: str


class DriftSummaryResponse(BaseModel):
    total: int
    critical: int
    warning: int
    info: int
    pending: int
    resolved: int


# ═══════════════════════════════════════════════════════════════════════════════
# Import Wizard
# ═══════════════════════════════════════════════════════════════════════════════


class ImportStartRequest(BaseModel):
    site_id: UUID


class ImportSessionResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    current_step: int
    status: str
    discovered_devices: dict[str, Any]
    role_assignments: dict[str, Any]
    scan_results: dict[str, Any]
    conflicts: list[dict[str, Any]]
    reconciliation_decisions: dict[str, Any]
    distribution_ids: list[str]
    verification_report: dict[str, Any]
    initiated_by: UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleAssignmentSubmission(BaseModel):
    assignments: list[RoleAssignmentData]


class ReconciliationDecisions(BaseModel):
    decisions: dict[str, str]
    # resource_key → action ("adopt_brain", "adopt_limb", "keep_both", "ignore")


# ═══════════════════════════════════════════════════════════════════════════════
# Suppression Rules
# ═══════════════════════════════════════════════════════════════════════════════


class SuppressionRuleCreate(BaseModel):
    """Create a DHCP/DNS suppression rule."""

    site_id: UUID
    device_id: UUID
    resource_type: str = Field(..., pattern=r"^(dhcp|dns)$")
    scope: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=500)
    suppression_action: str = Field(
        default="suppress",
        pattern=r"^(suppress|warn|log)$",
    )


class SuppressionRuleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    device_id: UUID
    resource_type: str
    scope: str
    reason: str
    suppression_action: str
    is_active: bool
    applied_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════════════════════════
# Import Wizard (additional schemas)
# ═══════════════════════════════════════════════════════════════════════════════


class ImportSessionCreate(BaseModel):
    """Start a new brownfield import session."""

    site_id: UUID


class ImportSessionStep(BaseModel):
    """Submit data for the next import wizard step."""

    payload: dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayDashboardResponse(BaseModel):
    brain_status: dict[str, Any] | None
    vlan_summary: dict[str, int]
    vpn_summary: dict[str, int]
    recent_drift_events: list[DriftEventResponse]
    active_suppressions: int
    last_sync_at: datetime | None


# ═══════════════════════════════════════════════════════════════════════════════
# Imported (read-only) schemas
# ═══════════════════════════════════════════════════════════════════════════════


class ImportedRuleResponse(BaseModel):
    id: UUID
    external_id: str
    name: str
    description: str | None
    rule_index: int
    direction: str
    action: str
    protocol: str
    source: dict[str, Any]
    destination: dict[str, Any]
    is_enabled: bool
    hit_count: int
    last_hit: datetime | None
    last_synced_at: datetime

    model_config = {"from_attributes": True}


class ImportedRuleListResponse(PaginatedResponse):
    items: list[ImportedRuleResponse]


class ImportedNATResponse(BaseModel):
    id: UUID
    external_id: str
    name: str
    description: str | None
    nat_type: str
    source: dict[str, Any]
    destination: dict[str, Any]
    translation: dict[str, Any]
    is_enabled: bool
    last_synced_at: datetime

    model_config = {"from_attributes": True}


class ImportedNATListResponse(PaginatedResponse):
    items: list[ImportedNATResponse]


class ImportedVPNResponse(BaseModel):
    id: UUID
    external_id: str
    name: str
    description: str | None
    vpn_type: str
    status: str
    local_config: dict[str, Any]
    remote_config: dict[str, Any]
    stats: dict[str, Any]
    last_synced_at: datetime

    model_config = {"from_attributes": True}


class ImportedVPNListResponse(PaginatedResponse):
    items: list[ImportedVPNResponse]


class ImportedIDSEventResponse(BaseModel):
    id: UUID
    event_time: datetime
    signature: str
    severity: str
    source_ip: str | None
    source_port: int | None
    dest_ip: str | None
    dest_port: int | None
    action_taken: str | None
    message: str | None
    last_synced_at: datetime

    model_config = {"from_attributes": True}


class ImportedIDSListResponse(PaginatedResponse):
    items: list[ImportedIDSEventResponse]


class ImportedInterfaceResponse(BaseModel):
    id: UUID
    external_id: str
    name: str
    description: str | None
    if_type: str | None
    mac_address: str | None
    mtu: int | None
    is_enabled: bool
    is_up: bool
    ipv4_address: str | None
    ipv4_subnet: str | None
    ipv6_address: str | None
    vlan_tag: int | None
    parent_interface: str | None
    stats: dict[str, Any]
    last_synced_at: datetime

    model_config = {"from_attributes": True}


class ImportedInterfaceListResponse(PaginatedResponse):
    items: list[ImportedInterfaceResponse]


class ImportedDHCPLeaseResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    device_id: UUID
    ip_address: str
    mac_address: str
    hostname: str | None
    interface: str | None
    status: str | None
    last_synced_at: datetime | None

    model_config = {"from_attributes": True}


class ImportedDHCPLeaseListResponse(PaginatedResponse):
    items: list[ImportedDHCPLeaseResponse]


# ═══════════════════════════════════════════════════════════════════════════════
# Passthrough
# ═══════════════════════════════════════════════════════════════════════════════


class PingRequest(BaseModel):
    target: str
    count: int = Field(default=4, ge=1, le=20)


class TracerouteRequest(BaseModel):
    target: str
    max_hops: int = Field(default=30, ge=1, le=64)


class DNSLookupRequest(BaseModel):
    hostname: str
    record_type: str = "A"
    server: str | None = None


class DiagnosticResponse(BaseModel):
    success: bool
    output: str
    duration_ms: int


class BackupResponse(BaseModel):
    success: bool
    backup_id: str | None = None
    message: str


class RestoreRequest(BaseModel):
    backup_id: str


class FirmwareStatusResponse(BaseModel):
    current_version: str
    latest_version: str | None
    update_available: bool
    changelog: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# VLAN Templates
# ═══════════════════════════════════════════════════════════════════════════════


class VLANTemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: str | None = None
    vlan_id: int = Field(..., ge=1, le=4094)
    subnet_template: str
    gateway_ip_template: str = ""
    purpose: str = "general"
    dhcp_enabled: bool = True
    dhcp_options: dict[str, Any] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)


class VLANTemplateUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64)
    description: str | None = None
    vlan_id: int | None = Field(None, ge=1, le=4094)
    subnet_template: str | None = Field(None, min_length=1)
    gateway_ip_template: str | None = None
    purpose: str | None = Field(None, min_length=1)
    dhcp_enabled: bool | None = None
    dhcp_options: dict[str, Any] | None = None
    settings: dict[str, Any] | None = None


class VLANTemplateResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    vlan_id: int
    subnet_template: str
    gateway_ip_template: str
    purpose: str
    dhcp_enabled: bool
    dhcp_options: dict[str, Any]
    settings: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VLANTemplateListResponse(PaginatedResponse):
    items: list[VLANTemplateResponse]
