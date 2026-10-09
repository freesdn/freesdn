# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""SDN observations are not an authorization to apply networking changes."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

SdnReadStatus = Literal["available", "denied", "unsupported_or_missing", "unavailable", "invalid"]


class SdnCollection(BaseModel):
    status: SdnReadStatus
    items: list[dict[str, Any]] | None = None
    omitted_fields: int = 0
    observed_at: datetime


class SdnResourceObservation(BaseModel):
    resource: Literal["zones", "vnets", "controllers"]
    configured: SdnCollection
    running: SdnCollection
    pending: SdnCollection


class SdnInspection(BaseModel):
    controller_id: UUID
    started_at: datetime
    finished_at: datetime
    resources: list[SdnResourceObservation]
    permissions_status: SdnReadStatus
    audit_at_sdn: bool | None = None
    allocate_at_sdn: bool | None = None
    audit_propagates: bool | None = None
    allocate_propagates: bool | None = None
    pending_state: Literal["changes_detected", "no_visible_changes", "unknown"]
    visibility: Literal["partial_or_unverified"] = "partial_or_unverified"
    atomic_snapshot: Literal[False] = False
    writes_enabled: Literal[False] = False
    unobserved_resources: list[str] = Field(
        default_factory=lambda: ["subnets", "ipams", "dns", "fabrics", "prefix-lists", "route-maps"]
    )
    blockers: list[str] = Field(
        default_factory=lambda: [
            "complete_pending_scope_unverified",
            "native_lock_lifecycle_unqualified",
            "node_reload_outcomes_unverified",
            "guest_and_management_connectivity_unverified",
        ]
    )


class SdnDiffSummary(BaseModel):
    changed: bool
    added_lines: int
    removed_lines: int


class SdnDryRunObservation(BaseModel):
    controller_id: UUID
    node: str
    status: SdnReadStatus
    observed_at: datetime
    interfaces: SdnDiffSummary | None = None
    frr: SdnDiffSummary | None = None
    content_withheld: Literal[True] = True
    connectivity_verified: Literal[False] = False


SdnDependencyResource = Literal[
    "zones",
    "vnets",
    "controllers",
    "subnets",
    "ipams",
    "dns",
    "fabrics",
    "fabric-nodes",
    "prefix-lists",
    "route-maps",
    "prefix-list-entries",
    "route-map-entries",
]
SdnView = Literal["configured", "running", "pending"]


class SdnDependencyCollection(BaseModel):
    resource: SdnDependencyResource
    view: SdnView
    parent_id: str | None = None
    status: SdnReadStatus | Literal["not_observed"]
    reason: (
        Literal[
            "view_not_exposed",
            "inspection_deadline",
            "response_limit",
            "parent_inventory_unavailable",
        ]
        | None
    ) = None
    content_scope: Literal["allowlisted_fields", "identities_only"] = "allowlisted_fields"
    items: list[dict[str, Any]] | None = None
    omitted_fields: int = 0
    observed_at: datetime


class SdnDependencyReference(BaseModel):
    source_resource: SdnDependencyResource
    source_id: str
    field: str
    view: Literal["configured", "running"]
    target_resource: SdnDependencyResource
    target_id: str
    target_view: Literal["configured", "running"]
    status: Literal["visible", "not_visible", "target_unavailable"]


class SdnDependencyInspection(BaseModel):
    controller_id: UUID
    started_at: datetime
    finished_at: datetime
    collections: list[SdnDependencyCollection]
    references: list[SdnDependencyReference]
    pending_state: Literal["changes_detected", "unknown"]
    subnet_parent_limit: int
    subnet_parents_selected: int
    subnet_parents_omitted_by_limit: int
    subnet_parent_inventory_complete: Literal[False] = False
    request_limit: int = Field(
        description="Maximum logical collection reads; excludes transport retries"
    )
    requests_made: int = Field(
        description="Logical collection reads started; not HTTP attempt count"
    )
    response_limit_reached: bool
    visibility: Literal["partial_or_unverified"] = "partial_or_unverified"
    atomic_snapshot: Literal[False] = False
    dependency_graph_complete: Literal[False] = False
    writes_enabled: Literal[False] = False
    unobserved_dependencies: list[str] = Field(
        default_factory=lambda: [
            "guest_nic_references",
            "host_network_interfaces",
            "withheld_or_unobserved_policy_fields",
            "policy_evaluation_and_enforcement",
            "fabric_runtime_and_withheld_fields",
            "provider_version_and_plugin_support",
        ]
    )


SdnAttachmentStatus = SdnReadStatus | Literal["not_observed"]
SdnAttachmentReason = Literal["inspection_deadline", "response_limit"]
SdnAttachmentMatch = Literal[
    "visible", "not_visible", "target_unavailable", "not_observed", "no_bridge"
]


class SdnAttachmentRead(BaseModel):
    status: SdnAttachmentStatus
    reason: SdnAttachmentReason | None = None
    observed_at: datetime
    omitted_fields: int = 0


class SdnAttachmentInventory(SdnAttachmentRead):
    visible_count: int | None = None
    selected: int = 0
    omitted_by_limit: int = 0
    selection_limit: int
    visibility_complete: Literal[False] = False


class SdnNicAttachment(BaseModel):
    key: str
    bridge: str | None = None
    tag: int | None = None
    trunks: str | None = None
    link_down: bool | None = None
    firewall: bool | None = None
    omitted_options: int = 0
    configured_vnet: SdnAttachmentMatch = "not_observed"
    running_vnet: SdnAttachmentMatch = "not_observed"
    host_interface: SdnAttachmentMatch = "not_observed"


class SdnGuestAttachments(SdnAttachmentRead):
    node: str
    vmid: int
    guest_type: Literal["qemu", "lxc"]
    view: Literal["current", "pending_merged"]
    nics: list[SdnNicAttachment] | None = None


class SdnHostInterface(BaseModel):
    iface: str
    interface_type: str
    active: bool | None = None
    exists: bool | None = None
    bridge_ports: list[str] | None = None
    slaves: list[str] | None = None
    ovs_ports: list[str] | None = None
    ovs_bonds: list[str] | None = None
    vlan_raw_device: str | None = None


class SdnHostInterfaces(SdnAttachmentRead):
    node: str
    view: Literal["native_report"] = "native_report"
    interfaces: list[SdnHostInterface] | None = None


class SdnAttachmentVnets(SdnAttachmentRead):
    view: Literal["configured", "running"]
    identities: list[str] | None = None


class SdnAttachmentInspection(BaseModel):
    controller_id: UUID
    started_at: datetime
    finished_at: datetime
    guest_inventory: SdnAttachmentInventory
    node_inventory: SdnAttachmentInventory
    vnets: list[SdnAttachmentVnets]
    guests: list[SdnGuestAttachments]
    hosts: list[SdnHostInterfaces]
    request_limit: int = Field(description="Maximum logical reads; excludes transport retries")
    requests_made: int = Field(description="Logical reads started; not HTTP attempt count")
    response_limit_reached: bool
    visibility: Literal["partial_or_unverified"] = "partial_or_unverified"
    atomic_snapshot: Literal[False] = False
    dependency_graph_complete: Literal[False] = False
    connectivity_verified: Literal[False] = False
    writes_enabled: Literal[False] = False
    unobserved_dependencies: list[str] = Field(
        default_factory=lambda: [
            "hidden_or_unselected_guests_and_nodes",
            "guest_snapshots_and_passthrough",
            "host_pending_diff_and_management_path",
            "nested_sdn_policies_and_fabric_peers",
            "provider_version_and_plugin_support",
            "live_connectivity_and_reload_outcomes",
        ]
    )
