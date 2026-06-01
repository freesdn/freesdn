# mypy: disable-error-code=no-untyped-def
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN

"""
FreeSDN Hypervisor Module - API Endpoints
==========================================

REST API for Proxmox VE hypervisor management.
Mounted at /api/v1/hypervisor/.
"""

from __future__ import annotations

import logging
import re
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, File, HTTPException, Path, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.exceptions import AdapterError
from app.api.v1.deps import get_db, require_min_role
from app.core.dependencies import is_unscoped_superuser, require_permissions
from app.core.redaction import redact_secrets
from app.core.tenancy import tenant_filter
from app.models.core import Controller, Site, User
from app.modules.hypervisor.schemas import (
    AgentExecRequest,
    AgentFileReadRequest,
    AgentFileWriteRequest,
    BackupAgeResponse,
    BackupJobCreateRequest,
    BackupJobResponse,
    BackupJobUpdateRequest,
    BackupRunRequest,
    BulkActionRequest,
    BulkActionResult,
    BulkMigrateRequest,
    CephDetailResponse,
    CephStatusResponse,
    CloneRequest,
    CloudInitConfig,
    ClusterFirewallOptions,
    ClusterResourceItem,
    ClusterStatusResponse,
    ConsoleProxyResponse,
    CreateContainerRequest,
    CreateGuestFirewallRuleRequest,
    CreateSdnVnetRequest,
    CreateSdnZoneRequest,
    CreateVMRequest,
    CreateVMResponse,
    DiskInfoResponse,
    FirewallRuleCreateRequest,
    FirewallRuleResponse,
    FleetDashboardResponse,
    FleetTaskStatistics,
    GuestAgentInfoResponse,
    GuestAgentNetworkInterface,
    GuestFirewallOptions,
    HAGroupCreateRequest,
    HAGroupResponse,
    HAResourceCreateRequest,
    HAResourceResponse,
    HypervisorDashboardResponse,
    HysteresisEvaluateRequest,
    HysteresisEvaluateResponse,
    MigrateRequest,
    NetworkInterfaceResponse,
    NextVMIDResponse,
    NodeResponse,
    NodeSensors,
    NodeServiceResponse,
    PreflightRequest,
    PreflightResponse,
    PruneBackupsRequest,
    RemoteMigrateRequest,
    ResizeDiskRequest,
    ResourcePoolResponse,
    RestoreBackupRequest,
    RRDPointResponse,
    SnapshotCreateRequest,
    SnapshotResponse,
    StorageContentItem,
    StorageResponse,
    SyslogEntry,
    TaskDetailResponse,
    TaskLogEntry,
    TaskResponse,
    UpdateConfigRequest,
    UploadCertificateRequest,
    UploadResponse,
    VMActionRequest,
    VMResponse,
)
from app.modules.hypervisor.service import HypervisorService, evaluate_with_hysteresis

logger = logging.getLogger(__name__)

router = APIRouter()


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════


async def _get_controller(
    controller_id: UUID,
    session: AsyncSession,
    current_user: User | None = None,
) -> Controller:
    """Fetch and validate a Proxmox controller with tenant scoping."""
    stmt = select(Controller).where(
        Controller.id == controller_id,
        Controller.deleted_at.is_(None),
    )
    # Tenant scoping: non-superadmin users can only access controllers
    # belonging to sites in their organization. super_admin bypasses (matches
    # the controllers-list global view; without this a super_admin in org A
    # got a 404 on org B's controller).
    # do NOT guard on a truthy organization_id — a scoped super_admin
    # key with organization_id=None would otherwise skip tenant scoping entirely.
    # A non-unscoped caller with no org yields ``Site.organization_id IS NULL``
    # (no rows) = fail-closed. Background callers (current_user None) stay org-wide.
    if current_user and not is_unscoped_superuser(current_user):
        stmt = stmt.join(Site, Controller.site_id == Site.id).where(
            Site.organization_id == current_user.organization_id,
        )
        # site-limited callers (non-admin with >=1 grant) may
        # only reach controllers in granted sites. Use is_org_admin (covers the
        # 'admin' role too, hierarchy level 80) — a literal == ORG_ADMIN check
        # wrongly site-limited org-wide 'admin' users.
        if not current_user.is_org_admin:
            from app.models.core import UserSiteAccess

            grants = (
                (
                    await session.execute(
                        select(UserSiteAccess.site_id).where(
                            UserSiteAccess.user_id == current_user.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            if grants:
                stmt = stmt.where(Controller.site_id.in_(list(grants)))
    ctrl = (await session.execute(stmt)).scalar_one_or_none()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Controller not found")
    if ctrl.controller_type not in ("proxmox", "pve"):
        raise HTTPException(
            status_code=400,
            detail=f"Controller type '{ctrl.controller_type}' is not a Proxmox controller",
        )
    return ctrl


# Safe-char regex patterns for Proxmox path parameters
_RE_NODE = re.compile(r"^[a-zA-Z0-9._-]+$")
_RE_SNAP = re.compile(r"^[a-zA-Z0-9_-]+$")
_RE_STORAGE = re.compile(r"^[a-zA-Z0-9._-]+$")
_RE_HA_SID = re.compile(r"^(vm|ct):\d+$")
_RE_VOLID = re.compile(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_./-]+$")
_RE_UPID_SAFE = re.compile(r"^[^/]+$")  # UPIDs must not contain slashes
# Sensitive keys stripped from VM config responses
_SENSITIVE_CONFIG_KEYS = {"cipassword", "sshkeys", "args", "hookscript"}


def _validate_path_param(value: str, pattern: re.Pattern[str], name: str) -> str:
    """Validate a path parameter against a regex pattern."""
    if not pattern.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {name}: {value!r}")
    return value


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/dashboard",
    response_model=HypervisorDashboardResponse,
    summary="Get hypervisor dashboard summary",
)
async def get_dashboard(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_dashboard(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (conn->502, read-only->403); AdapterConnectionError is NOT a builtin ConnectionError
    except Exception as e:
        logger.error("Hypervisor dashboard error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch hypervisor dashboard")


# ═══════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT SAFETY (dry-run impact preview)
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/preflight",
    response_model=PreflightResponse,
    summary="Dry-run impact assessment for a prospective write (no mutation)",
)
async def preflight_preview(
    controller_id: UUID,
    body: PreflightRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    """Preview a prospective staged write's destructiveness and live impact
    BEFORE staging it. Strictly read-only — mutates nothing. Returns the risk
    class, whether the write will need ``confirmed=true`` to apply, and any
    device-observed warnings (running guests on a node, VM power state, the
    size of a volume about to be deleted). Gated to ``site_admin`` — the same
    role that can stage these writes — so it exposes nothing extra."""
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.preflight_preview(ctrl, body.feature, body.operation, body.payload)
        return PreflightResponse(**result)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (conn->502, read-only->403)
    except Exception as e:
        logger.error("Preflight preview error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to assess pre-flight impact")


# ═══════════════════════════════════════════════════════════════════════════
# CLUSTER
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/cluster/status",
    response_model=ClusterStatusResponse,
    summary="Get cluster status",
)
async def get_cluster_status(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_cluster_status(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.error("Cluster status error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch cluster status")


@router.get(
    "/controllers/{controller_id}/cluster/resources",
    response_model=list[ClusterResourceItem],
    summary="Get cluster resources",
)
async def get_cluster_resources(
    controller_id: UUID,
    type: Literal["node", "qemu", "lxc", "storage", "sdn"] | None = Query(
        None, description="Filter: node, qemu, lxc, storage, sdn"
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_cluster_resources(ctrl, type)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# NODES
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes",
    response_model=list[NodeResponse],
    summary="List all cluster nodes",
)
async def get_nodes(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_nodes(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}",
    response_model=NodeResponse,
    summary="Get node detail",
)
async def get_node_detail(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_detail(ctrl, node)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# VMs & CONTAINERS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/vms",
    response_model=list[VMResponse],
    summary="List all VMs across all nodes",
)
async def get_all_vms(
    controller_id: UUID,
    type: Literal["qemu", "lxc"] | None = Query(None, description="Filter by VM type"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_all_vms(ctrl, type)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/vms",
    response_model=list[VMResponse],
    summary="List VMs on a specific node",
)
async def get_node_vms(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_vms(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/containers",
    response_model=list[VMResponse],
    summary="List containers on a specific node",
)
async def get_node_containers(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_containers(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/config",
    response_model=dict,
    summary="Get VM/container configuration",
)
async def get_vm_config(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        config = await svc.get_vm_config(ctrl, node, vmid, vm_type=vm_type)
        # Use the central redact_secrets() — strips ~158 sensitive
        # key names + Proxmox cloud-init ``ipconfigN`` prefix patterns
        # (which can carry inline passwords). The previous 4-key
        # strip (_SENSITIVE_CONFIG_KEYS) missed ssh_key, private_key,
        # auth_key, snmp community, etc. that may appear in
        # operator-supplied VM custom fields.
        return redact_secrets(config) if isinstance(config, dict) else config
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/action",
    summary="Perform a VM/container power action",
)
async def vm_action(
    controller_id: UUID,
    body: VMActionRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.vm_action(ctrl, node, vmid, body.action, vm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# SNAPSHOTS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots",
    response_model=list[SnapshotResponse],
    summary="List snapshots",
)
async def get_snapshots(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_snapshots(ctrl, node, vmid, vm_type)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots",
    summary="Create a snapshot",
)
async def create_snapshot(
    controller_id: UUID,
    body: SnapshotCreateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_snapshot(
            ctrl, node, vmid, body.snapname, body.description, vm_type, body.vmstate
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots/{snapname}/rollback",
    summary="Rollback to a snapshot",
)
async def rollback_snapshot(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    snapname: str = Path(..., min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$"),
    confirmed: bool = Query(
        False,
        description="Must be true to roll back (discards all guest state since the "
        "snapshot). The UI's type-to-confirm dialog sets this; without it the API "
        "returns 409.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.rollback_snapshot(ctrl, node, vmid, snapname, vm_type, confirmed=confirmed)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots/{snapname}",
    summary="Delete a snapshot",
)
async def delete_snapshot(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    snapname: str = Path(..., min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_snapshot(ctrl, node, vmid, snapname, vm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# STORAGE
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/storage",
    response_model=list[StorageResponse],
    summary="List storage pools",
)
async def get_storage(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_storage(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/storage/{storage}/content",
    response_model=list[StorageContentItem],
    summary="List storage content",
)
async def get_storage_content(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    storage: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    content: Literal["images", "iso", "backup", "rootdir", "vztmpl", "snippets"] | None = Query(
        None, description="Filter: images, iso, backup, rootdir, vztmpl, snippets"
    ),
    vmid: int | None = Query(None, ge=100, le=999999999, description="Filter by VMID"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_storage_content(ctrl, node, storage, content, vmid=vmid)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/network",
    response_model=list[NetworkInterfaceResponse],
    summary="List node network interfaces",
)
async def get_node_network(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_network(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# TASKS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/tasks",
    response_model=list[TaskResponse],
    summary="List recent tasks",
)
async def get_tasks(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_tasks(ctrl, node, limit)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# MONITORING
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/rrd",
    response_model=list[RRDPointResponse],
    summary="Get node RRD monitoring data",
)
async def get_node_rrd(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    timeframe: Literal["hour", "day", "week", "month", "year"] = Query("hour"),
    max_points: int = Query(500, ge=10, le=5000, description="Max data points (LTTB downsampling)"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_rrd(ctrl, node, timeframe, max_points=max_points)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/rrd",
    response_model=list[RRDPointResponse],
    summary="Get VM RRD monitoring data",
)
async def get_vm_rrd(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    timeframe: Literal["hour", "day", "week", "month", "year"] = Query("hour"),
    max_points: int = Query(500, ge=10, le=5000, description="Max data points (LTTB downsampling)"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_vm_rrd(ctrl, node, vmid, timeframe, max_points=max_points)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/backup/jobs",
    response_model=list[BackupJobResponse],
    summary="List scheduled backup jobs",
)
async def get_backup_jobs(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_backup_jobs(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/backup",
    summary="Run a manual backup",
)
async def run_backup(
    controller_id: UUID,
    body: BackupRunRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.run_backup(ctrl, node, vmid, body.storage, body.mode, body.compress)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CLONE / MIGRATE / RESIZE
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/clone",
    summary="Clone a VM or container",
)
async def clone_vm(
    controller_id: UUID,
    body: CloneRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.clone_vm(
            ctrl,
            node,
            vmid,
            body.newid,
            vm_type,
            name=body.name,
            target=body.target,
            full=body.full,
            storage=body.storage,
            description=body.description,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/migrate",
    summary="Migrate a VM or container to another node",
)
async def migrate_vm(
    controller_id: UUID,
    body: MigrateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.migrate_vm(ctrl, node, vmid, body.target, vm_type, body.online)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/resize",
    summary="Resize a VM/CT disk",
)
async def resize_disk(
    controller_id: UUID,
    body: ResizeDiskRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.resize_disk(ctrl, node, vmid, body.disk, body.size, vm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/config",
    summary="Update VM/CT configuration",
)
async def update_config(
    controller_id: UUID,
    body: UpdateConfigRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        config = {k: v for k, v in body.model_dump().items() if v is not None}
        if not config:
            raise HTTPException(status_code=400, detail="No config fields provided")
        svc = HypervisorService(session)
        return await svc.update_config(ctrl, node, vmid, config, vm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/template",
    summary="Convert VM/CT to template",
)
async def convert_to_template(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.convert_to_template(ctrl, node, vmid, vm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CONSOLE
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/console",
    response_model=ConsoleProxyResponse,
    summary="Get console proxy ticket",
)
async def get_console_proxy(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    console_type: Literal["vnc", "spice", "term"] = Query("vnc"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_console_proxy(ctrl, node, vmid, vm_type, console_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# TASK DETAILS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/tasks/{upid}/status",
    response_model=TaskDetailResponse,
    summary="Get task status detail",
)
async def get_task_status(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    upid: str = Path(..., min_length=10, pattern=r"^UPID:[^/]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_task_status(ctrl, node, upid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/tasks/{upid}/log",
    response_model=list[TaskLogEntry],
    summary="Get task log output",
)
async def get_task_log(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    upid: str = Path(..., min_length=10, pattern=r"^UPID:[^/]+$"),
    start: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_task_log(ctrl, node, upid, start, limit)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/tasks/{upid}",
    summary="Stop a running task",
)
async def stop_task(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    upid: str = Path(..., min_length=10, pattern=r"^UPID:[^/]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.stop_task(ctrl, node, upid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/firewall/rules",
    response_model=list[FirewallRuleResponse],
    summary="Get cluster firewall rules",
)
async def get_cluster_firewall_rules(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_firewall_rules(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/firewall/rules",
    response_model=list[FirewallRuleResponse],
    summary="Get node firewall rules",
)
async def get_node_firewall_rules(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_firewall_rules(ctrl, node=node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/firewall/rules",
    summary="Create a node firewall rule",
)
async def create_node_firewall_rule(
    controller_id: UUID,
    body: FirewallRuleCreateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_firewall_rule(
            ctrl,
            node=node,
            action=body.action,
            rule_type=body.type,
            enable=body.enable,
            source=body.source,
            dest=body.dest,
            sport=body.sport,
            dport=body.dport,
            proto=body.proto,
            macro=body.macro,
            comment=body.comment,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/firewall/rules/{pos}",
    summary="Delete a node firewall rule",
)
async def delete_node_firewall_rule(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    pos: int = Path(..., ge=0),
    session: AsyncSession = Depends(get_db),
    # P0: was only get_current_user — any authenticated user could
    # delete cluster firewall rules. Aligned with every other DELETE
    # in this router (site_admin minimum).
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_firewall_rule(ctrl, pos, node=node)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# NODE EXTRAS
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/shutdown",
    summary="Shutdown a node",
)
async def shutdown_node(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    confirmed: bool = Query(
        False,
        description="Must be true to shut the node down (catastrophic — takes the "
        "whole node offline with no auto-recovery). The UI's type-to-confirm dialog "
        "sets this; without it the API returns 409.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.shutdown_node(ctrl, node, confirmed=confirmed)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/reboot",
    summary="Reboot a node",
)
async def reboot_node(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    confirmed: bool = Query(
        False,
        description="Must be true to reboot the node (catastrophic — takes the "
        "whole node and its guests offline). The UI's type-to-confirm dialog sets "
        "this; without it the API returns 409.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.reboot_node(ctrl, node, confirmed=confirmed)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/services",
    response_model=list[NodeServiceResponse],
    summary="Get node services",
)
async def get_node_services(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_services(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/disks",
    response_model=list[DiskInfoResponse],
    summary="Get node physical disks",
)
async def get_node_disks(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_disks(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/syslog",
    response_model=list[SyslogEntry],
    summary="Get node syslog entries",
)
async def get_node_syslog(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    limit: int = Query(50, ge=1, le=500),
    start: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_node_syslog(ctrl, node, limit, start)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/storage/{storage}/content/{volume:path}",
    summary="Delete a storage volume",
)
async def delete_storage_volume(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    storage: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    volume: str = Path(..., min_length=1),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    _validate_path_param(volume, _RE_VOLID, "volume")
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_storage_volume(ctrl, node, storage, volume)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# HA
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/ha/resources",
    response_model=list[HAResourceResponse],
    summary="Get HA resources",
)
async def get_ha_resources(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_ha_resources(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/ha/groups",
    response_model=list[HAGroupResponse],
    summary="Get HA groups",
)
async def get_ha_groups(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_ha_groups(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# RESOURCE POOLS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/pools",
    response_model=list[ResourcePoolResponse],
    summary="Get resource pools",
)
async def get_pools(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_pools(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CEPH
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/ceph/status",
    response_model=CephStatusResponse,
    summary="Get Ceph cluster status",
)
async def get_ceph_status(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_ceph_status(ctrl, node)
        if result is None:
            raise HTTPException(status_code=404, detail="Ceph not available on this node")
        return result
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# VM/CT CREATION & DELETION
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nextid",
    response_model=NextVMIDResponse,
    summary="Get next available VMID",
)
async def get_next_vmid(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_next_vmid(ctrl)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/vms",
    response_model=CreateVMResponse,
    summary="Create a new QEMU virtual machine",
)
async def create_vm(
    controller_id: UUID,
    body: CreateVMRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_vm(
            ctrl,
            vmid=body.vmid,
            name=body.name,
            node=body.node,
            cores=body.cores,
            sockets=body.sockets,
            memory=body.memory,
            balloon=body.balloon,
            ostype=body.ostype,
            storage=body.storage,
            disk_size=body.disk_size,
            iso=body.iso,
            net_bridge=body.net_bridge,
            net_model=body.net_model,
            cpu_type=body.cpu_type,
            bios=body.bios,
            machine=body.machine,
            start=body.start_after_create,
            pool=body.pool,
            description=body.description,
            onboot=body.onboot,
            tags=body.tags,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/containers",
    response_model=CreateVMResponse,
    summary="Create a new LXC container",
)
async def create_container(
    controller_id: UUID,
    body: CreateContainerRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_container(
            ctrl,
            vmid=body.vmid,
            hostname=body.hostname,
            node=body.node,
            ostemplate=body.ostemplate,
            cores=body.cores,
            memory=body.memory,
            swap=body.swap,
            storage=body.storage,
            rootfs_size=body.rootfs_size,
            net_bridge=body.net_bridge,
            net_ip=body.net_ip,
            password=body.password,
            ssh_public_keys=body.ssh_public_keys,
            start=body.start_after_create,
            pool=body.pool,
            description=body.description,
            unprivileged=body.unprivileged,
            onboot=body.onboot,
            tags=body.tags,
            nameserver=body.nameserver,
            searchdomain=body.searchdomain,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}",
    summary="Delete a VM or container",
)
async def delete_vm(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: Literal["qemu", "lxc"] = Path(...),
    vmid: int = Path(..., ge=100, le=999999999),
    confirmed: bool = Query(
        False,
        description="Must be true to destroy the guest (irreversible). The UI's "
        "type-to-confirm dialog sets this; without it the API returns 409.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_vm(ctrl, node, vmid, vm_type, confirmed=confirmed)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# HA MANAGEMENT (CREATE/DELETE)
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/ha/resources",
    summary="Add a VM/CT to HA management",
)
async def create_ha_resource(
    controller_id: UUID,
    body: HAResourceCreateRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_ha_resource(
            ctrl,
            body.sid,
            group=body.group,
            max_relocate=body.max_relocate,
            max_restart=body.max_restart,
            state=body.state,
            comment=body.comment,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/ha/resources/{sid}",
    summary="Remove a VM/CT from HA management",
)
async def delete_ha_resource(
    controller_id: UUID,
    sid: str = Path(..., min_length=3, max_length=20, pattern=r"^(vm|ct):\d+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_ha_resource(ctrl, sid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/ha/groups",
    summary="Create an HA group",
)
async def create_ha_group(
    controller_id: UUID,
    body: HAGroupCreateRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.create_ha_group(
            ctrl,
            body.group,
            body.nodes,
            nofailback=body.nofailback,
            restricted=body.restricted,
            comment=body.comment,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/ha/groups/{group}",
    summary="Delete an HA group",
)
async def delete_ha_group(
    controller_id: UUID,
    group: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9_-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_ha_group(ctrl, group)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# BULK OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/bulk-action",
    response_model=list[BulkActionResult],
    summary="Execute an action on multiple VMs/CTs",
)
async def bulk_action(
    controller_id: UUID,
    body: BulkActionRequest,
    confirmed: bool = Query(
        False,
        description="Required for action=delete (irreversible). The UI's "
        "type-to-confirm dialog sets this; without it each delete is refused. "
        "Ignored for non-destructive actions.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        targets = [t.model_dump() for t in body.targets]
        results = await svc.bulk_action(ctrl, targets, body.action, confirmed=confirmed)
        return [BulkActionResult(**r) for r in results]
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/bulk-migrate",
    response_model=list[BulkActionResult],
    summary="Migrate multiple VMs/CTs to a target node",
)
async def bulk_migrate(
    controller_id: UUID,
    body: BulkMigrateRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        targets = [t.model_dump() for t in body.targets]
        results = await svc.bulk_migrate(ctrl, targets, body.target_node, body.online)
        return [BulkActionResult(**r) for r in results]
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# GUEST AGENT
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/agent/info",
    response_model=GuestAgentInfoResponse,
    summary="Get guest agent info for a QEMU VM",
)
async def get_guest_agent_info(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_guest_agent_info(ctrl, node, vmid)
        if not result.success:
            raise HTTPException(status_code=502, detail=result.error or "Guest agent not available")
        raw = result.data
        # Parse guest agent network interfaces
        interfaces = []
        if isinstance(raw, dict):
            for iface in raw.get("result", []):
                if not isinstance(iface, dict):
                    continue
                ips = []
                for addr in iface.get("ip-addresses", []):
                    if isinstance(addr, dict) and addr.get("ip-address"):
                        ips.append(addr["ip-address"])
                interfaces.append(
                    GuestAgentNetworkInterface(
                        name=iface.get("name", ""),
                        mac_address=iface.get("hardware-address", ""),
                        ip_addresses=ips,
                    )
                )
        return GuestAgentInfoResponse(interfaces=interfaces)
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP JOB CRUD
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/backup/jobs",
    summary="Create a scheduled backup job",
)
async def create_backup_job(
    controller_id: UUID,
    body: BackupJobCreateRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
        result = await svc.create_backup_job(ctrl, **kwargs)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to create backup job"
            )
        return {"status": "ok", "data": result.data}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put(
    "/controllers/{controller_id}/backup/jobs/{job_id}",
    summary="Update a backup job",
)
async def update_backup_job(
    controller_id: UUID,
    body: BackupJobUpdateRequest,
    job_id: str = Path(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_:-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
        if not kwargs:
            raise HTTPException(status_code=400, detail="No fields to update")
        result = await svc.update_backup_job(ctrl, job_id, **kwargs)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to update backup job"
            )
        return {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/backup/jobs/{job_id}",
    summary="Delete a backup job",
)
async def delete_backup_job(
    controller_id: UUID,
    job_id: str = Path(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_:-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.delete_backup_job(ctrl, job_id)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to delete backup job"
            )
        return {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CONTAINER RRD
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/lxc/{vmid}/rrd",
    response_model=list[RRDPointResponse],
    summary="Get container RRD monitoring data",
)
async def get_container_rrd(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    timeframe: Literal["hour", "day", "week", "month", "year"] = Query("hour"),
    max_points: int = Query(500, ge=10, le=5000, description="Max data points (LTTB downsampling)"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_container_rrd(ctrl, node, vmid, timeframe, max_points=max_points)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# STORAGE UPLOAD
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/storage/{storage}/upload",
    response_model=UploadResponse,
    summary="Upload a file (ISO/template) to storage",
)
async def upload_to_storage(
    controller_id: UUID,
    file: UploadFile = File(...),
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    storage: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    temp_path: str | None = None
    try:
        import os
        import tempfile

        MAX_UPLOAD_SIZE = 4 * 1024 * 1024 * 1024  # 4GB
        total_size = 0
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_path = tmp.name
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="File too large (max 4GB)")
                tmp.write(chunk)
        filename = file.filename or "upload"
        content_type = file.content_type or "application/octet-stream"
        svc = HypervisorService(session)
        result = await svc.upload_to_storage(ctrl, node, storage, filename, content_type, temp_path)
        if isinstance(result, dict) and not result.get("success", True):
            raise HTTPException(status_code=400, detail=result.get("error", "Upload failed"))
        upid = None
        if isinstance(result, dict):
            upid = str(result.get("data")) if result.get("data") else None
        return UploadResponse(
            filename=filename,
            size=total_size,
            content_type=content_type,
            upid=upid,
        )
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning("Failed to remove temp upload file: %s", temp_path)


# ═══════════════════════════════════════════════════════════════════════════
# FLEET DASHBOARD (MULTI-CLUSTER)
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/fleet/dashboard",
    response_model=FleetDashboardResponse,
    summary="Get fleet-wide hypervisor dashboard across all Proxmox clusters",
)
async def get_fleet_dashboard(
    site_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    """Aggregate hypervisor metrics across ALL registered Proxmox controllers."""
    stmt = select(Controller).where(
        Controller.controller_type.in_(("proxmox", "pve")),
        Controller.deleted_at.is_(None),
    )
    if site_id:
        stmt = stmt.where(Controller.site_id == site_id)
    # Tenant scoping (canonical helper: org-via-Site + per-user site grant).
    if current_user:
        stmt = stmt.where(tenant_filter(Controller, current_user))
    result = await session.execute(stmt)
    controllers = list(result.scalars().all())

    if not controllers:
        return FleetDashboardResponse()

    try:
        svc = HypervisorService(session)
        return await svc.get_fleet_dashboard(controllers)
    except Exception as e:
        logger.error("Fleet dashboard error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch fleet dashboard")


# ═══════════════════════════════════════════════════════════════════════════
# APT / UPDATES
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/apt/updates",
    response_model=None,
    summary="Get available APT package updates",
)
async def get_node_apt_updates(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_node_apt_updates(ctrl, node)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to get APT updates")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/apt/refresh",
    response_model=None,
    summary="Refresh APT package index",
)
async def refresh_node_apt(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.refresh_node_apt(ctrl, node)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to refresh APT")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/apt/versions",
    response_model=None,
    summary="Get installed package versions",
)
async def get_node_apt_versions(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_node_apt_versions(ctrl, node)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get APT versions"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CERTIFICATES
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/certificates",
    response_model=None,
    summary="Get node TLS certificates",
)
async def get_node_certificates(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_node_certificates(ctrl, node)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get certificates"
            )
        # Cert listings include the certificate body (public) but
        # Proxmox CAN echo private-key fields on custom uploads.
        # redact_secrets covers private_key / tls_key / privkey /
        # ca_key keys.
        return redact_secrets(result.data) if isinstance(result.data, (dict, list)) else result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/certificates/acme/renew",
    response_model=None,
    summary="Renew ACME certificate on a node",
)
async def renew_node_acme_certificate(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    force: bool = Query(False),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.renew_node_acme_certificate(ctrl, node, force)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to renew ACME certificate"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/certificates/custom",
    response_model=None,
    summary="Upload a custom TLS certificate",
)
async def upload_custom_certificate(
    controller_id: UUID,
    body: UploadCertificateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    # replacing the node TLS cert can lock the operator out of
    # pveproxy if the cert/key is bad. Require an explicit confirmed=true (parity
    # with the destructive-op confirm class and the staged-apply catastrophic
    # gate added in adapter_proxmox_preflight).
    if not body.confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Uploading a custom TLS certificate can lock pveproxy out if the "
                "cert/key is invalid; resubmit with confirmed=true to proceed."
            ),
        )
    try:
        svc = HypervisorService(session)
        result = await svc.upload_custom_certificate(
            ctrl,
            node,
            certificates=body.certificates,
            key=body.key,
            force=body.force,
            restart=body.restart,
        )
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to upload certificate"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/certificates/custom",
    response_model=None,
    summary="Delete custom TLS certificate",
)
async def delete_custom_certificate(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    restart: bool = Query(False),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.delete_custom_certificate(ctrl, node, restart)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to delete certificate"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# SUBSCRIPTION
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/subscription",
    response_model=None,
    summary="Get node subscription status",
)
async def get_node_subscription(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_node_subscription(ctrl, node)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get subscription"
            )
        # Subscription key + signature are sensitive. redact_secrets
        # strips ``key``, ``signature``, plus the standard token /
        # secret family.
        return redact_secrets(result.data) if isinstance(result.data, dict) else result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CLUSTER MIGRATION
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/remote-migrate",
    response_model=None,
    summary="Remote-migrate a VM to another cluster",
)
async def remote_migrate_vm(
    controller_id: UUID,
    body: RemoteMigrateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    # a source-destroying remote migration must be explicitly
    # confirmed — never silent. (The default is now delete_source=false; this
    # guards the case where an operator sets delete_source=true.)
    if body.delete_source and not body.confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Remote migration with delete_source=true permanently destroys the "
                "source VM after transfer; resubmit with confirmed=true to proceed."
            ),
        )
    try:
        svc = HypervisorService(session)
        result = await svc.remote_migrate_vm(ctrl, node, vmid, body)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Remote migration failed")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/lxc/{vmid}/remote-migrate",
    response_model=None,
    summary="Remote-migrate a container to another cluster",
)
async def remote_migrate_container(
    controller_id: UUID,
    body: RemoteMigrateRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    # a source-destroying remote migration must be explicitly
    # confirmed — never silent. (The default is now delete_source=false; this
    # guards the case where an operator sets delete_source=true.)
    if body.delete_source and not body.confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Remote migration with delete_source=true permanently destroys the "
                "source container after transfer; resubmit with confirmed=true to proceed."
            ),
        )
    try:
        svc = HypervisorService(session)
        result = await svc.remote_migrate_container(ctrl, node, vmid, body)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Remote migration failed")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# SDN
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/sdn/zones",
    response_model=None,
    summary="Get SDN zones",
)
async def get_sdn_zones(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_sdn_zones(ctrl)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to get SDN zones")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/sdn/vnets",
    response_model=None,
    summary="Get SDN vnets",
)
async def get_sdn_vnets(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_sdn_vnets(ctrl)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to get SDN vnets")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/sdn/controllers",
    response_model=None,
    summary="Get SDN controllers",
)
async def get_sdn_controllers(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_sdn_controllers(ctrl)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get SDN controllers"
            )
        # a Proxmox SDN controller of type bgp/evpn carries a `password`
        # (BGP MD5 / TCP-AO neighbor auth secret). Redact before returning to a
        # hypervisor:read (viewer) caller — parity with get_node_certificates (:2284).
        return redact_secrets(result.data) if isinstance(result.data, (dict, list)) else result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/sdn/zones",
    response_model=None,
    summary="Create an SDN zone",
)
async def create_sdn_zone(
    controller_id: UUID,
    body: CreateSdnZoneRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        kwargs = {
            k: v for k, v in body.model_dump(exclude={"zone", "type"}).items() if v is not None
        }
        result = await svc.create_sdn_zone(ctrl, body.zone, body.type, **kwargs)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to create SDN zone")
        return result.data or {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/sdn/vnets",
    response_model=None,
    summary="Create an SDN vnet",
)
async def create_sdn_vnet(
    controller_id: UUID,
    body: CreateSdnVnetRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        kwargs = {
            k: v for k, v in body.model_dump(exclude={"vnet", "zone"}).items() if v is not None
        }
        result = await svc.create_sdn_vnet(ctrl, body.vnet, body.zone, **kwargs)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to create SDN vnet")
        return result.data or {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/sdn/zones/{zone}",
    response_model=None,
    summary="Delete an SDN zone",
)
async def delete_sdn_zone(
    controller_id: UUID,
    zone: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        # SAFETY: check if any vnets depend on this zone before deleting
        vnets_result = await svc.get_sdn_vnets(ctrl)
        if vnets_result.success and isinstance(vnets_result.data, list):
            dependent_vnets = [
                v.get("vnet", v.get("name", "?"))
                for v in vnets_result.data
                if v.get("zone") == zone
            ]
            if dependent_vnets:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot delete zone '{zone}': {len(dependent_vnets)} vnet(s) "
                    f"depend on it ({', '.join(dependent_vnets[:5])}). Delete those first.",
                )
        result = await svc.delete_sdn_zone(ctrl, zone)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to delete SDN zone")
        return {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/sdn/vnets/{vnet}",
    response_model=None,
    summary="Delete an SDN vnet",
)
async def delete_sdn_vnet(
    controller_id: UUID,
    vnet: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.delete_sdn_vnet(ctrl, vnet)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to delete SDN vnet")
        return {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/sdn/apply",
    response_model=None,
    summary="Apply pending SDN configuration",
)
async def apply_sdn(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.apply_sdn(ctrl)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to apply SDN config"
            )
        return {"status": "ok"}
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# GUEST AGENT (EXEC / FILE)
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/agent/exec",
    response_model=None,
    summary="Execute a command via QEMU guest agent",
)
async def agent_exec(
    controller_id: UUID,
    body: AgentExecRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    confirmed: bool = Query(
        False,
        description="Must be true to run the command (arbitrary code execution in "
        "the guest). Submitting the command via the UI sets this; without it the API "
        "returns 409. Still refused while read-only mode is on.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.agent_exec(
            ctrl, node, vmid, body.command, body.input_data, confirmed=confirmed
        )
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Agent exec failed")
        # Guest output flows straight to the FE — whatever the
        # command printed (cat /etc/shadow, env, env | grep PASS)
        # would otherwise be returned verbatim.
        return redact_secrets(result.data)
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/agent/exec-status/{pid}",
    response_model=None,
    summary="Get guest agent exec status",
)
async def agent_exec_status(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    pid: int = Path(..., ge=0),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.agent_exec_status(ctrl, node, vmid, pid)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Agent exec status failed")
        # The exec-status payload carries stdout/stderr from the
        # finished command — redact the same way as agent_exec.
        return redact_secrets(result.data)
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/agent/file-read",
    response_model=None,
    summary="Read a file inside VM via guest agent",
)
async def agent_file_read(
    controller_id: UUID,
    body: AgentFileReadRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.agent_file_read(ctrl, node, vmid, body.file)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Agent file read failed")
        # File contents flow through unredacted otherwise — reading
        # /home/.bash_history, /etc/cloud/cloud.cfg, etc. would
        # surface secrets the guest has on disk.
        return redact_secrets(result.data)
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/agent/file-write",
    response_model=None,
    summary="Write a file inside VM via guest agent",
)
async def agent_file_write(
    controller_id: UUID,
    body: AgentFileWriteRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    confirmed: bool = Query(
        False,
        description="Must be true to write the file (modifies the guest filesystem). "
        "Submitting via the UI sets this; without it the API returns 409. Still "
        "refused while read-only mode is on.",
    ),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.agent_file_write(
            ctrl, node, vmid, body.file, body.content, confirmed=confirmed
        )
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Agent file write failed")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# PENDING CONFIG
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/pending",
    response_model=None,
    summary="Get VM pending configuration changes",
)
async def get_vm_pending_config(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_vm_pending_config(ctrl, node, vmid)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get pending config"
            )
        # Strip sensitive keys from pending config entries
        data = result.data
        if isinstance(data, list):
            data = [
                e
                for e in data
                if not (isinstance(e, dict) and e.get("key") in _SENSITIVE_CONFIG_KEYS)
            ]
        return data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/lxc/{vmid}/pending",
    response_model=None,
    summary="Get container pending configuration changes",
)
async def get_container_pending_config(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_container_pending_config(ctrl, node, vmid)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get pending config"
            )
        # Strip sensitive keys from pending config entries
        data = result.data
        if isinstance(data, list):
            data = [
                e
                for e in data
                if not (isinstance(e, dict) and e.get("key") in _SENSITIVE_CONFIG_KEYS)
            ]
        return data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# CLUSTER EXTRAS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/cluster/options",
    response_model=None,
    summary="Get cluster-wide options",
)
async def get_cluster_options(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_cluster_options(ctrl)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get cluster options"
            )
        # Cluster options can hold notifications API tokens, mail
        # auth, etc. Apply central redact_secrets defense.
        return redact_secrets(result.data) if isinstance(result.data, dict) else result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/cluster/log",
    response_model=None,
    summary="Get cluster log",
)
async def get_cluster_log(
    controller_id: UUID,
    max_entries: int = Query(50, ge=1, le=5000),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_cluster_log(ctrl, max_entries)
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Failed to get cluster log")
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/cluster/config/nodes",
    response_model=None,
    summary="Get cluster corosync config nodes",
)
async def get_cluster_config_nodes(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_cluster_config_nodes(ctrl)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get config nodes"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/cluster/replication",
    response_model=None,
    summary="Get cluster replication jobs",
)
async def get_cluster_replication(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_cluster_replication(ctrl)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get replication jobs"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/cluster/replication/{replication_id}/log",
    response_model=None,
    summary="Get replication job log",
)
async def get_replication_log(
    controller_id: UUID,
    replication_id: str = Path(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._:-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        result = await svc.get_replication_log(ctrl, replication_id)
        if not result.success:
            raise HTTPException(
                status_code=400, detail=result.error or "Failed to get replication log"
            )
        return result.data
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except AdapterError:
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# GUEST FIREWALL (per VM/CT)
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/firewall/rules",
    response_model=None,
    summary="Get guest firewall rules for a VM/CT",
)
async def get_guest_firewall_rules(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: str = Path(..., pattern=r"^(qemu|lxc)$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_guest_firewall_rules(ctrl, node, vm_type, vmid)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/firewall/rules",
    summary="Create a guest firewall rule on a VM/CT",
)
async def create_guest_firewall_rule(
    controller_id: UUID,
    body: CreateGuestFirewallRuleRequest,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: str = Path(..., pattern=r"^(qemu|lxc)$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        rule = {k: v for k, v in body.model_dump().items() if v is not None}
        return await svc.create_guest_firewall_rule(ctrl, node, vm_type, vmid, rule)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/firewall/rules/{pos}",
    summary="Delete a guest firewall rule on a VM/CT",
)
async def delete_guest_firewall_rule(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: str = Path(..., pattern=r"^(qemu|lxc)$"),
    vmid: int = Path(..., ge=100, le=999999999),
    pos: int = Path(..., ge=0),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.delete_guest_firewall_rule(ctrl, node, vm_type, vmid, pos)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/firewall/options",
    response_model=None,
    summary="Get guest firewall options for a VM/CT",
)
async def get_guest_firewall_options(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: str = Path(..., pattern=r"^(qemu|lxc)$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_guest_firewall_options(ctrl, node, vm_type, vmid)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put(
    "/controllers/{controller_id}/nodes/{node}/{vm_type}/{vmid}/firewall/options",
    summary="Update guest firewall options for a VM/CT",
)
async def update_guest_firewall_options(
    controller_id: UUID,
    body: GuestFirewallOptions,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    vm_type: str = Path(..., pattern=r"^(qemu|lxc)$"),
    vmid: int = Path(..., ge=100, le=999999999),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        options = {k: v for k, v in body.model_dump().items() if v is not None}
        if not options:
            raise HTTPException(status_code=400, detail="No options provided")
        svc = HypervisorService(session)
        return await svc.update_guest_firewall_options(ctrl, node, vm_type, vmid, options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get(
    "/controllers/{controller_id}/cluster/firewall/options",
    response_model=None,
    summary="Get cluster firewall options",
)
async def get_cluster_fw_options(
    controller_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_cluster_firewall_options(ctrl)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put(
    "/controllers/{controller_id}/cluster/firewall/options",
    summary="Update cluster firewall options",
)
async def update_cluster_fw_options(
    controller_id: UUID,
    body: ClusterFirewallOptions,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        options = {k: v for k, v in body.model_dump().items() if v is not None}
        if not options:
            raise HTTPException(status_code=400, detail="No options provided")
        svc = HypervisorService(session)
        return await svc.update_cluster_firewall_options(ctrl, options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# FLEET TASK STATISTICS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/fleet/task-statistics",
    response_model=FleetTaskStatistics,
    summary="Get cross-controller task statistics",
)
async def get_fleet_task_statistics(
    site_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    """Aggregate task statistics across all registered Proxmox controllers."""
    stmt = select(Controller).where(
        Controller.controller_type.in_(("proxmox", "pve")),
        Controller.deleted_at.is_(None),
    )
    if site_id:
        stmt = stmt.where(Controller.site_id == site_id)
    # Tenant scoping (canonical helper: org-via-Site + per-user site grant).
    if current_user:
        stmt = stmt.where(tenant_filter(Controller, current_user))
    result = await session.execute(stmt)
    controllers = list(result.scalars().all())

    if not controllers:
        return FleetTaskStatistics()

    try:
        svc = HypervisorService(session)
        return await svc.get_fleet_task_statistics(controllers)
    except Exception as e:
        logger.error("Fleet task statistics error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch fleet task statistics")


# ═══════════════════════════════════════════════════════════════════════════
# CEPH DETAIL
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/ceph/detail",
    response_model=CephDetailResponse,
    summary="Get full Ceph cluster detail",
)
async def get_ceph_detail(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_ceph_detail(ctrl, node)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# NODE SENSORS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/sensors",
    response_model=NodeSensors,
    summary="Get node sensor/temperature data",
)
async def get_node_sensors(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        data = await svc.get_node_sensors(ctrl, node)
        return NodeSensors(**data)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# DISK SMART
# ═══════════════════════════════════════════════════════════════════════════


_RE_DISK = re.compile(r"^/dev/[a-z]+[0-9]*$")


@router.get(
    "/controllers/{controller_id}/nodes/{node}/disks/smart",
    summary="Get SMART health data for a specific disk",
)
async def get_disk_smart(
    controller_id: UUID,
    node: str = Path(..., min_length=1, max_length=63, pattern=r"^[a-zA-Z0-9._-]+$"),
    disk: str = Query(..., description="Disk device path, e.g. /dev/sda"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    _validate_path_param(node, _RE_NODE, "node")
    if not _RE_DISK.match(disk):
        raise HTTPException(status_code=400, detail=f"Invalid disk path: {disk!r}")
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_disk_smart(ctrl, node, disk)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except (AdapterError, HTTPException):
        raise  # app-level handlers map these (read-only->403, conn->502); HTTPExceptions pass through
    except Exception as e:
        logger.error("Hypervisor API error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP AGE REPORT
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/backup/age-report",
    response_model=BackupAgeResponse,
    summary="Get backup age report across all VMs",
)
async def get_backup_age_report(
    controller_id: UUID,
    threshold_hours: int = Query(24, ge=1, le=8760, description="Stale threshold in hours"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    ctrl = await _get_controller(controller_id, session, current_user)
    try:
        svc = HypervisorService(session)
        return await svc.get_backup_age_report(ctrl, threshold_hours)
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.error("Backup age report error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate backup age report")


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP RESTORE
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/controllers/{controller_id}/backup/restore",
    response_model=None,
    summary="Restore a VM or container from a backup archive",
)
async def restore_backup(
    controller_id: UUID,
    body: RestoreBackupRequest = Body(...),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    """Restore a VM or container from a backup archive."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        result = await svc.restore_backup(
            ctrl,
            body.node,
            body.vm_type,
            body.archive,
            body.vmid,
            body.storage,
            body.start_after_restore,
            body.unique_mac,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Failed to restore backup")
        raise HTTPException(status_code=500, detail="Failed to restore backup")


# ═══════════════════════════════════════════════════════════════════════════
# PRUNE BACKUPS
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/storage/{storage}/prune-preview",
    response_model=None,
    summary="Get prune preview for backup storage",
)
async def get_prune_preview(
    controller_id: UUID,
    node: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    storage: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int | None = Query(None, ge=100),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    """Get prune preview showing which backups would be kept/removed."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        return await svc.get_prune_preview(ctrl, node, storage, vmid)
    except Exception:
        logger.exception("Failed to get prune preview")
        raise HTTPException(status_code=500, detail="Failed to get prune preview")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/storage/{storage}/prune",
    response_model=None,
    summary="Execute backup pruning on storage",
)
async def prune_backups(
    controller_id: UUID,
    node: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    storage: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    body: PruneBackupsRequest = Body(...),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    """Execute backup pruning with the specified retention policy."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        return await svc.prune_backups(
            ctrl,
            node,
            storage,
            body.keep_last,
            body.keep_hourly,
            body.keep_daily,
            body.keep_weekly,
            body.keep_monthly,
            body.keep_yearly,
            body.vmid,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Failed to prune backups")
        raise HTTPException(status_code=500, detail="Failed to prune backups")


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDINIT
# ═══════════════════════════════════════════════════════════════════════════


@router.get(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/cloudinit",
    response_model=None,
    summary="Get CloudInit config for a QEMU VM",
)
async def get_cloudinit(
    controller_id: UUID,
    node: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_permissions("hypervisor:read")),
):
    """Get the CloudInit configuration for a QEMU virtual machine."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        cfg = await svc.get_cloudinit_config(ctrl, node, vmid)
        # CloudInit may contain cipassword, sshkeys, ipconfigN with
        # inline credentials. redact_secrets() centralizes the
        # strip-list + handles the ipconfig prefix-match pattern.
        return redact_secrets(cfg) if isinstance(cfg, dict) else cfg
    except Exception:
        logger.exception("Failed to get CloudInit config")
        raise HTTPException(status_code=500, detail="Failed to get CloudInit config")


@router.put(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/cloudinit",
    response_model=None,
    summary="Update CloudInit config for a QEMU VM",
)
async def update_cloudinit(
    controller_id: UUID,
    node: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100),
    body: CloudInitConfig = Body(...),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    """Update CloudInit configuration (ciuser, sshkeys, ipconfig, etc.)."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        config = {k: v for k, v in body.model_dump().items() if v is not None}
        return await svc.update_cloudinit_config(ctrl, node, vmid, config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Failed to update CloudInit config")
        raise HTTPException(status_code=500, detail="Failed to update CloudInit config")


@router.post(
    "/controllers/{controller_id}/nodes/{node}/qemu/{vmid}/cloudinit/regenerate",
    response_model=None,
    summary="Regenerate CloudInit drive",
)
async def regenerate_cloudinit(
    controller_id: UUID,
    node: str = Path(..., pattern=r"^[a-zA-Z0-9._-]+$"),
    vmid: int = Path(..., ge=100),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_min_role("site_admin")),
):
    """Regenerate the CloudInit ISO drive after config changes."""
    try:
        ctrl = await _get_controller(controller_id, session, current_user)
        svc = HypervisorService(session)
        return await svc.regenerate_cloudinit(ctrl, node, vmid)
    except Exception:
        logger.exception("Failed to regenerate CloudInit drive")
        raise HTTPException(status_code=500, detail="Failed to regenerate CloudInit drive")


# ═══════════════════════════════════════════════════════════════════════════
# ALERT HYSTERESIS
# ═══════════════════════════════════════════════════════════════════════════


@router.post(
    "/alerts/evaluate-hysteresis",
    response_model=HysteresisEvaluateResponse,
    summary="Evaluate alert hysteresis state machine",
)
async def evaluate_hysteresis(
    request: HysteresisEvaluateRequest,
    current_user=Depends(require_permissions("hypervisor:read")),
):
    try:
        new_state, should_fire, should_resolve = evaluate_with_hysteresis(
            current_value=request.current_value,
            threshold=request.threshold,
            operator=request.operator,
            state=request.state,
            config=request.config,
        )
        return HysteresisEvaluateResponse(
            state=new_state,
            should_fire=should_fire,
            should_resolve=should_resolve,
        )
    except Exception as e:
        logger.error("Hysteresis evaluation error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to evaluate hysteresis")
