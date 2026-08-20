# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Discovery Endpoints
=================================

Endpoints for:
- Network scanning (subnet scan, port scan, service probing)
- Controller-based discovery (via adapters)
- Fingerprinting
- Driver listing
"""

import asyncio
import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    org_scope_or_platform,
    require_permissions,
)
from app.core.site_access import (
    assert_can_access_site,
    site_ids_for_request,
    site_scope_filter,
)
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models import Controller, Site
from app.schemas import MessageResponse
from app.schemas.discovery import (
    DiscoveredHostSchema,
    DriverDetailsSchema,
    DriverSchema,
    FingerprintRequestSchema,
    FingerprintResultSchema,
    ScanProgressSchema,
    ScanRequestSchema,
    ScanResultsSchema,
    ScanStartedResponse,
)
from app.services.discovery import DiscoveryError, DiscoveryService

logger = logging.getLogger(__name__)


def _task_error_handler(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Background task failed: %s", exc, exc_info=exc)


router = APIRouter()


# ===========================================
# In-Memory Scan Store
# ===========================================
# NOTE: This uses an in-memory dict intentionally. The default deployment is
# single-worker, where in-memory storage is simpler and avoids a hard Redis
# dependency.  For multi-worker deployments behind a load balancer, scan
# requests could land on a different worker than the one running the scan.
# To support that topology, replace this dict with a Redis-backed store
# (e.g. redis HSET keyed by scan_id).  The tradeoff is acceptable for now
# because discovery scans are infrequent, short-lived operations that are
# typically initiated from a single admin session.

import contextlib

from app.services.scanner import (
    DiscoveredHost,
    NetworkScanner,
    ScanConfig,
    ScanMethod,
    ScanProgress,
    ScanStatus,
)

_active_scans: dict[str, dict[str, Any]] = {}
# Strong refs for fire-and-forget event-bus publish tasks: the loop only weakly
# references tasks, so a bare create_task can be GC-killed mid-publish.
_BG_TASKS: set["asyncio.Task[Any]"] = set()
# scan_id -> { "scanner": NetworkScanner, "progress": ScanProgress, "results": list[DiscoveredHost], "task": asyncio.Task }

#: Maximum number of concurrent scans to prevent memory exhaustion
_MAX_ACTIVE_SCANS = 20


def _evict_completed_scans() -> None:
    """Remove completed/failed scans from the in-memory store."""
    to_remove = []
    for scan_id, entry in _active_scans.items():
        task = entry.get("task")
        if task and task.done():
            to_remove.append(scan_id)
    for scan_id in to_remove:
        _active_scans.pop(scan_id, None)


def _scan_visible_to(entry: dict[str, Any], current_user: Any) -> bool:
    """Tenant-isolation check for an in-memory scan entry.

    _active_scans is a process-global pool shared across all tenants;
    each entry is stamped with the owning organization_id at creation.
    A non-superuser may only see scans owned by their own org.
    """
    if is_unscoped_superuser(current_user):
        return True
    owner_org = entry.get("organization_id")
    user_org = str(current_user.organization_id) if current_user.organization_id else None
    return owner_org is not None and owner_org == user_org


# ===========================================
# Network Scan Endpoints
# ===========================================


@router.post("/scan", response_model=ScanStartedResponse)
async def start_scan(
    request: ScanRequestSchema,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Start a network scan.

    Accepts target IPs, CIDRs, or ranges and kicks off an async
    4-phase discovery pipeline (protocol discovery -> port scan ->
    service probing -> hostname resolution).
    """
    # SECURITY: Evict completed scans and enforce max active scan limit
    _evict_completed_scans()
    if len(_active_scans) >= _MAX_ACTIVE_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({_MAX_ACTIVE_SCANS}) reached. "
            "Please wait for existing scans to complete.",
        )

    # SECURITY: defense-in-depth — the pydantic schema already
    # capped CIDR sizes, but reject again here to protect any caller that
    # bypasses the schema or constructs ScanRequestSchema programmatically.
    from app.schemas.discovery import _validate_scan_target

    try:
        for _t in list(request.targets) + list(request.exclude_targets or []):
            _validate_scan_target(_t)
    except ValueError as _e:
        raise HTTPException(status_code=400, detail=str(_e)) from _e

    import asyncio

    # Build ScanConfig from request
    methods = []
    for m in request.scan_methods:
        with contextlib.suppress(ValueError):
            methods.append(ScanMethod(m))
    if not methods:
        methods = [ScanMethod.TCP_CONNECT, ScanMethod.MDNS, ScanMethod.SSDP]

    config = ScanConfig(targets=request.targets, exclude_targets=request.exclude_targets)
    config.methods = methods
    if request.tcp_ports:
        config.tcp_ports = request.tcp_ports
    if request.options:
        config.max_concurrent_hosts = request.options.max_concurrent_hosts
        config.max_concurrent_ports = request.options.max_concurrent_ports
        config.tcp_timeout = request.options.tcp_timeout
        config.probe_services = request.options.probe_services
        config.resolve_hostnames = request.options.resolve_hostnames

    scanner = NetworkScanner(config)

    from app.services.scanner import TargetExpansionLimitError, expand_targets

    # expand_targets fully materializes targets+excludes into a set
    # (bounded by _MAX_EXPAND_HOSTS). Run it off the event loop so even a
    # worst-case bounded expansion can't stall the async worker, and surface the
    # limit as a clean 400 rather than a 500.
    try:
        total = len(await asyncio.to_thread(expand_targets, config.targets, config.exclude_targets))
    except TargetExpansionLimitError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Start scan in background. Stamp the owning org (and user) so the
    # results/progress endpoints can enforce tenant isolation — without
    # this, _active_scans is a global pool any discovery:run user could
    # read another tenant's scan from by ID, and /scans/latest returns
    # whichever scan ran most recently across ALL tenants.
    scan_entry: dict[str, Any] = {
        "scanner": scanner,
        "progress": None,
        "results": [],
        "task": None,
        "organization_id": (
            str(current_user.organization_id) if current_user.organization_id else None
        ),
        "owner_user_id": str(current_user.id),
    }

    async def _run_scan():
        try:
            async for host in scanner.scan(progress_callback=_on_progress):
                scan_entry["results"].append(host)
        except Exception as e:
            logger.error("Scan failed: %s", e)
            if scan_entry.get("progress"):
                scan_entry["progress"].status = ScanStatus.FAILED
                scan_entry["progress"].errors.append(str(e))

    def _on_progress(progress: ScanProgress):
        scan_entry["progress"] = progress
        _active_scans[progress.scan_id] = scan_entry
        # Also try to broadcast via event bus
        try:
            from app.core.events import discovery_event, get_event_bus

            bus = get_event_bus()
            _bg = asyncio.create_task(
                bus.publish(
                    discovery_event(
                        "scan_progress",
                        organization_id=scan_entry.get("organization_id"),
                        scan_id=progress.scan_id,
                        status=progress.status.value
                        if hasattr(progress.status, "value")
                        else str(progress.status),
                        phase=progress.current_phase,
                        progress_pct=progress.progress_pct,
                        discovered=progress.discovered_hosts,
                        total=progress.total_hosts,
                    )
                )
            )
            _BG_TASKS.add(_bg)  # strong ref so it isn't GC-killed mid-publish
            _bg.add_done_callback(_BG_TASKS.discard)
            _bg.add_done_callback(_task_error_handler)
        except Exception:
            pass

    task = asyncio.create_task(_run_scan())
    scan_entry["task"] = task

    # Wait briefly for scan_id to be available (progress callback fires quickly)
    await asyncio.sleep(0.3)

    scan_id = "unknown"
    if scan_entry["progress"]:
        scan_id = scan_entry["progress"].scan_id
    elif scanner.progress:
        scan_id = scanner.progress.scan_id
        scan_entry["progress"] = scanner.progress

    _active_scans[scan_id] = scan_entry

    return ScanStartedResponse(
        scan_id=scan_id,
        status="running",
        total_targets=total,
        message=f"Scan started for {total} targets",
    )


@router.get("/scan/{scan_id}/progress", response_model=ScanProgressSchema)
async def get_scan_progress(
    scan_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Get live progress of an active scan."""
    entry = _active_scans.get(scan_id)
    if not entry or not entry.get("progress") or not _scan_visible_to(entry, current_user):
        raise HTTPException(status_code=404, detail="Scan not found")

    prog = entry["progress"]
    return ScanProgressSchema(
        scan_id=prog.scan_id,
        status=prog.status.value if hasattr(prog.status, "value") else str(prog.status),
        total_hosts=prog.total_hosts,
        scanned_hosts=prog.scanned_hosts,
        discovered_hosts=prog.discovered_hosts,
        current_phase=prog.current_phase,
        phase_progress=prog.phase_progress,
        progress_pct=prog.progress_pct,
        hosts_found=prog.hosts_found,
        errors=prog.errors,
        elapsed_seconds=prog.elapsed_seconds,
        estimated_remaining_seconds=prog.estimated_remaining_seconds,
        started_at=prog.started_at,
    )


@router.get("/scan/{scan_id}/results", response_model=ScanResultsSchema)
async def get_scan_results(
    scan_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Get results of a completed or in-progress scan."""
    entry = _active_scans.get(scan_id)
    if not entry or not _scan_visible_to(entry, current_user):
        raise HTTPException(status_code=404, detail="Scan not found")

    prog = entry.get("progress")
    hosts: list[DiscoveredHost] = entry.get("results", [])

    devices = []
    for h in hosts:
        d = h.to_dict()
        devices.append(
            DiscoveredHostSchema(
                ip_address=d["ip_address"],
                mac_address=d.get("mac_address"),
                hostname=d.get("hostname"),
                vendor=d.get("vendor"),
                vendor_confidence=d.get("vendor_confidence", 0),
                device_type=d.get("device_type"),
                open_ports=d.get("open_ports", []),
                services=d.get("services", {}),
                discovered_via=d.get("discovered_via", []),
                discovered_at=d.get("discovered_at"),
                mdns_services=d.get("mdns_services", []),
                ssdp_info=d.get("ssdp_info"),
                likely_device_types=d.get("likely_device_types", []),
                http_title=d.get("http_title"),
                http_server=d.get("http_server"),
                is_manageable=bool(d.get("likely_device_types")),
            )
        )

    return ScanResultsSchema(
        scan_id=scan_id,
        status=prog.status.value
        if prog and hasattr(prog.status, "value")
        else (str(prog.status) if prog else "unknown"),
        started_at=prog.started_at if prog else None,
        elapsed_seconds=prog.elapsed_seconds if prog else 0,
        total_targets=prog.total_hosts if prog else 0,
        total_discovered=len(devices),
        total_manageable=sum(1 for d in devices if d.is_manageable),
        devices=devices,
        errors=prog.errors if prog else [],
    )


@router.get("/scans/latest/results", response_model=ScanResultsSchema)
async def get_latest_scan_results(
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Get results from the most recent scan."""
    if not _active_scans:
        raise HTTPException(status_code=404, detail="No scans found")

    # Find latest by started_at — but only among scans the caller's org
    # owns, so "latest" never leaks another tenant's most-recent scan.
    latest_id = None
    latest_time = None
    for sid, entry in _active_scans.items():
        if not _scan_visible_to(entry, current_user):
            continue
        prog = entry.get("progress")
        if prog and prog.started_at:
            if latest_time is None or prog.started_at > latest_time:
                latest_time = prog.started_at
                latest_id = sid

    if not latest_id:
        raise HTTPException(status_code=404, detail="No scans found")

    return await get_scan_results(latest_id, current_user)


@router.post("/scan/{scan_id}/cancel", response_model=MessageResponse)
async def cancel_scan(
    scan_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Cancel an active scan."""
    entry = _active_scans.get(scan_id)
    if not entry or not _scan_visible_to(entry, current_user):
        raise HTTPException(status_code=404, detail="Scan not found")

    scanner: NetworkScanner = entry["scanner"]
    scanner.cancel()

    task = entry.get("task")
    if task and not task.done():
        task.cancel()

    return MessageResponse(message=f"Scan {scan_id} cancelled")


@router.delete("/scan/{scan_id}", response_model=MessageResponse)
async def delete_scan(
    scan_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Delete scan results."""
    # Tenant isolation: only the owning org may delete a scan. Mirrors the
    # visibility check in get_scan_results / cancel_scan — without it a caller
    # could pop another org's scan out of the shared in-memory pool (IDOR).
    entry = _active_scans.get(scan_id)
    if not entry or not _scan_visible_to(entry, current_user):
        raise HTTPException(status_code=404, detail="Scan not found")

    _active_scans.pop(scan_id, None)
    task = entry.get("task")
    if task and not task.done():
        task.cancel()

    return MessageResponse(message=f"Scan {scan_id} deleted")


# ===========================================
# Fingerprint Endpoints
# ===========================================


@router.post("/fingerprint", response_model=FingerprintResultSchema)
async def fingerprint_device(
    request: FingerprintRequestSchema,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """
    Fingerprint a specific device by IP.
    Attempts vendor-specific API probes to identify the device.
    """
    import httpx

    ip = request.ip_address
    ports = request.ports
    result = FingerprintResultSchema(ip_address=ip, probes_tried=[], probes_succeeded=[])

    # SECURITY (SSRF-04): resolve+pin the target to a validated IP literal so the
    # MANY follow-up probes on the shared client below cannot DNS-rebind a
    # hostname target to loopback/link-local/metadata between validate-time and
    # request-time. follow_redirects=False is set CLIENT-WIDE (not just on the
    # first GET) so a 3xx Location can't re-introduce the hole on a sub-probe.
    from app.core.security_utils import resolve_and_pin_host

    try:
        ip = resolve_and_pin_host(ip)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e}",
        )

    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
        for port in ports:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{ip}:{port}"
                try:
                    resp = await client.get(f"{url}/", follow_redirects=False)
                    body = resp.text.lower()
                    server = (resp.headers.get("server") or "").lower()

                    # Omada controller probe
                    if "omada" in body or "tplink" in body:
                        result.probes_tried.append("omada")
                        try:
                            info_resp = await client.get(f"{url}/api/v2/info")
                            if info_resp.status_code == 200:
                                data = info_resp.json()
                                result.vendor = "tp-link"
                                result.device_type = "omada_controller"
                                result.model = data.get("result", {}).get("controllerName")
                                result.firmware_version = data.get("result", {}).get(
                                    "controllerVer"
                                )
                                result.probes_succeeded.append("omada")
                                result.confidence = 0.95
                        except Exception:
                            pass

                    # Hikvision ISAPI probe
                    if "hikvision" in body or "hikvision" in server or "davinci" in server:
                        result.probes_tried.append("isapi")
                        try:
                            import re

                            info_resp = await client.get(
                                f"{url}/ISAPI/System/deviceInfo", timeout=3.0
                            )
                            if info_resp.status_code in (200, 401):
                                result.vendor = "hikvision"
                                result.device_type = "camera" if 554 in ports else "nvr"
                                if info_resp.status_code == 200:
                                    text = info_resp.text
                                    model_m = re.search(r"<model>(.*?)</model>", text, re.I)
                                    fw_m = re.search(
                                        r"<firmwareVersion>(.*?)</firmwareVersion>", text, re.I
                                    )
                                    sn_m = re.search(
                                        r"<serialNumber>(.*?)</serialNumber>", text, re.I
                                    )
                                    if model_m:
                                        result.model = model_m.group(1)
                                    if fw_m:
                                        result.firmware_version = fw_m.group(1)
                                    if sn_m:
                                        result.serial_number = sn_m.group(1)
                                    result.probes_succeeded.append("isapi")
                                    result.confidence = 0.95
                                else:
                                    result.confidence = 0.7
                        except Exception:
                            pass

                    # MikroTik RouterOS probe
                    if "mikrotik" in body or "routeros" in body or "webfig" in body:
                        result.probes_tried.append("mikrotik")
                        result.vendor = "mikrotik"
                        result.device_type = "router"
                        result.confidence = 0.8
                        result.probes_succeeded.append("mikrotik")

                    # pfSense probe
                    if "pfsense" in body:
                        result.probes_tried.append("pfsense")
                        result.vendor = "netgate"
                        result.device_type = "firewall"
                        result.confidence = 0.85
                        result.probes_succeeded.append("pfsense")

                    # OPNsense probe
                    if "opnsense" in body:
                        result.probes_tried.append("opnsense")
                        result.vendor = "deciso"
                        result.device_type = "firewall"
                        result.confidence = 0.85
                        result.probes_succeeded.append("opnsense")

                    # Grandstream probe
                    if "grandstream" in body:
                        result.probes_tried.append("grandstream")
                        result.vendor = "grandstream"
                        result.device_type = "voip"
                        result.confidence = 0.8
                        result.probes_succeeded.append("grandstream")

                    # UniFi probe
                    if "unifi" in body or "ubiquiti" in body:
                        result.probes_tried.append("unifi")
                        result.vendor = "ubiquiti"
                        result.device_type = "unifi_controller"
                        result.confidence = 0.85
                        result.probes_succeeded.append("unifi")

                    if result.confidence > 0:
                        break

                except (httpx.ConnectError, httpx.ReadTimeout, Exception):
                    continue

            if result.confidence >= 0.9:
                break

    return result


# ===========================================
# Driver Endpoints
# ===========================================

DRIVER_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "omada_controller",
        "name": "TP-Link Omada Controller",
        "vendor": "tp-link",
        "adapter_type": "omada",
        "device_types": ["omada_controller", "access_point", "switch", "gateway"],
        "version": "1.0.0",
        "description": "TP-Link Omada SDN Controller adapter. Discovers and manages APs, switches, and gateways.",
        "capabilities": ["discovery", "monitoring", "firmware", "configuration", "clients"],
        "supported_models": ["OC200", "OC300", "Software Controller"],
    },
    {
        "id": "hikvision_isapi",
        "name": "Hikvision ISAPI",
        "vendor": "hikvision",
        "adapter_type": "hikvision",
        "device_types": ["camera", "nvr", "dvr"],
        "version": "1.0.0",
        "description": "Hikvision camera/NVR adapter via ISAPI protocol.",
        "capabilities": ["discovery", "monitoring", "firmware", "streams"],
        "supported_models": ["DS-2CD series", "DS-7600 series", "DS-9600 series"],
    },
    {
        "id": "opnsense_api",
        "name": "OPNsense Firewall",
        "vendor": "deciso",
        "adapter_type": "opnsense",
        "device_types": ["firewall", "router", "gateway"],
        "version": "1.0.0",
        "description": "OPNsense firewall adapter via REST API.",
        "capabilities": ["discovery", "monitoring", "firewall_rules", "vpn", "dhcp"],
        "supported_models": ["OPNsense 23.x", "OPNsense 24.x"],
    },
    {
        "id": "pfsense_api",
        "name": "pfSense Firewall",
        "vendor": "netgate",
        "adapter_type": "pfsense",
        "device_types": ["firewall", "router", "gateway"],
        "version": "1.0.0",
        "description": "pfSense firewall adapter via REST API.",
        "capabilities": ["discovery", "monitoring", "firewall_rules", "vpn", "dhcp"],
        "supported_models": ["pfSense CE", "pfSense Plus"],
    },
    {
        "id": "mikrotik_routeros",
        "name": "MikroTik RouterOS",
        "vendor": "mikrotik",
        "adapter_type": "mikrotik",
        "device_types": ["router", "switch", "access_point"],
        "version": "1.0.0",
        "description": "MikroTik RouterOS adapter via REST API.",
        "capabilities": ["discovery", "monitoring", "configuration", "firmware"],
        "supported_models": ["RB series", "CCR series", "CRS series", "hAP series"],
    },
    {
        # Catch-all fallback for adopt-with-auto-match when no vendor adapter
        # fits — IoT sensors, generic desktops, phones without a SIP API.
        # The device is tracked in inventory but has no management plane.
        "id": "generic",
        "name": "Generic Tracked Device",
        "vendor": "generic",
        "adapter_type": "generic",
        "device_types": ["other", "iot_device", "voip_phone", "switch", "router", "camera"],
        "version": "1.0.0",
        "description": "Inventory-only tracking. No management plane.",
        "capabilities": ["inventory"],
        "supported_models": ["*"],
    },
]


@router.get("/drivers", response_model=list[DriverSchema])
async def list_drivers(
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """List all available device drivers."""
    return [DriverSchema(**d) for d in DRIVER_REGISTRY]


@router.get("/drivers/{driver_id}", response_model=DriverDetailsSchema)
async def get_driver_details(
    driver_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """Get details for a specific driver."""
    for d in DRIVER_REGISTRY:
        if d["id"] == driver_id:
            return DriverDetailsSchema(**d)
    raise HTTPException(status_code=404, detail="Driver not found")


# ===========================================
# Controller Discovery Endpoints
# ===========================================


@router.post("/controllers/{controller_id}", response_model=dict[str, Any])
async def discover_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    background_tasks: BackgroundTasks,
    sync: bool = False,
) -> Any:
    """
    Trigger device discovery for a specific controller.

    - **sync**: If True, run synchronously and return results. If False, run in background.
    """
    query = select(Controller).where(
        Controller.id == controller_id, Controller.deleted_at.is_(None)
    )

    if not is_unscoped_superuser(current_user):
        query = query.join(Site).where(Site.organization_id == current_user.organization_id)

    result = await session.execute(query)
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controller not found")

    # Per-user site grant: a site-limited caller must hold the controller's site.
    assert_can_access_site(current_user, controller.site_id, detail="Controller not found")

    discovery_service = DiscoveryService(session)

    if sync:
        try:
            stats = await discovery_service.discover_controller(controller_id)
            return {"status": "completed", "controller_id": str(controller_id), "stats": stats}
        except DiscoveryError as e:
            logger.error("Discovery failed for controller %s: %s", controller_id, e, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Discovery operation failed"
            )
    else:
        # NOTE: do NOT pass the request-scoped `session` — it is closed by the
        # time the background task runs. _run_discovery_task opens its own.
        background_tasks.add_task(
            _run_discovery_task,
            controller_id,
        )
        return {
            "status": "started",
            "controller_id": str(controller_id),
            "message": "Discovery started in background",
        }


@router.post("/sites/{site_id}", response_model=dict[str, Any])
async def discover_site(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    background_tasks: BackgroundTasks,
) -> Any:
    """Trigger device discovery for all controllers in a site."""
    query = select(Site).where(Site.id == site_id, Site.deleted_at.is_(None))

    if not is_unscoped_superuser(current_user):
        query = query.where(Site.organization_id == current_user.organization_id)

    result = await session.execute(query)
    site = result.scalar_one_or_none()

    if not site:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")

    # Per-user site grant: a site-limited caller must hold this site.
    assert_can_access_site(current_user, site.id, detail="Site not found")

    # NOTE: do NOT pass the request-scoped `session` — it is closed by the
    # time the background task runs. _run_site_discovery_task opens its own.
    background_tasks.add_task(
        _run_site_discovery_task,
        site_id,
    )

    return {
        "status": "started",
        "site_id": str(site_id),
        "message": "Discovery started for all controllers in site",
    }


@router.post("/all", response_model=dict[str, Any])
async def discover_all(
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    background_tasks: BackgroundTasks,
) -> Any:
    """Trigger device discovery for all controllers.

    SECURITY: the underlying service used to select EVERY controller
    in the database with no org/site scope, so a non-superuser (or a
    site-limited caller) could open adapter connections against every other
    tenant's controllers and against sibling sites they were never granted.
    Scope the run to the caller's org and — for a site-limited caller — to
    their granted site set. super_admin (no org) runs unscoped as before.
    """
    # only an UNSCOPED super_admin runs the all-tenant maintenance path
    # (org_scope None). A scoped super_admin key (organization_id None) must NOT
    # fall through to it — org_scope_or_platform returns None only for an unscoped
    # super_admin and fails closed (403) for a scoped/no-org caller.
    org_scope = org_scope_or_platform(current_user)
    # Per-user site grant: a site-limited caller only discovers granted sites.
    # site_ids=None means "no per-user restriction" (org_admin / super_admin).
    site_scope = (
        list(current_user.accessible_site_ids or [])
        if getattr(current_user, "is_site_limited", False)
        else None
    )

    # NOTE: do NOT pass the request-scoped `session` — it is closed by the
    # time the background task runs. _run_all_discovery_task opens its own.
    background_tasks.add_task(
        _run_all_discovery_task,
        None,
        org_scope,
        site_scope,
    )

    return {"status": "started", "message": "Discovery started for all controllers"}


# ===========================================
# Device Adoption & Onboarding Endpoints
# ===========================================

from datetime import UTC

from app.models import (
    AgentTask,
    AgentTaskStatus,
    AgentTaskType,
    Credential,
    Device,
    DeviceStatus,
    RemoteAgent,
)


class AdoptDeviceRequest(BaseModel):
    """Request to adopt a discovered device.

    Field caps mirror the DB columns (devices.devices.name VARCHAR(255),
    .ip_address VARCHAR(45), .device_type VARCHAR(50), .driver_id is
    looked up against DRIVER_REGISTRY so a stray 5000-char value is
    pure waste). ``tags`` was unbounded list and bypassed any sane
    storage limit on discovery_data JSONB.
    """

    ip_address: str = Field(..., min_length=1, max_length=45)
    name: str = Field(..., min_length=1, max_length=255)
    site_id: UUID
    # `driver_id` is now optional. When omitted, the server runs the
    # match-driver scorer against the matching DiscoveredHost row (if
    # any) and either picks the best match or falls back to "generic".
    # This is what makes auto-adopt from the agent ergonomic.
    driver_id: str | None = Field(None, max_length=64)
    credential_id: UUID | None = None
    device_type: str = Field(default="other", max_length=50)
    mac_address: str | None = Field(None, max_length=17)
    controller_id: UUID | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)
    auto_provision: bool = False

    @field_validator("tags")
    @classmethod
    def _cap_tags(cls, v: list[str]) -> list[str]:
        for t in v:
            if not isinstance(t, str) or len(t) > 64:
                raise ValueError("each tag must be a string <= 64 chars")
        return v


class AdoptDeviceResponse(BaseModel):
    """Response after adopting a device."""

    device_id: UUID
    name: str
    status: str
    driver_id: str
    message: str


class BulkAdoptRequest(BaseModel):
    """Bulk adopt multiple devices.

    Capped at 100 entries — a 5000-device payload was accepted and
    persisted in one transaction (5000 devices created in the lab
    during the audit; cleaned up immediately). 100 covers realistic
    onboarding batches; larger imports should be split.
    """

    devices: list[AdoptDeviceRequest] = Field(..., min_length=1, max_length=100)


class BulkAdoptResponse(BaseModel):
    """Bulk adoption results."""

    total: int
    succeeded: int
    failed: int
    results: list[dict[str, Any]]


class TestCredentialRequest(BaseModel):
    """Test credentials against a target.

    Caps mirror the credentials endpoint baseline (username <= 512,
    password <= 16384 to cover PEM-key-shaped secrets used by some
    vendors). Without caps a 100 KB password slipped past pydantic
    and reached the httpx auth header.
    """

    ip_address: str = Field(..., min_length=1, max_length=64)
    driver_id: str | None = Field(None, max_length=64)
    credential_id: UUID | None = None
    username: str | None = Field(None, max_length=512)
    password: str | None = Field(None, max_length=16384)
    port: int | None = Field(None, ge=1, le=65535)
    verify_ssl: bool = True


class TestCredentialResponse(BaseModel):
    """Result of credential test."""

    success: bool
    message: str
    device_info: dict[str, Any] | None = None
    capabilities: list[str] = []


class MatchDriverRequest(BaseModel):
    """Request to match drivers for a device.

    fingerprint_data is a free-form JSONB that used to be unbounded —
    a 100 KB payload was happily accepted and walked through the
    driver-scoring loop. Cap entries + per-string value length to
    keep the per-request memory bounded.
    """

    ip_address: str = Field(..., min_length=1, max_length=64)
    mac_address: str | None = Field(None, max_length=17)
    open_ports: list[int] = Field(default_factory=list, max_length=128)
    vendor: str | None = Field(None, max_length=128)
    device_type: str | None = Field(None, max_length=64)
    fingerprint_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("open_ports")
    @classmethod
    def _validate_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"invalid TCP port {p}: must be 1-65535")
        return v

    @field_validator("fingerprint_data")
    @classmethod
    def _cap_fp(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 64:
            raise ValueError("fingerprint_data must contain at most 64 keys")
        for key, val in v.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("fingerprint_data keys must be strings <= 128 chars")
            if isinstance(val, str) and len(val) > 4096:
                raise ValueError(f"fingerprint_data['{key}'] exceeds 4096 chars")
        return v


class MatchDriverResponse(BaseModel):
    """Driver matching result."""

    matches: list[dict[str, Any]]
    recommended_driver: dict[str, Any] | None = None
    is_manageable: bool = False
    suggestions: list[str] = []


class AgentScanRequest(BaseModel):
    """Request agent-based L2/L3 deep scan."""

    agent_id: UUID
    targets: list[str] = Field(..., min_length=1, max_length=256)
    scan_type: str = "full"  # full, arp, icmp, l2_discovery

    @field_validator("targets")
    @classmethod
    def _validate_agent_targets(cls, values: list[str]) -> list[str]:
        """Cap CIDR sizes to protect agents from OOM."""
        from app.schemas.discovery import _validate_scan_target

        return [_validate_scan_target(v) for v in values]


class AgentScanResponse(BaseModel):
    """Response for agent scan request."""

    task_id: UUID
    agent_id: UUID
    status: str
    message: str


def _can_access_referenced_site(current_user, site_id) -> bool:
    """Per-user site-grant check for a referenced row's ``site_id``.

    Returns True (no-op) for a NULL site_id (org-level resource) and for any
    caller object that does not expose ``can_access_site`` (e.g. a minimal
    system/test principal) — the org-scope check upstream still applies.
    Mirrors ``assert_can_access_site`` semantics but returns a bool so the
    boolean reference-helpers below can short-circuit cleanly.
    """
    if site_id is None:
        return True
    check = getattr(current_user, "can_access_site", None)
    if check is None:
        return True
    return bool(check(site_id))


async def _credential_in_org(session, credential_id, current_user) -> bool:
    """True if the credential exists and belongs to the caller's org.

    SECURITY: also enforces the per-user site grant on the
    credential's ``site_id``. A site-limited caller granted Site A could
    otherwise attach a SITE-SCOPED credential belonging to sibling Site B
    (same org) to a device they adopt. A NULL site_id (org-level credential)
    is intentionally allowed — the grant check is a no-op for it.
    """
    if credential_id is None:
        return True
    q = select(Credential.id, Credential.site_id).where(
        Credential.id == credential_id,
        Credential.deleted_at.is_(None),
    )
    if not is_unscoped_superuser(current_user):
        if current_user.organization_id is None:
            return False
        q = q.where(Credential.organization_id == current_user.organization_id)
    row = (await session.execute(q)).first()
    if row is None:
        return False
    # Per-user site grant: block a site-scoped sibling-site credential.
    return _can_access_referenced_site(current_user, row.site_id)


async def _controller_in_org(session, controller_id, current_user) -> bool:
    """True if the controller exists and belongs to the caller's org
    (resolved via its Site).

    SECURITY: also enforces the per-user site grant on the
    controller's ``site_id`` (NOT NULL on Controller). A site-limited caller
    granted Site A could otherwise attach sibling Site B's controller to a
    device they adopt — a cross-site reference. ``can_access_site`` is a
    no-op for super_admin / org_admin / grant-less callers.
    """
    if controller_id is None:
        return True
    q = (
        select(Controller.id, Controller.site_id)
        .join(Site, Controller.site_id == Site.id)
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    if not is_unscoped_superuser(current_user):
        if current_user.organization_id is None:
            return False
        q = q.where(Site.organization_id == current_user.organization_id)
    row = (await session.execute(q)).first()
    if row is None:
        return False
    # Per-user site grant: block a sibling-site controller reference.
    return _can_access_referenced_site(current_user, row.site_id)


async def _site_in_org(session, site_id, current_user) -> bool:
    """True if the site exists and belongs to the caller's org."""
    q = select(Site.id).where(Site.id == site_id, Site.deleted_at.is_(None))
    if not is_unscoped_superuser(current_user):
        if current_user.organization_id is None:
            return False
        q = q.where(Site.organization_id == current_user.organization_id)
    return (await session.execute(q)).scalar_one_or_none() is not None


@router.post("/adopt", response_model=AdoptDeviceResponse)
async def adopt_device(
    request: AdoptDeviceRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Adopt a discovered device into the inventory.

    Creates a Device record with ADOPTING status and optionally
    starts background provisioning.
    """
    from datetime import datetime

    from app.models.devices import DiscoveredHost

    # Verify site exists
    site_query = select(Site).where(Site.id == request.site_id, Site.deleted_at.is_(None))
    if not is_unscoped_superuser(current_user):
        site_query = site_query.where(Site.organization_id == current_user.organization_id)
    site_result = await session.execute(site_query)
    site = site_result.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")

    # Per-user site grant: a site-limited caller must hold the target site.
    assert_can_access_site(current_user, site.id, detail="Site not found")

    # Look up the matching DiscoveredHost (by mac primary, ip fallback).
    # We use it for two things:
    #   - feeding open_ports/vendor into the auto-driver-match
    #   - marking is_adopted=True after the device is created
    dh_q = select(DiscoveredHost).where(
        DiscoveredHost.site_id == request.site_id,
        DiscoveredHost.deleted_at.is_(None),
        DiscoveredHost.is_adopted.is_(False),
    )
    if request.mac_address:
        dh_q = dh_q.where(DiscoveredHost.mac_address == request.mac_address)
    else:
        dh_q = dh_q.where(DiscoveredHost.ip_address == request.ip_address)
    # Row-level lock (FOR UPDATE) so two concurrent adopts of the SAME discovered
    # host serialize: the second waits, then re-reads is_adopted=True and finds no
    # matching row — instead of both reading the row, both creating a Device
    # (different MACs slip past uq_devices_mac_alive), and the second silently
    # overwriting the first's adopted_device_id back-reference.
    discovered_host = (await session.execute(dh_q.limit(1).with_for_update())).scalar_one_or_none()

    # Resolve driver_id — auto-pick if not provided.
    if not request.driver_id:
        request.driver_id = _auto_pick_driver(
            vendor=discovered_host.vendor if discovered_host else None,
            device_type=request.device_type,
            open_ports=list(discovered_host.open_ports or []) if discovered_host else [],
            fingerprint_data={
                "vendor": discovered_host.vendor if discovered_host else None,
                "hostname": discovered_host.hostname if discovered_host else None,
            },
        )

    # Verify driver exists
    driver = next((d for d in DRIVER_REGISTRY if d["id"] == request.driver_id), None)
    if not driver:
        raise HTTPException(status_code=400, detail=f"Unknown driver: {request.driver_id}")

    # Verify credential + controller are org-scoped (prevent attaching
    # another tenant's credential/controller to your device).
    if not await _credential_in_org(session, request.credential_id, current_user):
        raise HTTPException(status_code=404, detail="Credential not found")
    if not await _controller_in_org(session, request.controller_id, current_user):
        raise HTTPException(status_code=404, detail="Controller not found")

    # Check for existing device with same IP in site
    existing_q = select(Device).where(
        Device.site_id == request.site_id,
        Device.ip_address == request.ip_address,
        Device.deleted_at.is_(None),
    )
    existing_result = await session.execute(existing_q)
    existing = existing_result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Device with IP {request.ip_address} already exists in this site",
        )

    # Atomic tier-quota check (SELECT FOR UPDATE on org row, close TOCTOU).
    from app.services.organization import OrganizationService

    org_svc = OrganizationService(session)
    await org_svc._check_quota(site.organization_id, "devices")

    # Create device
    device = Device(
        name=request.name,
        ip_address=request.ip_address,
        mac_address=request.mac_address,
        device_type=request.device_type,
        site_id=request.site_id,
        controller_id=request.controller_id,
        driver_id=request.driver_id,
        credential_id=request.credential_id,
        status=DeviceStatus.ADOPTING,
        is_adopted=True,
        adopted_at=datetime.now(UTC),
        adopted_by=current_user.id,
        manufacturer=driver.get("vendor"),
        discovery_method="manual_adopt",
        discovery_data={"tags": request.tags},
    )
    session.add(device)
    # The existence check above (site_id + ip_address) is read-then-write and
    # races with a concurrent adopt of the same device. The DB backstop is the
    # partial-unique ``uq_devices_mac_alive`` index (one ALIVE device per real
    # MAC), so a same-MAC race that slips past the SELECT collides at flush. Map
    # that to a clean 409 instead of leaking an opaque 500 / IntegrityError.
    from sqlalchemy.exc import IntegrityError

    try:
        await session.flush()  # get device.id without final commit yet
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Device with IP {request.ip_address} already exists in this site",
        )

    # Close the loop: mark the discovered_host as adopted so it disappears
    # from the queue. Without this the list_discovered_hosts endpoint
    # (which defaults show_adopted=False) keeps returning the same row
    # forever.
    if discovered_host is not None:
        discovered_host.is_adopted = True
        discovered_host.adopted_device_id = device.id
        discovered_host.adopted_at = datetime.now(UTC)

    await session.commit()
    await session.refresh(device)

    # Emit event
    # NOTE: EventBus.publish() takes a single Event dataclass — passing
    # (event_type, payload_dict) silently TypeError'd inside the
    # try/except and adopters never saw a real-time WebSocket update.
    try:
        from app.core.events import Event, EventCategory, get_event_bus

        await get_event_bus().publish(
            Event(
                event_type="device.adopted",
                category=EventCategory.DEVICE,
                payload={
                    "device_id": str(device.id),
                    "name": device.name,
                    "ip_address": device.ip_address,
                    "driver_id": request.driver_id,
                },
                organization_id=(
                    str(current_user.organization_id) if current_user.organization_id else None
                ),
            )
        )
    except Exception:
        logger.exception("Failed to publish device.adopted event")

    return AdoptDeviceResponse(
        device_id=device.id,
        name=device.name,
        status="adopting",
        driver_id=request.driver_id,
        message=f"Device '{device.name}' adopted successfully",
    )


@router.post("/adopt/bulk", response_model=BulkAdoptResponse)
async def bulk_adopt_devices(
    request: BulkAdoptRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Adopt multiple devices at once."""
    from datetime import datetime

    from app.models.devices import DiscoveredHost

    # Atomic tier-quota check for the full batch. Counts existing devices
    # in the caller's org and adds ``len(request.devices)`` — if the caller
    # is super_admin without an org we skip (no org to rate-limit against).
    if current_user.organization_id is not None:
        from app.services.organization import OrganizationService

        org_svc = OrganizationService(session)
        await org_svc._check_quota(
            current_user.organization_id,
            "devices",
            increment=len(request.devices),
        )

    results = []
    succeeded = 0
    failed = 0

    for device_req in request.devices:
        try:
            # Per-item tenant checks — the batch endpoint must validate
            # EVERY referenced ID, not just rely on a blanket org filter.
            # Without this, a caller could adopt into another tenant's
            # site or attach a foreign credential/controller by ID.
            if not await _site_in_org(session, device_req.site_id, current_user):
                raise ValueError("Site not found")
            # Per-user site grant: a site-limited caller must hold each target site.
            assert_can_access_site(current_user, device_req.site_id, detail="Site not found")
            if not await _credential_in_org(session, device_req.credential_id, current_user):
                raise ValueError("Credential not found")
            if not await _controller_in_org(session, device_req.controller_id, current_user):
                raise ValueError("Controller not found")

            # Look up matching DiscoveredHost (used for both auto-match
            # and is_adopted bookkeeping).
            dh_q = select(DiscoveredHost).where(
                DiscoveredHost.site_id == device_req.site_id,
                DiscoveredHost.deleted_at.is_(None),
                DiscoveredHost.is_adopted.is_(False),
            )
            if device_req.mac_address:
                dh_q = dh_q.where(DiscoveredHost.mac_address == device_req.mac_address)
            else:
                dh_q = dh_q.where(DiscoveredHost.ip_address == device_req.ip_address)
            # Row-level lock (FOR UPDATE): serialize concurrent adopts of the same
            # discovered host so only one wins (see adopt_device above).
            discovered_host = (
                await session.execute(dh_q.limit(1).with_for_update())
            ).scalar_one_or_none()

            # Auto-pick driver if not provided
            if not device_req.driver_id:
                device_req.driver_id = _auto_pick_driver(
                    vendor=discovered_host.vendor if discovered_host else None,
                    device_type=device_req.device_type,
                    open_ports=(list(discovered_host.open_ports or []) if discovered_host else []),
                    fingerprint_data={
                        "vendor": discovered_host.vendor if discovered_host else None,
                        "hostname": discovered_host.hostname if discovered_host else None,
                    },
                )

            # Verify driver
            driver = next((d for d in DRIVER_REGISTRY if d["id"] == device_req.driver_id), None)
            if not driver:
                raise ValueError(f"Unknown driver: {device_req.driver_id}")

            # Check for existing
            existing_q = select(Device).where(
                Device.site_id == device_req.site_id,
                Device.ip_address == device_req.ip_address,
                Device.deleted_at.is_(None),
            )
            existing_result = await session.execute(existing_q)
            if existing_result.scalar_one_or_none():
                raise ValueError(f"Device already exists: {device_req.ip_address}")

            # Status on adopt depends on whether anything will drive the
            # device to ONLINE. A controller-backed device goes through
            # ADOPTING while the controller-sync task validates it. A
            # standalone agent-discovered device (no controller) has no
            # handshake to wait on — agent re-observation is its liveness
            # signal — so it lands ONLINE immediately with last_seen set.
            # Otherwise it would hang in ADOPTING forever.
            now = datetime.now(UTC)
            is_standalone = device_req.controller_id is None
            device = Device(
                name=device_req.name,
                ip_address=device_req.ip_address,
                mac_address=device_req.mac_address,
                device_type=device_req.device_type,
                site_id=device_req.site_id,
                controller_id=device_req.controller_id,
                driver_id=device_req.driver_id,
                credential_id=device_req.credential_id,
                status=DeviceStatus.ONLINE if is_standalone else DeviceStatus.ADOPTING,
                last_seen=now if is_standalone else None,
                is_adopted=True,
                adopted_at=now,
                adopted_by=current_user.id,
                manufacturer=driver.get("vendor"),
                discovery_method="bulk_adopt",
            )
            session.add(device)
            await session.flush()

            # Close the loop on the discovered_host row
            if discovered_host is not None:
                discovered_host.is_adopted = True
                discovered_host.adopted_device_id = device.id
                discovered_host.adopted_at = datetime.now(UTC)

            succeeded += 1
            results.append(
                {
                    "ip_address": device_req.ip_address,
                    "status": "adopted",
                    "name": device_req.name,
                    "driver_id": device_req.driver_id,
                    "device_id": str(device.id),
                }
            )

        except Exception as e:
            failed += 1
            results.append(
                {
                    "ip_address": device_req.ip_address,
                    "status": "failed",
                    "error": str(e),
                }
            )

    await session.commit()

    return BulkAdoptResponse(
        total=len(request.devices),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )


@router.post("/test-credentials", response_model=TestCredentialResponse)
async def test_credentials(
    request: TestCredentialRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Test credentials against a target device.

    Can use either stored credentials (by credential_id) or
    inline username/password.
    """
    import httpx

    username = request.username
    password = request.password

    # Resolve stored credential — MUST be org-scoped. Without this, a
    # caller could pass another tenant's credential_id together with an
    # ip_address they control and have the server decrypt that tenant's
    # secret and send it to the attacker's target (cross-tenant
    # credential exfiltration). Scope the lookup to the caller's org
    # (superuser may use any) exactly like the credentials CRUD does.
    if request.credential_id:
        cred_q = select(Credential).where(
            Credential.id == request.credential_id,
            Credential.deleted_at.is_(None),
        )
        if not is_unscoped_superuser(current_user):
            if current_user.organization_id is None:
                raise HTTPException(status_code=404, detail="Credential not found")
            cred_q = cred_q.where(Credential.organization_id == current_user.organization_id)
        cred_result = await session.execute(cred_q)
        cred = cred_result.scalar_one_or_none()
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        # Per-user site grant: a site-limited caller must not be able
        # to decrypt-and-exfiltrate a SITE-SCOPED credential belonging to a
        # sibling site (same org). NULL site_id (org-level credential) is a
        # no-op via assert_can_access_site's None short-circuit.
        assert_can_access_site(current_user, cred.site_id, detail="Credential not found")
        username = cred.username
        password = cred.encrypted_password or ""
        if password and is_encrypted(password):
            password = decrypt_credential(password)

    if not username:
        raise HTTPException(
            status_code=400, detail="Username is required (inline or via credential_id)"
        )

    target = request.ip_address
    port = request.port or 443

    # SECURITY: Validate target IP to prevent SSRF against loopback/metadata
    from app.core.security_utils import safe_http_request, validate_target_host

    try:
        validate_target_host(target)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e}",
        )

    # a STORED credential's decrypted plaintext must NOT egress to a
    # caller-chosen PUBLIC host (low-priv credential exfiltration — the direct
    # sibling of the firewall saved-gateway test fix). For the stored-credential
    # branch, pin to the validated IP and require it be private/on-prem; testing
    # an arbitrary public host requires the caller to supply INLINE credentials
    # (no stored secret is exposed in that case).
    if request.credential_id:
        # (residual hardening): testing a stored credential necessarily
        # sends its plaintext somewhere, so make every such test DETECTABLE — log
        # the actor + credential + requested destination (a public-host attempt is
        # rejected below, but the attempt is still recorded for monitoring).
        logger.warning(
            "AUDIT stored-credential test: actor=%s credential_id=%s requested_target=%s",
            getattr(current_user, "id", None),
            request.credential_id,
            request.ip_address,
        )
        from app.core.security_utils import is_private_ip, resolve_and_pin_host

        try:
            target = resolve_and_pin_host(target, allow_private=True)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid target: {e}"
            )
        if not is_private_ip(target):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "A stored credential may only be tested against a private/on-prem "
                    "address; supply inline username/password to test a public host."
                ),
            )

    try:
        device_info = {}
        for scheme in ["https", "http"]:
            verify_ssl = request.verify_ssl if scheme == "https" else True
            try:
                url = f"{scheme}://{target}:{port}"
                # SSRF-04: route through the IP-pinned safe_http_request. A bare
                # HOSTNAME target validated above is re-resolved by raw httpx at
                # request time, so a low-TTL attacker DNS record (public at
                # validate-time, 127.0.0.1/169.254.169.254 at request-time) would
                # bounce this authenticated probe to internal/metadata hosts.
                # safe_http_request resolves ONCE, validates every IP, pins the
                # connection to it, and sets Host for SNI/vhost. follow_redirects
                # stays False (a 3xx Location would re-introduce the same hole).
                #
                # Discovery targets are almost always private-LAN
                # devices (10/8, 172.16/12, 192.168/16). validate_target_host above
                # already accepted the target after blocking loopback, link-local,
                # and metadata addresses (which safe_http_request ALSO enforces via
                # _NEVER_BYPASSABLE_PROPERTIES regardless of allow_hosts). Passing
                # allow_hosts lets the transport layer honour that decision instead
                # of silently blocking every RFC-1918 target. The stored-credential
                # path (credential_id branch) uses the same target variable so both
                # paths receive identical transport treatment.
                resp = await safe_http_request(
                    "GET",
                    f"{url}/",
                    verify_tls=verify_ssl,
                    follow_redirects=False,
                    timeout=10,
                    allow_hosts=frozenset({target}),
                    auth=(username, password) if password else None,
                )
                device_info["status_code"] = resp.status_code
                device_info["server"] = resp.headers.get("server", "")
                device_info["url"] = url
                if scheme == "https":
                    device_info["verify_ssl"] = request.verify_ssl

                if resp.status_code < 400:
                    return TestCredentialResponse(
                        success=True,
                        message=f"Authentication successful via {scheme.upper()}",
                        device_info=device_info,
                        capabilities=["monitoring"],
                    )
                elif resp.status_code == 401:
                    return TestCredentialResponse(
                        success=False,
                        message="Authentication failed (401 Unauthorized)",
                        device_info=device_info,
                    )
            except (httpx.ConnectError, httpx.ReadTimeout, ValueError):
                # ValueError = safe_http_request rejected a DNS-rebind to a
                # blocked IP; treat like an unreachable target (no SSRF bounce).
                continue

        return TestCredentialResponse(
            success=False,
            message="Could not connect to target device",
        )

    except Exception as e:
        # Strip URL fragments from httpx exceptions before surfacing —
        # raw str(e) often includes the full target URL plus auth bits.
        # Same redaction pattern used by controllers.py.
        import re as _re

        safe_msg = _re.sub(r"https?://\S+", "<redacted-url>", str(e))[:200]
        logger.warning("test_credentials failed: %s", e, exc_info=True)
        return TestCredentialResponse(
            success=False,
            message=f"Connection failed: {safe_msg}" if safe_msg else "Connection failed",
        )


_DRIVER_PORT_HINTS: dict[str, set[int]] = {
    "omada_controller": {8043, 8088, 443, 80},
    "hikvision_isapi": {80, 443, 554, 8000},
    "opnsense_api": {443, 80},
    "pfsense_api": {443, 80},
    "mikrotik_routeros": {8728, 8729, 80, 443},
}


def _score_drivers(
    *,
    vendor: str | None,
    device_type: str | None,
    open_ports: list[int] | None,
    fingerprint_data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Score all DRIVER_REGISTRY entries against a host's fingerprint.

    Shared by /match-drivers (operator workflow) and the auto-match
    fallback inside /adopt and /adopt/bulk. The `generic` driver is
    intentionally excluded — it's a fallback the caller picks, not a
    "match" the scorer should recommend.
    """
    fp_vendor = (fingerprint_data or {}).get("vendor")
    matches: list[dict[str, Any]] = []
    for driver in DRIVER_REGISTRY:
        if driver["id"] == "generic":
            continue
        score = 0.0
        reasons: list[str] = []
        if vendor:
            vendor_lower = vendor.lower()
            driver_vendor = driver["vendor"].lower()
            if vendor_lower == driver_vendor or vendor_lower in driver_vendor:
                score += 0.4
                reasons.append(f"Vendor match: {vendor}")
        if device_type and device_type in driver["device_types"]:
            score += 0.3
            reasons.append(f"Device type match: {device_type}")
        expected_ports = _DRIVER_PORT_HINTS.get(driver["id"], set())
        if open_ports and expected_ports:
            overlap = set(open_ports) & expected_ports
            if overlap:
                port_score = len(overlap) / len(expected_ports)
                score += 0.2 * port_score
                reasons.append(f"Port match: {sorted(overlap)}")
        if fp_vendor and fp_vendor.lower() == driver["vendor"].lower():
            score += 0.1
            reasons.append("Fingerprint vendor confirmed")
        if score > 0.1:
            matches.append(
                {
                    "driver_id": driver["id"],
                    "driver_name": driver["name"],
                    "vendor": driver["vendor"],
                    "match_score": round(min(score, 1.0), 2),
                    "match_reasons": reasons,
                    "warnings": [],
                    "capabilities": driver.get("capabilities", []),
                    "device_types": driver["device_types"],
                }
            )
    matches.sort(key=lambda m: m["match_score"], reverse=True)
    return matches


def _auto_pick_driver(
    *,
    vendor: str | None,
    device_type: str | None,
    open_ports: list[int] | None,
    fingerprint_data: dict[str, Any] | None,
    min_score: float = 0.5,
) -> str:
    """Return the best driver_id for a host, or "generic" if no confident match.

    Used by /adopt and /adopt/bulk when caller omits driver_id.
    `min_score=0.5` is the same threshold /match-drivers uses for
    `is_manageable=True` — anything below that is "we don't really know,
    track as inventory".
    """
    matches = _score_drivers(
        vendor=vendor,
        device_type=device_type,
        open_ports=open_ports,
        fingerprint_data=fingerprint_data,
    )
    if matches and matches[0]["match_score"] >= min_score:
        return matches[0]["driver_id"]
    return "generic"


@router.post("/match-drivers", response_model=MatchDriverResponse)
async def match_drivers(
    request: MatchDriverRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
) -> Any:
    """
    Match available drivers against device characteristics.

    Uses port signatures, vendor info, and fingerprint data to
    rank the best matching drivers.
    """
    matches = _score_drivers(
        vendor=request.vendor,
        device_type=request.device_type,
        open_ports=request.open_ports,
        fingerprint_data=request.fingerprint_data,
    )

    recommended = matches[0] if matches else None
    is_manageable = bool(recommended and recommended["match_score"] >= 0.5)

    suggestions = []
    if not matches:
        suggestions.append("No matching drivers found. The device may not be supported yet.")
    elif not is_manageable:
        suggestions.append("Low confidence match. Consider fingerprinting the device first.")

    return MatchDriverResponse(
        matches=matches,
        recommended_driver=recommended,
        is_manageable=is_manageable,
        suggestions=suggestions,
    )


# ===========================================
# Agent-Based Discovery Endpoints
# ===========================================


@router.post("/agent-scan", response_model=AgentScanResponse)
async def start_agent_scan(
    request: AgentScanRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Dispatch a network scan task to a remote agent.

    The agent performs L2/L3 OS-level discovery (ARP, ICMP,
    mDNS, SSDP, SNMP) from the local network segment.
    Results are posted back via the agent task API.
    """
    # Verify agent exists, is not deleted, and belongs to the caller's org.
    # without the org constraint a caller could dispatch tasks into
    # another tenant's agent queue (cross-tenant write).
    agent_q = select(RemoteAgent).where(
        RemoteAgent.id == request.agent_id,
        RemoteAgent.deleted_at.is_(None),
        RemoteAgent.organization_id == current_user.organization_id,
    )
    agent_result = await session.execute(agent_q)
    agent = agent_result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # (cont.): also enforce per-user site grants for site-limited callers.
    from app.core.site_access import assert_can_access_site

    assert_can_access_site(current_user, agent.site_id, detail="Agent not found")

    if agent.status != "online":
        raise HTTPException(status_code=400, detail=f"Agent is {agent.status}, must be online")

    # The agent's live WebSocket is the only way work reaches it.
    #
    # This endpoint used to INSERT the AgentTask row below and stop there,
    # returning "Scan task dispatched to agent 'X'" and publishing
    # ``discovery.agent_scan_started``. Nothing dispatched anything. The only
    # consumer of a PENDING AgentTask row is ``GET /agents/{id}/tasks/pending``,
    # documented as "called by the agent process to poll for work" -- and the
    # shipped agent never calls it. It wires ``ws_client.on_command`` straight
    # to its TaskExecutor and receives work exclusively over the socket
    # (agent/src/freesdn_agent/daemon/main.py:114). There is no poller.
    #
    # So the row sat at PENDING forever, the Discovery page showed its "scan
    # started" toast, and its status poll returned "pending" until the operator
    # gave up. ``POST /agents/{id}/scan`` next door has always done this
    # correctly; this one was written against a polling model that was never
    # built.
    from datetime import datetime as _dt

    from app.api.v1.endpoints.agents import get_agent_registry
    from app.services.remote_agent import AgentCommand, AgentCommandType

    registry = await get_agent_registry(session)
    connection = registry.get_connection_for_site(agent.site_id)
    if connection is None or connection.info.agent_id != str(agent.id):
        raise HTTPException(
            status_code=409,
            detail=f"Agent has no active WebSocket connection (DB status: {agent.status})",
        )

    # Create agent task — the tracking record the UI polls, not the delivery
    # mechanism.
    task = AgentTask(
        agent_id=agent.id,
        task_type=AgentTaskType.SCAN_NETWORK,
        task_data={
            "targets": request.targets,
            "scan_type": request.scan_type,
            "requested_by": str(current_user.id),
        },
        priority=3,  # Higher priority for discovery
        status=AgentTaskStatus.PENDING,
    )
    session.add(task)
    await session.commit()
    await session.refresh(task)

    # Mark running before the push, so the UI never shows "pending" against a
    # command already on the wire.
    task.status = AgentTaskStatus.RUNNING
    task.started_at = _dt.now(UTC)
    await session.commit()

    registry.register_interactive_task(str(task.id))
    try:
        await connection.send_command(
            AgentCommand(
                id=str(task.id),
                type=AgentCommandType.SCAN_NETWORK,
                payload={"scan_type": request.scan_type, "targets": request.targets},
                priority=3,
                timeout_seconds=300.0,
            ),
            wait_result=False,
        )
    except Exception as exc:
        registry.unregister_interactive_task(str(task.id))
        task.status = AgentTaskStatus.FAILED
        task.error_message = f"Dispatch failed: {exc}"
        task.completed_at = _dt.now(UTC)
        await session.commit()
        logger.exception("Agent scan dispatch failed for agent %s", agent.id)
        raise HTTPException(
            status_code=409,
            detail="Agent disconnected before the scan could be dispatched",
        ) from exc

    # Emit event for WebSocket notification
    # NOTE: see comment on the device.adopted publish above — publish()
    # takes an Event dataclass, not (str, dict).
    try:
        from app.core.events import Event, EventCategory, get_event_bus

        await get_event_bus().publish(
            Event(
                event_type="discovery.agent_scan_started",
                category=EventCategory.SYSTEM,
                payload={
                    "task_id": str(task.id),
                    "agent_id": str(agent.id),
                    "agent_name": agent.name,
                    "targets": request.targets,
                },
                organization_id=(
                    str(current_user.organization_id) if current_user.organization_id else None
                ),
            )
        )
    except Exception:
        logger.exception("Failed to publish discovery.agent_scan_started event")

    return AgentScanResponse(
        task_id=task.id,
        agent_id=agent.id,
        status="running",
        message=f"Scan dispatched to agent '{agent.name}'",
    )


@router.get("/agent-scan/{task_id}", response_model=dict[str, Any])
async def get_agent_scan_status(
    task_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get the status and results of an agent scan task."""
    task_q = select(AgentTask).options(selectinload(AgentTask.agent)).where(AgentTask.id == task_id)
    task_result = await session.execute(task_q)
    task = task_result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if not is_unscoped_superuser(current_user) and (
        not task.agent or task.agent.organization_id != current_user.organization_id
    ):
        raise HTTPException(status_code=404, detail="Task not found")

    # Per-user site grant: the companion write path (start_agent_scan)
    # asserts the agent's site, but this read-by-id did not — a site-limited
    # caller could read the status/results of a scan dispatched to an agent in
    # a sibling site. No-op for super_admin / org_admin / grant-less callers.
    if task.agent is not None:
        assert_can_access_site(current_user, task.agent.site_id, detail="Task not found")

    return {
        "task_id": str(task.id),
        "agent_id": str(task.agent_id),
        "status": task.status,
        "progress": task.progress,
        "result": task.result,
        "error_message": task.error_message,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }


# ===========================================
# Scan History
# ===========================================


@router.get("/scans/history", response_model=list[dict[str, Any]])
async def list_scan_history(
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    limit: int = Query(default=20, le=100),
) -> Any:
    """Get recent scan history."""

    def _started_sort_key(item: tuple[str, dict[str, Any]]) -> str:
        # started_at is not a top-level scan_entry key; it lives on the
        # ScanProgress. Sort most-recent-first, oldest/pending last.
        prog = item[1].get("progress")
        return prog.started_at.isoformat() if prog and prog.started_at else ""

    # Tenant isolation: _active_scans is a process-global pool shared across
    # all orgs. Sibling scan endpoints gate on _scan_visible_to; this list did
    # not, leaking other tenants' scan ids/targets/status. Filter BEFORE the
    # limit slice so the cap counts only scans the caller may see.
    visible = [(sid, sd) for sid, sd in _active_scans.items() if _scan_visible_to(sd, current_user)]
    history = []
    for scan_id, scan_data in sorted(
        visible,
        key=_started_sort_key,
        reverse=True,
    )[:limit]:
        progress: ScanProgress = scan_data.get("progress")
        results: list[DiscoveredHost] = scan_data.get("results", [])
        # `started_at` / `targets` are NOT top-level keys on scan_entry — they
        # live on the ScanProgress and the scanner's ScanConfig respectively.
        # Reading scan_data.get("started_at"/"targets") always returned
        # None/[] so the FE rendered empty timestamp + target cells.
        started_at = progress.started_at.isoformat() if progress and progress.started_at else None
        scanner = scan_data.get("scanner")
        targets = list(scanner.config.targets) if scanner and scanner.config else []
        history.append(
            {
                "scan_id": scan_id,
                "status": progress.status.value if progress else "unknown",
                "started_at": started_at,
                "targets": targets,
                "total_discovered": len(results),
                "progress": progress.progress_pct if progress else 0,
            }
        )
    return history


# ===========================================
# Discovered Hosts — Agent ingestion + list
# ===========================================
#
# Storage backing for what the agent finds on the network before
# adoption. The audit (commit message) found three broken paths:
#
#   * GUI-initiated agent scans → no backend endpoint at all
#   * Backend-dispatched scans → resolved as Future result, never persisted
#   * Daemon-scheduled scans → WS scan_result with no handler → silently dropped
#
# These endpoints + the WS handler in services/remote_agent (registered
# at app startup) close all three.
# ===========================================


class _DiscoveredHostIn(BaseModel):
    """Single host as reported by the agent's ScanResult.to_dict()."""

    ip_address: str = Field(..., min_length=1, max_length=45)
    mac_address: str | None = Field(None, max_length=17)
    hostname: str | None = Field(None, max_length=255)
    vendor: str | None = Field(None, max_length=128)
    vendor_confidence: int | None = Field(None, ge=0, le=100)
    device_type: str | None = Field(None, max_length=64)
    # Which scanner(s) saw this host — agent passes a list, "arp",
    # "ping", "mdns", "ssdp", "lldp", "cdp", "snmp", "netbios", etc.
    # Was missing from the schema in the first cut so all values
    # were silently discarded by pydantic.
    discovered_via: list[str] = Field(default_factory=list, max_length=32)
    open_ports: list[int] = Field(default_factory=list, max_length=2048)
    services: dict[str, Any] = Field(default_factory=dict)
    mdns_services: list[str] = Field(default_factory=list, max_length=256)
    ssdp_info: dict[str, Any] | None = None
    http_title: str | None = Field(None, max_length=255)
    http_server: str | None = Field(None, max_length=255)
    likely_device_types: list[str] = Field(default_factory=list, max_length=16)
    recommended_driver: str | None = Field(None, max_length=64)
    # L2 topology hints
    lldp_chassis_id: str | None = Field(None, max_length=255)
    lldp_port_id: str | None = Field(None, max_length=255)
    lldp_system_name: str | None = Field(None, max_length=255)
    lldp_capabilities: list[str] | None = None


class DiscoveryResultsRequest(BaseModel):
    """Payload for POST /api/v1/discovery/results.

    The agent posts a batch of discovery findings here after running a
    scan. Each batch is associated with a single site (the site the
    agent is registered to). The host list is capped at 5000 per call
    to bound the per-request memory + DB write cost; agents with bigger
    finds should chunk.
    """

    site_id: UUID
    results: list[_DiscoveredHostIn] = Field(..., min_length=1, max_length=5000)


class DiscoveryResultsResponse(BaseModel):
    """Summary of what the upsert produced.

    `routed` is a per-site count of how many rows landed where, with
    keys as site_id strings. When auto-routing is on (default), rows
    whose IP matches another site's subnets are persisted to that
    site instead of the request's ``site_id`` — so an agent at Site A
    can hit /discovery/results with site_id=Site B and the rows will
    still land in Site C. ``site_id`` in the
    response remains the *request's* site_id (i.e. the fallback bucket
    for IPs that don't match any site's subnets).
    """

    created: int
    updated: int
    skipped: int
    site_id: UUID
    routed: dict[str, int] = Field(default_factory=dict)


@router.post(
    "/results",
    response_model=DiscoveryResultsResponse,
    summary="Agent → backend: push discovery results",
)
async def push_discovery_results(
    payload: DiscoveryResultsRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
) -> Any:
    """Ingest a batch of agent discovery results into devices.discovered_hosts.

    Authorization: ``discovery:write`` (admin / org_admin / site_admin).
    Cross-tenant guard: site_id must belong to the caller's org.
    """
    from app.services.discovered_hosts import upsert_batch

    # Cross-tenant guard
    site_q = await session.execute(
        select(Site).where(Site.id == payload.site_id, Site.deleted_at.is_(None))
    )
    site = site_q.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if not is_unscoped_superuser(current_user):
        if site.organization_id != current_user.organization_id:
            raise HTTPException(status_code=404, detail="Site not found")

    # Per-user site grant: a site-limited caller must hold this site.
    assert_can_access_site(current_user, site.id, detail="Site not found")

    summary = await upsert_batch(
        session,
        site_id=payload.site_id,
        organization_id=site.organization_id,
        # Future: when the WS handler also goes through here it will
        # know which agent it came from. The HTTP path is operator-
        # initiated (current_user.id is the actor), so we leave the
        # discovered_by_agent_id NULL on this call. Operator-attributed
        # discoveries can still be filtered by checking the audit log.
        discovered_by_agent_id=None,
        hosts=[h.model_dump() for h in payload.results],
        # constrain auto-routing to the caller's granted
        # sites. None for super/org-admin (unrestricted org-wide routing).
        allowed_site_ids=site_ids_for_request(current_user),
    )
    await session.commit()
    return DiscoveryResultsResponse(site_id=payload.site_id, **summary)


@router.get(
    "/discovered-hosts",
    response_model=list[dict[str, Any]],
    summary="List hosts the agent has seen but not yet adopted",
)
async def list_discovered_hosts(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    site_id: UUID | None = Query(None, description="Filter by site"),
    show_adopted: bool = Query(False, description="Include already-adopted hosts"),
    show_ignored: bool = Query(False, description="Include ignored hosts"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Any:
    """List discovered hosts (unadopted by default).

    Authorization: ``discovery:run`` (operator+). Org-scoped automatically.
    """
    from app.models.devices import DiscoveredHost

    q = select(DiscoveredHost).where(DiscoveredHost.deleted_at.is_(None))

    # Org scope + per-user site grant in one canonical predicate.
    q = q.where(tenant_filter(DiscoveredHost, current_user))

    if site_id:
        q = q.where(DiscoveredHost.site_id == site_id)
    if not show_adopted:
        q = q.where(DiscoveredHost.is_adopted.is_(False))
    if not show_ignored:
        q = q.where(DiscoveredHost.ignored.is_(False))

    q = q.order_by(DiscoveredHost.last_seen.desc()).offset(offset).limit(limit)
    rows = (await session.execute(q)).scalars().all()

    # Build the known-entity index once and tag each host with what
    # FreeSDN already knows about it (controller appliance, or a
    # managed/controller-synced device). This is what lets the agent
    # say "this is your MikroTik" instead of showing it as brand-new.
    from app.services.discovered_hosts import (
        build_known_entity_index,
        match_known_entity,
    )

    # a scoped super_admin key (organization_id None) must NOT build a
    # platform-wide entity index. org_scope_or_platform returns None only for an
    # unscoped super_admin and fails closed otherwise.
    index_org = org_scope_or_platform(current_user)
    # the visible rows above are already site-grant filtered, but the
    # enrichment index must be too — otherwise a site-limited viewer could learn
    # a sibling-site controller/device name via an IP/MAC collision. site_ids_for_
    # request is None for unrestricted callers (no-op) and the granted set for a
    # site-limited caller (fail-closed when empty).
    known_index = await build_known_entity_index(
        session,
        organization_id=index_org,
        site_id=site_id,
        allowed_site_ids=site_ids_for_request(current_user),
    )

    return [
        {
            "id": str(r.id),
            "site_id": str(r.site_id),
            "organization_id": str(r.organization_id),
            "ip_address": r.ip_address,
            "mac_address": r.mac_address,
            "hostname": r.hostname,
            "vendor": r.vendor,
            "device_type": r.device_type,
            "discovered_via": r.discovered_via or [],
            "open_ports": r.open_ports or [],
            "services": r.services or {},
            "mdns_services": r.mdns_services or [],
            "ssdp_info": r.ssdp_info,
            "http_title": r.http_title,
            "http_server": r.http_server,
            "lldp_chassis_id": r.lldp_chassis_id,
            "lldp_port_id": r.lldp_port_id,
            "lldp_system_name": r.lldp_system_name,
            "lldp_capabilities": r.lldp_capabilities,
            "likely_device_types": r.likely_device_types or [],
            "recommended_driver": r.recommended_driver,
            "is_adopted": r.is_adopted,
            "adopted_device_id": str(r.adopted_device_id) if r.adopted_device_id else None,
            "ignored": r.ignored,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "discovered_by_agent_id": str(r.discovered_by_agent_id)
            if r.discovered_by_agent_id
            else None,
            "known_as": match_known_entity(
                known_index,
                ip_address=r.ip_address,
                mac_address=r.mac_address,
            ),
        }
        for r in rows
    ]


@router.get(
    "/topology-edges",
    response_model=list[dict[str, Any]],
    summary="L2 topology edges observed by agents (LLDP / CDP)",
)
async def list_topology_edges(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    site_id: UUID | None = Query(None),
    protocol: str | None = Query(None, max_length=8),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> Any:
    """Return the agent-observed L2 edges for the topology view.

    Each row is one ``(agent_local_interface) ↔ (neighbor_chassis,
    neighbor_port)`` observation. The UI's existing React Flow
    topology view can render these as edges between nodes; the
    nodes themselves come from devices.devices + the new
    discovered_hosts table.

    Org-scoped automatically.
    """
    from app.models.devices import TopologyEdge

    q = select(TopologyEdge).where(TopologyEdge.deleted_at.is_(None))

    # Org scope + per-user site grant in one canonical predicate.
    q = q.where(tenant_filter(TopologyEdge, current_user))

    if site_id:
        q = q.where(TopologyEdge.site_id == site_id)
    if protocol:
        q = q.where(TopologyEdge.protocol == protocol)

    q = q.order_by(TopologyEdge.last_seen.desc()).offset(offset).limit(limit)
    rows = (await session.execute(q)).scalars().all()

    return [
        {
            "id": str(r.id),
            "site_id": str(r.site_id),
            "protocol": r.protocol,
            "local_interface": r.local_interface,
            "neighbor_chassis_id": r.neighbor_chassis_id,
            "neighbor_chassis_subtype": r.neighbor_chassis_subtype,
            "neighbor_port_id": r.neighbor_port_id,
            "neighbor_port_subtype": r.neighbor_port_subtype,
            "neighbor_port_description": r.neighbor_port_description,
            "neighbor_system_name": r.neighbor_system_name,
            "neighbor_system_description": r.neighbor_system_description,
            "neighbor_capabilities": r.neighbor_capabilities or [],
            "neighbor_mgmt_address": r.neighbor_mgmt_address,
            "vlan_id": r.vlan_id,
            "neighbor_device_id": str(r.neighbor_device_id) if r.neighbor_device_id else None,
            "discovered_by_agent_id": str(r.discovered_by_agent_id)
            if r.discovered_by_agent_id
            else None,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]


async def build_discovery_topology(
    session: AsyncSession,
    *,
    organization_id: UUID | None,
    site_id: UUID | None = None,
    include_adopted: bool = True,
    is_superuser: bool = False,
    limit: int = 500,
    current_user: CurrentUser | None = None,
) -> dict[str, Any]:
    """Pure assembly of the discovery topology graph.

    Extracted from the endpoint so it can be unit-tested without the
    full HTTP auth stack. Returns the same {nodes, edges, subnets}
    shape the endpoint exposes.

    When ``current_user`` is supplied the per-user site grant
    (``site_scope_filter``) is applied to BOTH the DiscoveredHost and
    TopologyEdge queries so a site-limited caller never sees sibling-site
    nodes/edges. It is a no-op for super_admin / org_admin.
    """
    import ipaddress

    from app.models.devices import DiscoveredHost, TopologyEdge

    if not is_superuser and not organization_id:
        return {"nodes": [], "edges": [], "subnets": []}

    # 1. Load discovered_hosts
    hq = select(DiscoveredHost).where(DiscoveredHost.deleted_at.is_(None))
    if not is_superuser:
        hq = hq.where(DiscoveredHost.organization_id == organization_id)
    if current_user is not None:
        hq = hq.where(site_scope_filter(current_user, DiscoveredHost.site_id))
    if site_id:
        hq = hq.where(DiscoveredHost.site_id == site_id)
    if not include_adopted:
        hq = hq.where(DiscoveredHost.is_adopted.is_(False))
    hq = hq.where(DiscoveredHost.ignored.is_(False))
    hq = hq.order_by(DiscoveredHost.last_seen.desc()).limit(limit)
    hosts = (await session.execute(hq)).scalars().all()

    # 2. Load site subnets so we can group hosts by claimed CIDR
    site_ids = {h.site_id for h in hosts}
    sites_by_id: dict[UUID, Site] = {}
    if site_ids:
        sq = select(Site).where(Site.id.in_(site_ids), Site.deleted_at.is_(None))
        for s in (await session.execute(sq)).scalars().all():
            sites_by_id[s.id] = s

    # 3. Build subnet network list for membership checks
    site_networks: list[tuple[Any, str, str]] = []
    seen_subnet_keys: set[str] = set()
    subnet_summary: list[dict[str, Any]] = []
    for s in sites_by_id.values():
        for sub in s.subnets or []:
            cidr = (sub or {}).get("cidr")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            key = f"{s.id}:{cidr}"
            if key in seen_subnet_keys:
                continue
            seen_subnet_keys.add(key)
            label = (sub or {}).get("name") or cidr
            site_networks.append((network, key, label))
            subnet_summary.append(
                {
                    "id": key,
                    "cidr": cidr,
                    "label": label,
                    "site_id": str(s.id),
                    "site_name": s.name,
                    "vlan_id": (sub or {}).get("vlan_id"),
                    "host_count": 0,
                }
            )
    site_networks.sort(key=lambda t: -t[0].prefixlen)

    def _subnet_for_ip(ip: str) -> str | None:
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, key, _label in site_networks:
            if target in network:
                return key
        return None

    # 4. Build nodes
    nodes: list[dict[str, Any]] = []
    subnet_counts: dict[str, int] = {}
    host_to_subnet: dict[str, str] = {}
    for h in hosts:
        subnet_key = _subnet_for_ip(h.ip_address)
        if subnet_key:
            subnet_counts[subnet_key] = subnet_counts.get(subnet_key, 0) + 1
            host_to_subnet[str(h.id)] = subnet_key
        nodes.append(
            {
                "id": str(h.id),
                "type": "host",
                "ip_address": h.ip_address,
                "mac_address": h.mac_address,
                "hostname": h.hostname,
                "vendor": h.vendor,
                "device_type": h.device_type,
                "discovered_via": h.discovered_via or [],
                "is_adopted": h.is_adopted,
                "adopted_device_id": str(h.adopted_device_id) if h.adopted_device_id else None,
                "site_id": str(h.site_id),
                "subnet_id": subnet_key,
                "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            }
        )
    for s_entry in subnet_summary:
        s_entry["host_count"] = subnet_counts.get(s_entry["id"], 0)
        nodes.append(
            {
                "id": s_entry["id"],
                "type": "subnet",
                "cidr": s_entry["cidr"],
                "label": s_entry["label"],
                "site_id": s_entry["site_id"],
                "site_name": s_entry["site_name"],
                "vlan_id": s_entry["vlan_id"],
                "host_count": s_entry["host_count"],
            }
        )

    # 5. Build edges — virtual host→subnet + real LLDP/CDP
    edges: list[dict[str, Any]] = []
    for host_id, subnet_id in host_to_subnet.items():
        edges.append(
            {
                "id": f"virt-{host_id}-{subnet_id}",
                "source": host_id,
                "target": subnet_id,
                "type": "subnet_member",
            }
        )

    eq = select(TopologyEdge).where(TopologyEdge.deleted_at.is_(None))
    if not is_superuser:
        eq = eq.where(TopologyEdge.organization_id == organization_id)
    if current_user is not None:
        eq = eq.where(site_scope_filter(current_user, TopologyEdge.site_id))
    if site_id:
        eq = eq.where(TopologyEdge.site_id == site_id)
    eq = eq.order_by(TopologyEdge.last_seen.desc()).limit(limit)
    edge_rows = (await session.execute(eq)).scalars().all()
    for e in edge_rows:
        local_node_id = f"agent-iface:{e.local_interface}"
        edges.append(
            {
                "id": str(e.id),
                "source": local_node_id,
                "target": e.neighbor_chassis_id,
                "protocol": e.protocol,
                "local_interface": e.local_interface,
                "neighbor_system_name": e.neighbor_system_name,
                "neighbor_port_id": e.neighbor_port_id,
                "vlan_id": e.vlan_id,
                "neighbor_device_id": str(e.neighbor_device_id) if e.neighbor_device_id else None,
                "type": e.protocol or "lldp",
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "subnets": [s for s in subnet_summary if s["host_count"] > 0],
    }


@router.get(
    "/topology",
    response_model=dict[str, Any],
    summary="Agent-discovered topology graph (nodes + edges + subnet groups)",
)
async def get_discovery_topology(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    site_id: UUID | None = Query(None, description="Filter by site"),
    include_adopted: bool = Query(
        True,
        description="Include adopted discovered_hosts (linked to Device rows)",
    ),
    limit: int = Query(500, ge=1, le=2000),
) -> Any:
    """Assemble a render-ready topology graph from agent discoveries.

    Returns three layers:
    - **nodes** — DiscoveredHost rows + one synthetic "subnet" node per
      site CIDR. Hosts attach to their subnet via a virtual edge so
      React Flow can group visually.
    - **edges** — real LLDP/CDP rows from devices.topology_edges + the
      virtual subnet-member edges.
    - **subnets** — detected subnet groupings with cidr/label/host count.

    Each host node carries is_adopted, vendor, hostname, mac,
    discovered_via so the FE can color/style. Capped at 500 by default.
    """
    return await build_discovery_topology(
        session,
        organization_id=current_user.organization_id,
        site_id=site_id,
        include_adopted=include_adopted,
        is_superuser=is_unscoped_superuser(current_user),
        limit=limit,
        current_user=current_user,
    )


class _TopologyEdgeIn(BaseModel):
    """One LLDP/CDP edge captured by a GUI-mode agent's brief sniff."""

    local_interface: str = Field(..., min_length=1, max_length=64)
    neighbor_chassis_id: str = Field(..., min_length=1, max_length=64)
    neighbor_port_id: str = Field(..., min_length=1, max_length=64)
    protocol: str = Field(default="lldp", max_length=8)
    neighbor_system_name: str | None = Field(None, max_length=255)
    neighbor_chassis_subtype: str | None = Field(None, max_length=16)
    neighbor_port_subtype: str | None = Field(None, max_length=16)
    neighbor_port_description: str | None = Field(None, max_length=255)
    neighbor_system_description: str | None = Field(None, max_length=2000)
    neighbor_capabilities: list[str] | None = None
    neighbor_mgmt_address: str | None = Field(None, max_length=45)
    vlan_id: int | None = Field(None, ge=1, le=4094)


class _TopologyEdgesRequest(BaseModel):
    site_id: UUID
    edges: list[_TopologyEdgeIn] = Field(..., min_length=1, max_length=500)


@router.post(
    "/topology-edges/batch",
    summary="Agent → backend: batch push LLDP/CDP edges (GUI mode)",
)
async def push_topology_edges(
    payload: _TopologyEdgesRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
) -> Any:
    """Companion to POST /discovery/results for the LLDP path.

    The GUI agent can't use the WS topology_update channel (it doesn't
    keep a long-lived WS connection), so this REST endpoint accepts a
    batch of edges captured during a brief sniff window. Same
    org-scoping + upsert logic the WS handler uses; just delivered
    over REST.
    """
    from app.services.agent_topology import upsert_topology_edges_batch

    site_q = await session.execute(
        select(Site).where(Site.id == payload.site_id, Site.deleted_at.is_(None))
    )
    site = site_q.scalar_one_or_none()
    if not site:
        raise HTTPException(404, "Site not found")
    if not is_unscoped_superuser(current_user):
        if site.organization_id != current_user.organization_id:
            raise HTTPException(404, "Site not found")

    # Per-user site grant: a site-limited caller must hold this site.
    assert_can_access_site(current_user, site.id, detail="Site not found")

    # Single existing-row query + one flush for the whole batch
    # — replaces the previous 2×N per-edge round trips.
    created, updated = await upsert_topology_edges_batch(
        session,
        site_id=payload.site_id,
        organization_id=site.organization_id,
        edges=[e.model_dump() for e in payload.edges],
        discovered_by_agent_id=None,
    )

    await session.commit()
    return {"created": created, "updated": updated, "site_id": str(payload.site_id)}


# ===========================================
# Background Task Helpers
# ===========================================


async def _run_discovery_task(controller_id: UUID):
    # SECURITY/CORRECTNESS: open a FRESH session here. These helpers run from
    # FastAPI BackgroundTasks AFTER the response is sent, at which point the
    # request-scoped Depends(get_session) session has already been committed
    # and CLOSED (get_session's `async with` exits when the request ends).
    # Reusing it raised on first use and silently failed the discovery run.
    from app.db import async_session_factory

    async with async_session_factory() as session:
        try:
            discovery_service = DiscoveryService(session)
            await discovery_service.discover_controller(controller_id)
        except Exception as e:
            logger.error("Background discovery failed for %s: %s", controller_id, e)


async def _run_site_discovery_task(site_id: UUID):
    from app.db import async_session_factory

    async with async_session_factory() as session:
        try:
            discovery_service = DiscoveryService(session)
            await discovery_service.discover_all(site_id=site_id)
        except Exception as e:
            logger.error("Background site discovery failed for %s: %s", site_id, e)


async def _run_all_discovery_task(
    site_id: UUID | None,
    organization_id: UUID | None = None,
    site_ids: list[UUID] | None = None,
):
    from app.db import async_session_factory

    async with async_session_factory() as session:
        try:
            discovery_service = DiscoveryService(session)
            await discovery_service.discover_all(
                site_id=site_id,
                organization_id=organization_id,
                site_ids=site_ids,
            )
        except Exception as e:
            logger.error("Background full discovery failed: %s", e)
