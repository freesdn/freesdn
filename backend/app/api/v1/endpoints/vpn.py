# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN API Endpoints
=================================

REST API for VPN integration with full CRUD and multi-provider support.

Endpoints:
  Connections (CRUD)
  - GET    /vpn/connections              - List all VPN connections
  - POST   /vpn/connections              - Create a VPN connection
  - GET    /vpn/connections/{id}         - Get connection details
  - PUT    /vpn/connections/{id}         - Update connection
  - DELETE /vpn/connections/{id}         - Delete connection
  - POST   /vpn/connections/{id}/action  - Connect / Disconnect

  General
  - GET    /vpn/subnets                  - List VPN accessible subnets
  - POST   /vpn/connectivity             - Check connectivity to target
  - GET    /vpn/status                   - Overall VPN status summary
  - GET    /vpn/providers                - List available VPN providers

  Tailscale
  - GET    /vpn/tailscale/status         - Tailscale daemon status
  - GET    /vpn/tailscale/devices        - List Tailscale nodes
  - GET    /vpn/tailscale/devices/{name} - Get single node
  - POST   /vpn/tailscale/ping           - Ping Tailscale target
  - GET    /vpn/tailscale/discover/{subnet} - Discover subnet devices

  WireGuard
  - GET    /vpn/wireguard/interfaces     - List WireGuard interfaces
  - GET    /vpn/wireguard/interfaces/{iface} - Get interface status

  Netbird
  - GET    /vpn/netbird/status           - Netbird daemon status
  - GET    /vpn/netbird/peers            - List Netbird peers
  - POST   /vpn/netbird/ping             - Ping Netbird peer

  OpenVPN
  - GET    /vpn/openvpn/connections      - List OpenVPN connections
  - GET    /vpn/openvpn/connections/{name} - Get OpenVPN connection status

  Site VPN Config
  - GET    /vpn/sites/{id}/config        - Get site VPN config
  - PUT    /vpn/sites/{id}/config        - Update site VPN config
  - POST   /vpn/sites/{id}/test          - Test site VPN connectivity
"""

import logging
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt_credential, encrypt_credential
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.db.session import get_logdb_session
from app.models import Site
from app.models.vpn import VPNConnectionRecord
from app.schemas.vpn import (
    ConnectivityCheckRequest,
    ConnectivityCheckResponse,
    NetbirdPeerResponse,
    NetbirdStatusResponse,
    OpenVPNStatusResponse,
    SiteVPNConfigCreate,
    SiteVPNConfigResponse,
    SiteVPNConfigUpdate,
    TailscaleActionResponse,
    TailscaleAuthKeyLoginRequest,
    TailscaleConfigureRequest,
    TailscaleInteractiveLoginRequest,
    TailscaleLoginResponse,
    TailscaleNodeResponse,
    TailscaleSetupStatusResponse,
    TailscaleStatusResponse,
    VPNConnectionActionRequest,
    VPNConnectionActionResponse,
    VPNConnectionCreate,
    VPNConnectionResponse,
    VPNConnectionUpdate,
    VPNProviderInfo,
    VPNProvidersResponse,
    VPNStatusSummaryResponse,
    VPNSubnetResponse,
)
from app.services.vpn_integration import (
    NetbirdService,
    OpenVPNService,
    PersistentVPNService,
    TailscaleService,
    WireGuardService,
    get_tailscale_setup,
    get_vpn_manager,
)

router = APIRouter()
logger = logging.getLogger(__name__)

svc = PersistentVPNService


# ─────────────────────────────────────────────────────────────────────────────
# Typed request bodies for brain / import endpoints
# ─────────────────────────────────────────────────────────────────────────────

_VPN_SERVER_ID_RE = re.compile(r"^[\w\-]{1,128}$")


def _redact_extra_data(data: dict | None) -> dict | None:
    """Strip sensitive keys from extra_data JSONB before API response.

    Delegates to the CENTRAL ``redact_secrets``: the previous local
    redactor was flat (non-recursive), exact-lowercase, and used a divergent
    10-key set, so nested ({"peer":{"private_key":..}}) and camelCase
    ({"clientSecret":..}) secrets leaked. The central helper is recursive,
    camelCase/hyphen-normalizing, and the single source of truth for the
    secret-key strip-list — every VPN-relevant key (setup_key/preshared_key/
    apikey/credential/...) is now in it.
    """
    if not data:
        return data
    from app.core.redaction import redact_secrets

    result = redact_secrets(data)
    return result if isinstance(result, dict) else data


class _BrainVPNImportRequest(BaseModel):
    """Typed payload for importing VPN config from a brain controller."""

    vpn_type: str = Field(..., pattern=r"^(openvpn|wireguard|ipsec)$")
    vpn_server_id: str = Field(..., min_length=1, max_length=128)
    site_id: UUID | None = None

    @field_validator("vpn_server_id")
    @classmethod
    def _safe_server_id(cls, v: str) -> str:
        if not _VPN_SERVER_ID_RE.match(v):
            raise ValueError(
                "vpn_server_id must be alphanumeric/hyphens/underscores, max 128 chars"
            )
        return v


class _OpenVPNImportRequest(BaseModel):
    """Typed payload for importing an OpenVPN .ovpn config."""

    site_id: UUID
    config_content: str = Field(..., min_length=1, max_length=102400)
    description: str = Field(default="", max_length=500)


# Allowlist for VPN interface / connection names passed to subprocess.
# WireGuard interfaces: wg0, wg1, tailscale0, utun3 …
# OpenVPN connection names: alphanumeric + hyphens/underscores, max 64 chars.
# create_subprocess_exec does NOT invoke a shell so there is no injection risk
# from shell metacharacters, but validating the pattern prevents unexpected
# OS errors and makes intent explicit.
_VPN_NAME_RE = re.compile(r"^[a-zA-Z0-9][\w\-]{0,62}$")


def _validate_vpn_name(name: str, label: str = "name") -> str:
    """Raise 400 if the VPN interface/connection name doesn't match the allowlist."""
    if not _VPN_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {label}: must be alphanumeric with hyphens/underscores, max 64 chars",
        )
    return name


def _safe_decrypt(ciphertext: str | None) -> str | None:
    """Decrypt a stored credential, returning None if it isn't decryptable.

    Defensive: a value stored before encryption was enabled (or with a different
    key) shouldn't 500 the connect action — treat it as absent.
    """
    if not ciphertext:
        return None
    try:
        return decrypt_credential(ciphertext)
    except Exception:
        logger.warning("Could not decrypt a stored VPN credential; treating as unset")
        return None


def _openvpn_conn_name(record: "VPNConnectionRecord") -> str:
    """Derive a stable, filesystem/process-safe OpenVPN connection name.

    Used for BOTH the on-disk <name>.conf and the daemon/process name, so the
    config materialized at connect matches the file the daemon reads. The record
    id guarantees uniqueness + a valid token regardless of the display name (the
    old `name.replace("OpenVPN (","").rstrip(")")` mangled legitimate names).
    """
    return f"ovpn-{record.id.hex}"


def _wireguard_iface_name(record: "VPNConnectionRecord") -> str:
    """Derive a stable, kernel-safe WireGuard interface name from the record.

    Linux network interface names are capped at 15 chars (IFNAMSIZ-1), so the
    display name can't be used directly. `wg` + 12 hex of the id = 14 chars,
    unique + a valid `_is_safe_iface_name` token, and identical for both the
    on-disk <iface>.conf and the `wg-quick` interface.
    """
    return f"wg{record.id.hex[:12]}"


async def _org_vpn_type_count(session: AsyncSession, org_id: UUID, vpn_type: str) -> int:
    res = await session.execute(
        select(func.count())
        .select_from(VPNConnectionRecord)
        .where(
            VPNConnectionRecord.organization_id == org_id,
            VPNConnectionRecord.vpn_type == vpn_type,
        )
    )
    return int(res.scalar() or 0)


async def _resolve_tailscale_netfilter_mode(session: AsyncSession, org_id: UUID) -> str | None:
    """Pick ``tailscale up --netfilter-mode``.

    Tailscale and NetBird both use the 100.64.0.0/10 CGNAT range, and Tailscale's
    default netfilter aggressively grabs those packets, so the two overlays
    collide on one host. Running Tailscale with ``--netfilter-mode=off`` lets them
    coexist (per netbirdio/netbird#... guidance). Operator env override wins;
    otherwise default to "off" automatically when a NetBird connection also exists.
    """
    env_mode = os.environ.get("FREESDN_TAILSCALE_NETFILTER_MODE", "").strip().lower()
    if env_mode in ("off", "nodivert", "on"):
        return env_mode
    if await _org_vpn_type_count(session, org_id, "netbird") > 0:
        return "off"
    return None


async def _live_connect_status(manager: Any, record: "VPNConnectionRecord") -> str:
    """Resolve the real post-connect status so the DB never claims a false 'connected'.

    Returns "connected" only when the daemon confirms the tunnel is up; otherwise
    "connecting" (the request was accepted but the link isn't established yet).
    """
    try:
        if record.vpn_type == "openvpn":
            st = await manager.openvpn.get_status(_openvpn_conn_name(record))
            mapped = st.get("status")
            return "connected" if mapped == "connected" else "connecting"
        if record.vpn_type == "netbird":
            st = await manager.netbird.get_status(refresh=True)
            return "connected" if st.get("connected") else "connecting"
        if record.vpn_type == "wireguard":
            st = await manager.wireguard.get_status(_wireguard_iface_name(record))
            return "connected" if st.get("status") == "connected" else "connecting"
        if record.vpn_type == "tailscale":
            ts = await manager.tailscale.get_status()
            return "connected" if getattr(ts, "backend_state", None) == "Running" else "connecting"
    except Exception:
        logger.debug("live status re-poll failed; recording 'connecting'", exc_info=True)
        return "connecting"
    # any other type: the connect action already returned success
    return "connected"


def _org_id(user: Any) -> UUID:
    """Extract organization_id from the current user or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _verify_site_org(session: AsyncSession, site_id: UUID, user: Any) -> "Site":
    """Load a site and verify it belongs to the user's organization. Returns the site."""
    org_id = _org_id(user)
    result = await session.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
    )
    site = result.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    # Enforce the per-user site grant (not just org membership): a site-limited
    # operator must not read/modify VPN config, health, tunnels, or run
    # connectivity/preflight for sibling sites in the same org. No-op for
    # super_admin / org_admin (non-site-limited). 404 to avoid an existence oracle.
    assert_can_access_site(user, site_id, detail="Site not found")
    return site


# ─────────────────────────────────────────────────────────────────────────────
# Providers
# ─────────────────────────────────────────────────────────────────────────────

VPN_PROVIDERS = [
    VPNProviderInfo(
        id="tailscale",
        name="Tailscale",
        description="Zero-config mesh VPN with NAT traversal and Magic DNS",
        icon="tailscale",
        features=["mesh", "magic_dns", "acl", "nat_traversal", "exit_node", "subnet_routing"],
    ),
    VPNProviderInfo(
        id="wireguard",
        name="WireGuard",
        description="Modern, fast, and secure VPN tunnel",
        icon="wireguard",
        features=["tunnel", "fast", "low_overhead", "site_to_site"],
    ),
    VPNProviderInfo(
        id="openvpn",
        name="OpenVPN",
        description="Enterprise-grade SSL VPN with broad compatibility",
        icon="openvpn",
        features=["ssl_vpn", "enterprise", "wide_compatibility", "tcp_udp"],
    ),
    VPNProviderInfo(
        id="netbird",
        name="Netbird",
        description="WireGuard-based mesh VPN with self-hosting support",
        icon="netbird",
        features=["mesh", "self_hosted", "acl", "nat_traversal", "wireguard_based"],
    ),
    VPNProviderInfo(
        id="ipsec",
        name="IPsec",
        description="Industry-standard site-to-site VPN protocol",
        icon="ipsec",
        features=["site_to_site", "industry_standard", "hardware_acceleration"],
    ),
]


@router.get("/providers", response_model=VPNProvidersResponse)
async def list_providers(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all supported VPN providers."""
    return VPNProvidersResponse(providers=VPN_PROVIDERS)


@router.get("/runtime")
async def get_vpn_runtime(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> dict[str, Any]:
    """Deploy-time VPN runtime status for the UI.

    FreeSDN is capless by default (no privileged VPN sidecar). The frontend reads
    this to render an honest state — e.g. a "VPN sidecar not deployed" banner when
    the module is enabled but the infra component isn't running — instead of empty
    or erroring widgets. PURE / best-effort: it only reads env + checks for the
    control socket / tun device; it never shells out, so it can't 500.
    """
    mode = settings.resolved_vpn_mode
    sidecar_reachable = False
    tun_available = False
    try:
        sidecar_reachable = os.path.exists("/var/run/tailscale/tailscaled.sock")
    except OSError:
        pass
    try:
        tun_available = os.path.exists("/dev/net/tun")
    except OSError:
        pass
    return {
        "enabled": mode != "off",
        "mode": mode,
        "sidecar_reachable": sidecar_reachable,
        "tun_available": tun_available,
    }


@router.get("/discovery")
async def discover_overlay(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> dict[str, Any]:
    """Discover adoptable devices on the connected overlay mesh (tailnet/netbird).

    The mesh is an inventory: each peer is a reachable device. Peers are classified
    from overlay metadata (OS, ACL tags, hostname) — capless, no active probing.
    Returns [] when no overlay is connected (the default). Each peer is then
    cross-referenced against the org's managed devices (by overlay address or
    hostname) so the inbox flags ones you already manage. See
    docs.freesdn.org.
    """
    from app.models import Device
    from app.services.overlay_discovery import (
        annotate_already_adopted,
        discover_overlay_devices,
        emit_overlay_discovery,
    )

    devices = await discover_overlay_devices()
    if devices:
        rows = (
            await session.execute(
                select(Device.id, Device.ip_address, Device.name)
                .join(Site, Device.site_id == Site.id)
                .where(
                    Site.organization_id == _org_id(user),
                    Device.deleted_at.is_(None),
                    Site.deleted_at.is_(None),
                )
            )
        ).all()
        annotate_already_adopted(devices, [(r.id, r.ip_address, r.name) for r in rows])
        # Surface newly-found (not-yet-managed) peers to the Fabric as
        # `overlay.peer.discovered` triggers — deduped, org-scoped, best-effort.
        await emit_overlay_discovery(devices, organization_id=str(_org_id(user)))
    return {
        "devices": devices,
        "count": len(devices),
        "mode": settings.resolved_vpn_mode,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Connections CRUD
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/connections", response_model=list[VPNConnectionResponse])
async def list_connections(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all VPN connections (from DB + live state)."""
    org_id = _org_id(user)
    # NOTE: sync_live_connections is handled by a periodic Celery task,
    # not inline on every GET — avoids 2N queries + subprocess overhead per request.

    offset = (page - 1) * page_size
    records = await svc.list_connections(
        session, organization_id=org_id, limit=page_size, offset=offset
    )

    results = []
    for r in records:
        results.append(
            VPNConnectionResponse(
                id=str(r.id),
                name=r.name,
                vpn_type=r.vpn_type,
                status=r.status,
                endpoint=r.endpoint,
                port=r.port,
                allowed_ips=r.allowed_ips,
                connected_at=r.connected_at.isoformat() if r.connected_at else None,
                connected_since=r.connected_at.isoformat() if r.connected_at else None,
                last_handshake=r.last_handshake.isoformat() if r.last_handshake else None,
                rx_bytes=r.rx_bytes,
                tx_bytes=r.tx_bytes,
                latency_ms=r.latency_ms,
                local_ip=r.local_ip,
                remote_ip=r.remote_ip,
                dns_servers=r.dns_servers,
                extra_data=_redact_extra_data(r.extra_data),
                openvpn_config_path=r.openvpn_config_path,
                openvpn_protocol=r.openvpn_protocol,
                netbird_management_url=r.netbird_management_url,
                organization_id=str(r.organization_id) if r.organization_id else None,
            )
        )
    return results


@router.post("/connections", response_model=VPNConnectionResponse, status_code=201)
async def create_connection(
    data: VPNConnectionCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create a new VPN connection."""
    org_id = _org_id(user)
    existing = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.name == data.name,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Connection name already exists")

    # Tailscale and NetBird are each driven by ONE shared daemon in the sidecar, so
    # a second connection of that type would clobber the first (tailscale up --reset
    # / netbird up with a different key migrates the single daemon and leaves the
    # other record falsely "connected"). Allow only one connection per singleton
    # overlay. (OpenVPN/WireGuard are per-interface and may have many.)
    if data.vpn_type in ("tailscale", "netbird") and (
        await _org_vpn_type_count(session, org_id, data.vpn_type) > 0
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                f"A {data.vpn_type} connection already exists. {data.vpn_type} uses a "
                "single shared daemon, so only one connection of this type is supported "
                "— edit the existing one instead."
            ),
        )

    record = VPNConnectionRecord(
        name=data.name,
        vpn_type=data.vpn_type,
        status="not_configured",
        endpoint=data.endpoint,
        port=data.port,
        local_ip=data.local_ip,
        remote_ip=data.remote_ip,
        allowed_ips=data.allowed_ips or [],
        dns_servers=data.dns_servers or [],
        openvpn_config_path=data.openvpn_config_path,
        openvpn_protocol=data.openvpn_protocol,
        # Encrypted at rest — the .ovpn text carries inline private keys. Already
        # validated against host-RCE directives by the schema.
        openvpn_config_content=encrypt_credential(data.openvpn_config_content)
        if data.openvpn_config_content
        else None,
        # Encrypted at rest — the wg-quick INI carries the interface private key +
        # PSK. Already validated against PostUp/PostDown/PreUp/PreDown by the schema.
        wireguard_config_content=encrypt_credential(data.wireguard_config_content)
        if data.wireguard_config_content
        else None,
        netbird_setup_key=encrypt_credential(data.netbird_setup_key)
        if data.netbird_setup_key
        else None,
        netbird_management_url=data.netbird_management_url,
        extra_data=data.extra_data or {},
        organization_id=org_id,
    )
    if hasattr(record, "created_by"):
        record.created_by = user.id
    session.add(record)
    await session.flush()

    return VPNConnectionResponse(
        id=str(record.id),
        name=record.name,
        vpn_type=record.vpn_type,
        status=record.status,
        endpoint=record.endpoint,
        port=record.port,
        allowed_ips=record.allowed_ips,
        local_ip=record.local_ip,
        remote_ip=record.remote_ip,
        dns_servers=record.dns_servers,
        extra_data=_redact_extra_data(record.extra_data),
        openvpn_config_path=record.openvpn_config_path,
        openvpn_protocol=record.openvpn_protocol,
        netbird_management_url=record.netbird_management_url,
        organization_id=str(record.organization_id) if record.organization_id else None,
    )


@router.get("/connections/{connection_id}", response_model=VPNConnectionResponse)
async def get_connection(
    connection_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get a single VPN connection."""
    org_id = _org_id(user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="VPN connection not found")

    return VPNConnectionResponse(
        id=str(record.id),
        name=record.name,
        vpn_type=record.vpn_type,
        status=record.status,
        endpoint=record.endpoint,
        port=record.port,
        allowed_ips=record.allowed_ips,
        connected_at=record.connected_at.isoformat() if record.connected_at else None,
        connected_since=record.connected_at.isoformat() if record.connected_at else None,
        last_handshake=record.last_handshake.isoformat() if record.last_handshake else None,
        rx_bytes=record.rx_bytes,
        tx_bytes=record.tx_bytes,
        latency_ms=record.latency_ms,
        local_ip=record.local_ip,
        remote_ip=record.remote_ip,
        dns_servers=record.dns_servers,
        extra_data=_redact_extra_data(record.extra_data),
        openvpn_config_path=record.openvpn_config_path,
        openvpn_protocol=record.openvpn_protocol,
        netbird_management_url=record.netbird_management_url,
        organization_id=str(record.organization_id) if record.organization_id else None,
    )


@router.put("/connections/{connection_id}", response_model=VPNConnectionResponse)
async def update_connection(
    connection_id: UUID,
    data: VPNConnectionUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Update a VPN connection."""
    org_id = _org_id(user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="VPN connection not found")

    _VPN_UPDATE_ALLOWED = {
        "name",
        "endpoint",
        "port",
        "local_ip",
        "remote_ip",
        "allowed_ips",
        "dns_servers",
        "openvpn_config_path",
        "openvpn_protocol",
        "openvpn_config_content",
        "wireguard_config_content",
        "netbird_setup_key",
        "netbird_management_url",
        "extra_data",
    }
    update_data = data.model_dump(exclude_unset=True)
    # SECURITY: encrypt credential-bearing fields before storage (the setup key
    # and the .ovpn / wg-quick text, which carry inline private keys). When the
    # field is present in the update, a non-empty value is encrypted and an empty
    # one clears the column (stored as NULL) — never leave plaintext or a stale
    # value behind.
    for _secret_field in (
        "netbird_setup_key",
        "openvpn_config_content",
        "wireguard_config_content",
    ):
        if _secret_field in update_data:
            val = update_data[_secret_field]
            update_data[_secret_field] = encrypt_credential(val) if val else None
    for key, value in update_data.items():
        if key in _VPN_UPDATE_ALLOWED:
            setattr(record, key, value)

    if hasattr(record, "updated_by"):
        record.updated_by = user.id

    await session.flush()

    return VPNConnectionResponse(
        id=str(record.id),
        name=record.name,
        vpn_type=record.vpn_type,
        status=record.status,
        endpoint=record.endpoint,
        port=record.port,
        allowed_ips=record.allowed_ips,
        connected_at=record.connected_at.isoformat() if record.connected_at else None,
        connected_since=record.connected_at.isoformat() if record.connected_at else None,
        last_handshake=record.last_handshake.isoformat() if record.last_handshake else None,
        rx_bytes=record.rx_bytes,
        tx_bytes=record.tx_bytes,
        latency_ms=record.latency_ms,
        local_ip=record.local_ip,
        remote_ip=record.remote_ip,
        dns_servers=record.dns_servers,
        extra_data=_redact_extra_data(record.extra_data),
        openvpn_config_path=record.openvpn_config_path,
        openvpn_protocol=record.openvpn_protocol,
        netbird_management_url=record.netbird_management_url,
        organization_id=str(record.organization_id) if record.organization_id else None,
    )


@router.delete("/connections/{connection_id}", status_code=204)
async def delete_connection(
    connection_id: UUID,
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> None:
    """Delete a VPN connection and purge its health checks from LogDB."""
    org_id = _org_id(user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="VPN connection not found")

    # Tear down a live tunnel + remove its materialized key-bearing config BEFORE
    # deleting the row. Otherwise the sidecar keeps the tunnel up with no API path
    # left to stop it, and the 0600 .ovpn/.conf (private keys) lingers on the
    # shared volume. Best-effort — a teardown failure must not block the delete.
    try:
        manager = get_vpn_manager()
        if record.vpn_type == "openvpn":
            await manager.openvpn.cleanup(_openvpn_conn_name(record))
        elif record.vpn_type == "wireguard":
            await manager.wireguard.cleanup(_wireguard_iface_name(record))
        elif record.vpn_type == "netbird":
            await manager.netbird.disconnect()
    except Exception:
        logger.warning("VPN teardown during delete failed; deleting record anyway", exc_info=True)

    # Purge health checks from LogDB (prevents orphaned time-series data)
    from sqlalchemy import text

    await logdb.execute(
        text("DELETE FROM vpn.vpn_health_checks WHERE connection_id = :conn_id"),
        {"conn_id": connection_id},
    )
    await logdb.commit()

    await session.delete(record)
    await session.flush()
    return None


@router.post("/connections/{connection_id}/action", response_model=VPNConnectionActionResponse)
async def connection_action(
    connection_id: UUID,
    data: VPNConnectionActionRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Connect or disconnect a VPN connection."""
    org_id = _org_id(user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="VPN connection not found")

    manager = get_vpn_manager()
    action_result: dict[str, Any] = {"success": False, "message": "Unsupported VPN type"}

    if record.vpn_type == "tailscale":
        action_result = {"success": True, "message": "Tailscale managed at system level"}

    elif record.vpn_type == "wireguard":
        iface = _wireguard_iface_name(record)
        if data.action == "connect":
            # materialize the stored wg-quick INI to disk, then the sidecar runs
            # `wg-quick up` (the api lacks NET_ADMIN to do it itself)
            config_content = _safe_decrypt(record.wireguard_config_content)
            action_result = await manager.wireguard.connect(iface, config_content=config_content)
        else:
            action_result = await manager.wireguard.disconnect(iface)

    elif record.vpn_type == "openvpn":
        name = _openvpn_conn_name(record)
        if data.action == "connect":
            # materialize the stored .ovpn text to disk, then bring it up
            config_content = _safe_decrypt(record.openvpn_config_content)
            action_result = await manager.openvpn.connect(name, config_content=config_content)
        else:
            action_result = await manager.openvpn.disconnect(name)

    elif record.vpn_type == "netbird":
        if data.action == "connect":
            action_result = await manager.netbird.connect(
                setup_key=_safe_decrypt(record.netbird_setup_key),
                management_url=record.netbird_management_url,
            )
        else:
            action_result = await manager.netbird.disconnect()

    # Update status in DB. HONEST STATUS: a successful "connect" REQUEST does not
    # mean the tunnel is up (the sidecar enacts openvpn asynchronously; netbird
    # `up` can return 0 while still NeedsLogin). Re-poll the live state and only
    # record "connected" when the daemon confirms it — otherwise "connecting".
    if action_result.get("success"):
        if data.action == "connect":
            live = await _live_connect_status(manager, record)
            record.status = live
            record.connected_at = datetime.now(UTC) if live == "connected" else None
        else:
            record.status = "disconnected"
        await session.flush()

    return VPNConnectionActionResponse(
        success=action_result.get("success", False),
        message=action_result.get("message", ""),
        connection_id=str(connection_id),
    )


# ─────────────────────────────────────────────────────────────────────────────
# General
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/subnets", response_model=list[VPNSubnetResponse])
async def list_subnets(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all VPN-accessible subnets from all providers."""
    manager = get_vpn_manager()
    try:
        subnets = await manager.discover_vpn_accessible_subnets()
        return [VPNSubnetResponse(**s) for s in subnets]
    except Exception:
        return []


@router.post("/connectivity", response_model=ConnectivityCheckResponse)
async def check_connectivity(
    data: ConnectivityCheckRequest,
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Check connectivity to a VPN target."""
    manager = get_vpn_manager()
    result = await manager.tailscale.check_connectivity(data.target)
    return ConnectivityCheckResponse(
        target=data.target,
        reachable=result.get("reachable", False),
        latency_ms=result.get("latency_ms"),
        connection_type=result.get("connection_type"),
    )


@router.get("/status", response_model=VPNStatusSummaryResponse)
async def get_vpn_status_summary(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get overall VPN status summary."""
    from sqlalchemy import func

    org_id = _org_id(user)
    q = (
        select(
            func.count().label("total"),
            func.count().filter(VPNConnectionRecord.status == "connected").label("connected"),
            func.count().filter(VPNConnectionRecord.status == "disconnected").label("disconnected"),
            func.count().filter(VPNConnectionRecord.status == "error").label("errors"),
            func.sum(VPNConnectionRecord.rx_bytes).label("total_rx"),
            func.sum(VPNConnectionRecord.tx_bytes).label("total_tx"),
        )
        .select_from(VPNConnectionRecord)
        .where(
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    row = (await session.execute(q)).one()
    return {
        "total_connections": row.total,
        "connected": row.connected,
        "disconnected": row.disconnected,
        "error": row.errors,
        "tailscale_connected": False,
        "wireguard_tunnels": 0,
        "total_peers": 0,
        "total_rx_bytes": row.total_rx or 0,
        "total_tx_bytes": row.total_tx or 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tailscale
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/tailscale/status", response_model=TailscaleStatusResponse)
async def get_tailscale_status(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get Tailscale daemon status."""
    ts = TailscaleService()
    ts_status = await ts.get_status(refresh=True)

    peers = []
    for p in ts_status.peers:
        peers.append(
            TailscaleNodeResponse(
                id=p.id,
                name=p.name,
                hostname=p.hostname,
                dns_name=p.dns_name,
                tailscale_ip=p.primary_ip,
                tailscale_ips=p.tailscale_ips,
                advertised_routes=p.advertised_routes,
                status="online" if p.online else "offline",
                online=p.online,
                is_exit_node=p.is_exit_node,
                relay=p.relay,
                direct=p.direct,
                os=p.os,
                user=p.user,
                tags=p.tags,
            )
        )

    self_node = None
    if ts_status.self_node:
        sn = ts_status.self_node
        self_node = TailscaleNodeResponse(
            id=sn.id,
            name=sn.name,
            hostname=sn.hostname,
            dns_name=sn.dns_name,
            tailscale_ip=sn.primary_ip,
            tailscale_ips=sn.tailscale_ips,
            status="online",
            online=True,
            os=sn.os,
        )

    return TailscaleStatusResponse(
        connected=ts_status.is_connected,
        backend_state=ts_status.backend_state,
        tailnet_name=ts_status.tailnet_name,
        magic_dns_suffix=ts_status.magic_dns_suffix,
        magic_dns_enabled=ts_status.magic_dns_enabled,
        has_exit_node=ts_status.has_exit_node,
        self_node=self_node,
        peers=peers,
        peer_count=len(peers),
    )


@router.get("/tailscale/devices", response_model=list[TailscaleNodeResponse])
async def list_tailscale_devices(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all Tailscale devices."""
    ts = TailscaleService()
    devices = await ts.list_devices()
    return [
        TailscaleNodeResponse(
            id=d.id,
            name=d.name,
            hostname=d.hostname,
            dns_name=d.dns_name,
            tailscale_ip=d.primary_ip,
            tailscale_ips=d.tailscale_ips,
            advertised_routes=d.advertised_routes,
            status="online" if d.online else "offline",
            online=d.online,
            is_exit_node=d.is_exit_node,
            relay=d.relay,
            direct=d.direct,
            os=d.os,
            user=d.user,
            tags=d.tags,
        )
        for d in devices
    ]


@router.get("/tailscale/devices/{name}", response_model=TailscaleNodeResponse)
async def get_tailscale_device(
    name: str,
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get a specific Tailscale device."""
    ts = TailscaleService()
    device = await ts.get_device(name)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return TailscaleNodeResponse(
        id=device.id,
        name=device.name,
        hostname=device.hostname,
        dns_name=device.dns_name,
        tailscale_ip=device.primary_ip,
        tailscale_ips=device.tailscale_ips,
        advertised_routes=device.advertised_routes,
        status="online" if device.online else "offline",
        online=device.online,
        is_exit_node=device.is_exit_node,
        relay=device.relay,
        direct=device.direct,
        os=device.os,
        user=device.user,
        tags=device.tags,
    )


_PING_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:]{1,253}$")


@router.post("/tailscale/ping")
async def ping_tailscale_target(
    target: str = Query(...),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Ping a Tailscale target."""
    if not _PING_TARGET_RE.match(target):
        raise HTTPException(status_code=400, detail="Invalid ping target (IP or hostname expected)")
    ts = TailscaleService()
    latency = await ts.ping(target)
    return {
        "target": target,
        "reachable": latency is not None,
        "latency_ms": latency,
    }


@router.get("/tailscale/discover/{subnet}")
async def discover_tailscale_subnet(
    subnet: str,
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Discover devices on a Tailscale subnet route."""
    import ipaddress as _ipaddress

    try:
        _ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CIDR subnet format")
    ts = TailscaleService()
    return await ts.discover_site_devices(subnet)


# ─────────────────────────────────────────────────────────────────────────────
# Tailscale Setup / Enrollment
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/tailscale/setup/status", response_model=TailscaleSetupStatusResponse)
async def get_tailscale_setup_status(
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Get comprehensive Tailscale agent setup status."""
    setup = get_tailscale_setup()
    result = await setup.get_setup_status()
    return TailscaleSetupStatusResponse(**result)


@router.post("/tailscale/setup/start-daemon", response_model=TailscaleActionResponse)
async def start_tailscale_daemon(
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Start the tailscaled daemon if it's not running."""
    setup = get_tailscale_setup()
    result = await setup.start_daemon()
    return TailscaleActionResponse(**result)


@router.post("/tailscale/setup/login-authkey", response_model=TailscaleLoginResponse)
async def tailscale_login_authkey(
    data: TailscaleAuthKeyLoginRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Authenticate Tailscale using a pre-auth key.

    Enterprise-recommended approach. Generate keys at:
    https://login.tailscale.com/admin/settings/keys

    Supports:
    - Reusable vs single-use keys
    - Ephemeral nodes
    - Pre-approved nodes (skip admin approval)
    - ACL tag assignment
    """
    setup = get_tailscale_setup()
    netfilter_mode = await _resolve_tailscale_netfilter_mode(session, _org_id(user))
    result = await setup.login_with_authkey(
        auth_key=data.auth_key,
        hostname=data.hostname,
        accept_routes=data.accept_routes,
        advertise_routes=data.advertise_routes,
        advertise_exit_node=data.advertise_exit_node,
        shields_up=data.shields_up,
        netfilter_mode=netfilter_mode,
    )
    if netfilter_mode == "off" and result.get("message"):
        result["message"] += " (NetBird coexistence: Tailscale started with --netfilter-mode=off)"
    return TailscaleLoginResponse(**result)


@router.post("/tailscale/setup/login-interactive", response_model=TailscaleLoginResponse)
async def tailscale_login_interactive(
    data: TailscaleInteractiveLoginRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Start browser-based interactive Tailscale login.

    Returns a URL the admin must open in a browser to authorize this node.
    Useful when auth keys are not available.
    """
    setup = get_tailscale_setup()
    netfilter_mode = await _resolve_tailscale_netfilter_mode(session, _org_id(user))
    result = await setup.login_interactive(
        hostname=data.hostname,
        accept_routes=data.accept_routes,
        netfilter_mode=netfilter_mode,
    )
    return TailscaleLoginResponse(**result)


@router.post("/tailscale/setup/configure", response_model=TailscaleActionResponse)
async def configure_tailscale(
    data: TailscaleConfigureRequest,
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Reconfigure the running Tailscale agent (hostname, routes, DNS, exit node)."""
    setup = get_tailscale_setup()
    result = await setup.configure(
        hostname=data.hostname,
        accept_routes=data.accept_routes,
        advertise_routes=data.advertise_routes,
        accept_dns=data.accept_dns,
        advertise_exit_node=data.advertise_exit_node,
        shields_up=data.shields_up,
    )
    return TailscaleActionResponse(**result)


@router.post("/tailscale/setup/disconnect", response_model=TailscaleActionResponse)
async def disconnect_tailscale(
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Disconnect Tailscale (keeps auth -- can reconnect without re-login)."""
    setup = get_tailscale_setup()
    result = await setup.disconnect()
    return TailscaleActionResponse(**result)


@router.post("/tailscale/setup/reconnect", response_model=TailscaleActionResponse)
async def reconnect_tailscale(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Reconnect a previously disconnected Tailscale agent."""
    setup = get_tailscale_setup()
    # reconnect uses `tailscale up --reset` (wipes prefs); re-resolve + re-apply
    # the NetBird-coexistence netfilter mode so it survives the reconnect.
    netfilter_mode = await _resolve_tailscale_netfilter_mode(session, _org_id(user))
    result = await setup.reconnect(netfilter_mode=netfilter_mode)
    return TailscaleActionResponse(**result)


@router.post("/tailscale/setup/logout", response_model=TailscaleActionResponse)
async def logout_tailscale(
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Fully deauthorize and remove this node from the Tailscale network."""
    setup = get_tailscale_setup()
    result = await setup.logout()
    return TailscaleActionResponse(**result)


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/wireguard/interfaces", response_model=list[str])
async def list_wireguard_interfaces(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List WireGuard interfaces."""
    wg = WireGuardService()
    return await wg.get_interfaces()


@router.get("/wireguard/interfaces/{iface}")
async def get_wireguard_interface(
    iface: str,
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get WireGuard interface health status."""
    _validate_vpn_name(iface, "interface name")
    wg = WireGuardService()
    health = await wg.check_tunnel_health(iface)
    return health


# ─────────────────────────────────────────────────────────────────────────────
# Netbird
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/netbird/status", response_model=NetbirdStatusResponse)
async def get_netbird_status(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get Netbird daemon status."""
    nb = NetbirdService()
    nb_status = await nb.get_status(refresh=True)

    peers = []
    for p in nb_status.get("peers", []):
        peers.append(NetbirdPeerResponse(**p))

    return NetbirdStatusResponse(
        connected=nb_status.get("connected", False),
        management_state=nb_status.get("management_state", "Unknown"),
        signal_state=nb_status.get("signal_state", "Unknown"),
        management_url=nb_status.get("management_url"),
        self_ip=nb_status.get("self_ip"),
        fqdn=nb_status.get("fqdn"),
        interface=nb_status.get("interface"),
        peers=peers,
        peer_count=nb_status.get("peer_count", 0),
        connected_peers=nb_status.get("connected_peers", 0),
    )


@router.get("/netbird/peers", response_model=list[NetbirdPeerResponse])
async def list_netbird_peers(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all Netbird peers."""
    nb = NetbirdService()
    peers = await nb.list_peers()
    return [NetbirdPeerResponse(**p) for p in peers]


@router.post("/netbird/ping")
async def ping_netbird_target(
    target: str = Query(...),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Ping a Netbird peer."""
    if not _PING_TARGET_RE.match(target):
        raise HTTPException(status_code=400, detail="Invalid ping target (IP or hostname expected)")
    nb = NetbirdService()
    latency = await nb.ping(target)
    return {
        "target": target,
        "reachable": latency is not None,
        "latency_ms": latency,
    }


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/openvpn/connections")
async def list_openvpn_connections(
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List configured OpenVPN connections."""
    ovpn = OpenVPNService()
    connections = await ovpn.get_connections()
    return [
        {
            "name": c.name,
            "status": c.status.value if hasattr(c.status, "value") else c.status,
            "vpn_type": "openvpn",
            "config_path": c.extra_data.get("config_path"),
        }
        for c in connections
    ]


@router.get("/openvpn/connections/{name}", response_model=OpenVPNStatusResponse)
async def get_openvpn_connection(
    name: str,
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get OpenVPN connection status."""
    _validate_vpn_name(name, "connection name")
    ovpn = OpenVPNService()
    status_data = await ovpn.get_status(name)
    return OpenVPNStatusResponse(**status_data)


# ─────────────────────────────────────────────────────────────────────────────
# Site VPN Config
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/sites/{site_id}/config", response_model=SiteVPNConfigResponse)
async def get_site_vpn_config(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get VPN configuration for a site."""
    await _verify_site_org(session, site_id, user)
    config = await svc.get_site_config(session, site_id)
    if not config:
        raise HTTPException(status_code=404, detail="No VPN config for this site")
    return config


@router.put("/sites/{site_id}/config", response_model=SiteVPNConfigResponse)
async def update_site_vpn_config(
    site_id: UUID,
    data: SiteVPNConfigUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create or update VPN configuration for a site."""
    await _verify_site_org(session, site_id, user)
    config = await svc.upsert_site_config(
        session,
        site_id,
        data.model_dump(exclude_unset=True),
        created_by=user.id,
    )
    return config


@router.post("/sites/{site_id}/test")
async def test_site_vpn(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Test VPN connectivity for a site."""
    await _verify_site_org(session, site_id, user)
    config = await svc.get_site_config(session, site_id)
    if not config:
        raise HTTPException(status_code=404, detail="No VPN config for this site")

    result: dict[str, Any] = {
        "site_id": str(site_id),
        "vpn_type": config.vpn_type,
        "vpn_connected": False,
        "latency_ms": None,
    }

    manager = get_vpn_manager()

    if config.health_check_ip:
        if config.vpn_type in ("tailscale", "generic"):
            conn_result = await manager.tailscale.check_connectivity(config.health_check_ip)
            result["vpn_connected"] = conn_result.get("reachable", False)
            result["latency_ms"] = conn_result.get("latency_ms")
        elif config.vpn_type == "netbird":
            latency = await manager.netbird.ping(config.health_check_ip)
            result["vpn_connected"] = latency is not None
            result["latency_ms"] = latency
        elif config.vpn_type == "openvpn":
            latency = await manager.tailscale.ping(config.health_check_ip)
            result["vpn_connected"] = latency is not None
            result["latency_ms"] = latency
        elif config.vpn_type == "wireguard" and config.wireguard_interface:
            wg_health = await manager.wireguard.check_tunnel_health(
                config.wireguard_interface,
            )
            result["vpn_connected"] = wg_health.get("healthy", False)

    # Update status
    new_status = "connected" if result["vpn_connected"] else "disconnected"
    config.status = new_status
    config.last_health_check = datetime.now(UTC)
    await session.flush()

    return result


# =============================================================================
# WireGuard Agent Provisioning
# =============================================================================


class _ProvisionAgentRequest(BaseModel):
    """Typed, validated request for WireGuard agent provisioning."""

    site_id: UUID
    server_public_key: str = Field(min_length=44, max_length=44, pattern=r"^[A-Za-z0-9+/]{43}=$")
    server_endpoint: str = Field(max_length=253, pattern=r"^[a-zA-Z0-9.\-]+:\d{1,5}$")
    agent_address: str = Field(max_length=43)
    site_subnets: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("agent_address")
    @classmethod
    def validate_agent_address(cls, v: str) -> str:
        import ipaddress as _ip

        try:
            _ip.ip_interface(v.strip())
        except ValueError:
            raise ValueError(f"Invalid agent address: {v}")
        return v.strip()

    @field_validator("site_subnets")
    @classmethod
    def validate_subnets(cls, v: list[str]) -> list[str]:
        import ipaddress as _ip

        validated = []
        for s in v:
            try:
                validated.append(str(_ip.ip_network(s.strip(), strict=False)))
            except ValueError:
                raise ValueError(f"Invalid CIDR in site_subnets: {s}")
        return validated

    @field_validator("server_endpoint")
    @classmethod
    def validate_port(cls, v: str) -> str:
        port = int(v.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")
        return v


@router.post(
    "/wireguard/provision-agent",
    summary="Generate WireGuard config for an agent at a site",
)
async def provision_agent_wireguard(
    payload: _ProvisionAgentRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Generate a WireGuard keypair for a site agent and return:
    - Agent's WireGuard config (INI)
    - Server peer block to append
    - Keys for storage

    All inputs are validated via Pydantic (CIDR, base64 key, host:port).
    Private key is returned ONE TIME — the caller must store it securely.
    """
    try:
        # Verify site access (org-scoped)
        org_id = _org_id(current_user)
        site = (
            await session.execute(
                select(Site).where(
                    Site.id == payload.site_id,
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if not site:
            raise HTTPException(404, detail="Site not found")
        # Per-user site grant: a site-limited operator must not provision a
        # WireGuard agent (generate keys + write SiteVPNConfiguration) for a
        # sibling site in the same org. No-op for super_admin / org_admin; 404
        # to avoid an existence oracle.
        assert_can_access_site(current_user, payload.site_id, detail="Site not found")

        # Generate keypair (CSPRNG Curve25519)
        agent_private_key, agent_public_key = WireGuardService.generate_keypair()

        # Generate agent config (all values pre-validated by Pydantic + WireGuardService)
        agent_config = WireGuardService.generate_agent_config(
            agent_private_key=agent_private_key,
            agent_address=payload.agent_address,
            server_public_key=payload.server_public_key,
            server_endpoint=payload.server_endpoint,
            allowed_ips=["10.100.0.0/16"] + payload.site_subnets,
            persistent_keepalive=25,
        )

        # Generate server peer block
        import ipaddress as _ip

        agent_host = str(_ip.ip_interface(payload.agent_address).ip)
        agent_allowed_ips = [f"{agent_host}/32"] + payload.site_subnets
        server_peer = WireGuardService.generate_server_peer_block(
            agent_public_key=agent_public_key,
            agent_allowed_ips=agent_allowed_ips,
        )

        # Update site VPN config if not already configured
        from app.models.vpn import SiteVPNConfiguration

        vpn_config = (
            await session.execute(
                select(SiteVPNConfiguration).where(
                    SiteVPNConfiguration.site_id == site.id,
                    SiteVPNConfiguration.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()

        if not vpn_config:
            vpn_config = SiteVPNConfiguration(
                site_id=site.id,
                organization_id=org_id,
                vpn_type="wireguard",
                enabled=True,
                wireguard_peer_public_key=agent_public_key,
                remote_subnets=payload.site_subnets,
                status="disconnected",
            )
            session.add(vpn_config)
        else:
            vpn_config.wireguard_peer_public_key = agent_public_key

        await session.flush()

        return {
            "agent_private_key": agent_private_key,
            "agent_public_key": agent_public_key,
            "agent_config": agent_config,
            "server_peer_block": server_peer,
            "agent_address": payload.agent_address,
            "site_id": str(site.id),
            "site_name": site.name,
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, detail="Failed to provision WireGuard agent")


# =============================================================================
# Brain VPN Integration — Connect via site's brain (firewall/gateway)
# =============================================================================


@router.get(
    "/brain/{controller_id}/servers",
    summary="Discover VPN servers running on a brain controller",
)
async def discover_brain_vpn_servers(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """
    Query a brain controller (OPNsense/pfSense/MikroTik/OpenWrt) for its
    available VPN servers: OpenVPN, WireGuard, IPsec.

    The brain device already has VPN capabilities built-in. This endpoint
    lists what's available so FreeSDN can connect to it.
    """
    from app.services.brain_vpn import BrainVPNService

    try:
        svc_brain = BrainVPNService(session)
        return await svc_brain.discover_vpn_servers(controller_id, _org_id(current_user))
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc))
    except Exception:
        raise HTTPException(500, detail="Failed to discover VPN servers on brain")


@router.post(
    "/brain/{controller_id}/import",
    summary="Import VPN config from a brain controller into site config",
)
async def import_brain_vpn(
    controller_id: UUID,
    payload: "_BrainVPNImportRequest",
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Import a VPN server config from the brain into the site's VPN configuration.

    After import, FreeSDN knows how to connect to the brain's VPN server,
    gaining L3 access to all subnets behind the brain.
    """
    assert_can_access_site(current_user, payload.site_id, detail="Site not found")
    from app.services.brain_vpn import BrainVPNService

    try:
        svc_brain = BrainVPNService(session)
        config = await svc_brain.import_from_brain(
            controller_id=controller_id,
            org_id=_org_id(current_user),
            vpn_type=payload.vpn_type,
            vpn_server_id=payload.vpn_server_id,
            site_id=payload.site_id,
        )
        return {
            "success": True,
            "message": f"Imported {payload.vpn_type} config from brain",
            "vpn_config_id": str(config.id),
            "vpn_type": config.vpn_type,
            "vpn_endpoint": config.vpn_endpoint,
            "remote_subnets": config.remote_subnets,
        }
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc))
    except Exception:
        raise HTTPException(500, detail="Failed to import VPN config from brain")


@router.post(
    "/brain/{controller_id}/sync-subnets",
    summary="Pull subnets from brain's routing table into site",
)
async def sync_brain_subnets(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Pull the brain's routing table / interface subnets and merge into Site.subnets.

    The brain (firewall/gateway) is the site's router — it knows every subnet.
    This is more reliable than agent-based subnet discovery.
    """
    from app.services.brain_vpn import BrainVPNService

    try:
        svc_brain = BrainVPNService(session)
        result = await svc_brain.sync_subnets_from_brain(controller_id, _org_id(current_user))
        return {
            "success": True,
            "message": f"Synced {result['added']} subnet(s) from {result['controller']}",
            **result,
        }
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc))
    except Exception:
        raise HTTPException(500, detail="Failed to sync subnets from brain")


@router.post(
    "/openvpn/import-config",
    summary="Import an OpenVPN .ovpn config for a site",
)
async def import_openvpn_config(
    payload: "_OpenVPNImportRequest",
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """
    Import an OpenVPN client config (.ovpn file content) for a site.

    The config is validated for:
    - Size limits (max 100KB)
    - Dangerous directives (script-security, up/down hooks, plugin)
    - Structure (remote, protocol, port extraction)
    """
    assert_can_access_site(current_user, payload.site_id, detail="Site not found")
    from app.services.brain_vpn import BrainVPNService

    try:
        svc_brain = BrainVPNService(session)
        config = await svc_brain.import_openvpn_config(
            site_id=payload.site_id,
            org_id=_org_id(current_user),
            config_content=payload.config_content,
            description=payload.description,
        )
        return {
            "success": True,
            "message": "OpenVPN config imported",
            "vpn_config_id": str(config.id),
            "vpn_endpoint": config.vpn_endpoint,
            "protocol": config.openvpn_protocol,
            "port": config.vpn_port,
        }
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc))
    except Exception:
        raise HTTPException(500, detail="Failed to import OpenVPN config")


# =============================================================================
# Health History API
# =============================================================================


@router.get(
    "/connections/{connection_id}/health-history",
    summary="Get health check time-series for a VPN connection",
)
async def get_health_history(
    connection_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Return time-series health data for a VPN connection."""
    org_id = _org_id(current_user)
    # Verify connection belongs to user's org
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, detail="Connection not found")

    history = await svc.get_health_history(
        logdb, connection_id=connection_id, hours=hours, limit=limit
    )
    return history


# =============================================================================
# Auto-Reconnect Status
# =============================================================================


@router.get(
    "/connections/{connection_id}/reconnect-status",
    summary="Get auto-reconnect state for a VPN connection",
)
async def get_reconnect_status(
    connection_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Return current reconnect state (attempts, next retry, backoff)."""
    org_id = _org_id(current_user)
    # Verify connection belongs to user's org
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, detail="Connection not found")

    from app.services.vpn_reconnect import VPNReconnectService

    reconnect_svc = VPNReconnectService(session)
    status = await reconnect_svc.get_reconnect_status(connection_id)
    if not status:
        return {
            "connection_id": str(connection_id),
            "attempt_count": 0,
            "max_attempts": 10,
            "next_retry_at": None,
            "backoff_seconds": 30,
            "state": "idle",
            "last_error": None,
        }
    return status


@router.post(
    "/connections/{connection_id}/reconnect-reset",
    summary="Reset exhausted auto-reconnect state",
)
async def reset_reconnect_state(
    connection_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Reset an exhausted reconnect state for manual retry."""
    org_id = _org_id(current_user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, detail="Connection not found")

    from app.services.vpn_reconnect import VPNReconnectService

    reconnect_svc = VPNReconnectService(session)
    reset = await reconnect_svc.reset_reconnect_state(connection_id)
    await session.commit()
    return {
        "success": reset,
        "message": "Reconnect state reset" if reset else "No reconnect state found",
    }


# =============================================================================
# Pre-flight VPN Check
# =============================================================================


@router.post(
    "/preflight/site/{site_id}",
    summary="Check VPN connectivity to a site",
)
async def preflight_site(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Pre-flight check: verify VPN connectivity before device operations."""
    await _verify_site_org(session, site_id, current_user)

    from app.services.vpn_preflight import VPNPreflightService

    preflight_svc = VPNPreflightService(session)
    result = await preflight_svc.check_site_reachable(site_id)
    return {
        "reachable": result.reachable,
        "vpn_type": result.vpn_type,
        "latency_ms": result.latency_ms,
        "vpn_status": result.vpn_status,
        "error": result.error,
        "skipped": result.skipped,
    }


@router.post(
    "/preflight/device/{device_id}",
    summary="Check VPN connectivity to a specific device",
)
async def preflight_device(
    device_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Pre-flight check: verify VPN connectivity to a specific device."""
    # Verify device belongs to user's org via site
    from app.models import Device

    org_id = _org_id(current_user)
    dev_result = await session.execute(
        select(Device)
        .where(Device.id == device_id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Site.organization_id == org_id,
        )
    )
    device = dev_result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")
    # Enforce the per-user site grant on the device's OWN site: a site-limited
    # operator must not preflight a device in a sibling site of the same org.
    # No-op for super_admin / org_admin; 404 to avoid an existence oracle.
    assert_can_access_site(
        current_user, getattr(device, "site_id", None), detail="Device not found"
    )

    from app.services.vpn_preflight import VPNPreflightService

    preflight_svc = VPNPreflightService(session)
    result = await preflight_svc.check_device_reachable(device_id, organization_id=org_id)
    return {
        "reachable": result.reachable,
        "vpn_type": result.vpn_type,
        "latency_ms": result.latency_ms,
        "vpn_status": result.vpn_status,
        "error": result.error,
        "skipped": result.skipped,
    }


# =============================================================================
# VPN Event Log
# =============================================================================


@router.get(
    "/events",
    summary="List VPN events (audit trail)",
)
async def list_vpn_events(
    site_id: UUID | None = Query(None),
    event_type: str | None = Query(None, max_length=50),
    severity: str | None = Query(None, pattern=r"^(info|warning|error|critical)$"),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List VPN events with optional filters."""
    from sqlalchemy import func

    from app.core.site_access import site_scope_filter
    from app.models.vpn import VPNEvent

    org_id = _org_id(current_user)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    # Per-user site grant: a site-limited operator only sees events for sites
    # they're granted (events with NULL site_id are org-level and excluded by
    # the IN-filter). No-op for super_admin / org_admin.
    site_scope = site_scope_filter(current_user, VPNEvent.site_id)

    stmt = select(VPNEvent).where(
        VPNEvent.organization_id == org_id,
        VPNEvent.created_at >= cutoff,
        site_scope,
    )
    count_stmt = (
        select(func.count())
        .select_from(VPNEvent)
        .where(
            VPNEvent.organization_id == org_id,
            VPNEvent.created_at >= cutoff,
            site_scope,
        )
    )

    if site_id:
        stmt = stmt.where(VPNEvent.site_id == site_id)
        count_stmt = count_stmt.where(VPNEvent.site_id == site_id)
    if event_type:
        stmt = stmt.where(VPNEvent.event_type == event_type)
        count_stmt = count_stmt.where(VPNEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(VPNEvent.severity == severity)
        count_stmt = count_stmt.where(VPNEvent.severity == severity)

    total = (await session.execute(count_stmt)).scalar() or 0
    stmt = stmt.order_by(VPNEvent.created_at.desc()).offset(offset).limit(limit)
    events = (await session.execute(stmt)).scalars().all()

    return {
        "events": [
            {
                "id": str(e.id),
                "organization_id": str(e.organization_id),
                "site_id": str(e.site_id) if e.site_id else None,
                "connection_id": str(e.connection_id) if e.connection_id else None,
                "tunnel_id": str(e.tunnel_id) if e.tunnel_id else None,
                "event_type": e.event_type,
                "severity": e.severity,
                "title": e.title,
                "details": e.details,
                "source": e.source,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "total": total,
    }


@router.get(
    "/events/summary",
    summary="VPN event counts by type and severity",
)
async def vpn_events_summary(
    hours: int = Query(24, ge=1, le=720),
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Event counts by type and severity for dashboard widgets."""
    from sqlalchemy import func

    from app.core.site_access import site_scope_filter
    from app.models.vpn import VPNEvent

    org_id = _org_id(current_user)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    # Per-user site grant: a site-limited operator's summary counts only events
    # for sites they're granted. No-op for super_admin / org_admin.
    site_scope = site_scope_filter(current_user, VPNEvent.site_id)

    # By severity
    sev_q = (
        select(
            VPNEvent.severity,
            func.count().label("cnt"),
        )
        .where(
            VPNEvent.organization_id == org_id,
            VPNEvent.created_at >= cutoff,
            site_scope,
        )
        .group_by(VPNEvent.severity)
    )

    sev_rows = (await session.execute(sev_q)).all()
    by_severity = {r.severity: r.cnt for r in sev_rows}

    # By type
    type_q = (
        select(
            VPNEvent.event_type,
            func.count().label("cnt"),
        )
        .where(
            VPNEvent.organization_id == org_id,
            VPNEvent.created_at >= cutoff,
            site_scope,
        )
        .group_by(VPNEvent.event_type)
    )

    type_rows = (await session.execute(type_q)).all()
    by_type = {r.event_type: r.cnt for r in type_rows}

    total = sum(by_severity.values())

    return {
        "total": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "period_hours": hours,
    }


# =============================================================================
# Bandwidth / Latency Metrics
# =============================================================================


@router.get(
    "/connections/{connection_id}/metrics",
    summary="Time-series bandwidth/latency metrics for a connection",
)
async def get_connection_metrics(
    connection_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    interval: str = Query("5m", pattern=r"^(5m|1h|1d)$"),
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Time-bucketed bandwidth/latency metrics."""
    from sqlalchemy import text

    # Ownership check against primary DB
    org_id = _org_id(current_user)
    result = await session.execute(
        select(VPNConnectionRecord).where(
            VPNConnectionRecord.id == connection_id,
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, detail="Connection not found")

    # timedelta (not a string): asyncpg encodes it as a PG interval natively.
    interval_map = {"5m": timedelta(minutes=5), "1h": timedelta(hours=1), "1d": timedelta(days=1)}
    pg_interval = interval_map[interval]

    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    # Time-series query against LogDB (TimescaleDB)
    rows = await logdb.execute(
        text("""
            SELECT
                time_bucket(:interval, time) AS bucket,
                AVG(latency_ms) AS avg_latency_ms,
                MAX(latency_ms) AS max_latency_ms,
                MAX(rx_bytes) - MIN(rx_bytes) AS rx_bytes_delta,
                MAX(tx_bytes) - MIN(tx_bytes) AS tx_bytes_delta,
                AVG(CASE WHEN is_healthy THEN 100.0 ELSE 0.0 END) AS health_pct
            FROM vpn.vpn_health_checks
            WHERE connection_id = :conn_id AND time >= :cutoff
            GROUP BY bucket
            ORDER BY bucket DESC
            LIMIT 500
        """),
        {"interval": pg_interval, "conn_id": connection_id, "cutoff": cutoff},
    )

    return [
        {
            "time": r.bucket.isoformat() if r.bucket else None,
            "avg_latency_ms": round(r.avg_latency_ms, 2) if r.avg_latency_ms else None,
            "max_latency_ms": round(r.max_latency_ms, 2) if r.max_latency_ms else None,
            "rx_bytes_delta": max(r.rx_bytes_delta or 0, 0),
            "tx_bytes_delta": max(r.tx_bytes_delta or 0, 0),
            "health_pct": round(r.health_pct or 100, 1),
        }
        for r in rows.fetchall()
    ]


@router.get(
    "/metrics/aggregate",
    summary="Org-wide aggregate VPN bandwidth metrics",
)
async def get_aggregate_metrics(
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Org-wide aggregate bandwidth and latency metrics."""
    from sqlalchemy import func

    org_id = _org_id(current_user)

    q = select(
        func.count().label("count"),
        func.sum(VPNConnectionRecord.rx_bytes).label("total_rx"),
        func.sum(VPNConnectionRecord.tx_bytes).label("total_tx"),
        func.avg(VPNConnectionRecord.latency_ms).label("avg_latency"),
    ).where(VPNConnectionRecord.organization_id == org_id)

    row = (await session.execute(q)).one()

    # Per-provider breakdown
    provider_q = (
        select(
            VPNConnectionRecord.vpn_type,
            func.count().label("count"),
            func.sum(VPNConnectionRecord.rx_bytes).label("rx"),
            func.sum(VPNConnectionRecord.tx_bytes).label("tx"),
            func.avg(VPNConnectionRecord.latency_ms).label("avg_lat"),
        )
        .where(
            VPNConnectionRecord.organization_id == org_id,
        )
        .group_by(VPNConnectionRecord.vpn_type)
    )

    provider_rows = (await session.execute(provider_q)).all()
    by_provider = {
        r.vpn_type: {
            "count": r.count,
            "rx_bytes": r.rx or 0,
            "tx_bytes": r.tx or 0,
            "avg_latency_ms": round(r.avg_lat, 2) if r.avg_lat else None,
        }
        for r in provider_rows
    }

    return {
        "total_rx_bytes": row.total_rx or 0,
        "total_tx_bytes": row.total_tx or 0,
        "avg_latency_ms": round(row.avg_latency, 2) if row.avg_latency else None,
        "connection_count": row.count or 0,
        "by_provider": by_provider,
    }


# =============================================================================
# Configurable Health Check
# =============================================================================


@router.put(
    "/sites/{site_id}/health-config",
    summary="Update health check settings for a site VPN config",
)
async def update_health_config(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
    health_check_interval: int | None = Query(None, ge=30, le=3600),
    health_check_ip: str | None = Query(None, max_length=45),
    latency_threshold_ms: int | None = Query(None, ge=50, le=5000),
) -> Any:
    """Update health check interval, IP, and latency threshold for a site."""
    await _verify_site_org(session, site_id, current_user)

    from app.models.vpn import SiteVPNConfiguration

    org_id = _org_id(current_user)
    result = await session.execute(
        select(SiteVPNConfiguration).where(
            SiteVPNConfiguration.site_id == site_id,
            SiteVPNConfiguration.organization_id == org_id,
        )
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(404, detail="No VPN configuration for this site")

    if health_check_interval is not None:
        config.health_check_interval = health_check_interval
    if health_check_ip is not None:
        if health_check_ip:
            import ipaddress as _ipa

            try:
                addr = _ipa.ip_address(health_check_ip)
            except ValueError:
                raise HTTPException(400, detail="Invalid IP address format")
            if addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise HTTPException(
                    400, detail="health_check_ip must not be loopback, link-local, or reserved"
                )
        config.health_check_ip = health_check_ip or None
    if latency_threshold_ms is not None:
        config.latency_threshold_ms = latency_threshold_ms

    await session.commit()
    return {
        "success": True,
        "health_check_interval": config.health_check_interval,
        "health_check_ip": config.health_check_ip,
        "latency_threshold_ms": config.latency_threshold_ms,
    }


# =============================================================================
# Device Reachability Map
# =============================================================================


@router.get(
    "/sites/{site_id}/reachability",
    summary="Check VPN reachability to all devices at a site",
)
async def site_reachability(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Per-device reachability check through VPN tunnel."""
    await _verify_site_org(session, site_id, current_user)

    from app.services.vpn_preflight import VPNPreflightService

    preflight_svc = VPNPreflightService(session)
    devices = await preflight_svc.check_site_device_reachability(site_id, _org_id(current_user))
    return {
        "site_id": str(site_id),
        "devices": [
            {
                "device_id": d.device_id,
                "device_name": d.device_name,
                "device_type": d.device_type,
                "ip": d.ip,
                "reachable": d.reachable,
                "latency_ms": d.latency_ms,
                "error": d.error,
            }
            for d in devices
        ],
    }


# =============================================================================
# VPN Dashboard Widget
# =============================================================================


@router.get(
    "/dashboard",
    summary="Pre-aggregated VPN dashboard data",
)
async def vpn_dashboard(
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Pre-aggregated dashboard data (connection health, S2S status, alerts, bandwidth)."""
    from sqlalchemy import func, or_

    from app.core.site_access import site_ids_for_request, site_scope_filter
    from app.models.vpn import SiteToSiteTunnel, SiteVPNConfiguration, VPNEvent

    org_id = _org_id(current_user)

    # Per-user site grant for the site-scoped aggregates below. ``None`` ⇒ the
    # caller is unrestricted (super_admin / org_admin) and sees the whole org.
    granted_site_ids = site_ids_for_request(current_user)

    # Connection stats.
    # EXPLICIT cross-site policy: VPNConnectionRecord has NO site_id column
    # (connections are org-level, not site-scoped — see app/models/vpn.py), so
    # there is no per-site dimension to restrict. A site-limited operator with
    # vpn:read sees the org-level connection rollup, by design. The
    # regression test pins this policy so it can't silently regress.
    conn_q = (
        select(
            func.count().label("total"),
            func.count().filter(VPNConnectionRecord.status == "connected").label("connected"),
            func.count().filter(VPNConnectionRecord.status == "error").label("errors"),
            func.avg(VPNConnectionRecord.latency_ms).label("avg_lat"),
            func.sum(VPNConnectionRecord.rx_bytes).label("rx"),
            func.sum(VPNConnectionRecord.tx_bytes).label("tx"),
        )
        .select_from(VPNConnectionRecord)
        .where(
            VPNConnectionRecord.organization_id == org_id,
        )
    )
    conn_row = (await session.execute(conn_q)).one()

    # S2S tunnel stats. A tunnel spans two sites (site_a_id / site_b_id); a
    # site-limited operator only counts tunnels touching a site they're granted.
    tunnel_q = (
        select(
            func.count().label("total"),
            func.count().filter(SiteToSiteTunnel.status == "active").label("active"),
            func.count().filter(SiteToSiteTunnel.status == "error").label("errors"),
        )
        .select_from(SiteToSiteTunnel)
        .where(
            SiteToSiteTunnel.organization_id == org_id,
        )
    )
    if granted_site_ids is not None:
        ids = list(granted_site_ids)
        tunnel_q = tunnel_q.where(
            or_(
                SiteToSiteTunnel.site_a_id.in_(ids),
                SiteToSiteTunnel.site_b_id.in_(ids),
            )
            if ids
            else SiteToSiteTunnel.id.in_([])
        )
    try:
        tunnel_row = (await session.execute(tunnel_q)).one()
        active_tunnels = tunnel_row.active
        error_tunnels = tunnel_row.errors
    except Exception:
        active_tunnels = 0
        error_tunnels = 0

    # VPN alerts (last 24h) — scoped to the caller's granted sites.
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    try:
        alert_count = (
            await session.execute(
                select(func.count())
                .select_from(VPNEvent)
                .where(
                    VPNEvent.organization_id == org_id,
                    VPNEvent.severity.in_(["warning", "error", "critical"]),
                    VPNEvent.created_at >= cutoff,
                    site_scope_filter(current_user, VPNEvent.site_id),
                )
            )
        ).scalar() or 0
    except Exception:
        alert_count = 0

    # Sites with VPN — scoped to the caller's granted sites.
    try:
        site_stats = (
            await session.execute(
                select(
                    func.count().label("total"),
                    func.count()
                    .filter(SiteVPNConfiguration.status == "connected")
                    .label("healthy"),
                )
                .select_from(SiteVPNConfiguration)
                .where(
                    SiteVPNConfiguration.organization_id == org_id,
                    site_scope_filter(current_user, SiteVPNConfiguration.site_id),
                )
            )
        ).one()
        sites_with_vpn = site_stats.total
        sites_healthy = site_stats.healthy
    except Exception:
        sites_with_vpn = 0
        sites_healthy = 0

    healthy_pct = (
        round(conn_row.connected / conn_row.total * 100, 1) if conn_row.total > 0 else 100.0
    )

    return {
        "active_connections": conn_row.connected or 0,
        "healthy_pct": healthy_pct,
        "avg_latency_ms": round(conn_row.avg_lat, 2) if conn_row.avg_lat else None,
        "total_rx_bytes": conn_row.rx or 0,
        "total_tx_bytes": conn_row.tx or 0,
        "active_tunnels": active_tunnels,
        "error_tunnels": error_tunnels,
        "vpn_alerts": alert_count,
        "sites_with_vpn": sites_with_vpn,
        "sites_healthy": sites_healthy,
    }


# =============================================================================
# Multi-VPN Per Site
# =============================================================================


@router.get(
    "/sites/{site_id}/configs",
    summary="List all VPN configurations for a site",
)
async def list_site_vpn_configs(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Return all VPN configs for a site (multi-VPN support)."""
    await _verify_site_org(session, site_id, current_user)
    from app.models.vpn import SiteVPNConfiguration

    result = await session.execute(
        select(SiteVPNConfiguration)
        .where(SiteVPNConfiguration.site_id == site_id)
        .order_by(SiteVPNConfiguration.priority.desc(), SiteVPNConfiguration.created_at)
    )
    configs = result.scalars().all()
    return {
        "configs": [SiteVPNConfigResponse.model_validate(c) for c in configs],
        "total": len(configs),
    }


@router.post(
    "/sites/{site_id}/configs",
    summary="Add a VPN configuration to a site",
    status_code=201,
)
async def create_site_vpn_config(
    site_id: UUID,
    data: SiteVPNConfigCreate,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create an additional VPN configuration for a site (multi-VPN)."""
    site = await _verify_site_org(session, site_id, current_user)
    from app.models.vpn import SiteVPNConfiguration

    config = SiteVPNConfiguration(
        site_id=site_id,
        organization_id=site.organization_id,
        **data.model_dump(),
    )
    session.add(config)

    # If marked as primary, demote other configs
    if data.is_primary:
        existing = await session.execute(
            select(SiteVPNConfiguration).where(
                SiteVPNConfiguration.site_id == site_id,
                SiteVPNConfiguration.id != config.id,
                SiteVPNConfiguration.is_primary.is_(True),
            )
        )
        for c in existing.scalars().all():
            c.is_primary = False

    await session.commit()
    await session.refresh(config)
    return SiteVPNConfigResponse.model_validate(config)


@router.delete(
    "/sites/{site_id}/configs/{config_id}",
    summary="Delete a specific VPN configuration from a site",
    status_code=204,
)
async def delete_site_vpn_config(
    site_id: UUID,
    config_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> None:
    """Delete a specific VPN configuration from a site."""
    await _verify_site_org(session, site_id, current_user)
    from app.models.vpn import SiteVPNConfiguration

    result = await session.execute(
        select(SiteVPNConfiguration).where(
            SiteVPNConfiguration.id == config_id,
            SiteVPNConfiguration.site_id == site_id,
        )
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="VPN config not found")
    await session.delete(config)
    await session.commit()


@router.put(
    "/sites/{site_id}/configs/{config_id}/primary",
    summary="Set a VPN config as primary for a site",
)
async def set_primary_vpn_config(
    site_id: UUID,
    config_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Set a specific VPN configuration as the primary for a site."""
    await _verify_site_org(session, site_id, current_user)
    from app.models.vpn import SiteVPNConfiguration

    result = await session.execute(
        select(SiteVPNConfiguration).where(
            SiteVPNConfiguration.id == config_id,
            SiteVPNConfiguration.site_id == site_id,
        )
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="VPN config not found")

    # Demote all others
    all_result = await session.execute(
        select(SiteVPNConfiguration).where(
            SiteVPNConfiguration.site_id == site_id,
            SiteVPNConfiguration.is_primary.is_(True),
        )
    )
    for c in all_result.scalars().all():
        c.is_primary = False

    config.is_primary = True
    await session.commit()
    return {"success": True, "primary_config_id": str(config_id)}


# =============================================================================
# Route Conflict Detection
# =============================================================================


@router.get(
    "/routes/conflicts",
    summary="Detect overlapping VPN route/subnet conflicts",
)
async def detect_route_conflicts(
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Analyze all VPN connections, tunnels, and site configs for overlapping subnets."""
    from app.services.vpn_route_conflicts import VPNRouteConflictService

    svc_conflicts = VPNRouteConflictService(session)
    return await svc_conflicts.detect_conflicts(_org_id(current_user))


# =============================================================================
# Certificate Lifecycle
# =============================================================================


@router.get(
    "/certs/expiring",
    summary="List VPN certificates approaching expiry",
)
async def list_expiring_certs(
    days: int = Query(30, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List all VPN certificates that expire within the given number of days."""
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    cert_svc = VPNCertLifecycleService(session)
    certs = await cert_svc.get_expiring_certs(_org_id(current_user), days_ahead=days)
    return {"certs": certs, "total": len(certs)}


@router.post(
    "/certs/scan",
    summary="Scan VPN configs for certificates and update metadata",
)
async def scan_certificates(
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Scan all site VPN configs for X.509 certificates and update metadata."""
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    cert_svc = VPNCertLifecycleService(session)
    result = await cert_svc.scan_certificates(_org_id(current_user))
    await session.commit()
    return result


# =============================================================================
# Auto WireGuard Key Exchange
# =============================================================================


@router.post(
    "/tunnels/{tunnel_id}/generate-keys",
    summary="Generate WireGuard keypairs for a S2S tunnel",
)
async def generate_tunnel_keys(
    tunnel_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
    site_a_endpoint: str | None = Query(None, max_length=253),
    site_b_endpoint: str | None = Query(None, max_length=253),
    site_a_port: int = Query(51820, ge=1, le=65535),
    site_b_port: int = Query(51821, ge=1, le=65535),
    mtu: int | None = Query(None, ge=576, le=9000),
) -> Any:
    """Generate WireGuard keypairs and configs for both sides of a S2S tunnel."""
    from app.services.vpn_key_exchange import VPNKeyExchangeService

    key_svc = VPNKeyExchangeService(session)
    result = await key_svc.generate_s2s_wireguard_config(
        tunnel_id=tunnel_id,
        org_id=_org_id(current_user),
        site_a_endpoint=site_a_endpoint,
        site_b_endpoint=site_b_endpoint,
        site_a_port=site_a_port,
        site_b_port=site_b_port,
        mtu=mtu,
    )
    await session.commit()
    return result


@router.post(
    "/tunnels/{tunnel_id}/push-config/{side}",
    summary="Push WireGuard config to a gateway device",
)
async def push_tunnel_config(
    tunnel_id: UUID,
    side: str,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Push WireGuard config to the gateway device on the specified side (a or b)."""
    if side not in ("a", "b"):
        raise HTTPException(400, detail="side must be 'a' or 'b'")
    from app.services.vpn_key_exchange import VPNKeyExchangeService

    key_svc = VPNKeyExchangeService(session)
    return await key_svc.push_config_to_gateway(
        tunnel_id=tunnel_id,
        org_id=_org_id(current_user),
        side=side,
    )
