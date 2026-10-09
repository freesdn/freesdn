# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Agent Downloads API
===================================

Endpoints for agent release management and download distribution.

Public (no auth):
  GET  /agents/downloads/latest       → latest release for platform/type
  GET  /agents/downloads/versions     → all available versions
  GET  /agents/downloads/page         → aggregated downloads-page payload
  GET  /agents/updates/check          → agent self-update check

Admin only:
  POST /agents/downloads/releases     → publish a new release
"""

import hashlib
import logging
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.models.agents import AgentRelease, RemoteAgent
from app.schemas.agent_downloads import (
    AgentReleaseLatest,
    AgentReleaseSummary,
    AgentUpdateCheckResponse,
    DownloadsPageResponse,
    PlatformInstallInfo,
)

VALID_PLATFORMS = {"windows", "linux", "macos"}
VALID_AGENT_TYPES = {"daemon", "desktop"}

logger = logging.getLogger(__name__)


def _release_org_bucket(org_id: "UUID | None") -> Any:
    """Predicate selecting the is_latest bucket for an org.

    A release's organization_id partitions the is_latest namespace: NULL is the
    GLOBAL (super_admin-published) bucket, a non-NULL id is that org's bucket.
    Clearing/serving must stay within one bucket so a tenant admin can never
    touch the global or another org's latest release.
    """
    return (
        AgentRelease.organization_id.is_(None)
        if org_id is None
        else AgentRelease.organization_id == org_id
    )


router = APIRouter()


# =============================================================================
# Rate limiting (per-IP, in-memory sliding window)
# =============================================================================
#
# NOTE: the public download endpoints below sit in front of
# real release data — version strings, download URLs and SHA-256 checksums.
# After the ``not Column`` bug in the prior wave was fixed, these endpoints
# returned real rows again and became a viable enumeration / scraping
# target. The global ``RateLimitMiddleware`` already protects every route
# at ~60 req/min by IP, but downloads/updates are bursty and we want a
# tighter per-endpoint cap as defence-in-depth.
#
# We keep this in-process (no Redis dependency) because the limit is
# coarse and these endpoints are rarely hit in normal operation. The cap
# survives a single-pod restart only — that's acceptable for a public
# read-only endpoint serving public artifacts.

_PUBLIC_DOWNLOAD_WINDOW_SECONDS = 60.0
_PUBLIC_DOWNLOAD_MAX_REQUESTS = 30
_public_rate_buckets: dict[str, list[float]] = {}


def _public_download_rate_limit(request: Request) -> None:
    """Refuse anonymous downloads above 30 req/min per source IP.

    Bucket key is the client IP from ``request.client``. We do not honor
    ``X-Forwarded-For`` here on purpose: if you're behind a proxy that
    rewrites client.host, configure ``ProxyHeadersMiddleware`` upstream.
    Pre-auth, trusting ``X-Forwarded-For`` lets a caller rotate the value
    and bypass the limiter.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - _PUBLIC_DOWNLOAD_WINDOW_SECONDS
    history = _public_rate_buckets.get(ip, [])
    # Drop entries outside the sliding window.
    history = [t for t in history if t >= window_start]
    if len(history) >= _PUBLIC_DOWNLOAD_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for agent downloads",
            headers={"Retry-After": "60"},
        )
    history.append(now)
    _public_rate_buckets[ip] = history
    # Opportunistic cleanup so the dict can't grow unbounded across IPs
    # that hit us once and never come back.
    if len(_public_rate_buckets) > 4096:
        cutoff = window_start
        for stale_ip in [k for k, v in _public_rate_buckets.items() if not v or v[-1] < cutoff]:
            _public_rate_buckets.pop(stale_ip, None)


async def _authenticate_agent_for_update_check(
    session: AsyncSession,
    agent_id_header: str | None,
    agent_key_header: str | None,
) -> RemoteAgent:
    """Validate the X-Agent-ID + X-Agent-Key headers for self-update checks.

    The original endpoint was completely unauthenticated, meaning anyone
    could probe the backend for the latest release for any platform/type.
    Self-update polling MUST come from a real agent so we tighten this to
    require the same X-Agent-Key the heartbeat / task endpoints already use.

    Returns the matching ``RemoteAgent`` on success, raises 401 otherwise.
    Failure cases are collapsed to a single error message to avoid leaking
    "agent exists but is disabled" enumeration data, mirroring the
    same treatment applied to /auth/verify.
    """
    generic = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Agent authentication required",
        headers={"WWW-Authenticate": "X-Agent-Key"},
    )
    if not agent_id_header or not agent_key_header:
        raise generic
    try:
        agent_uuid = UUID(agent_id_header)
    except ValueError:
        raise generic from None

    key_hash = hashlib.sha256(agent_key_header.encode()).hexdigest()
    result = await session.execute(
        select(RemoteAgent).where(
            RemoteAgent.id == agent_uuid,
            RemoteAgent.agent_key == key_hash,
            RemoteAgent.deleted_at.is_(None),
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        logger.warning("agent update-check auth failed: id=%s reason=no_match", agent_id_header)
        raise generic
    if not agent.is_enabled:
        logger.warning("agent update-check auth failed: id=%s reason=disabled", agent.id)
        raise generic
    if not agent.is_approved:
        logger.warning("agent update-check auth failed: id=%s reason=not_approved", agent.id)
        raise generic
    return agent


# =============================================================================
# Public endpoints
# =============================================================================


@router.get(
    "/downloads/latest",
    response_model=AgentReleaseLatest,
    dependencies=[Depends(_public_download_rate_limit)],
)
async def get_latest_release(
    platform: str = Query(..., examples=["windows"]),
    agent_type: str = Query("daemon", examples=["daemon", "desktop"]),
    session: AsyncSession = Depends(get_session),
) -> Any:
    """Get the latest release for a given platform and agent type."""
    if platform.lower() not in VALID_PLATFORMS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid platform: {platform}")
    if agent_type.lower() not in VALID_AGENT_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid agent_type: {agent_type}")
    # NOTE: `not AgentRelease.is_prerelease` is a Python `not` against
    # a SQLAlchemy column — it evaluates to `False` at query-build time, which
    # produced `WHERE ... AND false` and silently returned zero rows. Use the
    # SQLAlchemy expression API (`.is_(False)`) so the predicate compiles to
    # `is_prerelease IS FALSE`.
    # the public page advertises only GLOBAL (super_admin-
    # published) releases — never a tenant's org-scoped release.
    result = await session.execute(
        select(AgentRelease)
        .where(
            and_(
                AgentRelease.platform == platform.lower(),
                AgentRelease.agent_type == agent_type.lower(),
                AgentRelease.is_latest.is_(True),
                AgentRelease.is_prerelease.is_(False),
                AgentRelease.organization_id.is_(None),
            )
        )
        .limit(1)
    )
    release = result.scalar_one_or_none()
    if not release:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No release found for {platform}/{agent_type}",
        )
    return release


@router.get(
    "/downloads/versions",
    response_model=list[AgentReleaseSummary],
    dependencies=[Depends(_public_download_rate_limit)],
)
async def list_versions(
    include_prerelease: bool = Query(False),
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> Any:
    """List all available agent versions with their supported platforms."""
    # public version listing exposes only GLOBAL releases.
    query = (
        select(AgentRelease)
        .where(AgentRelease.organization_id.is_(None))
        .order_by(AgentRelease.published_at.desc())
    )

    if not include_prerelease:
        # NOTE: see comment on get_latest_release — Python `not` on
        # a Column was producing `WHERE false` and breaking version listing.
        query = query.where(AgentRelease.is_prerelease.is_(False))

    # Cap rows fetched — each version has at most 6 rows (3 platforms x 2 types),
    # so limit * 6 is a safe upper bound to satisfy `limit` grouped versions.
    query = query.limit(limit * 6)

    result = await session.execute(query)
    releases = result.scalars().all()

    # Group by version
    version_map: dict[str, dict[str, Any]] = {}
    for r in releases:
        if r.version not in version_map:
            version_map[r.version] = {
                "version": r.version,
                "platforms": [],
                "agent_types": [],
                "release_date": r.published_at,
                "is_latest": r.is_latest,
                "is_prerelease": r.is_prerelease,
            }
        if r.platform not in version_map[r.version]["platforms"]:
            version_map[r.version]["platforms"].append(r.platform)
        if r.agent_type not in version_map[r.version]["agent_types"]:
            version_map[r.version]["agent_types"].append(r.agent_type)
        if r.is_latest:
            version_map[r.version]["is_latest"] = True

    summaries = list(version_map.values())[:limit]
    return [AgentReleaseSummary(**s) for s in summaries]


@router.get(
    "/downloads/page",
    response_model=DownloadsPageResponse,
    dependencies=[Depends(_public_download_rate_limit)],
)
async def get_downloads_page(
    session: AsyncSession = Depends(get_session),
) -> Any:
    """
    Aggregated payload for the frontend Downloads page.

    Returns latest releases grouped by platform with install instructions.
    """
    # NOTE: same Python-bool-on-Column bug here — broke the
    # Downloads page payload entirely (returned 0 platforms).
    # downloads page serves only GLOBAL releases.
    result = await session.execute(
        select(AgentRelease).where(
            and_(
                AgentRelease.is_latest.is_(True),
                AgentRelease.is_prerelease.is_(False),
                AgentRelease.organization_id.is_(None),
            )
        )
    )
    releases = result.scalars().all()

    # Group by platform
    platform_map: dict[str, dict[str, Any]] = {}
    latest_version = ""

    for r in releases:
        if r.platform not in platform_map:
            platform_map[r.platform] = {"daemon": None, "desktop": None}
        platform_map[r.platform][r.agent_type] = AgentReleaseLatest(
            version=r.version,
            platform=r.platform,
            agent_type=r.agent_type,
            download_url=r.download_url,
            checksum_sha256=r.checksum_sha256,
            file_size=r.file_size,
            release_notes=r.release_notes,
        )
        if not latest_version:
            latest_version = r.version

    PLATFORM_META = {
        "windows": {
            "display_name": "Windows",
            "icon": "windows",
            "install_commands": [
                "# Download and run the MSI installer, then:",
                'freesdn-agent register --server https://your-freesdn.com --name "Office Agent"',
                "# Approve the agent in FreeSDN UI → Agents",
                "freesdn-agent daemon",
            ],
        },
        "linux": {
            "display_name": "Linux (Debian/Ubuntu)",
            "icon": "linux",
            "install_commands": [
                "sudo dpkg -i freesdn-agent_*.deb",
                'sudo freesdn-agent register --server https://your-freesdn.com --name "DC Agent"',
                "# Approve in FreeSDN UI → Agents",
                "sudo systemctl enable --now freesdn-agent",
            ],
        },
        "macos": {
            "display_name": "macOS",
            "icon": "apple",
            "install_commands": [
                "sudo installer -pkg freesdn-agent-*.pkg -target /",
                'sudo freesdn-agent register --server https://your-freesdn.com --name "Mac Agent"',
                "# Approve in FreeSDN UI → Agents",
                "sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist",
            ],
        },
    }

    platforms = []
    for plat_key, releases_dict in platform_map.items():
        meta = PLATFORM_META.get(
            plat_key,
            {
                "display_name": plat_key.title(),
                "icon": "",
                "install_commands": [],
            },
        )
        platforms.append(
            PlatformInstallInfo(
                platform=plat_key,
                display_name=meta["display_name"],
                icon=meta["icon"],
                daemon=releases_dict.get("daemon"),
                desktop=releases_dict.get("desktop"),
                install_commands=meta["install_commands"],
            )
        )

    return DownloadsPageResponse(
        platforms=platforms,
        latest_version=latest_version,
        server_version=settings.APP_VERSION,
    )


@router.get(
    "/updates/check",
    response_model=AgentUpdateCheckResponse,
    dependencies=[Depends(_public_download_rate_limit)],
)
async def check_for_updates(
    current_version: str = Query(..., examples=["0.3.0"]),
    platform: str = Query(..., examples=["windows"]),
    agent_type: str = Query("daemon"),
    session: AsyncSession = Depends(get_session),
    x_agent_id: Annotated[str | None, Header(alias="X-Agent-ID")] = None,
    x_agent_key: Annotated[str | None, Header(alias="X-Agent-Key")] = None,
) -> Any:
    """Agent self-update check endpoint.

    NOTE: this endpoint is now authenticated. Previously
    anyone could poll it and learn which agent versions/checksums the
    backend was advertising. Real agents already ship an X-Agent-Key (used
    by ``/heartbeat`` and ``/tasks``), so requiring it here costs no client
    work and closes the information-disclosure path.
    """
    agent = await _authenticate_agent_for_update_check(session, x_agent_id, x_agent_key)

    if platform.lower() not in VALID_PLATFORMS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid platform: {platform}")
    if agent_type.lower() not in VALID_AGENT_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid agent_type: {agent_type}")

    # SECURITY: scope the update feed to the requesting
    # agent's organization. Prefer the agent's org-specific release; fall back
    # to a GLOBAL (organization_id IS NULL, super_admin-published) release. The
    # publish/upload paths force a non-super_admin's release to be org-scoped, so
    # a tenant admin's release can NEVER become the latest update for another
    # tenant's agents (the cross-tenant supply-chain poisoning vector).
    async def _latest_for(org_pred: Any) -> "AgentRelease | None":
        res = await session.execute(
            select(AgentRelease)
            .where(
                and_(
                    AgentRelease.platform == platform.lower(),
                    AgentRelease.agent_type == agent_type.lower(),
                    AgentRelease.is_latest.is_(True),
                    AgentRelease.is_prerelease.is_(False),
                    org_pred,
                )
            )
            .limit(1)
        )
        return res.scalar_one_or_none()

    latest = None
    if agent.organization_id is not None:
        latest = await _latest_for(AgentRelease.organization_id == agent.organization_id)
    if latest is None:
        latest = await _latest_for(AgentRelease.organization_id.is_(None))

    if not latest or latest.version == current_version:
        return AgentUpdateCheckResponse(update_available=False)

    from app.services.release_signing import parse_agent_version

    # Version ordering MUST match the agent's parser exactly. It did not, and the
    # disagreement went both ways:
    #
    #   "1.0.0.0" vs "1.0.0" -- raw tuples make (1,0,0,0) > (1,0,0), so the
    #       backend advertised an update the agent then rejected as not-newer.
    #       The agent had already DOWNLOADED the binary by then, so it repeated
    #       that download every poll interval, forever.
    #   "v2.0.0"  -- the release schema permits the leading v; int() raised, the
    #       old code substituted (0,0,0), and a genuinely newer release was never
    #       offered at all.
    #
    # ``tests/api/test_version_parity.py`` pins both implementations against one
    # shared vector table so they cannot drift apart again.
    if parse_agent_version(latest.version) <= parse_agent_version(current_version):
        return AgentUpdateCheckResponse(update_available=False)

    # Rebuild the manifest the signature covers, from the stored row. The agent
    # verifies the signature over this and then checks the fields against
    # itself -- a self-consistent manifest is exactly what a replayed OLD
    # release has, so the binding is only useful if the agent compares it to
    # what it is running and what it downloaded.
    from app.services.release_signing import build_release_manifest

    try:
        _manifest = build_release_manifest(
            digest_hex=latest.checksum_sha256,
            version=latest.version,
            platform=latest.platform,
            agent_type=latest.agent_type,
            channel="prerelease" if latest.is_prerelease else "stable",
        )
    except ValueError:
        # A row too incomplete to describe cannot be offered as a verified
        # update; the agent fails closed on a missing manifest.
        logger.warning(
            "Release %s is not describable as a manifest — not offering it as an update",
            latest.id,
        )
        return AgentUpdateCheckResponse(update_available=False)

    return AgentUpdateCheckResponse(
        update_available=True,
        latest_version=latest.version,
        download_url=latest.download_url,
        checksum_sha256=latest.checksum_sha256,
        release_notes=latest.release_notes,
        signature=latest.signature or "",
        manifest=_manifest,
    )


# =============================================================================
# Admin endpoints
# =============================================================================


@router.post("/downloads/releases", deprecated=True, summary="Retired one-step release mutation")
async def publish_release(
    request: Request,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
) -> Any:
    """Refuse before consuming a body or changing release rows/files.

    Clients must retain and review an explicit operation intent. There is no
    redirect or automatic replay, and no inferred recovery from an old request.
    """
    raise HTTPException(
        410,
        "This one-step release mutation is retired. Use the release-operation "
        "workflow, retain the original intent, and inspect any earlier uncertain "
        "outcome before explicitly starting or resuming an operation.",
        headers={"Cache-Control": "private, no-store", "Pragma": "no-cache"},
    )
