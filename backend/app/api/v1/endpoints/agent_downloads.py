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
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import CurrentUser, is_unscoped_superuser, require_permissions
from app.db.session import get_session
from app.models.agents import AgentRelease, RemoteAgent
from app.schemas.agent_downloads import (
    AgentReleaseCreate,
    AgentReleaseLatest,
    AgentReleaseResponse,
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

    # Simple semver comparison
    def parse_version(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0, 0, 0)

    if parse_version(latest.version) <= parse_version(current_version):
        return AgentUpdateCheckResponse(update_available=False)

    return AgentUpdateCheckResponse(
        update_available=True,
        latest_version=latest.version,
        download_url=latest.download_url,
        checksum_sha256=latest.checksum_sha256,
        release_notes=latest.release_notes,
        signature=latest.signature or "",
    )


# =============================================================================
# Admin endpoints
# =============================================================================


@router.post(
    "/downloads/releases",
    response_model=AgentReleaseResponse,
    status_code=status.HTTP_201_CREATED,
)
async def publish_release(
    data: AgentReleaseCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
) -> Any:
    """
    Publish a new agent release (admin only).

    Automatically sets is_latest=True for this platform/type
    and clears is_latest on previous releases.
    """
    if data.platform.lower() not in VALID_PLATFORMS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid platform: {data.platform}")
    if data.agent_type.lower() not in VALID_AGENT_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid agent_type: {data.agent_type}")

    # SECURITY: only super_admin may publish a GLOBAL
    # (organization_id IS NULL) release; every other admin's release is forced
    # to their own organization. This stops a tenant org_admin from publishing a
    # release that becomes the latest update for agents across all tenants.
    is_super = is_unscoped_superuser(current_user)
    release_org = None if is_super else current_user.organization_id
    if not is_super and release_org is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "An organization context is required to publish a release.",
        )

    # Clear is_latest ONLY within the same org bucket (so a tenant admin can't
    # demote the global or another org's latest release).
    await session.execute(
        update(AgentRelease)
        .where(
            and_(
                AgentRelease.platform == data.platform.lower(),
                AgentRelease.agent_type == data.agent_type.lower(),
                AgentRelease.is_latest,
                _release_org_bucket(release_org),
            )
        )
        .values(is_latest=False)
    )

    # sign the release server-side (ECDSA-P256) so the URL-publish path
    # no longer produces UNSIGNED releases (the agent fails closed on missing
    # signatures). Mirrors the upload path; signs the checksum the agent re-derives.
    #
    # fail closed on signing failure. Every release published
    # through this endpoint is marked is_latest=True; an unsigned latest release
    # silently bypasses the agent's signature-verification gate. Roll back the
    # is_latest demotion already executed above so the previous latest release is
    # restored before raising.
    from app.services.release_signing import sign_digest

    try:
        _signature = sign_digest(data.checksum_sha256)
    except Exception:
        logger.exception(
            "Release signing failed at publish version=%s platform=%s — rolling back is_latest demotion",
            data.version,
            data.platform,
        )
        # The UPDATE above demoted the previous latest; undo it so agents
        # continue to receive the last known-good signed release.
        await session.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Release signing failed; the release was not published. "
            "Check the signing-key configuration and retry.",
        )

    release = AgentRelease(
        version=data.version,
        platform=data.platform.lower(),
        agent_type=data.agent_type.lower(),
        download_url=data.download_url,
        checksum_sha256=data.checksum_sha256,
        file_size=data.file_size,
        release_notes=data.release_notes,
        min_backend_version=data.min_backend_version,
        is_latest=True,
        is_prerelease=data.is_prerelease,
        published_at=datetime.now(UTC),
        download_count=0,
        organization_id=release_org,
        signature=_signature,
    )
    session.add(release)
    await session.commit()
    await session.refresh(release)

    logger.info(
        "Published agent release %s for %s/%s",
        data.version,
        data.platform,
        data.agent_type,
    )
    return release
