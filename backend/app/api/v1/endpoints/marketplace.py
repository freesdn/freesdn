# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Marketplace API
=======================================

Browse, search, and install plugins from the FreeSDN marketplace catalog.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user, is_unscoped_superuser
from app.core.query import MAX_PAGE
from app.core.security_utils import escape_like
from app.db import get_session
from app.models.marketplace import MarketplacePlugin, MarketplacePluginVersion, PluginReview
from app.models.plugins import InstalledPlugin
from app.plugins.mutation_authority import capture_plugin_mutation_authority
from app.services import marketplace_catalog as catalog_policy
from app.services.audit import AuditAction, AuditService, ResourceType

logger = logging.getLogger(__name__)
router = APIRouter()

# registry.freesdn.org serves the signed catalogue produced by
# registry/build.py. This default named the same host for a long time while
# nothing was attached to it, so the very first sync on every deployment failed
# and the marketplace stayed empty; keep the URL and the registry in step.
MARKETPLACE_REGISTRY_URL = os.getenv(
    "MARKETPLACE_REGISTRY_URL",
    "https://registry.freesdn.org/plugins.json",
)

# Pinned Ed25519 publisher public key (hex) used to verify a detached signature
# over the canonicalised catalog before any DB write. The catalog is signed with
# the matching private key by registry/build.py in this repository.
#
# Empty HERE by default so a source checkout stays neutral, but the shipped
# docker-compose.yml pins the real key, so a normal deployment verifies
# signatures out of the box. See the posture in _verify_catalog_signature.
MARKETPLACE_PUBLISHER_PUBLIC_KEY = os.getenv("MARKETPLACE_PUBLISHER_PUBLIC_KEY", "").strip()
# Explicit, conscious opt-out (dev / fully-trusted private registries). When no
# publisher key is pinned, sync is REFUSED unless this is set — the marketplace
# never silently trusts an unsigned catalog.
MARKETPLACE_ALLOW_UNSIGNED = os.getenv("MARKETPLACE_ALLOW_UNSIGNED", "").strip().lower() in (
    "1",
    "true",
    "yes",
)

# Independent restore floor. Invalid values fail closed when sync/install is used.
MARKETPLACE_MIN_SERIAL = os.getenv("MARKETPLACE_MIN_SERIAL", "0").strip()


def _catalog_identity() -> str:
    return catalog_policy.publisher_identity(
        MARKETPLACE_REGISTRY_URL, MARKETPLACE_PUBLISHER_PUBLIC_KEY
    )


async def _require_current_catalog(session: AsyncSession, plugin: MarketplacePlugin) -> None:
    if not MARKETPLACE_PUBLISHER_PUBLIC_KEY and not MARKETPLACE_ALLOW_UNSIGNED:
        raise HTTPException(
            403, "Pin a marketplace publisher key before installing catalog plugins."
        )
    await catalog_policy.require_installable(
        session, plugin, _catalog_identity(), catalog_policy.minimum_serial(MARKETPLACE_MIN_SERIAL)
    )


def _marketplace_mutation_check(
    check_account: Callable[[], Awaitable[None]],
    session: AsyncSession,
    plugin: MarketplacePlugin,
) -> Callable[[], Awaitable[None]]:
    # Copy the accepted offer before any archive download or lifecycle wait.
    # The account callback was already captured before catalog resolution.
    offer = catalog_policy.CatalogOffer.from_plugin(plugin)

    async def check() -> None:
        if not MARKETPLACE_PUBLISHER_PUBLIC_KEY and not MARKETPLACE_ALLOW_UNSIGNED:
            raise HTTPException(403, "Marketplace publisher authorization changed.")
        floor = catalog_policy.minimum_serial(MARKETPLACE_MIN_SERIAL)
        envelope = await catalog_policy.require_current_offer(
            session,
            offer,
            _catalog_identity(),
            floor,
        )
        await check_account()
        # Account revalidation can await SQL/Redis. Recheck catalog time after it.
        envelope.require_current(catalog_policy.minimum_serial(MARKETPLACE_MIN_SERIAL))

    return check


# NOTE: registry sync ingests third-party JSON that ends up populating
# install pages and (via /install) executes code with full backend privileges.
# Hardening:
#   - HTTPS enforced (no plaintext catalog).
#   - Streaming size cap (5 MB) — no unbounded body buffering.
#   - Field allowlist applied per-entry (server-controlled flags like
#     ``is_verified``, ``is_featured``, ``status`` CANNOT be set from the
#     catalog feed; otherwise a single malicious registry could mark its own
#     plugin "Verified by FreeSDN" with a one-step push).
#   - Ed25519 detached signature over the canonicalised catalog verified
#     with a pinned publisher key (_verify_catalog_signature) before any DB write,
#     so a compromised/MITM'd registry cannot drive plugin URL/checksum → install.
#   - Signed freshness and a transaction-locked serial floor prevent replay;
#     installation requires current snapshot provenance and rechecks after download.
MAX_REGISTRY_CATALOG_BYTES = 5 * 1024 * 1024  # 5 MB


def _canonical_catalog_bytes(catalog: dict[str, Any]) -> bytes:
    """Deterministic bytes that the signature covers: the catalog object with the
    ``signature`` field removed, JSON-serialised with sorted keys + compact
    separators. MUST match the publisher signing tool's canonicalisation exactly."""
    import json as _json

    payload = {k: v for k, v in catalog.items() if k != "signature"}
    return _json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _verify_catalog_signature(catalog: dict[str, Any]) -> None:
    """Enforce catalog authenticity before ingest.

    Posture:
      - publisher key pinned  → REQUIRE a valid detached Ed25519 signature
        (reject missing/invalid). This is the production default once the project
        publishes a signed catalog + pins its key.
      - no key pinned + ALLOW_UNSIGNED → proceed with a loud SECURITY warning
        (dev / fully-trusted private registry; conscious opt-out).
      - no key pinned + not allowed (DEFAULT) → REFUSE: the marketplace never
        silently trusts an unsigned catalog.
    """
    if not MARKETPLACE_PUBLISHER_PUBLIC_KEY:
        if MARKETPLACE_ALLOW_UNSIGNED:
            logger.warning(
                "SECURITY: marketplace catalog signature verification DISABLED "
                "(MARKETPLACE_ALLOW_UNSIGNED set, no publisher key pinned). "
                "A compromised/MITM'd registry could drive plugin install. Pin "
                "MARKETPLACE_PUBLISHER_PUBLIC_KEY for production."
            )
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Marketplace catalog is unsigned and no publisher key is pinned. "
                "Set MARKETPLACE_PUBLISHER_PUBLIC_KEY (recommended) or, for a "
                "fully-trusted private/dev registry, MARKETPLACE_ALLOW_UNSIGNED=1."
            ),
        )

    sig_hex = catalog.get("signature")
    if not isinstance(sig_hex, str) or not sig_hex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Marketplace catalog is missing its required 'signature' field.",
        )

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(MARKETPLACE_PUBLISHER_PUBLIC_KEY))
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Marketplace publisher key or catalog signature is not valid hex.",
        )

    try:
        pub.verify(signature, _canonical_catalog_bytes(catalog))
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Marketplace catalog signature is INVALID — refusing to ingest "
                "(possible tampering or MITM)."
            ),
        )


# Fields the registry may set on a MarketplacePlugin row. Anything not listed
# here (id/timestamps/server-controlled trust flags/download_count/etc.) is
# stripped to prevent supply-chain trust hijack.
_CATALOG_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "short_description",
        "category",
        "tags",
        "version",
        "latest_version",
        "author",
        "author_name",
        "author_url",
        "homepage_url",
        "download_url",
        "checksum_sha256",
        "min_freesdn_version",
        "min_core_version",
        "requires_python",
        "screenshots",
        "icon_url",
        "banner_url",
        "slug",
        "plugin_id",
        # Descriptive only: the loader reads real schedules from the
        # installed manifest, so this cannot change what runs. Present so
        # the marketplace can show that a plugin works unattended.
        "schedules",
    }
)


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────


class MarketplacePluginSummary(BaseModel):
    plugin_id: str
    slug: str
    name: str
    short_description: str
    author_name: str
    category: str
    tags: list[str]
    latest_version: str
    icon_url: str | None
    download_count: int
    rating: float
    rating_count: int
    is_verified: bool
    is_featured: bool
    status: str

    class Config:
        from_attributes = True


class MarketplacePluginDetail(MarketplacePluginSummary):
    description: str | None
    author_url: str | None
    banner_url: str | None
    screenshots: list[str]
    download_url: str
    checksum_sha256: str
    package_size: int | None
    min_core_version: str


class ReviewSubmit(BaseModel):
    # Previously the rating bounds were checked post-hoc in the handler
    # (``if not 1 <= body.rating <= 5``); moving to the schema layer
    # gives a crisp 422 + plays nicely with OpenAPI clients.
    rating: int = Field(..., ge=1, le=5)
    title: str | None = Field(None, max_length=200)
    # Reviews were unbounded — a single 10 MB review would bloat the
    # JSONB and slow every plugin-detail load.
    body: str | None = Field(None, max_length=4000)


class ReviewResponse(BaseModel):
    id: UUID
    user_id: UUID
    rating: int
    title: str | None
    body: str | None
    created_at: str

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=dict[str, Any])
async def browse_plugins(
    session: Annotated[AsyncSession, Depends(get_session)],
    # ``q`` is LIKE-escaped via ``escape_like`` (good) but was
    # otherwise unbounded; a 10 KB search query still hit the DB.
    q: str | None = Query(None, max_length=128, description="Search query"),
    category: str | None = Query(None, max_length=64, description="Filter by category"),
    sort: str = Query("downloads", enum=["downloads", "rating", "newest", "name"]),
    # ``le=MAX_PAGE``: this route takes no auth dependency, so an
    # unauthenticated caller could pass a 24-digit page, overflow the int64
    # bound to ``OFFSET $n::BIGINT`` and turn every request into a 500 plus a
    # full SQL statement in the log. Bound it at the edge, not just in the
    # DataError handler.
    page: int = Query(1, ge=1, le=MAX_PAGE),
    per_page: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Browse marketplace plugins with optional filtering and sorting."""
    query = select(MarketplacePlugin).where(MarketplacePlugin.status == "published")

    if q:
        escaped_q = escape_like(q)
        query = query.where(
            MarketplacePlugin.name.ilike(f"%{escaped_q}%", escape="\\")
            | MarketplacePlugin.short_description.ilike(f"%{escaped_q}%", escape="\\")
        )
    if category:
        query = query.where(MarketplacePlugin.category == category)

    if sort == "downloads":
        query = query.order_by(MarketplacePlugin.download_count.desc())
    elif sort == "rating":
        query = query.order_by(MarketplacePlugin.rating.desc())
    elif sort == "newest":
        query = query.order_by(MarketplacePlugin.created_at.desc())
    elif sort == "name":
        query = query.order_by(MarketplacePlugin.name.asc())

    count_result = await session.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await session.execute(query)
    plugins = result.scalars().all()

    return {
        "plugins": [MarketplacePluginSummary.model_validate(p).model_dump() for p in plugins],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/featured", response_model=list[MarketplacePluginSummary])
async def featured_plugins(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[MarketplacePlugin]:
    """List featured plugins."""
    result = await session.execute(
        select(MarketplacePlugin)
        .where(MarketplacePlugin.is_featured, MarketplacePlugin.status == "published")
        .order_by(MarketplacePlugin.download_count.desc())
        .limit(6)
    )
    return list(result.scalars().all())


@router.get("/categories")
async def list_categories(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """List plugin categories with counts."""
    result = await session.execute(
        select(MarketplacePlugin.category, func.count(MarketplacePlugin.id).label("count"))
        .where(MarketplacePlugin.status == "published")
        .group_by(MarketplacePlugin.category)
        .order_by(func.count(MarketplacePlugin.id).desc())
    )
    categories = [{"category": row[0], "count": row[1]} for row in result.all()]
    return {"categories": categories}


@router.get("/{slug}", response_model=MarketplacePluginDetail)
async def get_plugin(
    slug: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MarketplacePlugin:
    """Get full plugin detail by slug."""
    result = await session.execute(
        select(MarketplacePlugin).where(
            MarketplacePlugin.slug == slug,
            MarketplacePlugin.status == "published",
        )
    )
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin


@router.get("/{slug}/versions")
async def plugin_versions(
    slug: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """List version history for a plugin."""
    plugin_result = await session.execute(
        select(MarketplacePlugin.id).where(MarketplacePlugin.slug == slug)
    )
    plugin_id = plugin_result.scalar_one_or_none()
    if not plugin_id:
        raise HTTPException(status_code=404, detail="Plugin not found")

    result = await session.execute(
        select(MarketplacePluginVersion)
        .where(MarketplacePluginVersion.marketplace_plugin_id == plugin_id)
        .order_by(MarketplacePluginVersion.released_at.desc())
    )
    versions = [
        {
            "version": v.version,
            "changelog": v.changelog,
            "min_core_version": v.min_core_version,
            "released_at": v.released_at.isoformat(),
        }
        for v in result.scalars().all()
    ]
    return {"versions": versions}


async def _resolve_published(session: AsyncSession, slug: str) -> MarketplacePlugin:
    """The catalogue entry for ``slug``, or a refusal that says which kind it is.

    "Never heard of it" and "withdrawn" need opposite reactions from the
    operator, and a flat 404 made a plugin the registry had deliberately pulled
    look like a typo.
    """
    result = await session.execute(
        select(MarketplacePlugin).where(
            MarketplacePlugin.slug == slug,
            MarketplacePlugin.status == "published",
        )
    )
    plugin = result.scalar_one_or_none()
    if plugin:
        await _require_current_catalog(session, plugin)
        return plugin

    withdrawn_row = await session.execute(
        select(MarketplacePlugin.status).where(MarketplacePlugin.slug == slug)
    )
    if withdrawn_row.scalar_one_or_none() == "withdrawn":
        raise HTTPException(
            status_code=410,
            detail=(
                f"'{slug}' has been withdrawn from the registry and can no longer be "
                "installed or updated. If you already have it installed it keeps "
                "running, but it will not receive updates."
            ),
        )
    raise HTTPException(status_code=404, detail="Plugin not found")


async def _download_and_verify(plugin: MarketplacePlugin) -> bytes:
    """Fetch the archive the catalogue points at and prove it is the one it named.

    Streaming and DNS-rebinding-safe. This used to call ``safe_http_request``,
    which buffers the whole body and only then checks ``len(raw) > 50 MB`` -- so
    a hostile or compromised download_url had already consumed the memory before
    the check ran. The loader's downloader caps the running total during chunked
    reads and aborts at 50 MB without buffering the full body.

    The checksum is the only thing standing between a signed catalogue entry and
    arbitrary code: the signature proves the catalogue is authentic, and this
    proves the bytes are the ones it vouched for.
    """
    import hashlib

    from app.api.v1.endpoints.plugins import _download_plugin_archive

    try:
        raw = await _download_plugin_archive(plugin.download_url)
    except HTTPException:
        raise
    except ValueError as ssrf_exc:
        raise HTTPException(status_code=400, detail=f"Unsafe download URL: {ssrf_exc}")

    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != plugin.checksum_sha256:
        raise HTTPException(
            status_code=400,
            detail=f"Checksum mismatch: expected {plugin.checksum_sha256}, got {actual_hash}",
        )
    return raw


@router.post("/{slug}/install", status_code=status.HTTP_201_CREATED)
async def install_from_marketplace(
    slug: str,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Install a plugin directly from the marketplace."""
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise HTTPException(status_code=403, detail="Requires super admin role")

    check_account = capture_plugin_mutation_authority(request, current_user, session)
    plugin = await _resolve_published(session, slug)
    check_authority = _marketplace_mutation_check(check_account, session, plugin)

    from app.plugins.loader import PluginLoadError, plugin_loader

    try:
        raw = await _download_and_verify(plugin)
        # Downloads can outlast catalog validity. Refuse before changing files
        # or stopping a running plugin when authorization has expired.
        await _require_current_catalog(session, plugin)

        record = await plugin_loader.install_plugin(
            source=raw,
            db=session,
            installed_by_id=current_user.id,
            before_mutation=check_authority,
            source_url=f"marketplace:{slug}",
            expected_plugin_id=plugin.plugin_id,
            expected_version=plugin.latest_version,
        )

        # START it. Installing wrote the files and the database row and stopped
        # there: no per-organisation runtime was created and no routes were
        # mounted, so a plugin installed from the marketplace did nothing at all
        # until the next API restart -- while the button reported success and
        # the plugin list showed it installed. The upload path had always called
        # this; the marketplace path, which is the one in the UI, never did.
        from app.api.v1.endpoints.plugins import _start_plugin_everywhere

        await _start_plugin_everywhere(record.plugin_id, session, request.app)

        # Audit trail for marketplace installs
        try:
            audit = AuditService(session)
            await audit.log(
                action=AuditAction.INSTALL,
                resource_type=ResourceType.PLUGIN,
                resource_name=record.name,
                actor_id=current_user.id,
                actor_name=getattr(current_user, "full_name", None)
                or getattr(current_user, "email", None),
                actor_email=getattr(current_user, "email", None),
                organization_id=getattr(current_user, "organization_id", None),
                extra_metadata={
                    "plugin_id": record.plugin_id,
                    "plugin_version": record.version,
                    "source": f"marketplace:{slug}",
                    "checksum_sha256": plugin.checksum_sha256,
                },
                tags=["plugin", "supply-chain", "marketplace"],
            )
        except Exception:
            logger.warning(
                "Failed to create audit log for marketplace plugin install: %s", slug, exc_info=True
            )

        # Increment download count
        plugin.download_count += 1
        await session.commit()

        # Whether this install is fully live, answered the SAME way as every
        # other install and upgrade path.
        #
        # This used to ask "are the plugin's routes mounted?", which was the
        # right question before method bodies reloaded in place: back then any
        # mounted plugin really did keep serving old handlers. It is now the
        # wrong one -- it is true for essentially every install of an already
        # mounted plugin -- so the marketplace demanded a restart that nothing
        # needed, on almost every install, while the upload path (same install,
        # different button) correctly said no restart was required. Reporting a
        # restart nobody needs is how an operator learns to ignore the message
        # that will one day matter.
        from app.api.v1.endpoints.plugins import _reload_note

        return {
            "plugin_id": record.plugin_id,
            "version": record.version,
            "status": "installed",
            **_reload_note(record.plugin_id),
        }
    except PluginLoadError as exc:
        # Surface the loader's own message. It is written for the person doing
        # the install ("already installed, use upgrade", "requires FreeSDN X or
        # newer", "checksum mismatch", "requirements.txt is missing --hash="),
        # and every one of those is actionable. The flat
        # "Marketplace plugin installation failed" made a version-floor refusal,
        # a tampered archive and an unpinned dependency all look identical, with
        # the real reason visible only in the container log.
        #
        # This endpoint already requires an UNSCOPED SUPER ADMIN, so there is no
        # audience here that should not see a plugin diagnostic.
        logger.error("Marketplace plugin install failed for %s: %s", slug, exc, exc_info=True)
        raise HTTPException(status_code=400, detail=f"Plugin installation failed: {exc}") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Marketplace install failed for %s: %s", slug, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Plugin installation failed")


@router.post("/{slug}/upgrade")
async def upgrade_from_marketplace(
    slug: str,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Update an installed plugin to the version the catalogue carries.

    The missing half of the marketplace. You could install a plugin from the UI
    and then never update it from the UI: the only upgrade path took an uploaded
    ZIP, so keeping a plugin current meant going and finding the archive by hand
    -- and pressing Install again just answered "already installed, use upgrade".
    """
    if not is_unscoped_superuser(current_user):
        raise HTTPException(status_code=403, detail="Requires super admin role")

    check_account = capture_plugin_mutation_authority(request, current_user, session)
    plugin = await _resolve_published(session, slug)
    check_authority = _marketplace_mutation_check(check_account, session, plugin)

    from app.plugins.loader import PluginLoadError, _version_tuple, plugin_loader

    installed = (
        await session.execute(
            select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin.plugin_id)
        )
    ).scalar_one_or_none()
    if installed is None or installed.status != "installed":
        raise HTTPException(
            status_code=404,
            detail=f"'{slug}' is not installed. Install it first.",
        )

    from_version = installed.version
    target = plugin.latest_version

    # Refuse anything that is not forward motion, and say which it is. Both
    # cases arrive here by pressing a button labelled "update", so silently
    # reinstalling or silently rolling back would be the wrong answer to what
    # the operator asked for.
    current_t, target_t = _version_tuple(from_version or ""), _version_tuple(target or "")
    if current_t and target_t:
        if current_t == target_t:
            raise HTTPException(
                status_code=409,
                detail=f"'{slug}' is already on {from_version}. Sync the registry if you "
                "expected a newer version.",
            )
        if current_t > target_t:
            raise HTTPException(
                status_code=409,
                detail=f"'{slug}' is installed at {from_version}, which is newer than the "
                f"{target} the registry carries. Refusing to roll back; uninstall and "
                "install if that is really what you want.",
            )

    try:
        raw = await _download_and_verify(plugin)
        # Downloads can outlast catalog validity. Refuse before changing files
        # or stopping a running plugin when authorization has expired.
        await _require_current_catalog(session, plugin)

        # The loader validates before stopping active runtimes and serializes
        # shutdown with file replacement. A rejected archive must not leave a
        # working plugin stopped merely because this endpoint was called.
        record = await plugin_loader.upgrade_plugin(
            plugin_id=plugin.plugin_id,
            source=raw,
            db=session,
            installed_by_id=current_user.id,
            expected_version=target,
            before_mutation=check_authority,
        )
        from app.api.v1.endpoints.plugins import _start_plugin_everywhere

        await _start_plugin_everywhere(record.plugin_id, session, request.app, replace_routes=True)

        try:
            audit = AuditService(session)
            await audit.log(
                action=AuditAction.UPGRADE,
                resource_type=ResourceType.PLUGIN,
                resource_name=record.name,
                actor_id=current_user.id,
                actor_name=getattr(current_user, "full_name", None)
                or getattr(current_user, "email", None),
                actor_email=getattr(current_user, "email", None),
                organization_id=getattr(current_user, "organization_id", None),
                extra_metadata={
                    "plugin_id": record.plugin_id,
                    "plugin_version": record.version,
                    "previous_version": from_version,
                    "source": f"marketplace:{slug}",
                    "checksum_sha256": plugin.checksum_sha256,
                },
                tags=["plugin", "supply-chain", "marketplace"],
            )
        except Exception:
            logger.warning(
                "Failed to create audit log for marketplace plugin upgrade: %s", slug, exc_info=True
            )

        await session.commit()

        from app.api.v1.endpoints.plugins import _reload_note

        return {
            "plugin_id": record.plugin_id,
            "version": record.version,
            "previous_version": from_version,
            "status": "upgraded",
            **_reload_note(record.plugin_id),
        }
    except PluginLoadError as exc:
        # The loader's own message names the reason -- a version floor, a
        # tampered archive, an unpinned dependency -- and every one is
        # actionable by the unscoped super admin this endpoint already requires.
        logger.error("Marketplace plugin upgrade failed for %s: %s", slug, exc, exc_info=True)
        raise HTTPException(status_code=400, detail=f"Plugin upgrade failed: {exc}") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Marketplace upgrade failed for %s: %s", slug, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Plugin upgrade failed") from exc


@router.get("/{slug}/reviews")
async def list_reviews(
    slug: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    # Also unauthenticated - same int64 OFFSET overflow as browse_plugins.
    page: int = Query(1, ge=1, le=MAX_PAGE),
    per_page: int = Query(10, ge=1, le=50),
) -> dict[str, Any]:
    """List reviews for a plugin."""
    plugin_result = await session.execute(
        select(MarketplacePlugin.id).where(MarketplacePlugin.slug == slug)
    )
    plugin_id = plugin_result.scalar_one_or_none()
    if not plugin_id:
        raise HTTPException(status_code=404, detail="Plugin not found")

    result = await session.execute(
        select(PluginReview)
        .where(PluginReview.marketplace_plugin_id == plugin_id)
        .order_by(PluginReview.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    reviews = [
        {
            "id": str(r.id),
            "rating": r.rating,
            "title": r.title,
            "body": r.body,
            "created_at": r.created_at.isoformat(),
        }
        for r in result.scalars().all()
    ]
    return {"reviews": reviews, "page": page}


@router.post("/{slug}/reviews", status_code=status.HTTP_201_CREATED)
async def submit_review(
    slug: str,
    body: ReviewSubmit,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Submit a review for a marketplace plugin (one per user)."""
    if not 1 <= body.rating <= 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    # Lock the plugin row FOR UPDATE so concurrent reviewers serialize: this
    # closes the read-modify-write race on rating/rating_count below (two
    # concurrent reviews would otherwise both read the same count and lose an
    # increment / clobber the average).
    plugin_result = await session.execute(
        select(MarketplacePlugin).where(MarketplacePlugin.slug == slug).with_for_update()
    )
    plugin = plugin_result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    # Check for existing review (one per user). This pre-check is best-effort
    # and racy on its own; the authoritative guard is the IntegrityError arm
    # below, which catches the loser of a concurrent insert once the DB unique
    # constraint on (marketplace_plugin_id, user_id) is present.
    existing = await session.execute(
        select(PluginReview).where(
            PluginReview.marketplace_plugin_id == plugin.id,
            PluginReview.user_id == current_user.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="You have already reviewed this plugin")

    review = PluginReview(
        marketplace_plugin_id=plugin.id,
        user_id=current_user.id,
        rating=body.rating,
        title=body.title,
        body=body.body,
    )
    session.add(review)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=409, detail="You have already reviewed this plugin"
        ) from exc

    # Recompute the average atomically from the persisted rows instead of the
    # read-modify-write arithmetic (which lost concurrent increments). The
    # FOR UPDATE lock above keeps this consistent across overlapping requests.
    agg = await session.execute(
        select(func.count(), func.coalesce(func.avg(PluginReview.rating), 0.0)).where(
            PluginReview.marketplace_plugin_id == plugin.id
        )
    )
    count, avg_rating = agg.one()
    plugin.rating_count = int(count)
    plugin.rating = float(avg_rating)

    await session.commit()
    return {"id": str(review.id), "rating": review.rating}


async def _fetch_registry_catalog(url: str) -> dict[str, Any]:
    """
    Fetch and parse the registry catalog with HTTPS enforcement, DNS-pinning,
    and a streamed size cap.

    NOTE: the previous implementation buffered the entire response
    body into memory before parsing — a hostile/compromised registry could
    serve a multi-GB payload (memory DoS) or sneak in fields that would
    later be mass-assigned onto trust flags (``is_verified``/``is_featured``)
    via the loop in ``sync_marketplace``. We now:
      * enforce ``https://`` scheme,
      * stream with a 5 MB hard cap (abort mid-read),
      * pin DNS to a validated public IP (no DNS rebinding),
      * keep an explicit ``follow_redirects=False`` so a 302 to a private
        endpoint cannot be used as a side channel.
    """
    import ipaddress
    import json as _json
    from urllib.parse import urlparse, urlunparse

    import httpx

    from app.core.security_utils import _is_ip_safe, _resolve_and_validate

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Marketplace registry URL must use https:// (refusing to sync over plaintext).",
        )
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Registry URL has no hostname")

    try:
        direct_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        direct_ip = None

    try:
        if direct_ip is not None:
            if not _is_ip_safe(direct_ip):
                raise ValueError(f"Registry URL targets blocked IP {parsed.hostname!r}")
            resolved = str(direct_ip)
        else:
            resolved = _resolve_and_validate(parsed.hostname)
    except ValueError as ssrf_err:
        raise HTTPException(status_code=400, detail=f"SSRF blocked: {ssrf_err}")

    port = parsed.port
    is_ipv6 = ":" in resolved
    if is_ipv6:
        netloc_ip = f"[{resolved}]:{port}" if port else f"[{resolved}]"
    else:
        netloc_ip = f"{resolved}:{port}" if port else resolved

    ip_url = urlunparse(
        (
            parsed.scheme,
            netloc_ip,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    host_headers = {"Host": parsed.hostname}
    # Pass sni_hostname so httpcore uses the ORIGINAL hostname for TLS SNI +
    # certificate verification even though the socket connects to the pinned IP.
    # Without this, an IP-literal URL causes TLS to verify the cert against the
    # IP address, which fails for virtually all real hostname certificates.
    stream_extensions: dict[str, object] = {}
    if parsed.scheme == "https":
        stream_extensions["sni_hostname"] = parsed.hostname

    total = 0
    chunks: list[bytes] = []
    async with (
        httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=False,
            max_redirects=0,
        ) as client,
        client.stream("GET", ip_url, headers=host_headers, extensions=stream_extensions) as resp,
    ):
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > MAX_REGISTRY_CATALOG_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Registry catalog exceeds {MAX_REGISTRY_CATALOG_BYTES // (1024 * 1024)} MB cap"
                    ),
                )
            chunks.append(chunk)
    try:
        return _json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, _json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Registry returned invalid JSON: {exc}",
        )


def _sanitize_catalog_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Apply the catalog field allowlist.

    NOTE: the previous code did ``setattr(row, k, v)`` for any
    attribute that exists on the ORM model — meaning a hostile registry
    could set ``is_verified=True``, ``is_featured=True``, ``status``,
    ``download_count``, or even ``id``/timestamps in a single push. We now
    only accept fields that the registry is allowed to control.
    """
    return {k: v for k, v in entry.items() if k in _CATALOG_ALLOWED_FIELDS}


@router.post("/sync", status_code=status.HTTP_200_OK)
async def sync_marketplace(
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Sync marketplace catalog from remote registry.
    Requires super_admin role.
    """
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise HTTPException(status_code=403, detail="Requires super_admin role")

    check_account = capture_plugin_mutation_authority(request, current_user, session)
    synced = 0

    # FETCH and VERIFY are separated deliberately, because they need opposite
    # failure behaviour and a single try/except cannot give both.
    #
    # These two arms used to share one `except HTTPException: raise`, added so a
    # SIGNATURE failure could not silently fall back to the seed. It also caught
    # the FETCH failure, which is supposed to fall back -- and the SSRF guard
    # reports an unreachable registry as an HTTPException. The default registry
    # was registry.freesdn.org, which has never resolved, so every sync on every
    # deployment raised 400 and the bundled seed was unreachable: the
    # marketplace was permanently empty and nothing said why. The default now
    # points at a live registry, but an air-gapped or offline install still
    # depends on this split behaving correctly.
    #
    #   fetch fails      -> fall back to the first-party bundled seed
    #   signature fails  -> refuse outright, never fall back
    catalog: dict[str, Any] | None = None
    used_seed = False
    try:
        # NOTE: hardened fetch — HTTPS-only, 5MB streamed cap,
        # DNS-rebinding-safe, no redirects.
        catalog = await _fetch_registry_catalog(MARKETPLACE_REGISTRY_URL)
    except Exception as exc:
        logger.warning("Remote registry fetch failed: %s. Trying seed file...", exc)
        import json
        from pathlib import Path

        # The seed file is first-party and bundled with the app distribution, so
        # it is trusted by provenance (no network) and not signature-checked here.
        seed_path = Path(__file__).parent.parent.parent.parent / "data" / "marketplace_seed.json"
        if seed_path.exists():
            catalog = json.loads(seed_path.read_text())
            used_seed = True
        else:
            raise HTTPException(
                status_code=503, detail="Remote registry unavailable and no seed file found"
            ) from exc

    # A fetch or offline fallback cannot retain a revoked initiating credential.
    # Keep this refusal outside the fetch exception handler.
    await check_account()

    if not isinstance(catalog, dict):
        raise HTTPException(400, "Marketplace catalog must be an object.")
    if not used_seed:
        # authenticate the REMOTE catalog (pinned-key Ed25519 signature)
        # before any ingest. Raises 403 on unsigned/invalid per the configured
        # posture, and that refusal must never degrade to the seed.
        _verify_catalog_signature(catalog or {})

    floor = catalog_policy.minimum_serial(MARKETPLACE_MIN_SERIAL)
    envelope = None if used_seed else catalog_policy.validate_envelope(catalog, floor)
    entries = catalog_policy.validate_entries(catalog.get("plugins"))
    identity = _catalog_identity()
    withdrawn: list[str] = []
    seed_ignored = False
    try:
        state = await catalog_policy.lock_catalog(session)
        await check_account()
        if used_seed and state.serial:
            # An unreachable registry is never authority to replace a previously
            # accepted snapshot. Keep the catalog and its expiry exactly as-is.
            seed_ignored = True
        else:
            if envelope is not None:
                catalog_policy.accept_envelope(state, envelope, identity, floor)
            seen_ids: set[str] = set()
            for entry in entries:
                sanitized = _sanitize_catalog_entry(entry)
                row = (
                    await session.execute(
                        select(MarketplacePlugin).where(
                            MarketplacePlugin.plugin_id == sanitized["plugin_id"]
                        )
                    )
                ).scalar_one_or_none()
                if used_seed and row is not None:
                    # Even before the first verified sync, legacy withdrawals
                    # and operator decisions survive an offline seed fallback.
                    continue
                if row is None:
                    row = MarketplacePlugin(**sanitized)
                    session.add(row)
                else:
                    for key, value in sanitized.items():
                        setattr(row, key, value)
                    if row.status == "withdrawn":
                        row.status = "published"
                if envelope is not None:
                    row.catalog_identity = identity
                    row.catalog_serial = envelope.serial
                seen_ids.add(sanitized["plugin_id"])
                synced += 1
            await session.flush()
            if not used_seed:
                # Empty signed snapshots are authoritative withdrawals too.
                stale = await session.execute(
                    select(MarketplacePlugin).where(
                        MarketplacePlugin.status == "published",
                        MarketplacePlugin.plugin_id.notin_(seen_ids),
                    )
                )
                for row in stale.scalars().all():
                    row.status = "withdrawn"
                    withdrawn.append(row.plugin_id)
        # Flush every pending catalog-row write before the final authority read:
        # row-lock waits must not move the commit beyond credential validation.
        await session.flush()
        await check_account()
        if envelope is not None:
            envelope.require_current(floor)
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            409,
            "Catalog conflicts with existing plugin identifiers or slugs; no snapshot was accepted.",
        ) from exc
    except Exception:
        await session.rollback()
        raise
    message = (
        "Registry unavailable; retained the accepted catalog without changes."
        if seed_ignored
        else f"Synced {synced} plugins from registry (0 skipped)"
    )
    if used_seed and not seed_ignored:
        message += ". Offline seed is browse-only until a current signed catalog is accepted."
    if withdrawn:
        message += f". Withdrawn (no longer in the registry): {', '.join(withdrawn)}"
    return {
        "synced": synced,
        "skipped": 0,
        "skipped_entries": [],
        "withdrawn": withdrawn,
        "used_seed": used_seed,
        "seed_ignored": seed_ignored,
        "catalog_serial": state.serial if state.serial else None,
        "catalog_expires_at": state.expires_at.isoformat() if state.expires_at else None,
        "message": message,
    }
