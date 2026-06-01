# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Agent release upload + binary serving.

Splits off from agent_downloads.py to keep concerns clean. The existing
publish endpoint takes a `download_url` string and assumes the binary
is hosted externally. This module adds:

- POST /agents/releases/upload  — admin streams a binary up; backend
  stores it, computes SHA-256, and creates the AgentRelease row with
  a backend-served download URL.
- GET  /agents/releases/{id}/binary  — public download endpoint
  (rate-limited via the same in-process bucket).
- DELETE /agents/releases/{id}  — admin soft-delete (file kept on
  disk; the row is removed from queries).
- PATCH /agents/releases/{id}/promote  — admin marks a release as
  latest, clearing the previous latest for the same platform/type.

Storage path is configured via FREESDN_AGENT_RELEASE_DIR (default
``/var/lib/freesdn/agent-releases`` inside the container). The
directory is created lazily on first upload.
"""

import hashlib
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    # Imported only for the "RemoteAgent | None" forward-ref annotation below;
    # the runtime import happens locally inside _authenticate_release_download.
    from app.models.agents import RemoteAgent

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.agent_downloads import (
    VALID_AGENT_TYPES,
    VALID_PLATFORMS,
    _public_download_rate_limit,
)
from app.core.dependencies import (
    CurrentUser,
    get_current_user_optional,
    is_unscoped_superuser,
    require_permissions,
)
from app.db.session import get_session
from app.models.agents import AgentRelease
from app.schemas.agent_downloads import AgentReleaseResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# 500 MB cap mirrors the agent's _MAX_DOWNLOAD_BYTES — anything larger
# can't be downloaded anyway.
_MAX_UPLOAD_BYTES = 500 * 1024 * 1024

# Version strings get embedded in file paths; cap them tight and reject
# anything that could escape the release dir or trip OS path parsing.
_VERSION_PATTERN = re.compile(r"^[a-zA-Z0-9._+-]{1,50}$")


def _release_dir() -> Path:
    """Where uploaded binaries live on disk.

    Default: ``/var/lib/freesdn/agent-releases``. Override via the
    FREESDN_AGENT_RELEASE_DIR env var so deployments can mount a
    persistent volume there. Directory is created on first call.
    """
    base = os.environ.get(
        "FREESDN_AGENT_RELEASE_DIR",
        "/var/lib/freesdn/agent-releases",
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _binary_path(release_id: UUID, filename: str) -> Path:
    """Resolve an on-disk path for a given release id + filename.

    Filename is preserved (so MIME type can be inferred + the agent
    sees a sensible suggested name). It's sanitized to avoid
    directory traversal — the only allowed chars are
    ``[A-Za-z0-9._+-]``; anything else collapses to ``_``.
    """
    safe = re.sub(r"[^A-Za-z0-9._+-]", "_", filename or "agent")[:128] or "agent"
    return _release_dir() / f"{release_id}-{safe}"


@router.get(
    "/releases",
    response_model=list[AgentReleaseResponse],
    summary="List all releases (admin view, raw rows)",
)
async def list_releases(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
    platform: str | None = None,
    agent_type: str | None = None,
) -> Any:
    """Return AgentRelease rows visible to the caller.

    Org-scoped: non-super_admin sees only releases
    owned by their org PLUS legacy NULL-org releases (treated as
    global). Super_admin sees everything.
    """
    q = select(AgentRelease)
    if not is_unscoped_superuser(current_user):
        org_id = current_user.organization_id
        if not org_id:
            return []
        # Caller's own releases OR legacy global (NULL org)
        q = q.where(
            (AgentRelease.organization_id == org_id) | (AgentRelease.organization_id.is_(None))
        )
    if platform:
        q = q.where(AgentRelease.platform == platform.lower())
    if agent_type:
        q = q.where(AgentRelease.agent_type == agent_type.lower())
    q = q.order_by(AgentRelease.published_at.desc())
    rows = (await session.execute(q)).scalars().all()
    return rows


async def _verify_release_access(
    session: AsyncSession,
    release_id: UUID,
    current_user: CurrentUser,
    *,
    mutate: bool = False,
) -> AgentRelease:
    """404-shape access check for /releases/{id}/* endpoints.

    Read access:
    - Super_admin: any release
    - Other: own-org release OR legacy NULL-org global

    Mutate access (promote/delete):
    - Super_admin: any release
    - Other: own-org release only. Legacy NULL-org releases require
      super_admin to mutate (so an org_admin can't promote a release
      uploaded by another org's admin or by super_admin).
    """
    q = await session.execute(select(AgentRelease).where(AgentRelease.id == release_id))
    release = q.scalar_one_or_none()
    if not release:
        raise HTTPException(404, "Release not found")
    if is_unscoped_superuser(current_user):
        return release
    org_id = current_user.organization_id
    if mutate:
        # mutate = own-org only
        if release.organization_id and release.organization_id == org_id:
            return release
    else:
        # read = own-org or legacy global
        if release.organization_id is None or release.organization_id == org_id:
            return release
    raise HTTPException(404, "Release not found")


@router.post(
    "/releases/upload",
    response_model=AgentReleaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a release binary and publish it (admin only)",
)
async def upload_release(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    file: Annotated[UploadFile, File(description="Agent binary (any platform-native format)")],
    version: Annotated[str, Form(min_length=1, max_length=50)],
    platform: Annotated[str, Form(min_length=1, max_length=50)],
    agent_type: Annotated[str, Form()] = "daemon",
    release_notes: Annotated[str, Form()] = "",
    min_backend_version: Annotated[str, Form()] = "",
    is_prerelease: Annotated[bool, Form()] = False,
    is_latest: Annotated[bool, Form()] = True,
    session: AsyncSession = Depends(get_session),
) -> Any:
    """Stream upload a release binary.

    Differences from POST /downloads/releases:
    - Binary stored on the backend (no external host needed).
    - SHA-256 computed on-the-fly during streaming; no chance for the
      checksum to drift from the file we'll later serve.
    - is_latest defaults to True so a fresh upload becomes the
      default for new agents.

    On success returns the new AgentRelease row, with download_url
    pointing at /api/v1/agents/releases/{id}/binary.
    """
    if not _VERSION_PATTERN.match(version):
        raise HTTPException(400, "version must match [A-Za-z0-9._+-]{1,50}")
    if platform.lower() not in VALID_PLATFORMS:
        raise HTTPException(400, f"Invalid platform: {platform}")
    if agent_type.lower() not in VALID_AGENT_TYPES:
        raise HTTPException(400, f"Invalid agent_type: {agent_type}")

    # SECURITY: only super_admin may publish a GLOBAL
    # (organization_id IS NULL) release; every other admin's upload is forced to
    # their own organization, and the is_latest clear below is scoped to that
    # same bucket — so a tenant admin can never poison the global / cross-tenant
    # update feed.
    is_super = is_unscoped_superuser(current_user)
    release_org = None if is_super else current_user.organization_id
    if not is_super and release_org is None:
        raise HTTPException(400, "An organization context is required to upload a release.")

    release_id = uuid4()
    # sanitize once + persist on the row so the
    # download endpoint can reconstruct the path deterministically.
    safe_filename = re.sub(r"[^A-Za-z0-9._+-]", "_", (file.filename or "agent"))[:128] or "agent"
    binary_path = _binary_path(release_id, safe_filename)
    sha = hashlib.sha256()
    bytes_written = 0

    # Stream to disk while computing checksum. Enforce size cap during
    # the read loop instead of buffering the whole file in memory.
    try:
        with binary_path.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)  # 1 MiB chunks
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > _MAX_UPLOAD_BYTES:
                    fh.close()
                    binary_path.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"Upload exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MiB cap",
                    )
                sha.update(chunk)
                fh.write(chunk)
    except HTTPException:
        raise
    except Exception:
        binary_path.unlink(missing_ok=True)
        logger.exception("Release upload failed")
        raise HTTPException(500, "Upload write failed")

    checksum = sha.hexdigest()
    download_url = f"/api/v1/agents/releases/{release_id}/binary"

    # Sign the digest with the backend's ECDSA-P256 release-signing
    # key. The agent verifies this signature before staging the
    # downloaded binary — defense in depth on top of the existing
    # HTTPS + checksum check (a compromised backend that swaps both
    # binary AND checksum row would also need the private signing key
    # to swap the signature).
    #
    # fail closed on signing failure for any release
    # that is (or would become) the latest. Unsigned latest releases
    # silently bypass the agent's signature-verification gate.
    # Only explicitly non-latest uploads (is_latest=False) may proceed
    # without a signature.
    from app.services.release_signing import sign_digest

    try:
        signature = sign_digest(checksum)
    except Exception:
        logger.exception(
            "Release signing failed for upload version=%s platform=%s", version, platform
        )
        if is_latest:
            # Remove the written binary before raising so we leave no
            # orphaned artifact on disk.
            binary_path.unlink(missing_ok=True)
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Release signing failed; the release was not created. "
                "Check the signing-key configuration and retry.",
            )
        # Non-latest / test artifact: unsigned is acceptable.
        logger.warning(
            "Proceeding with unsigned non-latest release version=%s platform=%s",
            version,
            platform,
        )
        signature = None

    # The binary is already on disk. If any DB step below fails (the
    # is_latest clear, the row insert, or the commit) we must roll back
    # AND remove the just-written binary — otherwise a failed publish
    # leaves an orphaned artifact in the release dir that no row points
    # at and that delete_release/promote_release can never reach.
    try:
        # Clear previous is_latest for this (platform, agent_type) WITHIN the
        # same org bucket only — NULL bucket is global/super_admin.
        if is_latest:
            org_bucket = (
                AgentRelease.organization_id.is_(None)
                if release_org is None
                else AgentRelease.organization_id == release_org
            )
            await session.execute(
                update(AgentRelease)
                .where(
                    and_(
                        AgentRelease.platform == platform.lower(),
                        AgentRelease.agent_type == agent_type.lower(),
                        AgentRelease.is_latest,
                        org_bucket,
                    )
                )
                .values(is_latest=False)
            )

        release = AgentRelease(
            id=release_id,
            version=version,
            platform=platform.lower(),
            agent_type=agent_type.lower(),
            download_url=download_url,
            checksum_sha256=checksum,
            signature=signature,
            file_size=bytes_written,
            release_notes=release_notes[:20000],
            min_backend_version=min_backend_version[:50],
            is_latest=is_latest,
            is_prerelease=is_prerelease,
            published_at=datetime.now(UTC),
            download_count=0,
            organization_id=release_org,  # super_admin→global, else own org
            filename=safe_filename,
        )
        session.add(release)
        await session.commit()
    except Exception:
        await session.rollback()
        binary_path.unlink(missing_ok=True)
        logger.exception(
            "Release DB write failed; removed orphaned binary version=%s platform=%s",
            version,
            platform,
        )
        raise HTTPException(500, "Release publish failed")
    await session.refresh(release)
    logger.info(
        "Uploaded agent release %s (%s/%s) — %d bytes, sha256=%s",
        version,
        platform,
        agent_type,
        bytes_written,
        checksum[:16],
    )
    return release


@router.get(
    "/releases/public-key",
    summary="ECDSA-P256 public key used to sign release binaries",
    response_class=PlainTextResponse,
)
async def release_public_key() -> str:
    """Return the PEM-encoded public key.

    Unauthenticated (public key is public). The agent fetches this
    once on startup + caches it; verifies each downloaded binary's
    signature against this key before staging.
    """
    from app.services.release_signing import public_key_pem

    return public_key_pem().decode("ascii")


async def _authenticate_release_download(
    session: AsyncSession,
    agent_id_header: str | None,
    agent_key_header: str | None,
) -> "RemoteAgent | None":
    """Same auth check used by /updates/check.

    Returns the matching RemoteAgent on success, raises 401 otherwise.
    Reused logic from agent_downloads.py so an agent's existing
    X-Agent-Key works on both endpoints.
    """
    import hashlib

    generic = HTTPException(
        status_code=401,
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
    result = await session.execute(select_remote_agent_for_auth(agent_uuid, key_hash))
    agent = result.scalar_one_or_none()
    # CONV2-003: a DISABLED agent must not download release binaries — mirror the
    # update-check authenticator (agent_downloads.py) which rejects is_enabled=False
    # so lifecycle revocation is consistent across both artifact paths.
    if not agent or not agent.is_approved or not getattr(agent, "is_enabled", True):
        raise generic
    return agent


def select_remote_agent_for_auth(agent_uuid: UUID, key_hash: str):
    """Helper to keep the SELECT shape in one place."""
    from app.models.agents import RemoteAgent

    return select(RemoteAgent).where(
        RemoteAgent.id == agent_uuid,
        RemoteAgent.agent_key == key_hash,
        RemoteAgent.deleted_at.is_(None),
    )


@router.get(
    "/releases/{release_id}/binary",
    dependencies=[Depends(_public_download_rate_limit)],
    summary="Serve the binary blob for a release (agent-authenticated)",
)
async def download_release_binary(
    release_id: UUID,
    session: AsyncSession = Depends(get_session),
    x_agent_id: Annotated[str | None, Header(alias="X-Agent-ID")] = None,
    x_agent_key: Annotated[str | None, Header(alias="X-Agent-Key")] = None,
    user: Annotated[CurrentUser | None, Depends(get_current_user_optional)] = None,
) -> Any:
    """Stream the on-disk binary back to the client.

    Dual auth: an agent presents its X-Agent-Key (the same headers it sends
    on /updates/check), OR a logged-in operator/admin presents
    a valid session (httpOnly cookie / Bearer / API key). The latter lets the
    Downloads + Releases admin pages fetch installers, which previously 401'd
    because only the agent-key path existed. UUID-in-URL alone is still not
    enough — at least one authenticated principal is required.
    """
    agent = None
    if user is None:
        # No logged-in session — fall back to (and require) agent-key auth.
        agent = await _authenticate_release_download(session, x_agent_id, x_agent_key)
    q = await session.execute(select(AgentRelease).where(AgentRelease.id == release_id))
    release = q.scalar_one_or_none()
    if not release:
        raise HTTPException(404, "Release not found")

    # SECURITY: scope the artifact fetch to the
    # caller's org. super_admin may fetch any; everyone else may fetch a GLOBAL
    # (organization_id IS NULL) release or their own org's — never another
    # tenant's binary by guessed/leaked UUID. 404-shape to avoid existence oracle.
    if not (user is not None and is_unscoped_superuser(user)):
        caller_org = (
            user.organization_id
            if user is not None
            else (agent.organization_id if agent is not None else None)
        )
        if release.organization_id is not None and release.organization_id != caller_org:
            raise HTTPException(404, "Release not found")

    # prefer the explicit filename column. Glob
    # fallback for legacy rows (uploaded before migration 030).
    if release.filename:
        path = _release_dir() / f"{release_id}-{release.filename}"
        if not path.exists():
            raise HTTPException(404, "Binary missing on disk")
    else:
        matches = list(_release_dir().glob(f"{release_id}-*"))
        if not matches:
            raise HTTPException(404, "Binary missing on disk")
        # Sort for determinism even on legacy rows
        matches.sort()
        path = matches[0]

    # Bump download counter (best-effort; doesn't block serving)
    try:
        release.download_count = (release.download_count or 0) + 1
        await session.commit()
    except Exception:
        logger.exception("Failed to bump download_count for %s", release_id)

    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=path.name.split("-", 1)[1] if "-" in path.name else path.name,
    )


@router.patch(
    "/releases/{release_id}/promote",
    response_model=AgentReleaseResponse,
    summary="Mark a release as the latest for its platform+type (admin)",
)
async def promote_release(
    release_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
) -> Any:
    """Atomically swap is_latest from the current row to this one.

    Org-scoped: non-super_admin can only promote their own org's
    releases. Legacy NULL-org releases require super_admin.
    """
    release = await _verify_release_access(
        session,
        release_id,
        current_user,
        mutate=True,
    )

    # Clear previous is_latest for this (platform, agent_type) WITHIN the same
    # org bucket only — NULL bucket is global/super_admin.
    org_bucket = (
        AgentRelease.organization_id.is_(None)
        if release.organization_id is None
        else AgentRelease.organization_id == release.organization_id
    )
    await session.execute(
        update(AgentRelease)
        .where(
            and_(
                AgentRelease.platform == release.platform,
                AgentRelease.agent_type == release.agent_type,
                AgentRelease.is_latest,
                org_bucket,
            )
        )
        .values(is_latest=False)
    )
    release.is_latest = True
    await session.commit()
    await session.refresh(release)
    return release


@router.delete(
    "/releases/{release_id}",
    summary="Delete a release (admin); also removes its on-disk binary",
)
async def delete_release(
    release_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
) -> Any:
    """Delete a release.

    Org-scoped: non-super_admin can only delete their own org's
    releases. Legacy NULL-org releases require super_admin.
    """
    release = await _verify_release_access(
        session,
        release_id,
        current_user,
        mutate=True,
    )

    # Remove the on-disk binary first; row delete is the source of truth
    # for "this release exists" so leaving the file orphaned is safer
    # than leaving a row pointing at a missing file.
    for path in _release_dir().glob(f"{release_id}-*"):
        try:
            path.unlink()
        except Exception:
            logger.warning("Could not remove %s", path, exc_info=True)

    await session.delete(release)
    await session.commit()
    return {"message": "Release deleted"}
