# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Release catalogue, verified binary serving and latest-version promotion.

The old one-step upload/delete URLs refuse before body consumption or writes.
Publication and retained deletion use the explicitly reviewed operation API.
Legacy binary reads do not adopt or remove old files as a side effect.
"""

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

if TYPE_CHECKING:
    # Imported only for the "RemoteAgent | None" forward-ref annotation below;
    # the runtime import happens locally inside _authenticate_release_download.
    from app.models.agents import RemoteAgent

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import PlainTextResponse
from pydantic import AwareDatetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.agent_downloads import (
    _public_download_rate_limit,
)
from app.core.config import settings
from app.core.dependencies import (
    CurrentUser,
    get_current_user_optional,
    is_unscoped_superuser,
    require_permissions,
)
from app.db.session import get_session
from app.models.agents import AgentRelease
from app.schemas.agent_downloads import AgentReleaseResponse
from app.schemas.agent_release_catalogue import CataloguePage
from app.schemas.agent_release_operation_contract import (
    release_context_contract,
    release_download_context_contract,
)
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_binary import create_release_binary_response
from app.services.agent_release_browser_context import (
    check_release_browser_context,
    check_release_download_context,
)
from app.services.agent_release_catalogue import (
    MAX_ROWS,
    NO_STORE,
    catalogue_rows,
    catalogue_statement,
    encode_catalogue_page,
    encode_legacy_catalogue,
)
from app.services.agent_release_promotion import (
    ReleasePromotionSnapshot,
    promote_verified_release,
)
from app.services.agent_release_read_authority import capture_release_read_authority
from app.services.release_signing_async import agent_release_operation

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
    summary="List up to 100 releases; use release-catalogue for larger catalogues",
    openapi_extra=release_context_contract(),
)
async def list_releases(
    request: Request,
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
    check_release_browser_context(request, current_user)
    authority = await ReleaseMutationAuthority.capture(
        request,
        current_user,
        secret_key=settings.SECRET_KEY.encode("utf-8"),
    )
    rows = await _list_visible_releases(current_user, session, platform, agent_type)
    # Authentication precedes the catalogue query. A database wait must not
    # turn that earlier account/key/session snapshot into continuing authority.
    # This fresh scalar read has no committing authentication side effects.
    content = encode_legacy_catalogue(rows)
    authority.validate(await authority._read())
    return Response(content=content, media_type="application/json", headers=NO_STORE)


async def _list_visible_releases(
    current_user: CurrentUser,
    session: AsyncSession,
    platform: str | None = None,
    agent_type: str | None = None,
) -> Any:
    """Only the scoped query, not an authentication or authorization entry point.

    The public caller checks current authority before and after this read.
    Kept separate so normalization units test the exact query without claiming
    that their deliberately inert session is a current-authentication fixture.
    """
    statement = catalogue_statement(
        current_user, platform=platform, agent_type=agent_type, limit=MAX_ROWS
    )
    return await catalogue_rows(session, statement)


@router.get(
    "/release-catalogue",
    response_model=CataloguePage,
    summary="Read a bounded, scoped release catalogue page",
    openapi_extra=release_context_contract(),
)
async def release_catalogue(
    request: Request,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
    platform: Annotated[str | None, Query(max_length=50)] = None,
    agent_type: Annotated[str | None, Query(max_length=50)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_ROWS)] = 50,
    before_published_at: AwareDatetime | None = None,
    before_id: UUID | None = None,
) -> Response:
    """Current observations ordered by timestamp then UUID, both descending.

    Cursor position grants no authority and is not a snapshot across requests.
    Concurrent publications require an explicit refresh from the first page.
    Stored URLs/signatures are metadata, not independently verified trust.
    """
    check_release_browser_context(request, current_user)
    authority = await ReleaseMutationAuthority.capture(
        request,
        current_user,
        secret_key=settings.SECRET_KEY.encode("utf-8"),
    )
    statement = catalogue_statement(
        current_user,
        platform=platform,
        agent_type=agent_type,
        limit=limit,
        before_published_at=before_published_at,
        before_id=before_id,
    )
    rows = await catalogue_rows(session, statement)
    content = encode_catalogue_page(rows, limit=limit)
    # Revalidate after query AND encoding; no auth routine commits last_used here.
    authority.validate(await authority._read())
    return Response(content=content, media_type="application/json", headers=NO_STORE)


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


@router.post("/releases/upload", deprecated=True, summary="Retired one-step release mutation")
async def upload_release(
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
    from app.services.release_signing import SigningKeyError
    from app.services.release_signing_async import SigningBusyError, public_key_pem_async

    try:
        public = await public_key_pem_async(public_request=True)
    except (SigningBusyError, SigningKeyError):
        raise HTTPException(
            503,
            "Release signing key is unavailable",
            headers={"Retry-After": "1"},
        ) from None
    return public.decode("ascii")


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


@router.head(
    "/releases/{release_id}/binary",
    dependencies=[Depends(_public_download_rate_limit)],
    include_in_schema=False,
)
@router.get(
    "/releases/{release_id}/binary",
    dependencies=[Depends(_public_download_rate_limit)],
    summary="Serve verified managed or legacy release bytes with current authority",
    response_class=Response,
    openapi_extra=release_download_context_contract(),
)
async def download_release_binary(
    request: Request,
    release_id: UUID,
    user: Annotated[CurrentUser | None, Depends(get_current_user_optional)] = None,
) -> Any:
    """Use current operator/agent authority and retain the verified descriptor.

    Managed history never falls back to legacy storage on error. GET and HEAD
    use the same verification/authority rules; HEAD does not increment counts.
    No pathname is passed to FileResponse or created as a side effect of reading.
    """
    check_release_download_context(request, user)
    authority = await capture_release_read_authority(
        request,
        user,
        secret_key=settings.SECRET_KEY.encode("utf-8"),
    )
    return await create_release_binary_response(
        authority=authority,
        release_id=release_id,
        policy=getattr(request.app.state, "agent_release_policy", None),
    )


@router.patch(
    "/releases/{release_id}/promote",
    response_model=AgentReleaseResponse,
    summary="Mark a release as the latest for its platform+type (admin)",
    openapi_extra=release_context_contract(),
)
@agent_release_operation
async def promote_release(
    request: Request,
    release_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: AsyncSession = Depends(get_session),
) -> Any:
    """Verify stored signature and current scoped authority before latest changes."""
    check_release_browser_context(request, current_user)
    authority = await ReleaseMutationAuthority.capture(
        request, current_user, secret_key=settings.SECRET_KEY.encode("utf-8")
    )
    release = await _verify_release_access(session, release_id, current_user, mutate=True)
    snapshot = ReleasePromotionSnapshot.capture(release)
    return await promote_verified_release(session, snapshot=snapshot, authority=authority)


@router.delete(
    "/releases/{release_id}", deprecated=True, summary="Retired one-step release mutation"
)
async def delete_release(
    request: Request,
    release_id: UUID,
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
