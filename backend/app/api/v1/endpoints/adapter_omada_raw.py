# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Omada raw passthrough endpoint
==========================================

Escape hatch for Omada API calls we have not typed yet. Power users
hit this when they need a controller feature FreeSDN's typed wrappers
do not cover — usually because the feature is brand-new on Omada or
deployment-specific.

Layout::

    POST /api/v1/gateway-raw/{controller_id}/call
        body: {
          method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
          path: "/sites/{omadaSiteId}/setting/...",
          params?: {...},
          body?: {...} | [...],
          stage?: false  // future: route mutations through staging
        }

READ-ONLY. Only ``method=GET`` is forwarded; every mutating method is
refused, because a raw write would reach the controller without a staged
change, a confirmation or the device slot. Make changes on the typed Omada
pages, which stage them.

Callers limited to some sites are refused: the path names an upstream Omada
site id that cannot be mapped back to a FreeSDN site grant. Responses pass
through ``redact_secrets`` before they are returned.

This is a power-user endpoint, scoped to ``controller:write`` so
ordinary users cannot probe arbitrary paths.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.redaction import redact_secrets
from app.db.session import get_session
from app.services.adapter_base import GatewayServiceBase

router = APIRouter(prefix="/gateway-raw", tags=["gateway-raw"])


# Path fragments that the typed wrappers intentionally route through
# staging (admin / user / role mutation, backup ops, controller
# system mutation). Refuse raw access to these so a caller can't
# circumvent the staging audit trail by going through the escape
# hatch. Match is case-insensitive and substring-anchored.
_RAW_PATH_BLOCKLIST = (
    "/admin",
    "/admins",
    "/users",
    "/roles",
    "/permissions",
    "/cmd/backup",
    # The real Omada backup-create/export/import/restore paths live under
    # /maintenance/ not /cmd/.  Block the full prefix so none of the
    # maintenance sub-paths (backup, export, import, restore, reboot, …)
    # can be reached via the raw escape hatch.
    "/maintenance/",
    "/setting/system/sslcert",
    "/setting/system/admin",
)


class RawCallRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(
        min_length=1,
        max_length=1024,
        description=(
            "Path relative to the Omada controller API root, e.g. "
            "/sites/abc123/setting/exotic/feature"
        ),
    )
    params: dict[str, Any] | None = None
    body: dict[str, Any] | list[Any] | None = None
    force: bool = Field(
        default=False,
        description="Ignored. Raw writes are refused; use the staged Omada pages.",
    )
    confirmed: bool = Field(
        default=False,
        description="Ignored. Raw writes are refused; use the staged Omada pages.",
    )


class RawCallResponse(BaseModel):
    method: str
    path: str
    response: Any


class _RawService(GatewayServiceBase):
    """Tiny service — just the controller resolution from the base."""

    # This endpoint is an Omada v2 passthrough, so a controller of any other
    # vendor must be refused at resolution rather than handed to the client.
    SUPPORTED_CONTROLLER_TYPE = "omada"


@router.post(
    "/{controller_id}/call",
    response_model=RawCallResponse,
    status_code=status.HTTP_200_OK,
    summary=(
        "Direct Omada v2 API passthrough. Use only when no typed "
        "endpoint exists. Read-only: only GET is forwarded."
    ),
)
async def raw_call(
    controller_id: UUID,
    body: RawCallRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Forward an arbitrary v2 GET to the controller, redacted.

    Writes are refused: they would bypass staging, confirmation and the
    device slot. Site-limited callers are refused: the upstream site id in the
    path cannot be checked against their FreeSDN site grants.
    """
    method_upper = body.method.upper()
    if user.is_site_limited:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "The raw Omada call is not available to users limited to some "
                "sites: it cannot check the Omada site in the path against your "
                "site access."
            ),
        )
    if method_upper != "GET":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                f"Raw Omada {method_upper} calls are disabled: a raw write would "
                "skip staging. Make the change on the Omada pages, which stage it "
                "for review before it is applied."
            ),
        )

    # Refuse paths that the typed wrappers intentionally route through
    # staging — admins, users, roles, backups, SSL/system mutation.
    # Going through /raw bypasses the staging audit trail; we'd rather
    # 403 here and force callers to use the typed endpoint.
    # build the EXACT canonical path the controller will act on, then both
    # validate AND forward that same value (no validate-decoded / forward-encoded
    # asymmetry). The client prepends a leading slash when absent, so a caller could
    # send ``maintenance/backup`` (no slash) to dodge the ``/maintenance/`` fragment;
    # and a MULTI-encoded payload (e.g. ``%252Fmaintenance%252Fbackup``) would pass a
    # decode-once gate yet reach the controller for a SECOND server-side decode onto
    # ``/maintenance/...``. So we decode repeatedly until stable, reject path
    # traversal, collapse slashes, match the blocklist on the result — and forward
    # the SAME canonical value to the client below. Applies to ALL methods (GET
    # maintenance reads are blocked too, not just read-only-gated writes).
    from urllib.parse import unquote

    _decoded = body.path or ""
    for _ in range(6):
        _nxt = unquote(_decoded)
        if _nxt == _decoded:
            break
        _decoded = _nxt
    else:
        raise HTTPException(400, detail="path has too many layers of percent-encoding")
    if ".." in _decoded:
        raise HTTPException(400, detail="path must not contain '..' segments")
    # Reject whitespace / control chars / backslash outright: no legitimate Omada
    # API path contains them, and they are exactly the characters an attacker would
    # splice between segments (``/maintenance%20/backup`` → ``/maintenance /backup``,
    # CRLF, tab, ``\``) to break the slash-anchored substring match while a forgiving
    # controller normalizes them back onto a blocked path.
    if any(c.isspace() or c == "\\" or ord(c) < 0x20 for c in _decoded):
        raise HTTPException(
            400, detail="path contains illegal whitespace, control, or backslash characters"
        )
    canonical_path = "/" + _decoded.lstrip("/")
    while "//" in canonical_path:
        canonical_path = canonical_path.replace("//", "/")
    path_lower = canonical_path.lower()
    for fragment in _RAW_PATH_BLOCKLIST:
        if fragment in path_lower:
            raise HTTPException(
                403,
                detail=(
                    f"path contains blocked fragment {fragment!r}; use the "
                    "typed staging endpoint instead"
                ),
            )

    # Audit-log every raw call. The escape hatch
    # bypasses the staging table, so the audit log is the only record
    # of what was called. Log BEFORE the controller fetch so the
    # access intent is recorded even if the call fails.
    from app.services.audit import AuditAction, AuditService, ResourceType

    audit = AuditService(db=session)
    try:
        await audit.log(
            action=AuditAction.READ,
            resource_type=ResourceType.CONTROLLER,
            resource_id=controller_id,
            organization_id=user.organization_id,
            actor_id=user.id,
            extra_metadata={
                "method": method_upper,
                "path": canonical_path,
                "requested_path": body.path,
                "source": "gateway-raw",
            },
        )
    except Exception as exc:
        raise HTTPException(
            503,
            detail="audit log unavailable; refusing raw call",
        ) from exc

    svc = _RawService(session)
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    client = await svc._get_client(ctrl)

    try:
        response = await client.raw_call(
            method_upper,
            canonical_path,
            params=body.params,
            body=body.body,
        )
    except ValueError as exc:
        # Bad method (or other client-side rejection)
        raise HTTPException(400, detail=str(exc)) from exc
    except Exception as exc:
        import logging

        logging.getLogger(__name__).exception(
            "raw_call failed: method=%s path=%s", method_upper, canonical_path
        )
        # Avoid leaking controller-internal URLs / tokens via the
        # exception's str() — surface only the type to the operator.
        raise HTTPException(
            502,
            detail=(f"controller rejected the call ({type(exc).__name__})"),
        ) from exc

    return {"method": method_upper, "path": canonical_path, "response": redact_secrets(response)}
