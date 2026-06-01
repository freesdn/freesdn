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

Reads (method=GET) run live unconditionally. Writes — POST, PUT,
PATCH, DELETE — refuse outright when ``settings.OMADA_READ_ONLY`` is
True UNLESS the body has ``force=true`` (matching the rest of the
gate). When read-only is off and force is True, the call goes through.

This is a power-user endpoint, scoped to ``controller:write`` so
ordinary users cannot probe arbitrary paths.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_base import GatewayServiceBase

router = APIRouter(prefix="/gateway-raw", tags=["gateway-raw"])


# Methods that mutate state and must respect the read-only gate.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

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


# Path-segment verbs for CATASTROPHIC / irreversible device-or-controller ops.
# The typed staging path classifies these features as catastrophic and forces
# BOTH ``confirmed=true`` (enforce_omada_preflight) AND a minimum ``site_admin``
# role (_required_apply_role) before apply. The raw escape hatch reaches the same
# controller commands directly (e.g. ``/sites/{id}/cmd/devices/{mac}/forget``,
# ``.../reboot``, ``.../upgrade``, ``/cmd/devices/batch/factoryReset``), so it
# MUST apply the same second factor + role gate or it becomes a way to fire a
# fleet wipe / firmware flash / unadopt with only ``controller:write`` and a
# single ``force`` toggle. Matched as a trailing ``/``-delimited PATH SEGMENT
# (case-insensitive) so we catch the real command verbs without false-matching
# read paths like ``/firmware/upgradeLog`` or ``/setting/firmwareUpgradeSchedule``.
_CATASTROPHIC_PATH_VERBS = frozenset(
    {
        "forget",  # unadopt — drops the device's controller-side config
        "reboot",  # device reboot — network blip / outage risk
        "upgrade",  # firmware flash — brick risk, not undoable
        "factoryreset",  # wipe device(s) to factory defaults — irreversible
    }
)


def _catastrophic_verb(canonical_path: str) -> str | None:
    """Return the catastrophic command verb if the path's last (or
    second-to-last, to cover ``.../{verb}/{trailing}``) segment is one.

    Segment-anchored so ``/firmware/upgradeLog`` (segment ``upgradelog``) and
    ``/setting/firmwareUpgradeSchedule`` do NOT match while the real command
    paths (``.../cmd/devices/{mac}/upgrade``, ``.../batch/factoryReset``,
    ``.../{mac}/reboot``, ``.../{mac}/forget``) do.
    """
    segments = [s for s in canonical_path.lower().split("/") if s]
    # Inspect the last two segments so a trailing id (rare for these cmds) or a
    # batch suffix doesn't hide the verb; the cmd verb is the last meaningful one.
    for seg in segments[-2:]:
        if seg in _CATASTROPHIC_PATH_VERBS:
            return seg
    return None


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
        description=(
            "Required for write methods (POST/PUT/PATCH/DELETE) when "
            "OMADA_READ_ONLY is True. Default-safe."
        ),
    )
    confirmed: bool = Field(
        default=False,
        description=(
            "Required IN ADDITION to force for catastrophic / irreversible "
            "device commands (factory-reset, forget/unadopt, reboot, firmware "
            "upgrade). Mirrors the confirmed=true second factor the typed "
            "staging path enforces. Default-safe."
        ),
    )


class RawCallResponse(BaseModel):
    method: str
    path: str
    response: Any


class _RawService(GatewayServiceBase):
    """Tiny service — just the controller resolution from the base."""


@router.post(
    "/{controller_id}/call",
    response_model=RawCallResponse,
    status_code=status.HTTP_200_OK,
    summary=(
        "Direct Omada v2 API passthrough. Use only when no typed "
        "endpoint exists. Writes are gated by OMADA_READ_ONLY + force."
    ),
)
async def raw_call(
    controller_id: UUID,
    body: RawCallRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Forward an arbitrary v2 call to the controller.

    Reads run live. Writes refuse unless ``OMADA_READ_ONLY=false`` AND
    ``force=true`` — same dual-gate as ``apply_change``.
    """
    method_upper = body.method.upper()

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

    # Gate writes on the read-only flag
    if method_upper in _WRITE_METHODS:
        read_only = bool(
            getattr(settings, "OMADA_READ_ONLY", True)
            or getattr(settings, "ADAPTER_READ_ONLY", True)
        )
        if read_only and not body.force:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    "OMADA_READ_ONLY is set — raw write refused. Pass "
                    "force=true on the request body AND set "
                    "OMADA_READ_ONLY=false on the server to override. "
                    "Both safeties must be down."
                ),
            )

        # Catastrophic device commands reached via the raw hatch (factory-reset,
        # forget/unadopt, reboot, firmware upgrade) must satisfy the SAME second
        # factor + role gate the typed staging path enforces — otherwise raw
        # becomes a way to fire a fleet wipe / firmware flash with only
        # controller:write and a single force toggle. site_admin role mirrors
        # _required_apply_role; confirmed=true mirrors enforce_omada_preflight.
        catastrophic_verb = _catastrophic_verb(canonical_path)
        if catastrophic_verb is not None:
            if not user.has_min_role("site_admin"):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"raw {catastrophic_verb} is a catastrophic / "
                        "irreversible device operation and requires minimum "
                        "role site_admin"
                    ),
                )
            if not body.confirmed:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail=(
                        f"raw {catastrophic_verb} is catastrophic / irreversible; "
                        "re-send with confirmed=true (in addition to force=true) "
                        "to proceed"
                    ),
                )

    # Audit-log every raw call (read or write). The escape hatch
    # bypasses the staging table, so the audit log is the only record
    # of what was called. Log BEFORE the controller fetch so the
    # access intent is recorded even if the call fails.
    from app.services.audit import AuditAction, AuditService, ResourceType

    audit = AuditService(db=session)
    try:
        await audit.log(
            action=(AuditAction.READ if method_upper == "GET" else AuditAction.UPDATE),
            resource_type=ResourceType.CONTROLLER,
            resource_id=controller_id,
            organization_id=user.organization_id,
            actor_id=user.id,
            extra_metadata={
                "method": method_upper,
                "path": canonical_path,
                "requested_path": body.path,
                "force": body.force,
                "confirmed": body.confirmed,
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

    return {"method": method_upper, "path": canonical_path, "response": response}
