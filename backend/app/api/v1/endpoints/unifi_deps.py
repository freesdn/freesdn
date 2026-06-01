# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Shared dependencies for the UniFi REST surface.

Centralises the tenant-scoped controller lookup + adapter
construction so each of the seven ``unifi_*`` endpoint files
imports a single helper instead of repeating the boilerplate.

Per the reference contract: every endpoint that touches a
UniFi controller goes through :func:`_get_controller` which joins
``Controller → Site`` and filters by ``current_user.organization_id``.
A user from organization A passing a controller_id owned by
organization B gets back a 404 (and crucially **not** a 403, so the
existence of the controller is not leaked).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, get_current_user, get_session
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import is_unscoped_superuser
from app.models import Controller

logger = logging.getLogger(__name__)


def _decrypt_if_needed(value: str | None) -> str:
    """Return plaintext for encrypted controller secrets."""
    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except Exception:
        # Bare value — return as-is so a mis-formatted credential
        # row doesn't 500 the entire UniFi surface.
        return value


async def _get_controller(
    controller_id: UUID,
    session: AsyncSession,
    current_user: CurrentUser,
) -> Controller:
    """Load a UniFi controller scoped to the caller's organization.

    Refuses any row that:
      * doesn't exist (or is soft-deleted)
      * is not owned by the caller's organization (404 — not 403, so
        we don't leak existence)
      * has a non-UniFi ``type``
    """
    stmt = (
        select(Controller)
        .options(selectinload(Controller.site))
        .where(
            Controller.id == controller_id,
            Controller.deleted_at.is_(None),
        )
    )
    result = await session.execute(stmt)
    controller = result.scalar_one_or_none()
    if controller is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")

    # a SCOPED super_admin key must stay org-confined here too.
    if not is_unscoped_superuser(current_user):
        site = controller.site
        if (
            site is None
            or site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            # 404 (not 403) — avoid existence leak across tenants.
            raise HTTPException(
                status_code=404,
                detail="UniFi controller not found",
            )

    ctype = (controller.type or "").lower()
    if ctype not in ("unifi", "ubiquiti"):
        raise HTTPException(
            status_code=400,
            detail=f"controller {controller_id} is not a UniFi controller "
            f"(type={controller.type!r})",
        )
    return controller


def _build_adapter(controller: Controller) -> UniFiAdapter:
    """Instantiate a NEW UniFiAdapter from a Controller row.

    This is the **fallback** path — prefer ``get_adapter_for_controller``
    which routes through the shared adapter pool. Used only when the
    pool fails (e.g. import-time, tests).
    """
    cfg: dict[str, Any] = controller.config or {}
    kwargs: dict[str, Any] = {
        "port": controller.port or 8443,
        "use_ssl": bool(controller.use_ssl),
        "verify_ssl": bool(controller.verify_ssl),
        "site": cfg.get("site", "default"),
    }
    if "is_unifi_os" in cfg:
        kwargs["is_unifi_os"] = bool(cfg["is_unifi_os"])
    return UniFiAdapter(
        host=controller.host,
        username=(controller.username or ""),
        password=_decrypt_if_needed(controller.password),
        **kwargs,
    )


async def get_adapter_for_controller(
    controller_id: UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> UniFiAdapter:
    """FastAPI dependency: returns a **pooled** connected UniFiAdapter.

    Pool path: shared adapter keyed on ``(controller_id, "unifi")``.
    The first caller logs in and seeds the TOKEN cookie; subsequent
    callers reuse the same session for the lifetime of the cookie
    (~2h on UniFi OS v10.x). Without this, every request built a
    fresh ``UniFiAdapter`` and POSTed ``/api/auth/login`` — which
    exhausts the UniFi OS
    Identity rate-limit (~10-15 attempts/min) and cascades into
    confusing "credentials rejected" errors across all read paths.

    Falls back to a fresh adapter if the pool errors so a pool bug
    cannot 502 every UniFi request.
    """
    controller = await _get_controller(controller_id, session, current_user)
    # Per-user FreeSDN site grant for the requested upstream slug. This OLDER
    # unifi_* REST surface takes ``{site}`` straight from the path and only checked
    # the CONTROLLER's own site — so a site-limited operator on a multi-site
    # controller could name a sibling upstream slug the shared credential sees. The
    # newer adapter_unifi_* services enforce this via ``enforce_unifi_site_grant``;
    # mirror it here at the shared chokepoint so every {site}-scoped route on this
    # surface is covered (no-op for controller-level routes with no {site} param).
    site_slug = request.path_params.get("site")
    if site_slug:
        from app.services.adapter_unifi_common import enforce_unifi_site_grant

        enforce_unifi_site_grant(controller, site_slug)
    cfg: dict[str, Any] = controller.config or {}
    common_kwargs: dict[str, Any] = {
        "port": controller.port or 8443,
        "use_ssl": bool(controller.use_ssl),
        "verify_ssl": bool(controller.verify_ssl),
        "site": cfg.get("site", "default"),
    }
    if "is_unifi_os" in cfg:
        common_kwargs["is_unifi_os"] = bool(cfg["is_unifi_os"])

    try:
        from app.adapters.pool import adapter_pool

        adapter = await adapter_pool.get_or_create_shared(
            adapter_id="unifi",
            controller_id=str(controller.id),
            host=controller.host,
            username=(controller.username or ""),
            password=_decrypt_if_needed(controller.password),
            **common_kwargs,
        )
        # Pool seeds connect() on first creation; reuse path skips it.
        # Belt-and-braces: if the cached adapter somehow ended up
        # disconnected (controller restarted), reconnect now.
        if not getattr(adapter, "_connected", False):
            await adapter.connect()
        return adapter  # type: ignore[no-any-return]
    except Exception:
        logger.exception("UniFi adapter pool failed for %s — falling back", controller.id)
        adapter = _build_adapter(controller)
        if not getattr(adapter, "_connected", False):
            await adapter.connect()
        return adapter


__all__ = [
    "_get_controller",
    "_build_adapter",
    "get_adapter_for_controller",
]
