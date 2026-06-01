# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Per-user site-grant authorization primitives
======================================================

The hybrid site-scoping model lives on ``CurrentUser``
(``is_site_limited`` / ``accessible_site_ids`` / ``can_access_site``), but it
was enforced inconsistently — most module routes checked only
``Site.organization_id == org`` and never the per-user grant. A security review (003/004/005/006/017) found a site-limited user could therefore read
or operate resources in sibling sites of the same org.

These two helpers make the enforcement a single, consistent primitive:

- :func:`assert_can_access_site` — single-resource (GET / mutate by id): call it
  AFTER the existing org-ownership check, with the resource's ``site_id``.
- :func:`site_scope_filter` — list / collection queries: AND the returned
  predicate into the query so a site-limited user only sees granted sites.

Both are no-ops for super_admin / org_admin and for users with zero grants
(backwards-compatible), matching ``CurrentUser.can_access_site`` semantics
exactly. A ``None`` site_id (org-level resource with no site) is allowed —
site-limiting does not apply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import true

if TYPE_CHECKING:
    from app.core.dependencies import CurrentUser


def assert_can_access_site(
    current_user: CurrentUser | Any,
    site_id: UUID | None,
    *,
    detail: str = "Not found",
) -> None:
    """Raise 404 if a site-limited caller may not access ``site_id``.

    No-op for super_admin / org_admin and grant-less users (they pass
    ``can_access_site``), and for a ``None`` site_id (org-level resource).
    Uses a 404 shape — not 403 — to avoid an existence oracle, matching the
    pre-existing ``_check_site_access`` convention in sites.py.
    """
    if site_id is None:
        return
    if not current_user.can_access_site(site_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def site_scope_filter(current_user: CurrentUser | Any, site_id_column: Any) -> Any:
    """Return a SQLAlchemy predicate scoping a list query to granted sites.

    ``true()`` (no-op) for non-site-limited users; ``site_id_column IN
    (accessible_site_ids)`` for site-limited users. Fail-closed (empty IN) in
    the shouldn't-happen case of a site-limited user with no grants.

    AND this into the WHERE clause of any collection query that returns
    site-scoped rows.
    """
    if not getattr(current_user, "is_site_limited", False):
        return true()
    ids = list(current_user.accessible_site_ids or [])
    return site_id_column.in_(ids) if ids else site_id_column.in_([])


# ─────────────────────────────────────────────────────────────────────────────
# Request-scoped current user (chokepoint enforcement)
# ─────────────────────────────────────────────────────────────────────────────
# Set once per request by the auth dependency (``get_current_active_user``), so
# deep, fan-out call chains — notably the Omada adapter ``_resolve_site_context``
# resolver, shared by ~12 sibling service modules — can enforce the per-user
# site grant at a single chokepoint WITHOUT threading ``current_user`` through
# every service signature. Request-local (same pattern as ``request_id_var``):
# FastAPI resolves the dependency inside the per-request task context, so the
# value never leaks across requests. Falls back to no-op when unset (system /
# background context) — the org-scope check upstream still applies.
from contextvars import ContextVar  # noqa: E402

current_user_var: ContextVar[Any | None] = ContextVar("freesdn_current_user", default=None)


def assert_site_access_for_request(
    site_id: UUID | None,
    *,
    detail: str = "Not found",
    current_user: CurrentUser | Any | None = None,
) -> None:
    """Chokepoint guard: enforce the per-user site grant using the explicit
    ``current_user`` if supplied, else the request-scoped ``current_user_var``.
    No-op if neither is available (org-scoping still applies upstream)."""
    user = current_user if current_user is not None else current_user_var.get()
    if user is not None:
        assert_can_access_site(user, site_id, detail=detail)


def site_ids_for_request(current_user: CurrentUser | Any | None = None) -> Any:
    """Granted site IDs for the request's site-limited user (for subquery
    filtering), or ``None`` when unrestricted / unavailable."""
    user = current_user if current_user is not None else current_user_var.get()
    if user is not None and getattr(user, "is_site_limited", False):
        return user.accessible_site_ids
    return None
