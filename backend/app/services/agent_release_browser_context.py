# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Optional browser intent equality; never credentials or target-scope grants."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import HTTPException, Request

if TYPE_CHECKING:
    from app.core.dependencies import CurrentUser


def check_release_browser_context(request: Request, user: CurrentUser | None) -> None:
    # Optional for non-browser API clients; our browser transport always sends
    # both. These are equality assertions, NEVER authority or target-org grants.
    actors = request.headers.getlist("X-FreeSDN-Release-Actor")
    organizations = request.headers.getlist("X-FreeSDN-Release-Organization")
    _check_context(actors, organizations, user)


def check_release_download_context(request: Request, user: CurrentUser | None) -> None:
    """Native navigation equality assertions; never credentials or target grants.

    A browser anchor cannot send custom headers. Query identities are nonsecret
    and must still match the currently authenticated operator. Existing agents
    and nonbrowser clients can omit both pairs. Header/query contradictions are
    refused; an asserted browser identity never falls back to agent authority.
    """
    _check_context(
        request.query_params.getlist("release_actor"),
        request.query_params.getlist("release_organization"),
        user,
    )
    check_release_browser_context(request, user)


def _check_context(actors: list[str], organizations: list[str], user: CurrentUser | None) -> None:
    if not actors and not organizations:
        return
    if len(actors) != 1 or len(organizations) != 1:
        raise HTTPException(400, "Complete release browser context required")
    actor, organization = actors[0], organizations[0]
    try:
        if len(actor) != 36 or str(UUID(actor)) != actor or UUID(actor).int == 0:
            raise ValueError("Invalid actor context")
        if organization != "none" and (
            len(organization) != 36
            or str(UUID(organization)) != organization
            or UUID(organization).int == 0
        ):
            raise ValueError("Invalid organization context")
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid release browser context") from None
    if user is None:
        raise HTTPException(
            401, "Current operator authentication required for release browser context"
        )
    actual_organization = str(user.organization_id) if user.organization_id is not None else "none"
    if actor != str(user.id) or organization != actual_organization:
        raise HTTPException(
            409, "Release browser context changed; inspect using the intended account"
        )
