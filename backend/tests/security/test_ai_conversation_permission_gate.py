# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: AI conversation routes must enforce ``ai.chat``.

``POST /ai/chat`` has always checked ``ai.chat`` inline, but the three
conversation-management routes (list / get / delete) depended only on
``get_current_active_user``. The module router is mounted with no router-level
permission dependency, so nothing else enforced it.

Why that mattered: ``CurrentUser.has_permission`` honours an explicit scope
ceiling (a scoped API key evaluates ONLY against its scope list -- no
super-admin or ``*`` bypass). So a key minted with ``["device:read"]`` was
correctly refused at ``/ai/chat`` yet could still read a conversation's full
message bodies, tool-call arguments, tool results and tool names, and could
DELETE the conversation. A user demoted to ``viewer`` (no ``ai.chat``) kept the
same access to their prior conversations.

These tests assert route WIRING, not the helper: the ceiling implementation was
already correct, the defect was that these routes never consulted it. A test
that only exercised ``require_permissions`` would have passed before the fix.

Pure-unit: no DB, no HTTP -- the FastAPI router is introspected directly.
"""

from __future__ import annotations

import pytest

# Routes that expose or destroy conversation CONTENT and therefore must sit
# behind the same capability as creating it.
GATED_CONVERSATION_ROUTES = {
    ("GET", "/conversations"),
    ("GET", "/conversations/{conversation_id}"),
    ("DELETE", "/conversations/{conversation_id}"),
}

REQUIRED_PERMISSION = "ai.chat"


def _required_permissions(route) -> set[str]:
    """Collect permission strings enforced by a route's dependency tree.

    ``require_permissions("x")`` returns a closure whose cell holds the
    permission tuple, so we recover it from ``__closure__`` rather than
    matching on the function name.
    """
    found: set[str] = set()

    def walk(dependant) -> None:
        call = getattr(dependant, "call", None)
        closure = getattr(call, "__closure__", None) or ()
        for cell in closure:
            try:
                value = cell.cell_contents
            except ValueError:  # pragma: no cover - empty cell
                continue
            if isinstance(value, tuple) and all(isinstance(v, str) for v in value):
                found.update(value)
            elif isinstance(value, str):
                found.add(value)
        for sub in getattr(dependant, "dependencies", ()):
            walk(sub)

    walk(route.dependant)
    return found


def _conversation_routes():
    from app.modules.ai.api import router

    out = []
    for route in router.routes:
        for method in getattr(route, "methods", set()) or set():
            key = (method, getattr(route, "path", ""))
            if key in GATED_CONVERSATION_ROUTES:
                out.append((key, route))
    return out


def test_all_conversation_routes_are_discovered() -> None:
    """Guard the guard: if a route is renamed, the ratchet must not silently pass."""
    discovered = {key for key, _ in _conversation_routes()}
    missing = GATED_CONVERSATION_ROUTES - discovered
    assert not missing, f"conversation routes not found in the AI router: {sorted(missing)}"


@pytest.mark.parametrize("method,path", sorted(GATED_CONVERSATION_ROUTES))
def test_conversation_route_requires_ai_chat(method: str, path: str) -> None:
    """Each conversation route must enforce ``ai.chat``.

    Fails before the fix: these routes depended only on
    ``get_current_active_user``, so no permission string was present anywhere in
    their dependency tree.
    """
    routes = dict(_conversation_routes())
    route = routes[(method, path)]
    perms = _required_permissions(route)
    assert REQUIRED_PERMISSION in perms, (
        f"{method} {path} does not enforce {REQUIRED_PERMISSION!r} "
        f"(permissions found in its dependency tree: {sorted(perms) or 'none'}). "
        "A scoped API key or a demoted viewer could read/delete conversation content."
    )


def test_scope_ceiling_actually_refuses_a_narrow_key() -> None:
    """The mechanism the routes now consult: a scoped key cannot exceed its scope.

    This is the reason the wiring matters -- it documents that ``ai.chat`` is a
    real ceiling for an API key, not a formality.
    """
    from uuid import uuid4

    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email="key-owner@example.com",
        organization_id=uuid4(),
        role="super_admin",  # deliberately the most privileged role
        hashed_password="x",
        is_active=True,
    )
    scoped_key = CurrentUser(user=user, permissions=["device:read"], scoped=True)

    # Even a super_admin's key, when scoped, must not reach ai.chat.
    assert scoped_key.has_permission("device:read") is True
    assert scoped_key.has_permission(REQUIRED_PERMISSION) is False
