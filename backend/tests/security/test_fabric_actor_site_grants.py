# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The event-driven half of the per-user site-grant gap, left open by the
earlier fix.

``POST /fabric/invoke`` threads ``accessible_site_ids``, and the AI tool
bridge was fixed to match. Two paths
were left: the Fabric negotiator (a Connection firing on an event) and the
automation engine (a rule running on a schedule). Both build the same
``OperationContext`` and both left the field ``None`` -- which the field's own
docstring documents as "unrestricted".

Neither has a live principal to take the grant from. What they DO have is the
``actor_id`` recorded when the Connection or rule was authored, so the grant is
resolved from that. Both paths already re-check the author's PERMISSION at run
time; what was missing was the narrowing, so a site-limited author's automation
could act on any site in the org while the same operation through the API could
not.

The resolver returns ``None`` -- unrestricted -- rather than an empty set for a
super_admin / org_admin and for an actor with no grants at all. That is not
laxness: it mirrors ``CurrentUser.is_site_limited`` exactly, and the hybrid
model in says zero grants means unrestricted, not denied.
Returning an empty set for those would be fail-CLOSED and would silently break
every existing automation rule -- a different outage, not a fix.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.site_access import resolve_actor_site_grants

SITE_A, SITE_B = uuid4(), uuid4()


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


class _Session:
    """Returns one user row for the actor lookup."""

    def __init__(self, user) -> None:
        self._user = user
        self.raises = False

    async def execute(self, _query):
        if self.raises:
            raise RuntimeError("database is unhappy")
        user = self._user
        return SimpleNamespace(scalar_one_or_none=lambda: user)


def _user(role: str = "operator", sites: list | None = None):
    return SimpleNamespace(
        id=uuid4(),
        role=role,
        deleted_at=None,
        site_access=[SimpleNamespace(site_id=s) for s in (sites or [])],
    )


# ── the resolver ─────────────────────────────────────────────────


async def test_a_site_limited_author_is_narrowed_to_their_grants() -> None:
    """
    The regression. This is the value that was always None, so an automation
    authored by a site-limited operator ran unrestricted.
    """
    session = _Session(_user("operator", [SITE_A]))
    assert await resolve_actor_site_grants(session, uuid4()) == {SITE_A}


async def test_multiple_grants_all_come_through() -> None:
    session = _Session(_user("operator", [SITE_A, SITE_B]))
    assert await resolve_actor_site_grants(session, uuid4()) == {SITE_A, SITE_B}


@pytest.mark.parametrize("role", ["super_admin", "admin", "org_admin"])
async def test_an_admin_stays_unrestricted(role: str) -> None:
    """
    Mirrors ``CurrentUser.is_site_limited``, which returns False for these
    roles regardless of any grant rows they happen to have.
    """
    session = _Session(_user(role, [SITE_A]))
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_an_actor_with_no_grants_is_unrestricted_not_denied() -> None:
    """
    FSDN-SEC-006's hybrid model: zero grants means unrestricted, for backwards
    compatibility. Returning an empty set here would be fail-CLOSED and would
    silently break every automation rule authored before site grants existed --
    an outage wearing a security fix's clothes.
    """
    session = _Session(_user("operator", []))
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_a_missing_actor_does_not_disable_the_automation() -> None:
    """
    A deleted or unresolvable author. These paths re-check the author's
    PERMISSION separately; the grant is a narrowing, not the authorisation, so
    failing closed on a lookup miss would stop automations for the wrong
    reason.
    """
    assert await resolve_actor_site_grants(_Session(None), uuid4()) is None


async def test_no_actor_id_is_unrestricted() -> None:
    assert await resolve_actor_site_grants(_Session(_user()), None) is None


async def test_a_database_error_does_not_raise_into_the_caller() -> None:
    session = _Session(_user("operator", [SITE_A]))
    session.raises = True
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_the_resolver_excludes_deleted_users() -> None:
    """A soft-deleted author must not resolve; the query has to say so."""
    assert "deleted_at.is_(None)" in _code(resolve_actor_site_grants)


def test_it_agrees_with_current_user_on_who_is_site_limited() -> None:
    """
    Two implementations of "is this principal site-limited" is how they drift.
    Pin the role set against the real property's source.
    """
    from app.core.dependencies import CurrentUser

    # is_site_limited is a property; getsource needs the underlying function.
    request_side = _code(CurrentUser.is_site_limited.fget)
    assert "is_superuser" in request_side and "is_org_admin" in request_side

    resolver = _code(resolve_actor_site_grants)
    for role in ("super_admin", "admin", "org_admin"):
        assert role in resolver, f"{role} is not treated as unrestricted"


# ── both call sites ──────────────────────────────────────────────


def test_the_negotiator_threads_the_authors_grant() -> None:
    # Imported by module path: ``app.core.fabric.negotiator`` is also the name
    # of a re-exported singleton, and the bare attribute resolves to that.
    import importlib

    code = _code(importlib.import_module("app.core.fabric.negotiator"))
    assert "resolve_actor_site_grants(db, conn.actor_id)" in code, (
        "a Connection still runs unrestricted regardless of its author's grants"
    )


def test_the_automation_engine_threads_the_authors_grant() -> None:
    from app.services import automation

    code = _code(automation)
    assert "resolve_actor_site_grants(db, rule_actor)" in code, (
        "an automation rule still runs unrestricted regardless of its author's grants"
    )


def test_the_automation_engine_still_rechecks_the_permission() -> None:
    """
    The grant narrows; it does not authorise. If the permission re-check ever
    goes away, resolving grants leniently on a lookup failure stops being safe.
    """
    from app.services import automation

    assert "no longer holds the required permission" in inspect.getsource(automation)


def test_every_operation_context_construction_now_passes_the_field() -> None:
    """
    Guard the class, not the two instances. A new OperationContext built
    without a grant is this bug again, and the field defaults to None --
    unrestricted -- so the omission is silent.
    """
    import ast
    import pathlib

    root = pathlib.Path(inspect.getfile(resolve_actor_site_grants)).parents[1]
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "OperationContext":
                continue
            if not any(kw.arg == "accessible_site_ids" for kw in node.keywords):
                offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, (
        f"OperationContext built without accessible_site_ids at {offenders} -- "
        "None means unrestricted, so this silently widens the operation"
    )


def test_the_field_still_means_unrestricted_when_none() -> None:
    """Premise. If None ever became fail-closed, all of the above inverts."""
    from app.core.fabric.execution import OperationContext

    assert "None = unrestricted" in inspect.getsource(OperationContext)
