# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two auth defects: one broke a victim's login, one let the attacker write the
forensic record about themselves.

1. A USERNAME COULD SHADOW SOMEONE ELSE'S EMAIL, AND THE VICTIM LOST LOGIN
   Both login endpoints matched ``or_(email == x, username == x)`` and then
   called ``scalar_one_or_none()`` -- which RAISES ``MultipleResultsFound``
   the moment two rows come back. Two rows was reachable: every uniqueness
   check in the product compares a field to ITSELF (username vs usernames,
   email vs emails), and the DB's unique indexes are per-column, so nothing
   anywhere stopped a username from equalling a different user's email.

   The damage landed entirely on the innocent party. Once user B holds the
   username ``alice@example.com``, Alice logging in with her own email address
   matches both rows and gets a 500 -- not a wrong-password error she could act
   on, and nothing she can fix, because the offending record is someone else's.
   Her account is unusable via email from that moment on.

   Fixed at both ends: the lookup now resolves deterministically with the exact
   EMAIL match winning (an email is issued identity; a username is a nickname),
   and the create / update / register paths all check cross-field so the
   collision cannot be created.

2. THE AUTH AUDIT TRAIL RECORDED AN ATTACKER-SUPPLIED IP
   ``endpoints/auth.py`` defined ``_client_ip`` TWICE. The second definition
   read ``X-Forwarded-For`` directly, and being later in the module it silently
   won for all four call sites -- including the two written above it, which read
   as though they still used the peer-only helper.

   So every ``FailedLoginRecord`` and every auth ``AuditLogRecord`` stored
   whatever the caller put in a header. On the Security Audit page that is a
   forensic trail the attacker writes: brute-force from one host while
   attributing each attempt to a different address, and the page shows a spread
   of innocent IPs and nothing about the real one.

   The rest of the codebase already had this right and says so at length --
   ``modules/voip/provisioning_auth.py`` and
   ``endpoints/agent_downloads.py`` both refuse the header and rely on
   ``request.client.host``, which uvicorn's ProxyHeadersMiddleware has already
   resolved against the operator's ``FORWARDED_ALLOW_IPS`` allowlist. auth.py
   was the outlier, as was the setup wizard's ownership-taking audit row.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.v1.endpoints import auth as auth_ep
from app.api.v1.endpoints import users as users_ep

VICTIM_EMAIL = "alice@example.com"
NL = chr(10)


# ── 1. the shadowed identifier ───────────────────────────────────


class _User(SimpleNamespace):
    pass


def _victim():
    return _User(
        id=uuid4(),
        email=VICTIM_EMAIL,
        username="alice",
        created_at=datetime.now(UTC) - timedelta(days=30),
    )


def _squatter():
    """A second, later account whose USERNAME is the victim's email address."""
    return _User(
        id=uuid4(),
        email="bob@example.com",
        username=VICTIM_EMAIL,
        created_at=datetime.now(UTC),
    )


class _Session:
    """Applies the query's ORDER BY / LIMIT to a fixed row set, like the DB would."""

    def __init__(self, rows: list) -> None:
        self.rows = rows
        self.last_query = None

    async def execute(self, query):
        self.last_query = query
        text = str(query)
        rows = list(self.rows)
        # Mirror `.order_by((User.email == identifier).desc())`: email matches
        # sort first, then oldest.
        if "ORDER BY" in text:
            rows.sort(key=lambda u: (u.email != VICTIM_EMAIL, u.created_at))
        if "LIMIT" in text:
            rows = rows[:2]
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: rows),
            first=lambda: (rows[0],) if rows else None,
            scalar_one_or_none=lambda: rows[0] if len(rows) == 1 else None,
        )


async def test_the_victim_can_still_log_in_when_a_username_shadows_their_email() -> None:
    """
    The regression. Pre-fix this call raised MultipleResultsFound -> HTTP 500,
    permanently, for the account that did nothing wrong.
    """
    victim, squatter = _victim(), _squatter()
    user = await auth_ep._lookup_login_identity(_Session([squatter, victim]), VICTIM_EMAIL)

    assert user is not None
    assert user.id == victim.id, "the email's owner must win their own address"


async def test_the_row_order_from_the_database_does_not_decide_it() -> None:
    """Whoever the DB happens to return first must not change who logs in."""
    victim, squatter = _victim(), _squatter()
    for rows in ([victim, squatter], [squatter, victim]):
        user = await auth_ep._lookup_login_identity(_Session(rows), VICTIM_EMAIL)
        assert user.id == victim.id


async def test_username_login_still_works() -> None:
    """
    Preferring email must not break the feature. With no email match, the
    username match is still the answer -- otherwise username login is dead.
    """
    squatter = _squatter()
    user = await auth_ep._lookup_login_identity(_Session([squatter]), VICTIM_EMAIL)
    assert user.id == squatter.id


async def test_an_unknown_identifier_still_returns_none() -> None:
    """
    None is what drives the timing-safe 401 branch. Returning anything else
    here would turn a clean auth failure into a crash or a bypass.
    """
    assert await auth_ep._lookup_login_identity(_Session([]), "nobody@example.com") is None


def test_neither_login_endpoint_calls_scalar_one_or_none_on_the_identifier() -> None:
    """
    Structural: the raising call is what made this a 500 rather than a
    tie-break. Both endpoints must go through the shared helper.
    """
    for fn in (auth_ep.login_for_access_token, auth_ep.login):
        src = inspect.getsource(fn)
        assert "_lookup_login_identity" in src
        assert "or_(User.email" not in src, f"{fn.__name__} rebuilt the ambiguous query inline"


def test_the_helper_is_bounded_and_ordered() -> None:
    """
    ``.first()`` without an ORDER BY would swap the 500 for a worse bug: two
    logins with the same credentials landing on different accounts.
    """
    src = inspect.getsource(auth_ep._lookup_login_identity)
    assert "order_by" in src
    assert "limit(2)" in src, "unbounded fetch on an identifier that may match many rows"


# ── the collision must not be creatable ──────────────────────────


def _uniqueness_predicate(fn, marker: str) -> str:
    """The source of the uniqueness pre-check inside `fn`."""
    src = textwrap.dedent(inspect.getsource(fn))
    start = src.index(marker)
    return src[start : start + 700]


@pytest.mark.parametrize(
    ("fn", "marker"),
    [
        pytest.param(users_ep.create_user, "for value in (", id="create"),
        pytest.param(users_ep.update_user, "for unique_field in", id="update"),
    ],
)
def test_the_user_endpoints_check_cross_field(fn, marker: str) -> None:
    """
    Same-field-only checks (username vs usernames) can never catch this: the
    colliding value lives in the OTHER column. Both must look at both.
    """
    block = _uniqueness_predicate(fn, marker)
    assert "or_(" in block
    assert "User.email ==" in block and "User.username ==" in block


def test_register_checks_cross_field_without_adding_an_enumeration_oracle() -> None:
    """
    Register deliberately returns one generic response for "already exists" so
    it is not an unauthenticated account-existence oracle. The new username arm
    must return the SAME response, or the fix reopens what closed.
    """
    src = textwrap.dedent(inspect.getsource(auth_ep.register))
    block = src[src.index("existing = await session.execute") :][:600]
    assert "User.username ==" in block
    assert "_GENERIC_REGISTER_OK" in block
    assert "409" not in block, "a distinct status here is an enumeration oracle"


def test_create_user_reports_a_conflict_without_naming_the_field() -> None:
    """
    The 409 detail must not say WHICH of the two collided -- that would tell an
    org_admin whether a given string is somebody's email or somebody's username.
    """
    src = inspect.getsource(users_ep.create_user)
    block = src[src.index("for value in (") :][:800]
    assert "Email already registered" in block
    assert "Username already registered" not in block


# ── 2. the client IP ─────────────────────────────────────────────


def test_auth_defines_client_ip_exactly_once() -> None:
    """
    The whole mechanism. Two module-level defs, and the later one silently won
    for every call site -- including the two above it, which read as if they
    still used the peer-only helper.
    """
    tree = ast.parse(inspect.getsource(auth_ep))
    defs = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == "_client_ip"
    ]
    assert len(defs) == 1, f"{len(defs)} definitions of _client_ip; the last one wins silently"


def test_the_forensic_ip_ignores_a_spoofed_header() -> None:
    """
    The record an attacker most wants to control. request.client is what
    uvicorn resolved from the operator's trusted-proxy allowlist; the raw
    header is not.
    """
    request = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={
            "x-forwarded-for": "1.2.3.4, 5.6.7.8",
            "x-real-ip": "9.9.9.9",
        },
    )
    assert auth_ep._client_ip(request) == "203.0.113.7"


def test_a_missing_peer_does_not_fall_back_to_the_header() -> None:
    """
    The fallback is the interesting case: "unknown" is honest, a header value
    is a fabricated attribution.
    """
    request = SimpleNamespace(client=None, headers={"x-forwarded-for": "1.2.3.4"})
    assert auth_ep._client_ip(request) == "unknown"


def _header_reads(module) -> list[str]:
    """Every string literal a `.get(...)` call in `module` looks up.

    Parsed rather than grepped, so the fixes' own explanatory prose -- which
    names the header repeatedly -- is not mistaken for a use of it.
    """
    found: list[str] = []
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("get", "getlist"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found.append(arg.value.lower())
    return found


_SPOOFABLE = {"x-forwarded-for", "x-real-ip", "forwarded", "x-client-ip"}


def test_no_auth_code_path_reads_a_spoofable_ip_header() -> None:
    """Guard the module, not the one helper."""
    offenders = _SPOOFABLE & set(_header_reads(auth_ep))
    assert not offenders, f"endpoints/auth.py reads {sorted(offenders)} for identity"


def test_the_setup_wizard_records_the_real_peer() -> None:
    """
    ``/setup/complete`` is pre-auth by definition, and its audit row records
    who took ownership of a brand-new instance -- the one record you least want
    the actor to be able to write themselves.
    """
    from app.setup import api as setup_api

    offenders = _SPOOFABLE & set(_header_reads(setup_api))
    assert not offenders, f"setup/api.py reads {sorted(offenders)} for identity"


def test_the_guard_would_notice_a_reintroduction() -> None:
    """Negative control for the parser: it must actually see such a read."""
    source = NL.join(
        [
            "def f(request):",
            "    return request.headers.get('X-Forwarded-For')",
        ]
    )
    found = [
        arg.value.lower()
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    ]
    assert _SPOOFABLE & set(found)


def test_the_session_row_still_fits_its_column() -> None:
    """
    ``UserSession.ip_address`` is String(45) (IPv6 + zone). The helper that
    used to feed it truncated; the surviving one does not, so the call sites
    must.
    """
    from app.models.core import UserSession

    assert UserSession.__table__.c.ip_address.type.length == 45
    src = inspect.getsource(auth_ep._upsert_session)
    assert src.count("_client_ip(request)[:45]") == 2
