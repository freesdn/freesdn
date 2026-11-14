# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A deleted or deactivated organization's users are signed out everywhere.

``DELETE /organizations/{id}`` only stamped ``organizations.deleted_at`` and
deactivating an organization only cleared ``organizations.is_active``. Every
authentication path checked the USER row (deleted, active, token version) and
never the organization, so after an organization was retired its users kept
signing in with their passwords, kept refreshing their sessions and kept using
their API keys.

Two kinds of test live here:

* the organization is retired by writing the row directly, which is the state
  an install upgraded from an earlier version is already in (nothing bumped the
  members' token versions then), so only the admission check can refuse them;
* the organization is retired through the API, which must also revoke the
  members' sessions so a later reactivation does not bring old tokens back.

Super admins are deliberately exempt (they manage every organization and are
the only accounts that can bring one back), and deleting the organization that
holds the last active super admin is refused.

Real PostgreSQL through the ``db_session`` savepoint fixture; the full ASGI app
serves the requests.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, create_refresh_token, get_password_hash
from app.core.security_utils import encrypt_field
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession

PASSWORD = "Retired-0rg-Passw0rd!"
_BAD_LOGIN = "Incorrect email/username or password"
_DEAD_TOKEN = "Could not validate credentials"


def _message(response: Any) -> str:
    """The error text, whichever envelope the app's handlers put it in."""
    body = response.json()
    if "detail" in body:
        return str(body["detail"])
    return str(body.get("error", {}).get("message"))


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


async def _org(db: AsyncSession, *, name: str = "Retired org probe") -> Organization:
    org = Organization(id=uuid4(), name=name, slug="retired-" + uuid4().hex[:12])
    db.add(org)
    await db.flush()
    return org


async def _user(
    db: AsyncSession,
    org: Organization | None,
    *,
    role: str = "viewer",
    mfa_seed: str | None = None,
) -> User:
    tag = uuid4().hex[:12]
    user = User(
        id=uuid4(),
        email=f"retired-{tag}@example.com",
        username=f"retired-{tag}",
        full_name="Retired org probe",
        hashed_password=get_password_hash(PASSWORD),
        role=role,
        is_active=True,
        is_verified=True,
        organization_id=org.id if org else None,
        mfa_enabled=mfa_seed is not None,
        mfa_secret=encrypt_field(mfa_seed) if mfa_seed else None,
    )
    db.add(user)
    await db.flush()
    return user


async def _api_key(db: AsyncSession, user: User) -> str:
    raw, prefix, key_hash = generate_api_key()
    db.add(
        APIKey(
            id=uuid4(),
            user_id=user.id,
            name="retired org probe",
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=[],
            is_active=True,
        )
    )
    await db.flush()
    return raw


def _access(user: User) -> str:
    return create_access_token(str(user.id), token_version=user.token_version or 0)


def _refresh(user: User) -> str:
    return create_refresh_token(str(user.id), token_version=user.token_version or 0)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@contextlib.asynccontextmanager
async def _client(db: AsyncSession) -> AsyncIterator[AsyncClient]:
    """The real app on this test's session, from a client address of its own.

    The login endpoints rate-limit per client address; a fresh address keeps
    one test's logins out of another's window.
    """

    async def _session() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_session] = _session
    peer = uuid4().int
    transport = ASGITransport(
        app=app, client=(f"198.18.{peer >> 8 & 255}.{peer & 255}", 40000 + peer % 20000)
    )
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_session, None)


async def _retire_directly(db: AsyncSession, org: Organization, how: str) -> None:
    """Retire the row the way an earlier version left it: no session bump."""
    if how == "deleted":
        org.deleted_at = datetime.now(UTC)
    else:
        org.is_active = False
    await db.flush()


async def _only_super_admin(db: AsyncSession, *keep: User) -> None:
    """Make ``keep`` the only active super admins (rolled back with the test)."""
    await db.execute(
        update(User)
        .where(User.role == "super_admin", User.id.not_in([u.id for u in keep]))
        .values(is_active=False)
        .execution_options(synchronize_session=False)
    )
    await db.flush()


RETIREMENTS = pytest.mark.parametrize("how", ["deleted", "deactivated"])


# ---------------------------------------------------------------------------
# admission: every place a principal is established
# ---------------------------------------------------------------------------


async def test_control_a_live_organization_member_gets_in(db_session: AsyncSession) -> None:
    org = await _org(db_session)
    member = await _user(db_session, org)
    key = await _api_key(db_session, member)

    async with _client(db_session) as client:
        login = await client.post(
            "/api/v1/auth/login", json={"login": member.email, "password": PASSWORD}
        )
        me = await client.get("/api/v1/auth/me", headers=_bearer(_access(member)))
        sites = await client.get("/api/v1/sites/", headers=_bearer(_access(member)))
        by_key = await client.get("/api/v1/sites/", headers={"X-API-Key": key})

    assert login.status_code == 200, login.text
    assert me.status_code == 200, me.text
    assert sites.status_code == 200, sites.text
    assert by_key.status_code == 200, by_key.text


@RETIREMENTS
async def test_a_retired_organizations_tokens_and_keys_stop_working(
    db_session: AsyncSession, how: str
) -> None:
    org = await _org(db_session)
    member = await _user(db_session, org)
    key = await _api_key(db_session, member)
    access, refresh = _access(member), _refresh(member)
    await _retire_directly(db_session, org, how)

    async with _client(db_session) as client:
        me = await client.get("/api/v1/auth/me", headers=_bearer(access))
        sites = await client.get("/api/v1/sites/", headers=_bearer(access))
        by_key = await client.get("/api/v1/sites/", headers={"X-API-Key": key})
        refreshed = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})

    assert me.status_code == 401, f"/auth/me still answers for a {how} organization"
    assert sites.status_code == 401, f"the REST API still answers for a {how} organization"
    assert by_key.status_code == 401, f"an API key still works for a {how} organization"
    assert refreshed.status_code == 401, f"a refresh token still rotates for a {how} organization"
    # Same answer as any other dead credential: nothing says the org exists.
    assert _message(sites) == _message(by_key) == _DEAD_TOKEN


@RETIREMENTS
async def test_password_login_is_refused_like_a_wrong_password(
    db_session: AsyncSession, how: str
) -> None:
    org = await _org(db_session)
    member = await _user(db_session, org)
    await _retire_directly(db_session, org, how)

    async with _client(db_session) as client:
        json_login = await client.post(
            "/api/v1/auth/login", json={"login": member.email, "password": PASSWORD}
        )
        form_login = await client.post(
            "/api/v1/auth/token", data={"username": member.username, "password": PASSWORD}
        )
        wrong = await client.post(
            "/api/v1/auth/login", json={"login": member.email, "password": PASSWORD + "x"}
        )

    assert json_login.status_code == 401, json_login.text
    assert form_login.status_code == 401, form_login.text
    assert wrong.status_code == 401
    assert _message(json_login) == _message(wrong) == _BAD_LOGIN
    assert _message(form_login) == _BAD_LOGIN


@RETIREMENTS
async def test_a_pending_mfa_challenge_cannot_be_completed(
    db_session: AsyncSession, how: str
) -> None:
    seed = pyotp.random_base32()
    org = await _org(db_session)
    member = await _user(db_session, org, mfa_seed=seed)
    challenge = create_access_token(
        str(member.id),
        expires_delta=timedelta(minutes=5),
        token_version=member.token_version or 0,
        extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"},
    )
    await _retire_directly(db_session, org, how)

    async with _client(db_session) as client:
        done = await client.post(
            "/api/v1/auth/login/mfa",
            json={"mfa_token": challenge, "code": pyotp.TOTP(seed).now()},
        )

    assert done.status_code == 401, done.text
    assert "set-cookie" not in done.headers


@RETIREMENTS
async def test_the_shared_user_loader_refuses_a_retired_member(
    db_session: AsyncSession, how: str
) -> None:
    """``_get_user_by_id`` also feeds the camera media handler and the stored
    authors of Fabric camera snapshots and automation rules."""
    from app.core.dependencies import _get_user_by_id

    org = await _org(db_session)
    member = await _user(db_session, org)
    assert await _get_user_by_id(db_session, str(member.id)) is not None
    await _retire_directly(db_session, org, how)

    assert await _get_user_by_id(db_session, str(member.id)) is None


@RETIREMENTS
async def test_sso_does_not_issue_tokens_to_a_retired_member(
    db_session: AsyncSession, how: str
) -> None:
    """OIDC, SAML and LDAP all end in ``SSOService._issue_tokens``."""
    from app.services.sso import SSOAuthError, SSOService

    org = await _org(db_session)
    member = await _user(db_session, org)
    await _retire_directly(db_session, org, how)

    with pytest.raises(SSOAuthError):
        await SSOService(db_session)._issue_tokens(member)


@RETIREMENTS
async def test_the_realtime_socket_drops_a_retired_member(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    from app.api.v1.endpoints import websocket as ws

    @contextlib.asynccontextmanager
    async def _factory() -> AsyncIterator[AsyncSession]:
        yield db_session

    monkeypatch.setattr("app.db.async_session_factory", _factory)
    org = await _org(db_session)
    member = await _user(db_session, org)
    info = ws.ConnectionInfo(
        websocket=None,
        user_id=str(member.id),
        organization_id=str(org.id),
        token_version=member.token_version or 0,
    )
    assert await ws._revalidate_ws_session(info) is True
    await _retire_directly(db_session, org, how)

    assert await ws._revalidate_ws_session(info) is False


@RETIREMENTS
async def test_the_auth_service_keeps_parity(db_session: AsyncSession, how: str) -> None:
    from app.services.auth import AuthService, InvalidCredentialsError, TokenInvalidError

    org = await _org(db_session)
    member = await _user(db_session, org)
    refresh = _refresh(member)
    await _retire_directly(db_session, org, how)

    with pytest.raises(InvalidCredentialsError):
        await AuthService(db_session).authenticate(member.email, PASSWORD)
    with pytest.raises(TokenInvalidError):
        await AuthService(db_session).refresh_tokens(refresh)


async def test_a_member_of_no_organization_is_unaffected(db_session: AsyncSession) -> None:
    loner = await _user(db_session, None)
    async with _client(db_session) as client:
        me = await client.get("/api/v1/auth/me", headers=_bearer(_access(loner)))
    assert me.status_code == 200, me.text


# ---------------------------------------------------------------------------
# retiring through the API
# ---------------------------------------------------------------------------


async def _world(db: AsyncSession) -> SimpleNamespace:
    org = await _org(db)
    member = await _user(db, org)
    platform = await _user(db, None, role="super_admin")
    device = UserSession(
        user_id=member.id,
        refresh_jti=uuid4().hex,
        access_jti=uuid4().hex,
        created_at=datetime.now(UTC),
        last_used_at=datetime.now(UTC),
        is_revoked=False,
    )
    db.add(device)
    await db.flush()
    return SimpleNamespace(org=org, member=member, platform=platform, device=device)


async def _member_state(
    db: AsyncSession, member: User, device: UserSession | None = None
) -> tuple[int, bool | None]:
    """The member's token version, and whether the seeded device row is revoked."""
    member_id, device_id = member.id, device.id if device is not None else None
    db.expire_all()
    tv = (await db.execute(select(User.token_version).where(User.id == member_id))).scalar_one()
    if device_id is None:
        return tv, None
    revoked = (
        await db.execute(select(UserSession.is_revoked).where(UserSession.id == device_id))
    ).scalar_one()
    return tv, revoked


async def test_deleting_an_organization_signs_its_members_out(db_session: AsyncSession) -> None:
    w = await _world(db_session)
    org_id = w.org.id
    before_tv = w.member.token_version or 0
    access = _access(w.member)

    async with _client(db_session) as client:
        deleted = await client.delete(
            f"/api/v1/organizations/{w.org.id}", headers=_bearer(_access(w.platform))
        )
        me = await client.get("/api/v1/auth/me", headers=_bearer(access))

    assert deleted.status_code == 204, deleted.text
    assert me.status_code == 401
    tv, revoked = await _member_state(db_session, w.member, w.device)
    assert tv == before_tv + 1, "the members' token version was not advanced"
    assert revoked is True, "the members' session rows were left live"
    row = (
        await db_session.execute(
            select(Organization.is_active)
            .where(Organization.id == org_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert row is False, "a deleted organization still reads as active to background jobs"


async def test_deactivating_signs_out_and_reactivating_does_not_revive_old_tokens(
    db_session: AsyncSession,
) -> None:
    w = await _world(db_session)
    before_tv = w.member.token_version or 0
    old_access = _access(w.member)
    admin = _bearer(_access(w.platform))

    async with _client(db_session) as client:
        off = await client.patch(
            f"/api/v1/organizations/{w.org.id}", json={"is_active": False}, headers=admin
        )
        refused = await client.post(
            "/api/v1/auth/login", json={"login": w.member.email, "password": PASSWORD}
        )
        on = await client.patch(
            f"/api/v1/organizations/{w.org.id}", json={"is_active": True}, headers=admin
        )
        stale = await client.get("/api/v1/auth/me", headers=_bearer(old_access))
        again = await client.post(
            "/api/v1/auth/login", json={"login": w.member.email, "password": PASSWORD}
        )

    assert off.status_code == 200, off.text
    assert refused.status_code == 401
    assert on.status_code == 200, on.text
    assert stale.status_code == 401, "a token minted before deactivation came back"
    assert again.status_code == 200, "a reactivated organization's member cannot sign in"
    tv, revoked = await _member_state(db_session, w.member, w.device)
    assert tv == before_tv + 1, "reactivating must not bump again, deactivating must"
    assert revoked is True, "the members' session rows were left live"


async def test_an_org_admin_cannot_switch_their_own_organization_off(
    db_session: AsyncSession,
) -> None:
    """It would sign out every member, the org admin included, with no way back
    short of a super admin. Saving the settings form (which always sends the
    current ``is_active``) still works."""
    org = await _org(db_session)
    org_admin = await _user(db_session, org, role="org_admin")
    headers = _bearer(_access(org_admin))

    async with _client(db_session) as client:
        off = await client.patch(
            f"/api/v1/organizations/{org.id}", json={"is_active": False}, headers=headers
        )
        save = await client.patch(
            f"/api/v1/organizations/{org.id}",
            json={"name": "Renamed by its admin", "is_active": True},
            headers=headers,
        )

    assert off.status_code == 403, off.text
    assert save.status_code == 200, save.text
    org_id = org.id
    db_session.expire_all()
    state = (
        await db_session.execute(
            select(Organization.is_active, Organization.name).where(Organization.id == org_id)
        )
    ).one()
    assert state == (True, "Renamed by its admin")


# ---------------------------------------------------------------------------
# super admins are never locked out
# ---------------------------------------------------------------------------


@RETIREMENTS
async def test_a_super_admin_keeps_access_when_their_own_organization_is_retired(
    db_session: AsyncSession, how: str
) -> None:
    org = await _org(db_session)
    home_admin = await _user(db_session, org, role="super_admin")
    key = await _api_key(db_session, home_admin)
    access = _access(home_admin)
    await _retire_directly(db_session, org, how)

    async with _client(db_session) as client:
        me = await client.get("/api/v1/auth/me", headers=_bearer(access))
        by_key = await client.get("/api/v1/sites/", headers={"X-API-Key": key})
        login = await client.post(
            "/api/v1/auth/login", json={"login": home_admin.email, "password": PASSWORD}
        )

    assert me.status_code == 200, me.text
    assert by_key.status_code == 200, by_key.text
    assert login.status_code == 200, login.text


async def test_a_super_admin_deleting_their_own_organization_stays_signed_in(
    db_session: AsyncSession,
) -> None:
    """Another super admin exists, so the delete goes ahead; the deleting super
    admin's own session is not revoked with the members'."""
    org = await _org(db_session)
    home_admin = await _user(db_session, org, role="super_admin")
    elsewhere = await _user(db_session, None, role="super_admin")
    await _only_super_admin(db_session, home_admin, elsewhere)
    before_tv = home_admin.token_version or 0
    access = _access(home_admin)

    async with _client(db_session) as client:
        deleted = await client.delete(f"/api/v1/organizations/{org.id}", headers=_bearer(access))
        me = await client.get("/api/v1/auth/me", headers=_bearer(access))

    assert deleted.status_code == 204, deleted.text
    assert me.status_code == 200, me.text
    tv, _ = await _member_state(db_session, home_admin)
    assert tv == before_tv


async def test_deleting_the_organization_of_the_last_super_admin_is_refused(
    db_session: AsyncSession,
) -> None:
    org = await _org(db_session)
    last = await _user(db_session, org, role="super_admin")
    await _only_super_admin(db_session, last)

    async with _client(db_session) as client:
        deleted = await client.delete(
            f"/api/v1/organizations/{org.id}", headers=_bearer(_access(last))
        )

    assert deleted.status_code == 409, deleted.text
    assert "last active super admin" in _message(deleted)
    org_id = org.id
    db_session.expire_all()
    state = (
        await db_session.execute(
            select(Organization.deleted_at, Organization.is_active)
            .where(Organization.id == org_id)
            .execution_options(include_deleted=True)
        )
    ).one()
    assert state == (None, True), "the refused delete still changed the organization"


async def test_a_super_admin_without_an_organization_counts_as_the_remaining_one(
    db_session: AsyncSession,
) -> None:
    """A super admin with no organization counts as the remaining one."""
    org = await _org(db_session)
    in_org = await _user(db_session, org, role="super_admin")
    platform = await _user(db_session, None, role="super_admin")
    await _only_super_admin(db_session, in_org, platform)

    async with _client(db_session) as client:
        deleted = await client.delete(
            f"/api/v1/organizations/{org.id}", headers=_bearer(_access(platform))
        )
        me = await client.get("/api/v1/auth/me", headers=_bearer(_access(platform)))

    assert deleted.status_code == 204, deleted.text
    assert me.status_code == 200, me.text
