# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The OIDC login flow, end to end, against a real identity provider.

OIDC single sign-on has only ever been validated by hand. That is a thin basis
for an authentication path: the last live round of OIDC testing found two real
bugs that the mocked tests had been happy with, because a mock agrees with
whatever you tell it about the IdP's behaviour.

This drives the real thing: FreeSDN resolves the IdP's endpoints from its
discovery document, the IdP's own login form is completed, and the authorization
code comes back carrying the state FreeSDN minted. Nothing on the IdP side is
stubbed.

The callback is covered too, via the ``committed_db`` fixture.
``SSOService._provision_or_update_user`` opens its own ``begin_nested()``, which
collides with the savepoint scheme ``integration_db`` uses to roll every test
back, and the collision surfaces as "Can't operate on closed transaction" --
a harness problem that reads exactly like a product one. The callback test
therefore runs against a session that really commits, and deletes what it
created.

SKIPS cleanly when no IdP is reachable, which is the normal case on a developer
machine and in CI. Point it elsewhere with FREESDN_TEST_OIDC_ISSUER. Setup is
in docs: a realm, a confidential client, and a user.

Two things about talking to Keycloak from a test, both of which cost time to
find and neither of which is obvious:

* It sets AUTH_SESSION_ID with ``Secure;SameSite=None``. An HTTP client's
  cookie jar stores that and then CORRECTLY refuses to send it back over plain
  HTTP, so the login POST arrives with no session and Keycloak answers 400
  "Cookie not found" -- which reads like bad credentials. The session cookies
  are therefore rebuilt into an explicit header.
* The login form carries the session in its action URL, so the action has to be
  read out of the page rather than constructed.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

ISSUER = os.environ.get(
    "FREESDN_TEST_OIDC_ISSUER", "http://localhost:8085/realms/freesdn-test"
)
CLIENT_ID = os.environ.get("FREESDN_TEST_OIDC_CLIENT_ID", "freesdn")
CLIENT_SECRET = os.environ.get("FREESDN_TEST_OIDC_CLIENT_SECRET", "freesdn-test-secret")
IDP_USERNAME = os.environ.get("FREESDN_TEST_OIDC_USERNAME", "ssouser")
IDP_PASSWORD = os.environ.get("FREESDN_TEST_OIDC_PASSWORD", "SsoP@ssw0rd!")
# FreeSDN's default callback. It must be registered with the IdP client.
REDIRECT_URI = "http://localhost:8000/auth/sso/callback"
# The SSO router is mounted under /auth/sso, not /sso.
SSO_PREFIX = "/api/v1/auth/sso"


def _loopback_issuer() -> bool:
    """FreeSDN refuses a loopback IdP, so the test cannot use one either.

    The SSRF guard blocks loopback outright; private addresses are allowed via
    the hosts derived in ``SSOService._trusted_idp_hosts``, which is the on-prem
    IdP topology it exists for. Point the issuer at a loopback address and
    discovery is refused, ``oidc_authorize`` silently falls back to the
    non-standard ``{issuer}/authorize`` guess, and the IdP 404s -- which looks
    like a product bug and is not one.

    Checking only that the TEST can reach the IdP is not enough: it can reach
    localhost perfectly well. What matters is whether FREESDN can use it.
    """
    from urllib.parse import urlparse

    host = (urlparse(ISSUER).hostname or "").lower()
    return host in {"localhost", "::1"} or host.startswith("127.")


def _skip_reason() -> str:
    if _loopback_issuer():
        return (
            f"the OIDC issuer {ISSUER} is a loopback address, which FreeSDN's "
            "SSRF guard refuses by design. Set FREESDN_TEST_OIDC_ISSUER to a "
            "non-loopback address for the same IdP (a LAN address works: that "
            "is the on-prem topology _trusted_idp_hosts exists for)."
        )
    return (
        f"no OIDC provider at {ISSUER}; set FREESDN_TEST_OIDC_ISSUER to run "
        "this against your own, or start the Keycloak fixture described in "
        "the module docstring"
    )


async def _idp_reachable() -> bool:
    if _loopback_issuer():
        return False

    import httpx

    try:
        async with httpx.AsyncClient(timeout=5) as probe:
            response = await probe.get(f"{ISSUER}/.well-known/openid-configuration")
            return response.status_code == 200
    except Exception:  # noqa: BLE001 - any failure means "no IdP here"
        return False


async def _complete_idp_login(authorize_url: str) -> tuple[str, str]:
    """Log in at the IdP and return its (code, state).

    Returns the code FreeSDN's callback needs. Raises AssertionError with the
    IdP's own message when the flow does not reach a redirect, because "no code"
    on its own is not a diagnosis.
    """
    import httpx

    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as client:
        page = await client.get(authorize_url)
        assert page.status_code == 200, (
            f"IdP authorize page returned {page.status_code} for {authorize_url}"
        )

        action = re.search(r'action="([^"]+)"', page.text)
        assert action, "no login form on the IdP page; its template changed"

        # See the module docstring: Secure cookies cannot travel over plain HTTP
        # from a cookie jar, so send them explicitly.
        jar = "; ".join(
            raw.split(";", 1)[0] for raw in page.headers.get_list("set-cookie")
        )
        submitted = await client.post(
            action.group(1).replace("&amp;", "&"),
            data={
                "username": IDP_USERNAME,
                "password": IDP_PASSWORD,
                "credentialId": "",
            },
            headers={"Cookie": jar},
        )

        location = submitted.headers.get("location", "")
        if not location:
            message = re.search(r'kc-feedback-text[^>]*>([^<]{3,200})', submitted.text)
            raise AssertionError(
                "the IdP did not redirect after login: "
                + (message.group(1).strip() if message else f"HTTP {submitted.status_code}")
            )

        query = parse_qs(urlparse(location).query)
        code = (query.get("code") or [""])[0]
        state = (query.get("state") or [""])[0]
        assert code, f"no authorization code in the redirect: {location}"
        return code, state


async def _provider(integration_db: Any) -> str:
    """An organization with an OIDC provider pointed at the IdP."""
    from app.models.core import Organization
    from app.models.sso import SSOProvider

    org = Organization(
        id=uuid4(),
        name="OIDC Org",
        slug=f"oidc-{uuid4().hex[:8]}",
        contact_email="oidc@example.com",
    )
    integration_db.add(org)
    await integration_db.flush()

    slug = f"keycloak-{uuid4().hex[:8]}"
    integration_db.add(
        SSOProvider(
            id=uuid4(),
            organization_id=org.id,
            name="Keycloak",
            slug=slug,
            protocol="oidc",
            status="active",
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT_ID,
            oidc_client_secret=CLIENT_SECRET,
            oidc_scopes="openid email profile",
        )
    )
    await integration_db.commit()
    return slug


async def test_authorize_resolves_endpoints_via_oidc_discovery(
    integration_db: Any, integration_client: Any
) -> None:
    """The authorize URL must come from the IdP's discovery document.

    ``oidc_authorize`` falls back to a non-standard ``{issuer}/authorize`` guess
    when discovery fails. That guess is wrong for Keycloak, Okta, Azure AD and
    Google, all of which publish ``authorization_endpoint``, so a regression
    that breaks discovery would silently produce an authorize URL the IdP 404s
    -- which is exactly what this test saw before the IdP was reachable.
    """
    if not await _idp_reachable():
        pytest.skip(_skip_reason())

    slug = await _provider(integration_db)
    started = await integration_client.post(
        f"{SSO_PREFIX}/oidc/authorize",
        json={"provider_slug": slug, "redirect_uri": REDIRECT_URI},
        headers={"X-CSRF-Token": "test-csrf"},
        cookies={"freesdn_csrf": "test-csrf"},
    )
    assert started.status_code == 200, started.text
    authorize_url = started.json()["authorize_url"]
    assert started.json()["state"], "no state issued"

    assert "/.well-known/" not in authorize_url
    assert "/protocol/openid-connect/auth" in authorize_url, (
        "the authorize URL did not come from the discovery document; it looks "
        f"like the {{issuer}}/authorize fallback: {authorize_url}"
    )
    assert "redirect_uri=" in authorize_url, (
        f"redirect_uri was dropped from the authorize URL: {authorize_url}"
    )


async def test_the_idp_returns_a_code_bound_to_the_state_we_issued(
    integration_db: Any, integration_client: Any
) -> None:
    """Drive the real IdP and check the state binding survives the round trip.

    This is the half an attacker influences: anyone can get a code from the IdP
    for themselves. What stops that code being injected into somebody else's
    login is that it comes back with the state FreeSDN minted.
    """
    if not await _idp_reachable():
        pytest.skip(_skip_reason())

    slug = await _provider(integration_db)
    started = await integration_client.post(
        f"{SSO_PREFIX}/oidc/authorize",
        json={"provider_slug": slug, "redirect_uri": REDIRECT_URI},
        headers={"X-CSRF-Token": "test-csrf"},
        cookies={"freesdn_csrf": "test-csrf"},
    )
    assert started.status_code == 200, started.text
    payload = started.json()

    code, returned_state = await _complete_idp_login(payload["authorize_url"])
    assert code, "the IdP produced no authorization code"
    assert returned_state == payload["state"], (
        "the IdP echoed a different state than FreeSDN issued; the binding "
        f"between them is broken: {returned_state!r} != {payload['state']!r}"
    )


async def test_a_replayed_or_unknown_state_is_refused(
    integration_db: Any, integration_client: Any
) -> None:
    """A code is worthless without the state FreeSDN issued for it.

    This is the half of the flow an attacker controls: anyone can obtain a code
    from the IdP for themselves. Binding it to server-issued state is what stops
    that code being injected into somebody else's session.
    """
    if not await _idp_reachable():
        pytest.skip(_skip_reason())

    await _provider(integration_db)

    refused = await integration_client.post(
        f"{SSO_PREFIX}/oidc/callback",
        json={"state": f"never-issued-{uuid4().hex}", "code": "irrelevant"},
        headers={"X-CSRF-Token": "test-csrf"},
        cookies={"freesdn_csrf": "test-csrf"},
    )
    assert refused.status_code != 404, (
        f"{SSO_PREFIX}/oidc/callback does not exist, so this test would prove "
        f"nothing: {refused.text}"
    )
    assert 400 <= refused.status_code < 500, (
        f"an unknown state was accepted: {refused.status_code} {refused.text}"
    )

async def _provider_committed(committed_db: Any) -> tuple[str, Any]:
    """Organization + OIDC provider on a session that really commits."""
    from app.models.core import Organization
    from app.models.sso import SSOProvider

    org_id = uuid4()
    committed_db.add(
        Organization(
            id=org_id,
            name="OIDC Callback Org",
            slug=f"oidc-cb-{uuid4().hex[:8]}",
            contact_email="oidc-cb@example.com",
        )
    )
    await committed_db.flush()

    slug = f"keycloak-cb-{uuid4().hex[:8]}"
    committed_db.add(
        SSOProvider(
            id=uuid4(),
            organization_id=org_id,
            name="Keycloak",
            slug=slug,
            protocol="oidc",
            status="active",
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT_ID,
            oidc_client_secret=CLIENT_SECRET,
            oidc_scopes="openid email profile",
        )
    )
    await committed_db.commit()
    return slug, org_id


async def _cleanup(committed_db: Any, org_id: Any) -> None:
    """Delete what the test created. Nothing rolls this fixture back."""
    from sqlalchemy import delete, select

    from app.models.core import Organization, User
    from app.models.sso import SSOProvider, SSOSession

    provider_ids = (
        await committed_db.execute(
            select(SSOProvider.id).where(SSOProvider.organization_id == org_id)
        )
    ).scalars().all()
    if provider_ids:
        await committed_db.execute(
            delete(SSOSession).where(SSOSession.provider_id.in_(provider_ids))
        )
    await committed_db.execute(
        delete(SSOProvider).where(SSOProvider.organization_id == org_id)
    )
    await committed_db.execute(delete(User).where(User.organization_id == org_id))
    await committed_db.execute(delete(Organization).where(Organization.id == org_id))
    await committed_db.commit()


async def test_the_callback_exchanges_a_real_code_for_a_freesdn_session(
    committed_db: Any, committed_client: Any
) -> None:
    """The whole flow, including the exchange the other tests stop short of.

    This is where the token request, the id_token signature and nonce checks,
    and user provisioning happen: the part of SSO where a defect is an
    authentication defect rather than an inconvenience.
    """
    if not await _idp_reachable():
        pytest.skip(_skip_reason())

    slug, org_id = await _provider_committed(committed_db)
    try:
        started = await committed_client.post(
            f"{SSO_PREFIX}/oidc/authorize",
            json={"provider_slug": slug, "redirect_uri": REDIRECT_URI},
            headers={"X-CSRF-Token": "test-csrf"},
            cookies={"freesdn_csrf": "test-csrf"},
        )
        assert started.status_code == 200, started.text
        payload = started.json()

        code, returned_state = await _complete_idp_login(payload["authorize_url"])
        assert returned_state == payload["state"]

        finished = await committed_client.post(
            f"{SSO_PREFIX}/oidc/callback",
            json={"state": payload["state"], "code": code},
            headers={"X-CSRF-Token": "test-csrf"},
            cookies={"freesdn_csrf": "test-csrf"},
        )
        assert finished.status_code == 200, (
            "FreeSDN refused an authorization code it had just asked the IdP "
            f"to mint: {finished.status_code} {finished.text}"
        )

        body = finished.json()
        issued = bool(finished.cookies.get("freesdn_access")) or any(
            key in body for key in ("access_token", "token", "user")
        )
        assert issued, f"login succeeded but no FreeSDN session was issued: {body}"

        # The IdP user must have been provisioned into the right organization.
        from sqlalchemy import select

        from app.models.core import User

        provisioned = (
            await committed_db.execute(
                select(User).where(User.organization_id == org_id)
            )
        ).scalars().all()
        assert provisioned, "the SSO login issued a session but provisioned no user"
    finally:
        await _cleanup(committed_db, org_id)


async def test_a_code_cannot_be_replayed(
    committed_db: Any, committed_client: Any
) -> None:
    """One authorization code, one login.

    An authorization code is a bearer credential until it is redeemed. If the
    state survives its first use, a code captured from a redirect or a log can
    be replayed into a second session.
    """
    if not await _idp_reachable():
        pytest.skip(_skip_reason())

    slug, org_id = await _provider_committed(committed_db)
    try:
        started = await committed_client.post(
            f"{SSO_PREFIX}/oidc/authorize",
            json={"provider_slug": slug, "redirect_uri": REDIRECT_URI},
            headers={"X-CSRF-Token": "test-csrf"},
            cookies={"freesdn_csrf": "test-csrf"},
        )
        assert started.status_code == 200, started.text
        payload = started.json()
        code, _ = await _complete_idp_login(payload["authorize_url"])

        first = await committed_client.post(
            f"{SSO_PREFIX}/oidc/callback",
            json={"state": payload["state"], "code": code},
            headers={"X-CSRF-Token": "test-csrf"},
            cookies={"freesdn_csrf": "test-csrf"},
        )
        assert first.status_code == 200, first.text

        replay = await committed_client.post(
            f"{SSO_PREFIX}/oidc/callback",
            json={"state": payload["state"], "code": code},
            headers={"X-CSRF-Token": "test-csrf"},
            cookies={"freesdn_csrf": "test-csrf"},
        )
        assert replay.status_code >= 400, (
            "the same authorization code and state were accepted twice; a "
            f"captured code can be replayed into a second session: {replay.text}"
        )
    finally:
        await _cleanup(committed_db, org_id)
