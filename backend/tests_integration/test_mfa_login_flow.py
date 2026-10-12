# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Multi-factor login, end to end, including the recovery-code path.

This area has already failed in production in a way no unit test noticed. In
26.09.0, ``/auth/mfa/setup`` minted recovery codes as ``token_hex(5).upper()``
-- ten characters -- while ``MfaLoginRequest.code`` capped the field at eight,
so **every recovery code the system had ever issued was rejected before
verification**. Each side was self-consistent and individually tested. Only
running the whole flow shows it, and nothing ran the whole flow.

So the recovery-code test here is not decoration: it is a regression test for a
shipped authentication outage, and it is the reason this file exists.

Covered: enrolment, that login starts challenging once MFA is on, that a
correct TOTP completes it, that a wrong code does not, that a recovery code
works, and that a recovery code cannot be used twice.

Uses ``committed_db`` because enrolment and login both commit, and the
rollback-per-test session rewrites commits into savepoints in a way that
collides with nested transactions. Nothing rolls back, so the test deletes what
it created.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

PASSWORD = "MfaFlowP@ssw0rd!"
AUTH = "/api/v1/auth"
CSRF = {"headers": {"X-CSRF-Token": "test-csrf"}, "cookies": {"freesdn_csrf": "test-csrf"}}


async def _user(committed_db: Any) -> tuple[str, Any]:
    from app.core.security import get_password_hash
    from app.models.core import Organization, User, UserRole

    org_id = uuid4()
    committed_db.add(
        Organization(
            id=org_id,
            name="MFA Org",
            slug=f"mfa-{uuid4().hex[:8]}",
            contact_email="mfa@example.com",
        )
    )
    await committed_db.flush()

    email = f"mfa-{uuid4().hex[:8]}@example.com"
    committed_db.add(
        User(
            id=uuid4(),
            email=email,
            username=f"mfa_{uuid4().hex[:8]}",
            full_name="MFA User",
            hashed_password=get_password_hash(PASSWORD),
            role=UserRole.ORG_ADMIN,
            organization_id=org_id,
            is_active=True,
            is_verified=True,
        )
    )
    await committed_db.commit()
    return email, org_id


async def _cleanup(committed_db: Any, org_id: Any) -> None:
    from sqlalchemy import delete

    from app.models.core import Organization, User

    await committed_db.execute(delete(User).where(User.organization_id == org_id))
    await committed_db.execute(delete(Organization).where(Organization.id == org_id))
    await committed_db.commit()


async def _login(client: Any, email: str) -> Any:
    return await client.post(
        f"{AUTH}/login", json={"login": email, "password": PASSWORD}, **CSRF
    )


async def _enrol(client: Any, email: str) -> tuple[str, list[str], str]:
    """Turn MFA on and return (secret, recovery_codes, code_used_to_enrol).

    The enrolment code is reported because it has been SPENT: the server
    refuses a TOTP it has already seen, so a test that reuses it inside the
    same 30-second step gets "Invalid MFA code" and looks like a product
    bug.
    """
    import pyotp

    first = await _login(client, email)
    assert first.status_code == 200, first.text
    token = first.cookies.get("freesdn_access") or first.json().get("access_token")
    assert token, f"no access token from the pre-MFA login: {first.text}"
    headers = {"Authorization": f"Bearer {token}", **CSRF["headers"]}

    setup = await client.post(
        f"{AUTH}/mfa/setup", json={}, headers=headers, cookies=CSRF["cookies"]
    )
    assert setup.status_code == 200, setup.text
    body = setup.json()
    secret, codes = body["secret"], body["backup_codes"]
    assert secret and codes, body

    enrol_code = pyotp.TOTP(secret).now()
    enable = await client.post(
        f"{AUTH}/mfa/enable",
        json={"code": enrol_code},
        headers=headers,
        cookies=CSRF["cookies"],
    )
    assert enable.status_code == 200, (
        f"enrolment refused a TOTP generated from the secret it just issued: "
        f"{enable.text}"
    )
    return secret, codes, enrol_code


async def _fresh_totp(secret: str, avoid: str) -> str:
    """A TOTP the server has not already consumed.

    Waits for the 30-second step to roll over rather than sleeping a fixed
    amount, so the test is as fast as the window allows.
    """
    import asyncio

    import pyotp

    totp = pyotp.TOTP(secret)
    for _ in range(70):
        candidate = totp.now()
        if candidate != avoid:
            return candidate
        await asyncio.sleep(0.5)
    raise AssertionError("the TOTP window never rolled over")


def _tokens_issued(response: Any) -> bool:
    body = response.json() if response.content else {}
    return bool(response.cookies.get("freesdn_access")) or any(
        key in body for key in ("access_token", "token", "expires_in")
    )


async def test_totp_login_challenges_then_succeeds(
    committed_db: Any, committed_client: Any
) -> None:
    email, org_id = await _user(committed_db)
    try:
        secret, _, enrol_code = await _enrol(committed_client, email)

        challenged = await _login(committed_client, email)
        assert challenged.status_code == 200, challenged.text
        body = challenged.json()
        assert body.get("require_mfa") is True, (
            f"password alone still logged in after MFA was enabled: {body}"
        )
        mfa_token = body.get("mfa_token")
        assert mfa_token, body
        assert not body.get("access_token"), (
            "the challenge response carried an access token, so MFA is "
            f"advisory rather than required: {body}"
        )

        completed = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={
                "mfa_token": mfa_token,
                "code": await _fresh_totp(secret, enrol_code),
            },
            **CSRF,
        )
        assert completed.status_code == 200, completed.text
        assert _tokens_issued(completed), completed.text
    finally:
        await _cleanup(committed_db, org_id)


async def test_a_wrong_code_does_not_complete_the_challenge(
    committed_db: Any, committed_client: Any
) -> None:
    email, org_id = await _user(committed_db)
    try:
        await _enrol(committed_client, email)
        challenged = await _login(committed_client, email)
        mfa_token = challenged.json()["mfa_token"]

        refused = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={"mfa_token": mfa_token, "code": "000000"},
            **CSRF,
        )
        assert refused.status_code >= 400, (
            f"an arbitrary six-digit code completed MFA: {refused.text}"
        )
        assert not _tokens_issued(refused), refused.text
    finally:
        await _cleanup(committed_db, org_id)


async def test_a_recovery_code_completes_the_challenge(
    committed_db: Any, committed_client: Any
) -> None:
    """REGRESSION: in 26.09.0 every recovery code ever issued was rejected.

    The codes are minted as ten characters and the request schema capped the
    field at eight, so verification was never reached. A user who had lost
    their authenticator had no way back in, and nothing failed until someone
    tried it.
    """
    email, org_id = await _user(committed_db)
    try:
        _, codes, _code = await _enrol(committed_client, email)
        challenged = await _login(committed_client, email)
        mfa_token = challenged.json()["mfa_token"]

        completed = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={"mfa_token": mfa_token, "code": codes[0]},
            **CSRF,
        )
        assert completed.status_code == 200, (
            f"a recovery code issued by /mfa/setup was rejected at login "
            f"(code length {len(codes[0])}): {completed.status_code} "
            f"{completed.text}"
        )
        assert _tokens_issued(completed), completed.text
    finally:
        await _cleanup(committed_db, org_id)


async def test_a_recovery_code_cannot_be_used_twice(
    committed_db: Any, committed_client: Any
) -> None:
    """Single use is the whole security model of a recovery code.

    They are written down, screenshotted and emailed to oneself. A code that
    still works after it has been used is a long-lived password in a form
    people treat casually.
    """
    email, org_id = await _user(committed_db)
    try:
        _, codes, _code = await _enrol(committed_client, email)

        first_challenge = await _login(committed_client, email)
        first = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={"mfa_token": first_challenge.json()["mfa_token"], "code": codes[0]},
            **CSRF,
        )
        assert first.status_code == 200, first.text

        second_challenge = await _login(committed_client, email)
        assert second_challenge.json().get("require_mfa") is True
        replay = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={"mfa_token": second_challenge.json()["mfa_token"], "code": codes[0]},
            **CSRF,
        )
        assert replay.status_code >= 400, (
            "the same recovery code was accepted twice; a written-down code "
            f"stays valid forever: {replay.text}"
        )
        assert not _tokens_issued(replay), replay.text
    finally:
        await _cleanup(committed_db, org_id)

async def test_a_totp_code_cannot_be_used_twice(
    committed_db: Any, committed_client: Any
) -> None:
    """A TOTP is single use, not merely time limited.

    Discovered by stumbling into it: reusing the enrolment code at login was
    refused, which first looked like a bug. It is the opposite. A TOTP stays
    valid for a whole 30-second step, so without single-use enforcement anyone
    who observes a code -- over the shoulder, in a proxy log, in a screenshot --
    has the rest of that window to replay it. Pinning it here so the protection
    cannot be dropped as a convenience.
    """
    email, org_id = await _user(committed_db)
    try:
        _secret, _codes, enrol_code = await _enrol(committed_client, email)

        challenged = await _login(committed_client, email)
        assert challenged.json().get("require_mfa") is True

        replay = await committed_client.post(
            f"{AUTH}/login/mfa",
            json={"mfa_token": challenged.json()["mfa_token"], "code": enrol_code},
            **CSRF,
        )
        assert replay.status_code >= 400, (
            "a TOTP already spent on enrolment completed a login in the same "
            f"window; observed codes are replayable: {replay.text}"
        )
        assert not _tokens_issued(replay), replay.text
    finally:
        await _cleanup(committed_db, org_id)
