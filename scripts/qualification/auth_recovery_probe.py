#!/usr/bin/env python3
"""Internal probe for check_auth_recovery.py; synthetic isolated fixtures only.

This is NOT a customer database repair command. The harness supplies a new
database and private /tmp/auth-recovery-state.json, never a deployment URL.
"""

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import httpx
import jwt
import pyotp
from app.core.cookies import ACCESS_COOKIE, REFRESH_COOKIE
from app.core.crypto import decrypt_credential, encrypt_credential
from app.core.security import create_access_token, get_password_hash
from app.core.security_utils import decrypt_field, encrypt_field
from app.db.session import async_session_factory
from app.main import app
from app.models.core import (
    Credential,
    CredentialType,
    Organization,
    User,
    UserRole,
    UserSession,
)
from sqlalchemy import select, update

STATE = Path("/tmp/auth-recovery-state.json")
PASSWORD = os.environ["RECOVERY_PROBE_PASSWORD"]
request_number = 0


async def request(method, path, **kwargs):
    global request_number
    request_number += 1
    # Independent clients deliberately do not retain cookies/CSRF state between
    # requests. Tokens are passed explicitly. Real auth middleware/DB/cache run.
    transport = httpx.ASGITransport(app=app, client=(f"192.0.2.{request_number}", 1234))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        return await client.request(method, "/api/v1/auth" + path, **kwargs)


def status(response, expected):
    assert response.status_code in expected, (
        f"Unexpected HTTP {response.status_code} at {response.url.path}"
    )


def payload(token):
    return jwt.decode(token, options={"verify_signature": False})


async def mint(state, label):
    response = await request(
        "POST",
        "/login",
        json={
            "login": "recovery-main",
            "password": PASSWORD,
            "remember_me": True,
        },
    )
    status(response, {200})
    access, refresh = response.cookies[ACCESS_COOKIE], response.cookies[REFRESH_COOKIE]
    assert payload(refresh)["rmb"] is True
    assert payload(refresh)["exp"] - payload(refresh)["iat"] >= 29 * 86400
    response = await request(
        "POST",
        "/login",
        json={
            "login": "recovery-mfa",
            "password": PASSWORD,
            "remember_me": True,
        },
    )
    status(response, {200})
    assert response.json()["require_mfa"] is True
    async with async_session_factory() as session:
        user = await session.get(User, UUID(state["users"]["reset"]))
        reset = create_access_token(
            str(user.id),
            expires_delta=timedelta(hours=1),
            token_version=user.token_version,
            extra_claims={"type": "password_reset"},
        )
    state["tokens"][label] = {
        "access": access,
        "refresh": refresh,
        "reset": reset,
        "mfa": response.json()["mfa_token"],
    }
    status(
        await request("GET", "/me", headers={"Authorization": "Bearer " + access}),
        {200},
    )
    await credential_api(access)


async def credential_api(access):
    """A decryptable restored row must also serialize safely through the API."""
    global request_number
    request_number += 1
    transport = httpx.ASGITransport(app=app, client=(f"192.0.2.{request_number}", 1234))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        response = await client.get(
            "/api/v1/credentials/", headers={"Authorization": "Bearer " + access}
        )
    status(response, {200})
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["name"] == "Synthetic offline credential"
    assert rows[0]["credential_type"] == "username_password"
    assert "synthetic-device-credential" not in response.text
    assert not {
        "password", "encrypted_password", "api_key", "token", "snmp_community",
        "ssh_private_key", "certificate",
    }.intersection(rows[0])


async def vault(state):
    async with async_session_factory() as session:
        credential = (await session.execute(select(Credential))).scalar_one()
        user = await session.get(User, UUID(state["users"]["mfa"]))
        assert (
            decrypt_credential(credential.encrypted_password)
            == "synthetic-device-credential"
        )
        assert decrypt_field(user.mfa_secret) == state["totp"]
        assert (
            hashlib.sha256(credential.encrypted_password.encode()).hexdigest()
            == state["credential_hash"]
        )
        assert (
            hashlib.sha256(user.mfa_secret.encode()).hexdigest() == state["field_hash"]
        )


async def tokens(state, label, allowed):
    bundle = state["tokens"][label]
    # Rejection must prove the recovery fence, not merely expired challenges.
    assert all(payload(token)["exp"] > time.time() for token in bundle.values())
    responses = {
        "access": await request(
            "GET", "/me", headers={"Authorization": "Bearer " + bundle["access"]}
        ),
        "refresh": await request(
            "POST", "/refresh", json={"refresh_token": bundle["refresh"]}
        ),
        "reset": await request(
            "POST",
            "/password/reset",
            json={
                "token": bundle["reset"],
                "new_password": PASSWORD,
            },
        ),
        "mfa": await request(
            "POST",
            "/login/mfa",
            json={
                "mfa_token": bundle["mfa"],
                "code": pyotp.TOTP(state["totp"]).now(),
            },
        ),
    }
    for name, response in responses.items():
        status(
            response, {200} if allowed else ({400, 401} if name == "reset" else {401})
        )
    assert all(payload(token)["exp"] > time.time() for token in bundle.values())
    return {name: r.status_code for name, r in responses.items()}


async def main():
    global request_number
    mode, *args = sys.argv[1:]
    state = (
        json.loads(STATE.read_text()) if STATE.exists() else {"tokens": {}, "users": {}}
    )
    result = {"mode": mode}
    request_number = state.get("request_number", 0)
    if mode == "seed":
        state["totp"] = pyotp.random_base32()
        async with async_session_factory() as session:
            org = Organization(
                name="Recovery qualification", slug="recovery-qualification"
            )
            session.add(org)
            await session.flush()
            for name in ("main", "reset", "mfa"):
                user = User(
                    organization_id=org.id,
                    username="recovery-" + name,
                    email=name + "@recovery.example.com",
                    role=UserRole.ORG_ADMIN,
                    hashed_password=get_password_hash(PASSWORD),
                    token_version=7,
                    mfa_enabled=name == "mfa",
                    mfa_secret=encrypt_field(state["totp"]) if name == "mfa" else None,
                )
                session.add(user)
                await session.flush()
                state["users"][name] = str(user.id)
                if name == "mfa":
                    state["field_hash"] = hashlib.sha256(
                        user.mfa_secret.encode()
                    ).hexdigest()
            cipher = encrypt_credential("synthetic-device-credential")
            session.add(
                Credential(
                    organization_id=org.id,
                    name="Synthetic offline credential",
                    credential_type=CredentialType.USERNAME_PASSWORD,
                    encrypted_password=cipher,
                )
            )
            state["credential_hash"] = hashlib.sha256(cipher.encode()).hexdigest()
            await session.commit()
        await mint(state, "legacy")
        await vault(state)
    elif mode == "upgraded":
        async with async_session_factory() as session:
            assert (
                await session.execute(select(User.token_version).distinct())
            ).scalars().all() == [8]
            sessions = (await session.execute(select(UserSession))).scalars().all()
            assert sessions and all(
                s.is_revoked and s.revoked_at is not None for s in sessions
            )
        result["rejected"] = await tokens(state, "legacy", allowed=False)
        await vault(state)
        await mint(state, "snapshot")
    elif mode == "post-snapshot":
        bundle = state["tokens"]["snapshot"]
        response = await request(
            "POST",
            "/logout-all",
            headers={"Authorization": "Bearer " + bundle["access"]},
        )
        status(response, {200})
        status(
            await request(
                "GET", "/me", headers={"Authorization": "Bearer " + bundle["access"]}
            ),
            {401},
        )
        # Simulate equivalent account-wide invalidation for the two dedicated
        # reset/MFA fixtures without consuming their snapshot-era challenges.
        async with async_session_factory() as session:
            await session.execute(
                update(User)
                .where(User.username.in_(["recovery-reset", "recovery-mfa"]))
                .values(token_version=User.token_version + 1)
            )
            await session.commit()
        await mint(state, "later")
    elif mode == "negative":
        # This deliberately proves the unsafe procedure accepts old tokens.
        # Run only against the harness-owned restored copies, never a live site.
        result["accepted"] = await tokens(state, args[0], allowed=True)
        await vault(state)
    elif mode == "recovered":
        result["rejected"] = {}
        for label in ("legacy", "snapshot", "later"):
            result["rejected"][label] = await tokens(state, label, allowed=False)
        await vault(state)
        await mint(state, "fresh")
        result["fresh"] = await tokens(state, "fresh", allowed=True)
        # Successful refresh/reset/MFA redemption must still be one-use.
        bundle = state["tokens"]["fresh"]
        for path, data in (
            ("/refresh", {"refresh_token": bundle["refresh"]}),
            ("/password/reset", {"token": bundle["reset"], "new_password": PASSWORD}),
            (
                "/login/mfa",
                {"mfa_token": bundle["mfa"], "code": pyotp.TOTP(state["totp"]).now()},
            ),
        ):
            status(await request("POST", path, json=data), {400, 401})
    elif mode == "restart":
        for label in ("legacy", "snapshot", "later"):
            await tokens(state, label, allowed=False)
        await vault(state)
        await mint(state, "restart")
    else:
        raise AssertionError("Unknown qualification mode")
    state["request_number"] = request_number
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    result["passed"] = True
    print("AUTH_RECOVERY_RESULT=" + json.dumps(result))


if __name__ == "__main__":
    asyncio.run(main())
