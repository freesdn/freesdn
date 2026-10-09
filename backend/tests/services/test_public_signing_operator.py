# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Public application signing contracts on owned SQL, Redis and key storage.

Only request database sessions are redirected. Authentication, cookie CSRF,
fresh local factors, signing phases and application middleware remain real.
Full lifespan, browser deployment and external IdP confirmation are separate.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import ACCESS_COOKIE
from app.core.security_utils import encrypt_field
from app.db.session import get_session
from app.main import create_application
from app.models.api_keys import APIKey
from app.services import agent_signing_lifecycle as lifecycle
from app.services import agent_signing_status as inspection
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.security import test_agent_signing_authority as account
from tests.services import test_agent_signing_lifecycle as owned
from tests.services.test_agent_signing_operator import command_body, execute_body

PREFIX = "/api/v1/auth/agent-signing"


@pytest_asyncio.fixture
async def public_signing(maintenance_engine, monkeypatch, tmp_path):
    async with asynccontextmanager(owned.owned_lifecycle.__wrapped__)(maintenance_engine, monkeypatch, tmp_path) as f:
        app = create_application()

        async def connection():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = connection
        octets = uuid4().bytes
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                    client=(f"198.19.{octets[0]}.{octets[1]}", 123)),
                base_url="http://owned-signing", follow_redirects=False,
            ) as client:
                f.public_signing_client = client
                yield f
        finally:
            layer = app.middleware_stack
            seen = set()
            while layer is not None and id(layer) not in seen:
                seen.add(id(layer))
                if type(layer).__name__ == "RateLimitMiddleware" and layer._redis is not None:
                    await layer._redis.aclose()
                layer = getattr(layer, "app", None)
            # The framework caches this fixture's dependency closure. Release
            # the already-closed client so that it cannot retain the full app.
            f.public_signing_client = None


async def credential(f, kind):
    headers = await owned.headers(f, "jwt" if kind == "cookie" else kind)
    if kind == "cookie":
        token = headers["Authorization"].removeprefix("Bearer ")
        return {"Cookie": f"{ACCESS_COOKIE}={token}; freesdn_csrf=owned-signing-csrf",
                "X-CSRF-Token": "owned-signing-csrf"}
    return headers


def no_secrets(response, f):
    assert f.password not in response.text and f.recovery not in response.text
    assert f.seed not in response.text and "BEGIN PRIVATE KEY" not in response.text
    if response.status_code < 400:
        assert "confirmation_id" not in response.text
    assert "untrusted-browser-receipt" not in response.text


@pytest.mark.parametrize("kind", ("jwt", "key", "cookie"))
@pytest.mark.parametrize("null_org", (False, True))
async def test_public_local_signing_initialization_and_inspection(public_signing, kind, null_org):
    f = public_signing
    if null_org:
        await account.mutate(f, {"organization_id": None})
    headers = await credential(f, kind)
    before = await owned.snapshot(f)
    status = await f.public_signing_client.get(PREFIX + "/status", headers=headers)
    preflight = await f.public_signing_client.post(PREFIX + "/preflight", headers=headers, json=command_body(f))
    assert status.status_code == preflight.status_code == 200
    assert await owned.snapshot(f) == before and not f.root.exists()
    assert status.json()["state"] == "unconfigured"
    assert status.json()["empty_state_proves_new_installation"] is False
    assert preflight.json()["database_eligible"] is True
    assert preflight.json()["authorization_granted"] is preflight.json()["storage_checked"] is False
    assert preflight.json()["local_confirmation_available"] is True
    result = await f.public_signing_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    after = await owned.snapshot(f)
    assert result.status_code == 200 and result.json()["state"] == "activated"
    assert len(after[0]) == len(after[1]) == 1 and after[2]
    assert after[0][0]["operation_id"] == after[1][0]["operation_id"] == f.command.operation_id
    selected = await f.public_signing_client.get(PREFIX + "/operations/" + str(f.command.operation_id), headers=headers)
    assert selected.status_code == 200 and selected.json()["operation"]["state"] == "activated"
    assert selected.json()["active"]["public_key_sha256"] == after[2][".public-key.pem"]
    assert await owned.snapshot(f) == after
    for response in (status, preflight, result, selected):
        assert "no-store" in response.headers["cache-control"]
        no_secrets(response, f)


@pytest.mark.parametrize("kind", ("jwt", "cookie"))
@pytest.mark.parametrize("phase", ("pending", "prepared", "activated"))
async def test_public_lost_response_preserves_phase_for_explicit_resume(public_signing, monkeypatch, kind, phase):
    f = public_signing
    headers = await credential(f, kind)
    original = lifecycle._phase

    async def lost_after_commit(*args, **kwargs):
        result = await original(*args, **kwargs)
        row = result[0] if isinstance(result, tuple) else result
        if row["state"] == phase:
            raise HTTPException(503, "Owned response loss after real signing commit")
        return result

    monkeypatch.setattr(lifecycle, "_phase", lost_after_commit)
    first = await f.public_signing_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    retained = await owned.snapshot(f)
    assert first.status_code == 503 and retained[0][0]["state"] == phase
    monkeypatch.setattr(lifecycle, "_phase", original)
    observed = await f.public_signing_client.get(PREFIX + "/operations/" + str(f.command.operation_id), headers=headers)
    assert observed.status_code == 200 and observed.json()["operation"]["state"] == phase
    assert await owned.snapshot(f) == retained
    resumed = await f.public_signing_client.post(PREFIX + "/execute-local", headers=headers,
        json=execute_body(f, action="resume"))
    after = await owned.snapshot(f)
    if phase == "pending":
        assert resumed.status_code == 409 and after == retained and not after[1] and not after[2]
    else:
        assert resumed.status_code == 200 and len(after[1]) == 1
        assert after[0][0]["state"] == "activated" and after[2] == retained[2]
    no_secrets(first, f)
    no_secrets(resumed, f)


@pytest.mark.parametrize("mode", ("wrong-password", "org-admin", "scoped-key", "external"))
async def test_public_signing_refusals_preserve_identity_and_files(public_signing, mode):
    f = public_signing
    body = execute_body(f)
    if mode == "wrong-password":
        body["password"] += "-wrong"
    elif mode == "org-admin":
        await account.mutate(f, {"role": "org_admin"})
    elif mode == "scoped-key":
        async with f.engine.begin() as db:
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    else:
        await account.mutate(f, {"auth_provider": "oidc", "sso_provider_id": f.provider,
                                 "external_id": "owned-verified-boundary-subject"})
    before = await owned.snapshot(f)
    response = await f.public_signing_client.post(PREFIX + "/execute-local", headers=await credential(f, "key"), json=body)
    assert await owned.snapshot(f) == before and not f.root.exists()
    assert response.status_code == {"wrong-password": 401, "org-admin": 403, "scoped-key": 403, "external": 409}[mode]
    no_secrets(response, f)


@pytest.mark.parametrize("route", ("preflight", "execute-local"))
async def test_public_cookie_signing_requires_csrf_before_body_read(public_signing, route):
    f = public_signing
    headers = await credential(f, "cookie")
    del headers["X-CSRF-Token"]
    headers["X-API-Key"] = "invalid-header-must-not-bypass-cookie-csrf"
    reads = 0

    async def body():
        nonlocal reads
        reads += 1
        yield b"untrusted-body"

    before = await owned.snapshot(f)
    response = await f.public_signing_client.post(PREFIX + "/" + route, headers=headers, content=body())
    assert response.status_code == 403 and response.json()["error"]["message"] == "CSRF token missing"
    assert reads == 0 and await owned.snapshot(f) == before and not f.root.exists()


@pytest.mark.parametrize("kind", ("jwt", "key"))
async def test_public_signing_rechecks_authority_after_real_snapshot(public_signing, monkeypatch, kind):
    f = public_signing
    original = inspection._read_snapshot
    reached, resume = asyncio.Event(), asyncio.Event()

    async def pause(operation_id):
        value = await original(operation_id)
        reached.set()
        await resume.wait()
        return value

    monkeypatch.setattr(inspection, "_read_snapshot", pause)
    request = asyncio.create_task(f.public_signing_client.get(PREFIX + "/status", headers=await credential(f, kind)))
    try:
        async with asyncio.timeout(10):
            await reached.wait()
            await account.mutate(f, {"is_active": False})
            resume.set()
            response = await request
        assert response.status_code == 401 and "retained_installation_id" not in response.text
        assert not f.root.exists()
    finally:
        resume.set()
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)


@pytest.mark.parametrize("provide_code", (False, True))
async def test_public_cookie_signing_keeps_mfa_confirmation_and_consumption(public_signing, provide_code):
    f = public_signing
    await account.mutate(f, {"mfa_enabled": True, "mfa_secret": encrypt_field(f.seed),
        "mfa_backup_codes": json.dumps([f.recovery_hash]), "mfa_last_totp_step": 123456})
    before = await owned.snapshot(f)
    body = execute_body(f)
    if provide_code:
        body["code"] = f.recovery
    response = await f.public_signing_client.post(PREFIX + "/execute-local", headers=await credential(f, "cookie"), json=body)
    state = await account.state(f)
    after = await owned.snapshot(f)
    assert response.status_code == (200 if provide_code else 401)
    if provide_code:
        assert json.loads(state["mfa_backup_codes"]) == [] and len(after[1]) == 1
    else:
        assert state["mfa_backup_codes"] == json.dumps([f.recovery_hash]) and after == before
    assert state["mfa_last_totp_step"] == 123456 and state["mfa_enabled"]
    no_secrets(response, f)


@pytest.mark.parametrize("route", ("status", "preflight"))
async def test_public_signing_without_credentials_is_refused(public_signing, route):
    f = public_signing
    before = await owned.snapshot(f)
    if route == "status":
        response = await f.public_signing_client.get(PREFIX + "/status")
    else:
        response = await f.public_signing_client.post(PREFIX + "/preflight", json=command_body(f),
            headers={"Cookie": "freesdn_csrf=anonymous-signing", "X-CSRF-Token": "anonymous-signing"})
    assert response.status_code == 401 and await owned.snapshot(f) == before and not f.root.exists()


@pytest.mark.parametrize("change", ({"acknowledge_identity_risk": False}, {"confirmation_id": "untrusted-browser-receipt"}))
async def test_public_signing_validation_does_not_disclose_submitted_factors(public_signing, change):
    f = public_signing
    before = await owned.snapshot(f)
    response = await f.public_signing_client.post(PREFIX + "/execute-local", headers=await credential(f, "jwt"),
        json={**execute_body(f), **change})
    assert response.status_code == 422 and await owned.snapshot(f) == before and not f.root.exists()
    no_secrets(response, f)


async def test_public_signing_uses_actual_redis_auth_quota(public_signing):
    f = public_signing
    headers = await credential(f, "cookie")
    for number in range(5):
        body = execute_body(f, action="initialize" if number == 0 else "resume")
        response = await f.public_signing_client.post(PREFIX + "/execute-local", headers=headers, json=body)
        assert response.status_code == 200 and response.json()["state"] == "activated"
    before = await owned.snapshot(f)
    response = await f.public_signing_client.post(PREFIX + "/execute-local", headers=headers,
        json=execute_body(f, action="resume"))
    assert response.status_code == 429 and await owned.snapshot(f) == before
    assert len(before[0]) == len(before[1]) == 1
    no_secrets(response, f)
