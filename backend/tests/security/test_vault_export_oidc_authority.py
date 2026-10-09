"""Real SQL authority/claim plus owned signed OIDC transport integration.

Only the upstream HTTP transport/DNS answer and connection factory are owned
test boundaries. Current authentication, SQL claim, signatures, account checks
and provider binding use production code. No external IdP/TLS acceptance.
"""

import asyncio
import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote_plus, urlsplit

import anyio
import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, HTTPException, Request
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security_utils
from app.core.dependencies import CurrentUser, get_current_user
from app.core.security_utils import encrypt_field
from app.core.vault_export_proof import bind_export_value
from app.core.vault_oidc_reauthentication import OIDCConfirmationError
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.models.sso import SSOSession
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_oidc import create_oidc_confirmation
from tests.security.test_vault_export_authority import credentials, mutate, real_wait, state
from tests.security.test_vault_export_authority import owned_export as owned_export


@pytest.fixture(scope="module")
def owned_oidc_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest_asyncio.fixture
async def oidc_export(owned_export, monkeypatch, owned_oidc_signing_key):
    from app.models.sso import SSOProvider

    f = owned_export
    f.issuer = "https://idp.example.invalid"
    f.redirect = "https://console.example.invalid/vault/confirmation"
    f.action = "create"
    f.operation = bind_export_value(
        {"owned_operation": secrets.token_hex(16)}, key=f.secret, domain="request"
    )
    f.client_secret = secrets.token_urlsafe(32)
    f.requests = []
    f.stream_closes = 0
    f.pause_token = False
    f.at_token = asyncio.Event()
    f.release_token = asyncio.Event()
    f.config_method = "client_secret_post"
    f.expiry = 120
    await mutate(
        f,
        {
            "auth_provider": "oidc",
            "sso_provider_id": f.provider,
            "external_id": "owned-subject",
            "hashed_password": "!SSO_MANAGED",
        },
    )
    async with AsyncSession(f.engine) as db:
        await db.execute(
            update(SSOProvider)
            .where(SSOProvider.id == f.provider)
            .values(
                oidc_discovery_url=f.issuer + "/discovery",
                oidc_client_secret=encrypt_field(f.client_secret),
                extra_settings={},
            )
        )
        await db.commit()

    # Add owned harness routes without modifying the original 52-case fixture.
    app = f.client._transport.app

    async def current(request, user):
        authority = await VaultExportAuthority.capture(
            request, user, action=f.action, secret_key=f.secret
        )
        return await create_oidc_confirmation(
            authority,
            request_binding=f.operation,
            redirect_uri=f.redirect,
            allowed_redirect_uris=(f.redirect,),
        )

    @app.post("/owned/oidc/start")
    async def begin(request: Request, user: CurrentUser = Depends(get_current_user)):
        try:
            service = await current(request, user)
            result = await service.begin()
        except OIDCConfirmationError:
            raise HTTPException(401, "Fresh identity confirmation failed") from None
        f.service = service
        f.start = result
        return {"state": result.state, "url": result.authorize_url}

    @app.post("/owned/oidc/complete")
    async def complete(request: Request, user: CurrentUser = Depends(get_current_user)):
        body = await request.json()
        try:
            service = await current(request, user)
            receipt = await service.complete(state=body["state"], code=body["code"])
        except OIDCConfirmationError:
            raise HTTPException(401, "Fresh identity confirmation failed") from None
        return {"provider": str(receipt.provider_id), "request_binding": receipt.request_binding}

    class Body(httpx.AsyncByteStream):
        def __init__(self, obj):
            self.raw = json.dumps(obj).encode()

        async def __aiter__(self):
            yield self.raw

        async def aclose(self):
            f.stream_closes += 1

    async def transport(request):
        assert request.url.host == "203.0.113.7"
        assert request.headers["host"] == "idp.example.invalid"
        assert request.extensions["sni_hostname"] == "idp.example.invalid"
        f.requests.append(request.url.path)
        if request.url.path == "/discovery":
            payload = {
                "issuer": f.issuer,
                "authorization_endpoint": f.issuer + "/authorize",
                "token_endpoint": f.issuer + "/token",
                "jwks_uri": f.issuer + "/jwks",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "client_secret_basic",
                    "none",
                ],
            }
        elif request.url.path == "/token":
            data = parse_qs(request.content.decode())
            query = parse_qs(urlsplit(f.start.authorize_url).query)
            assert data["code"] == ["owned-code"] and data["redirect_uri"] == [f.redirect]
            verifier = data["code_verifier"][0]
            assert (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
                == query["code_challenge"][0]
            )
            if f.config_method == "client_secret_post":
                assert data["client_secret"] == [f.client_secret]
            elif f.config_method == "client_secret_basic":
                expected = (
                    quote_plus("owned-client", safe="") + ":" + quote_plus(f.client_secret, safe="")
                )
                assert (
                    base64.b64decode(
                        request.headers["authorization"].removeprefix("Basic ")
                    ).decode()
                    == expected
                )
                assert "client_secret" not in data
            else:
                assert "client_secret" not in data and "authorization" not in request.headers
            f.at_token.set()
            if f.pause_token:
                await f.release_token.wait()
            now = int(time.time())
            payload = {
                "id_token": jwt.encode(
                    {
                        "iss": f.issuer,
                        "aud": "owned-client",
                        "sub": "owned-subject",
                        "iat": now,
                        "exp": now + 120,
                        "auth_time": now,
                        "nonce": query["nonce"][0],
                    },
                    owned_oidc_signing_key,
                    algorithm="RS256",
                    headers={"kid": "owned-key"},
                )
            }
        elif request.url.path == "/jwks":
            jwk = json.loads(RSAAlgorithm.to_jwk(owned_oidc_signing_key.public_key()))
            jwk.update(kid="owned-key", alg="RS256", use="sig")
            payload = {"keys": [jwk]}
        else:
            raise AssertionError("No ordinary login, JIT or UserInfo request is permitted")
        return httpx.Response(
            200, stream=Body(payload), headers={"content-type": "application/json"}
        )

    original = httpx.AsyncClient

    def owned_http(**kwargs):
        assert kwargs["verify"] is True and kwargs["follow_redirects"] is False
        return original(**kwargs, transport=httpx.MockTransport(transport))

    monkeypatch.setattr(httpx, "AsyncClient", owned_http)
    monkeypatch.setattr(security_utils, "_resolve_and_validate", lambda *_a, **_kw: "203.0.113.7")
    try:
        yield f
    finally:
        f.release_token.set()


async def start(f, kind="jwt"):
    f.headers, f.claims = credentials(f, kind, expires=f.expiry)
    response = await f.client.post("/owned/oidc/start", headers=f.headers)
    assert response.status_code == 200, response.text
    raw = response.json()["state"]
    flow = jwt.decode(
        raw,
        f.service._key,
        algorithms=["HS256"],
        audience="freesdn-vault-oidc-reauthentication",
        issuer="freesdn",
    )
    f.flow = flow
    f.flow_hash = hashlib.sha256(flow["jti"].encode()).hexdigest()
    f.token_hashes.add(f.flow_hash)
    return raw


async def finish(f, raw, headers=None):
    return await f.client.post(
        "/owned/oidc/complete",
        headers=headers or f.headers,
        json={"state": raw, "code": "owned-code"},
    )


async def claimed(f):
    async with AsyncSession(f.engine) as db:
        return await db.scalar(
            select(func.count())
            .select_from(TokenRevocation)
            .where(TokenRevocation.jti_hash == f.flow_hash)
        )


async def no_ordinary_login(f):
    async with AsyncSession(f.engine) as db:
        assert (
            await db.scalar(
                select(func.count()).select_from(User).where(User.organization_id == f.org)
            )
            == 1
        )
        assert (
            await db.scalar(
                select(func.count()).select_from(UserSession).where(UserSession.user_id == f.user)
            )
            == 0
        )
        assert (
            await db.scalar(
                select(func.count())
                .select_from(SSOSession)
                .where(SSOSession.provider_id == f.provider)
            )
            == 0
        )
    current = await state(f)
    assert (
        current["external_id"] == "owned-subject" and current["hashed_password"] == "!SSO_MANAGED"
    )


async def transition(f, name):
    from app.models.sso import SSOProvider, SSOProviderStatus

    async with AsyncSession(f.engine) as db:
        if name in {"inactive", "organization", "role", "counter", "subject"}:
            values = {
                "inactive": {"is_active": False},
                "organization": {"organization_id": f.other_org},
                "role": {"role": "viewer"},
                "counter": {"token_version": 18},
                "subject": {"external_id": "changed-subject"},
            }[name]
            await db.execute(update(User).where(User.id == f.user).values(**values))
        elif name in {"provider_inactive", "provider_issuer"}:
            values = (
                {"status": SSOProviderStatus.INACTIVE}
                if name == "provider_inactive"
                else {"oidc_issuer": "https://changed.example.invalid"}
            )
            await db.execute(
                update(SSOProvider).where(SSOProvider.id == f.provider).values(**values)
            )
        elif name in {"key_revoked", "key_scoped"}:
            values = {"is_active": False} if name == "key_revoked" else {"scopes": ["network:read"]}
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**values))
        else:
            assert name == "unchanged"
        await db.commit()


async def hold_claim(f, holder):
    pid = await holder.scalar(select(func.pg_backend_pid()))
    await holder.execute(
        insert(TokenRevocation).values(
            jti_hash=f.flow_hash, expires_at=datetime.fromtimestamp(f.flow["exp"], UTC)
        )
    )
    return pid


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("method", ["client_secret_post", "client_secret_basic", "none"])
async def test_actual_provider_mapping_and_durable_single_exchange(oidc_export, kind, method):
    from app.models.sso import SSOProvider

    f = oidc_export
    f.config_method = method
    async with AsyncSession(f.engine) as db:
        await db.execute(
            update(SSOProvider)
            .where(SSOProvider.id == f.provider)
            .values(
                extra_settings={"vault_export_client_auth_method": method},
                oidc_client_secret=None if method == "none" else encrypt_field(f.client_secret),
            )
        )
        await db.commit()
    raw = await start(f, kind)
    response = await finish(f, raw)
    retry = await finish(f, raw)
    assert response.status_code == 200 and retry.status_code == 401, (response.text, retry.text)
    assert await claimed(f) == 1 and f.requests.count("/token") == 1
    assert f.stream_closes == len(f.requests)
    assert response.json() == {"provider": str(f.provider), "request_binding": f.operation}
    await no_ordinary_login(f)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change",
    [
        "unchanged",
        "inactive",
        "organization",
        "role",
        "counter",
        "provider_inactive",
        "provider_issuer",
        "subject",
        "key_revoked",
        "key_scoped",
    ],
)
async def test_authority_rechecked_after_real_claim_insert_wait(oidc_export, kind, change, request):
    f = oidc_export
    raw = await start(f, kind)
    async with AsyncSession(f.engine) as holder:
        pid = await hold_claim(f, holder)
        task = asyncio.create_task(finish(f, raw))
        try:
            waiting = await real_wait(f, task, pid)
            await transition(f, change)
            await holder.rollback()
            response = await asyncio.wait_for(task, 10)
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    good = change == "unchanged" or (kind == "jwt" and change.startswith("key_"))
    observation = {
        "status": response.status_code,
        "claimed": await claimed(f),
        "token_posts": f.requests.count("/token"),
    }
    request.node.user_properties.append(("real_claim_INSERT_wait", bool(waiting)))
    assert observation == {
        "status": 200 if good else 401,
        "claimed": 1,
        "token_posts": int(good),
    }, observation


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_competing_HTTP_callbacks_have_one_committed_winner(oidc_export, kind, request):
    f = oidc_export
    raw = await start(f, kind)
    async with AsyncSession(f.engine) as holder:
        pid = await hold_claim(f, holder)
        tasks = [asyncio.create_task(finish(f, raw)) for _ in range(2)]
        together = asyncio.gather(*tasks)
        try:
            waiting = await real_wait(f, together, pid, count=2)
            await holder.rollback()
            responses = await asyncio.wait_for(together, 10)
        finally:
            await holder.rollback()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    request.node.user_properties.append(("two_real_claim_INSERT_waiters", len(waiting) == 2))
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert await claimed(f) == 1 and f.requests.count("/token") == 1
    await no_ordinary_login(f)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["inactive", "provider_inactive", "key_revoked"])
async def test_revoke_during_real_signed_exchange_is_not_accepted(oidc_export, kind, change):
    f = oidc_export
    raw = await start(f, kind)
    f.pause_token = True
    task = asyncio.create_task(finish(f, raw))
    try:
        await asyncio.wait_for(f.at_token.wait(), 10)
        assert await claimed(f) == 1
        await transition(f, change)
        f.release_token.set()
        response = await asyncio.wait_for(task, 10)
    finally:
        f.release_token.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert response.status_code == (200 if kind == "jwt" and change == "key_revoked" else 401), (
        response.text
    )
    assert await claimed(f) == 1 and f.requests.count("/token") == 1
    assert f.stream_closes == len(f.requests)


@pytest.mark.parametrize("change", ["operation", "action", "redirect", "credential"])
async def test_changed_purpose_binding_is_refused_before_claim_or_exchange(oidc_export, change):
    f = oidc_export
    raw = await start(f)
    headers = f.headers
    if change == "operation":
        f.operation = bind_export_value({"different": True}, key=f.secret, domain="request")
    elif change == "action":
        f.action = "download"
    elif change == "redirect":
        f.redirect = "https://console.example.invalid/different-callback"
    else:
        headers, _ = credentials(f, "jwt")
    response = await finish(f, raw, headers)
    assert response.status_code == 401, response.text
    assert await claimed(f) == 0 and f.requests.count("/token") == 0


@pytest.mark.parametrize(
    "invalid",
    ["method", "method_type", "public_with_secret", "no_secret", "http_issuer", "local_account"],
)
async def test_unusable_provider_configuration_does_not_start_confirmation(oidc_export, invalid):
    from app.models.sso import SSOProvider

    f = oidc_export
    if invalid == "local_account":
        await mutate(f, {"auth_provider": "local"})
    else:
        values = {
            "method": {"extra_settings": {"vault_export_client_auth_method": "unknown"}},
            "method_type": {"extra_settings": {"vault_export_client_auth_method": ["none"]}},
            "public_with_secret": {"extra_settings": {"vault_export_client_auth_method": "none"}},
            "no_secret": {"oidc_client_secret": None},
            "http_issuer": {"oidc_issuer": "http://idp.example.invalid"},
        }[invalid]
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(SSOProvider).where(SSOProvider.id == f.provider).values(**values)
            )
            await db.commit()
    headers, _ = credentials(f, "jwt")
    response = await f.client.post("/owned/oidc/start", headers=headers)
    assert response.status_code == 401, response.text
    assert f.requests == []


@pytest.mark.parametrize("mode", ["asyncio", "anyio"])
async def test_cancelled_exchange_keeps_durable_claim_spent(oidc_export, mode):
    f = oidc_export
    raw = await start(f)
    f.pause_token = True
    scope_ready = asyncio.Event()
    scopes = []

    async def invoke():
        if mode == "asyncio":
            return await finish(f, raw)
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            scope_ready.set()
            await finish(f, raw)

    task = asyncio.create_task(invoke())
    try:
        await asyncio.wait_for(f.at_token.wait(), 10)
        assert await claimed(f) == 1
        if mode == "asyncio":
            task.cancel()
        else:
            await scope_ready.wait()
            scopes[0].cancel()
        outcome = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)
        assert (
            isinstance(outcome[0], asyncio.CancelledError)
            if mode == "asyncio"
            else outcome == [None]
        )
    finally:
        f.release_token.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert (await finish(f, raw)).status_code == 401
    assert await claimed(f) == 1 and f.requests.count("/token") == 1


@pytest.mark.parametrize("expiry", ["credential", "flow"])
async def test_actual_expiry_during_claim_wait_retains_tombstone(oidc_export, expiry, request):
    f = oidc_export
    if expiry == "credential":
        f.expiry = 4
    raw = await start(f)
    target = f.claims["exp"]
    if expiry == "flow":
        target = int(time.time()) + 3
        f.flow.update(exp=target, iat=target - 300, nbf=target - 300)
        # An honestly aged server-signed challenge, with original TTL/binding.
        # No verifier or clock is replaced.
        raw = jwt.encode(f.flow, f.service._key, algorithm="HS256")
    async with AsyncSession(f.engine) as holder:
        pid = await hold_claim(f, holder)
        task = asyncio.create_task(finish(f, raw))
        try:
            waiting = await real_wait(f, task, pid)
            await asyncio.sleep(max(0, target - time.time()) + 0.05)
            await holder.rollback()
            response = await asyncio.wait_for(task, 10)
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    request.node.user_properties.append(("expiry_during_real_claim_INSERT_wait", bool(waiting)))
    assert response.status_code == 401, response.text
    assert await claimed(f) == 1 and f.requests.count("/token") == 0
