"""Planned actual application construction/router/middleware tests.

ASGI transport deliberately does not enter the application lifespan; these
probes cannot accept external IdPs, workers, hardware or deployment startup.
"""

from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
import pytest
from redis.asyncio import Redis
from redis.exceptions import AuthenticationError

import app.main as product
from app.core.config import get_settings
from app.core.cookies import ACCESS_COOKIE
from app.core.middleware import RateLimitMiddleware
from app.db.session import get_session
from app.services.vault_export_authority import VaultExportAuthority
from tests.security.test_vault_public_creation_lifecycle import creation_actor, rows, spent
from tests.security.test_vault_public_download_lifecycle import remember
from tests.services.test_backup_artifact_integrity_contract import create_request

PREFIX = "/api/v1/auth/vault-export"
ORIGIN = "https://owned-vault-ui.example"


@asynccontextmanager
async def registered_actor(monkeypatch, tmp_path, credential="jwt", callback="", api_prefix="/api/v1"):
    async with creation_actor(monkeypatch, tmp_path, "jwt" if credential == "cookie" else credential) as f:
        configured = product.settings.model_copy(update={"CORS_ORIGINS": [ORIGIN], "VAULT_OIDC_REDIRECT_URI": callback, "API_V1_PREFIX": api_prefix})
        monkeypatch.setattr(product, "settings", configured)
        application = product.create_application()
        original = f.client
        application.dependency_overrides[get_session] = original._transport.app.dependency_overrides[get_session]
        headers = dict(original.headers)
        cookies = {}
        if credential == "cookie":
            cookies[ACCESS_COOKIE] = headers.pop("authorization").removeprefix("Bearer ")
            cookies["freesdn_csrf"] = uuid4().hex
            headers["X-CSRF-Token"] = cookies["freesdn_csrf"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application, raise_app_exceptions=False),
                                     base_url="http://test", headers=headers, cookies=cookies) as client:
            f.client = client
            f.application = application
            f.confirmation_prefix = api_prefix + "/auth/vault-export"
            try:
                yield f
            finally:
                f.client = original


async def authorize(f, intent, **headers):
    response = await f.client.post(PREFIX + "/authorize/local", json={"intent": intent, "password": f.password}, headers=headers)
    assert response.status_code == 200, response.text
    token = response.json()["proof"]
    remember(f, token)
    return token


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
async def test_actual_application_confirmation_creation_and_download(monkeypatch, tmp_path, request, credential):
    async with registered_actor(monkeypatch, tmp_path, credential) as f:
        data = create_request(f, True)
        proof = await authorize(f, {"kind": "create", "backup": data})
        made = await f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": proof})
        request.node.user_properties.append(("creation_status", made.status_code))
        assert made.status_code == 201, made.text
        items = await rows(f)
        assert len(items) == 1 and items[0].status == "completed"
        backup = items[0]
        raw = (f.root / backup.storage_path).read_bytes()
        proof = await authorize(f, {"kind": "download_recorded", "backup_id": str(backup.id)})
        got = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": proof, "Origin": ORIGIN})
        properties = {"download_status": got.status_code, "exact_archive": got.content == raw, "all_proofs_spent": await spent(f),
                      "allowed_origin": got.headers.get("access-control-allow-origin"),
                      "integrity": got.headers.get("x-freesdn-artifact-integrity")}
        request.node.user_properties.extend(properties.items())
        assert properties == {"download_status": 200, "exact_archive": True, "all_proofs_spent": True,
                              "allowed_origin": ORIGIN, "integrity": "verified"}
        assert "x-freesdn-artifact-integrity" in got.headers["access-control-expose-headers"].lower()
        assert "content-disposition" in got.headers["access-control-expose-headers"].lower()
        assert "no-store" in got.headers["cache-control"]


@pytest.mark.parametrize("path", ["/authorize/local", "/identity/ldap", "/identity/oidc/start", "/identity/oidc/complete", "/authorize/external"])
async def test_registered_confirmation_never_admits_anonymous(monkeypatch, tmp_path, request, path):
    async with registered_actor(monkeypatch, tmp_path) as f:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=f.application, raise_app_exceptions=False), base_url="http://test", cookies={"freesdn_csrf": "owned-anonymous-csrf"},
                                     headers={"X-CSRF-Token": "owned-anonymous-csrf"}) as client:
            response = await client.post(PREFIX + path, json={})
        request.node.user_properties.append(("anonymous_status", response.status_code))
        assert response.status_code == 401
        assert "no-store" in response.headers["cache-control"]
        assert "proof" not in response.json()


@pytest.mark.parametrize("header", ["X-FreeSDN-Vault-Proof", "X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization"])
async def test_configured_origin_may_send_vault_headers(monkeypatch, tmp_path, request, header):
    async with registered_actor(monkeypatch, tmp_path) as f:
        response = await f.client.options(PREFIX + "/authorize/local", headers={"Origin": ORIGIN,
            "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": header})
        request.node.user_properties.append(("preflight_status", response.status_code))
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == ORIGIN
        assert header.lower() in response.headers["access-control-allow-headers"].lower()


async def test_unconfigured_origin_remains_refused(monkeypatch, tmp_path):
    async with registered_actor(monkeypatch, tmp_path) as f:
        response = await f.client.options(PREFIX + "/authorize/local", headers={"Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "X-FreeSDN-Vault-Proof"})
        assert response.status_code == 400 and "access-control-allow-origin" not in response.headers


async def test_absent_oidc_callback_does_not_use_request_host(monkeypatch, tmp_path, request):
    async with registered_actor(monkeypatch, tmp_path) as f:
        response = await f.client.post(PREFIX + "/identity/oidc/start", json={"intent": {"kind": "create", "backup": create_request(f, True)}},
                                       headers={"Host": "untrusted.example", "Origin": "https://untrusted.example"})
        request.node.user_properties.append(("missing_callback_status", response.status_code))
        assert response.status_code == 503
        assert "authorize_url" not in response.json()
        assert f.application.state.vault_confirmation_policy.oidc_redirect_uri is None


@pytest.mark.parametrize("callback", ["https://owned-ui.example/vault/callback", "https://owned-ui.example:8443/vault/callback"])
async def test_callback_policy_is_captured_once(monkeypatch, tmp_path, callback):
    async with registered_actor(monkeypatch, tmp_path, callback=callback) as f:
        monkeypatch.setattr(product, "settings", product.settings.model_copy(update={"VAULT_OIDC_REDIRECT_URI": "https://changed.example/late"}))
        assert f.application.state.vault_confirmation_policy.oidc_redirect_uri == callback


@pytest.mark.parametrize("callback", ["http://owned-ui.example/callback", "https://owned-ui.example/callback?next=evil", "https://user:password@owned-ui.example/callback", "https://owned-ui.example/callback#fragment"])
def test_invalid_deployment_callback_refuses_application_construction(monkeypatch, callback):
    configured = product.settings.model_copy(update={"VAULT_OIDC_REDIRECT_URI": callback})
    monkeypatch.setattr(product, "settings", configured)
    with pytest.raises(ValueError, match="Explicit HTTPS vault callback required"):
        product.create_application()


@pytest.mark.parametrize("path", ["/authorize/local", "/identity/ldap", "/authorize/external"])
async def test_confirmation_does_not_gain_a_csrf_exemption(monkeypatch, tmp_path, request, path):
    async with registered_actor(monkeypatch, tmp_path, "cookie") as f:
        async with httpx.AsyncClient(transport=f.client._transport, base_url="http://test", cookies=f.client.cookies) as client:
            response = await client.post(PREFIX + path, json={})
        request.node.user_properties.append(("missing_csrf_status", response.status_code))
        assert response.status_code == 403 and "proof" not in response.json()
        assert response.json()["error"]["message"] == "CSRF token missing"


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
async def test_real_app_wrong_fresh_password_never_issues_proof(monkeypatch, tmp_path, request, credential):
    async with registered_actor(monkeypatch, tmp_path, credential) as f:
        response = await f.client.post(PREFIX + "/authorize/local", json={
            "intent": {"kind": "create", "backup": create_request(f, True)}, "password": f.password + "-wrong",
        })
        observed = {"status": response.status_code, "proof_issued": "proof" in response.json(), "catalogue_rows": len(await rows(f))}
        request.node.user_properties.extend(observed.items())
        assert observed == {"status": 401, "proof_issued": False, "catalogue_rows": 0}
        assert f.password not in response.text and f.phrase not in response.text


@asynccontextmanager
async def rejecting_rate_client(monkeypatch):
    """The owned real Redis rejects this client's AUTH; no fake Redis method."""
    settings = get_settings()
    client = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password="owned-wrong-" + uuid4().hex,
                   socket_connect_timeout=1, socket_timeout=1)
    try:
        with pytest.raises(AuthenticationError):
            await client.ping()
        monkeypatch.setattr(RateLimitMiddleware, "_get_redis", lambda _self: client)
        yield
    finally:
        await client.aclose()


@pytest.mark.parametrize("api_prefix", ["/api/v1", "/owned-api/v2"])
@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
async def test_real_redis_auth_failure_blocks_confirmation_before_factors(monkeypatch, tmp_path, request, api_prefix, credential):
    async with registered_actor(monkeypatch, tmp_path, credential, api_prefix=api_prefix) as f:
        calls = []
        original = VaultExportAuthority.confirm_local

        async def observe(authority, **kwargs):
            calls.append(True)
            return await original(authority, **kwargs)

        monkeypatch.setattr(VaultExportAuthority, "confirm_local", observe)
        async with rejecting_rate_client(monkeypatch):
            response = await f.client.post(f.confirmation_prefix + "/authorize/local", json={
                "intent": {"kind": "create", "backup": create_request(f, True)}, "password": f.password,
            })
        props = {"status": response.status_code, "actual_factor_calls": len(calls), "proof_issued": "proof" in response.json()}
        request.node.user_properties.extend(props.items())
        assert props == {"status": 503, "actual_factor_calls": 0, "proof_issued": False}
        assert response.headers["retry-after"] == "10"


@pytest.mark.parametrize("api_prefix", ["/api/v1", "/owned-api/v2"])
@pytest.mark.parametrize("protected", [True, False])
async def test_real_rate_failure_gates_configured_auth_prefix_only(monkeypatch, tmp_path, request, api_prefix, protected):
    async with registered_actor(monkeypatch, tmp_path, api_prefix=api_prefix) as f:
        path = api_prefix + ("/auth/owned-rate-probe" if protected else "/owned-rate-probe")
        reached = []

        @f.application.post(path)
        async def marker():
            # No authentication or business mutation: observe middleware admission only.
            reached.append(True)
            return {"owned_marker": True}

        async with rejecting_rate_client(monkeypatch):
            response = await f.client.post(path, json={})
        props = {"status": response.status_code, "marker_reached": bool(reached)}
        request.node.user_properties.extend(props.items())
        assert props == {"status": 503 if protected else 200, "marker_reached": not protected}
