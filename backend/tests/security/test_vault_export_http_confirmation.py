"""Unrun real HTTP/SQL confirmation contracts; not archive or IdP acceptance."""

import hashlib
import json
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import Depends, Request

from app.api.v1.endpoints.vault_export import (
    VaultConfirmationPolicy,
    create_vault_confirmation_router,
)
from app.core.config import get_settings
from app.core.dependencies import CurrentUser, get_current_active_user
from app.schemas.vault_export import MAX_CONFIRMATION_BYTES, decode_vault_confirmation
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_permission import consume_export_permission
from tests.security.test_vault_export_authority import credentials, mutate
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_operation_state import operations as operations


@pytest_asyncio.fixture
async def confirmation(operations):
    f = operations
    app = f.client._transport.app
    app.include_router(create_vault_confirmation_router(VaultConfirmationPolicy()), prefix="/owned/vault")

    @app.post("/owned/vault-consume")
    async def consume(request: Request, user: CurrentUser = Depends(get_current_active_user)):
        body = await request.json()
        command = decode_vault_confirmation(json.dumps({"intent": body["intent"]}).encode(), "oidc_start")
        authority = await VaultExportAuthority.capture(
            request, user, action="create" if command.intent.operation == "create" else "download",
            secret_key=get_settings().SECRET_KEY.encode("utf-8"),
        )
        permission = await consume_export_permission(authority, command.intent, body["proof"])
        f.token_hashes.add(hashlib.sha256(permission.verified.jti.encode()).hexdigest())
        return {"operation": permission.state.intent.operation, "actor": str(authority.actor_id)}

    yield f


def create_intent(f):
    return {"kind": "create", "backup": f.data}


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("operation", ["create", "download_recorded"])
async def test_actual_confirmation_proof_is_consumed_once_for_original_operation(confirmation, kind, operation):
    f = confirmation
    headers, _ = credentials(f, kind)
    intent = create_intent(f) if operation == "create" else {"kind": operation, "backup_id": str(f.backup)}
    response = await f.client.post("/owned/vault/authorize/local", headers=headers,
                                   json={"intent": intent, "password": f.password})
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"proof"}
    assert "no-store" in response.headers["cache-control"]
    assert f.password not in response.text and f.data["passphrase"] not in response.text
    consumed = await f.client.post("/owned/vault-consume", headers=headers,
                                   json={"intent": intent, "proof": response.json()["proof"]})
    assert consumed.status_code == 200, consumed.text
    assert consumed.json() == {"operation": operation, "actor": str(f.user)}
    again = await f.client.post("/owned/vault-consume", headers=headers,
                               json={"intent": intent, "proof": response.json()["proof"]})
    assert again.status_code == 401, again.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["actor", "organization", "one-header", "duplicate", "malformed"])
async def test_browser_initiating_identity_cannot_be_replaced(confirmation, kind, change):
    f = confirmation
    headers, _ = credentials(f, kind)
    headers = list(headers.items()) + [("X-FreeSDN-Vault-Actor", str(f.user)),
                                      ("X-FreeSDN-Vault-Organization", str(f.org))]
    if change == "actor":
        headers[-2] = (headers[-2][0], str(uuid4()))
    elif change == "organization":
        headers[-1] = (headers[-1][0], str(f.other_org))
    elif change == "one-header":
        headers.pop()
    elif change == "duplicate":
        headers.append(headers[-1])
    else:
        headers[-2] = (headers[-2][0], "invalid")
    response = await f.client.post("/owned/vault/authorize/local", headers=headers,
                                   json={"intent": create_intent(f), "password": f.password})
    assert response.status_code == (409 if change in {"actor", "organization"} else 400), response.text
    assert "proof" not in response.json()
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["password", "role", "organization", "version"])
async def test_state_change_after_authentication_during_body_read_refuses(confirmation, kind, change):
    f = confirmation
    headers, _ = credentials(f, kind)
    raw = json.dumps({"intent": create_intent(f), "password": f.password}).encode()
    values = {"password": {"hashed_password": "!DISABLED"}, "role": {"role": "viewer"},
              "organization": {"organization_id": f.other_org}, "version": {"token_version": 18}}

    async def body():
        # ASGI receive is reached only after the actual auth dependency and
        # initiating browser check. Commit a change before the remaining body.
        yield raw[:1]
        await mutate(f, values[change])
        yield raw[1:]

    response = await f.client.post("/owned/vault/authorize/local",
                                   headers={**headers, "Content-Type": "application/json"}, content=body())
    assert response.status_code in {401, 403}, response.text
    assert "proof" not in response.json()
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize("payload", [
    b'{"intent":{},"intent":{},"password":"secret"}',
    b'{"intent":{"kind":"download_recorded","backup_id":"invalid"},"password":"secret"}',
    b'{"intent":{"kind":"download_legacy","backup_id":"00000000-0000-4000-8000-000000000001","observation":{}},"password":"secret"}',
    b'{"intent":{"kind":"create","backup":{"name":"x","include_secrets":true,"passphrase":"long enough phrase","organization_id":"foreign"}},"password":"secret"}',
    b'{"intent":{"kind":"create","backup":{"name":"x","include_secrets":"true","passphrase":"long enough phrase"}},"password":"secret"}',
    b'{"intent":{"kind":"create","backup":{"name":"x","include_secrets":true,"passphrase":"long enough phrase"}},"password":"secret","authenticated_at":123}',
    b'{"intent":NaN,"password":"secret"}',
    b'{"intent":null,"password":"secret"}',
    b'[]', b'\xff', b' ' * (MAX_CONFIRMATION_BYTES + 1),
])
def test_malformed_confirmation_never_echoes_secret_or_accepts_authority(payload):
    with pytest.raises(ValueError) as caught:
        decode_vault_confirmation(payload, "local")
    assert str(caught.value) == "Invalid vault confirmation command"


@pytest.mark.parametrize("callback", ["http://ui.example/vault", "https://user@ui.example/vault",
                                      "https://ui.example/vault?next=elsewhere", "https://ui.example/#fragment",
                                      "https://ui.example\\@foreign.example/vault", "https://ui.example:0/vault"])
def test_callback_is_explicit_safe_server_policy(callback):
    with pytest.raises(ValueError, match="Explicit HTTPS vault callback required"):
        VaultConfirmationPolicy(callback)


@pytest.mark.parametrize("action,extra", [
    ("local", {"password": "Owned local confirmation"}),
    ("ldap", {"password": "Owned directory confirmation"}),
    ("oidc_start", {}), ("oidc_complete", {"state": "owned-state", "code": "owned-code"}),
    ("external", {"identity_token": "owned-identity", "mfa_code": "123456"}),
])
def test_well_formed_commands_preserve_intent_without_invoking_factors(action, extra):
    intent = {"kind": "download_recorded", "backup_id": "00000000-0000-4000-8000-000000000001"}
    command = decode_vault_confirmation(json.dumps({"intent": intent, **extra}).encode(), action)
    assert command.intent.operation == "download_recorded"
    assert str(command.intent.backup_id) == intent["backup_id"]
    assert "owned-identity" not in repr(command)


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_configuration_missing_and_wrong_password_fail_without_proof(confirmation, kind):
    f = confirmation
    headers, _ = credentials(f, kind)
    password = await f.client.post("/owned/vault/authorize/local", headers=headers,
                                   json={"intent": create_intent(f), "password": "Wrong owned password"})
    assert password.status_code == 401, password.text
    oidc = await f.client.post("/owned/vault/identity/oidc/start", headers=headers,
                               json={"intent": create_intent(f)})
    assert oidc.status_code == 503, oidc.text
    assert "proof" not in oidc.json() and "authorize_url" not in oidc.json()


async def test_missing_authentication_refuses_before_secret_body_receive(confirmation):
    f = confirmation
    received = []

    async def body():
        received.append(True)
        yield b'{"password":"Must not be read"}'

    response = await f.client.post("/owned/vault/authorize/local",
                                   headers={"Content-Type": "application/json"}, content=body())
    assert response.status_code == 401, response.text
    assert received == []
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("case,expected", [
    ("media", 415), ("duplicate-media", 415), ("encoding", 415), ("oversized-declaration", 413),
    ("oversized-body", 413), ("length-mismatch", 400), ("duplicate-length", 400),
    ("malformed-json", 422),
])
async def test_actual_http_body_bounds_redact_input(confirmation, kind, case, expected):
    f = confirmation
    headers, _ = credentials(f, kind)
    raw = json.dumps({"intent": create_intent(f), "password": f.password}).encode()
    headers = list(headers.items()) + [("Content-Type", "application/json")]
    if case == "media":
        headers[-1] = ("Content-Type", "text/plain")
    elif case == "duplicate-media":
        headers.append(("Content-Type", "text/plain"))
    elif case == "encoding":
        headers.append(("Content-Encoding", "gzip"))
    elif case == "oversized-declaration":
        headers.append(("Content-Length", str(MAX_CONFIRMATION_BYTES + 1)))
    elif case == "oversized-body":
        raw = b" " * (MAX_CONFIRMATION_BYTES + 1)
    elif case == "length-mismatch":
        headers.append(("Content-Length", "1"))
    elif case == "duplicate-length":
        headers.extend([("Content-Length", str(len(raw))), ("Content-Length", str(len(raw)))])
    else:
        raw = b'{"password":"Unclosed private input"'
    async def streamed():
        yield raw[:10]
        yield raw[10:]

    # No auto Content-Length for this case; exercise accumulated stream bytes.
    content = streamed() if case == "oversized-body" else raw
    response = await f.client.post("/owned/vault/authorize/local", headers=headers, content=content)
    assert response.status_code == expected, response.text
    assert f.password not in response.text and "Unclosed private input" not in response.text
    assert "no-store" in response.headers["cache-control"]
