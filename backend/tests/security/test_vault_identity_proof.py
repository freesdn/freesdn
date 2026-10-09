"""Signed intermediate-identity contracts, not IdP/MFA or SQL qualification."""

import hashlib
import hmac
import secrets
import time
from dataclasses import replace
from uuid import uuid4

import jwt
import pytest

from app.core import vault_identity_proof as module
from app.core.vault_export_proof import (
    InvalidVaultProof,
    VaultProofContext,
    create_export_proof,
    verify_export_proof,
)


@pytest.fixture
def identity():
    key = secrets.token_bytes(32)
    context = VaultProofContext(
        uuid4(), uuid4(), 17, "access_jti", str(uuid4()), "create", "a" * 64
    )
    return {
        "context": context,
        "request_binding": "b" * 64,
        "provider_id": uuid4(),
        "protocol": "oidc",
        "server_key": key,
    }


def issue(identity, *, age=0, remaining=300):
    now = int(time.time())
    return module.create_identity_confirmation(
        **identity, authenticated_at=now - age, flow_expires_at=now + remaining
    )


def claims(raw, identity):
    return jwt.decode(
        raw,
        hmac.digest(identity["server_key"], b"FreeSDN/vault-identity/v1", "sha256"),
        algorithms=["HS256"],
        audience="freesdn-vault-identity-confirmation",
        issuer="freesdn",
    )


def resign(body, identity, *, algorithm="HS256", key=None):
    return jwt.encode(
        body,
        key
        if key is not None
        else hmac.digest(
            identity["server_key"], b"FreeSDN/vault-identity/v1", "sha256"
        ),
        algorithm=algorithm,
    )


@pytest.mark.parametrize("protocol", ["oidc", "ldap"])
@pytest.mark.parametrize("kind", ["access_jti", "api_key_id"])
@pytest.mark.parametrize("action", ["create", "download"])
def test_exact_identity_operation_and_credential(identity, protocol, kind, action):
    identity["protocol"] = protocol
    identity["context"] = replace(
        identity["context"],
        credential_kind=kind,
        credential_id=str(uuid4()),
        action=action,
    )
    token = issue(identity)
    receipt = module.verify_identity_confirmation(token, **identity)
    body = claims(token, identity)
    assert receipt.jti == body["jti"] and receipt.authenticated_at == body["auth_time"]
    assert receipt.expires_at == body["exp"]
    assert body["binding"] == identity["request_binding"]
    assert body["provider"] == str(identity["provider_id"])
    assert body["protocol"] == protocol and body["action"] == action
    assert body["credential_kind"] == kind
    assert (
        module.verify_identity_confirmation(token, **identity) == receipt
    )  # caller must consume durably
    assert claims(issue(identity), identity)["jti"] != receipt.jti


@pytest.mark.parametrize(
    "field",
    [
        "user_id",
        "organization_id",
        "token_version",
        "credential_kind",
        "credential_id",
        "action",
        "authority_digest",
    ],
)
def test_changed_current_context_refused(identity, field):
    token = issue(identity)
    values = {
        "user_id": uuid4(),
        "organization_id": uuid4(),
        "token_version": 18,
        "credential_kind": "api_key_id",
        "credential_id": str(uuid4()),
        "action": "download",
        "authority_digest": "c" * 64,
    }
    identity["context"] = replace(identity["context"], **{field: values[field]})
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(token, **identity)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_binding", "c" * 64),
        ("provider_id", uuid4()),
        ("protocol", "ldap"),
        ("server_key", b"other-server-secret" * 3),
    ],
)
def test_changed_purpose_provider_or_key_refused(identity, field, value):
    token = issue(identity)
    identity[field] = value
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(token, **identity)


@pytest.mark.parametrize(
    "field,value",
    [
        ("iss", "other"),
        ("aud", "freesdn-vault-export"),
        ("aud", ["freesdn-vault-identity-confirmation"]),
        ("type", "access"),
        ("type", "vault_export"),
        ("jti", "access:fake"),
        ("jti", "vault-identity:"),
        ("jti", "vault-identity:" + str(uuid4()).upper()),
        ("jti", 123),
        ("tv", True),
        ("tv", "17"),
        ("iat", True),
        ("nbf", "123"),
        ("exp", 9999999999),
        ("auth_time", True),
        ("auth_time", "123"),
        ("auth_time", -1),
        ("auth_time", 0),
        ("auth_time", 9999999999),
        ("binding", None),
        ("provider", None),
        ("protocol", "saml"),
        ("credential_kind", "refresh"),
        ("action", "restore"),
        ("authority", "c" * 64),
    ],
)
def test_signed_malformed_or_wrong_claim_refused(identity, field, value):
    body = claims(issue(identity), identity)
    body[field] = value
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(resign(body, identity), **identity)


@pytest.mark.parametrize(
    "field",
    [
        "iss",
        "aud",
        "type",
        "iat",
        "nbf",
        "exp",
        "jti",
        "sub",
        "org",
        "tv",
        "credential_kind",
        "credential_id",
        "action",
        "authority",
        "binding",
        "provider",
        "protocol",
        "auth_time",
    ],
)
def test_missing_signed_claim_refused(identity, field):
    body = claims(issue(identity), identity)
    del body[field]
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(resign(body, identity), **identity)


@pytest.mark.parametrize(
    "change", ["extra", "expired", "future-issued", "future-not-before", "skewed-nbf"]
)
def test_exact_shape_and_wall_clock_refusals(identity, change):
    body = claims(issue(identity), identity)
    if change == "extra":
        body["extra"] = "unexpected"
    elif change == "expired":
        body.update(
            iat=int(time.time()) - 121,
            nbf=int(time.time()) - 121,
            auth_time=int(time.time()) - 121,
            exp=int(time.time()) - 1,
        )
    elif change == "future-issued":
        body.update(
            iat=int(time.time()) + 60,
            nbf=int(time.time()) + 60,
            exp=int(time.time()) + 120,
        )
    elif change == "future-not-before":
        body["nbf"] = int(time.time()) + 60
    else:
        body["nbf"] -= 1
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(resign(body, identity), **identity)


@pytest.mark.parametrize(
    "age,remaining,max_lifetime",
    [(0, 300, 120), (100, 300, 20), (0, 7, 7), (100, 4, 4)],
)
def test_freshness_never_renews_old_idp_or_flow(identity, age, remaining, max_lifetime):
    start = int(time.time())
    receipt = module.verify_identity_confirmation(
        issue(identity, age=age, remaining=remaining), **identity
    )
    assert receipt.authenticated_at <= start - age + 1
    assert receipt.expires_at <= start + max_lifetime + 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"authenticated_at": True, "flow_expires_at": 9999999999},
        {"authenticated_at": -1, "flow_expires_at": 9999999999},
        {"authenticated_at": 9999999999, "flow_expires_at": 9999999999},
        {"authenticated_at": 0, "flow_expires_at": 9999999999},
        {"authenticated_at": int(time.time()), "flow_expires_at": True},
        {"authenticated_at": int(time.time()), "flow_expires_at": 0},
    ],
)
def test_invalid_verifier_observations_cannot_issue(identity, kwargs):
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.create_identity_confirmation(**identity, **kwargs)


@pytest.mark.parametrize(
    "value", [None, b"bytes", "", "x" * 8193, "not.a.jwt", "a.b.c.d"]
)
def test_bounded_token_input(identity, value):
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(value, **identity)


@pytest.mark.parametrize(
    "field,value",
    [
        ("context", {}),
        ("request_binding", "a"),
        ("provider_id", "not-uuid"),
        ("protocol", "saml"),
        ("server_key", b"short"),
    ],
)
def test_bad_server_binding_refused(identity, field, value):
    identity[field] = value
    with pytest.raises(module.InvalidIdentityConfirmation):
        issue(identity)


def test_signatures_and_token_domains_do_not_interchange(identity):
    token = issue(identity)
    body = claims(token, identity)
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(
            resign(body, identity, key=secrets.token_bytes(32)), **identity
        )
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(
            resign(body, identity, algorithm="HS384"), **identity
        )
    with pytest.raises(InvalidVaultProof):
        verify_export_proof(
            token,
            identity["context"],
            binding=identity["request_binding"],
            verification_key=identity["server_key"],
            algorithm="HS256",
        )
    final = create_export_proof(
        identity["context"],
        binding=identity["request_binding"],
        signing_key=identity["server_key"],
        algorithm="HS256",
    )
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(final, **identity)
    ordinary = jwt.encode(
        {**body, "aud": "freesdn-api", "type": "access"},
        identity["server_key"],
        algorithm="HS256",
    )
    with pytest.raises(module.InvalidIdentityConfirmation):
        module.verify_identity_confirmation(ordinary, **identity)
    assert (
        hashlib.sha256(token.encode()).digest()
        != hashlib.sha256(final.encode()).digest()
    )
