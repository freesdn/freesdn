# SPDX-License-Identifier: AGPL-3.0-only
"""Auth-only key rotation must invalidate JWTs without stranding the vault."""

from datetime import timedelta
from unittest.mock import AsyncMock

import jwt
import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError
from starlette.requests import Request

from app.core import crypto, security, security_utils
from app.core.config import Settings, settings
from app.core.cookies import ACCESS_COOKIE
from app.core.middleware import RateLimitMiddleware

VAULT_KEY = "test-original-vault-key-which-must-not-change"
SIGNING_KEY = "test-independent-signing-key-for-recovery-123"


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", VAULT_KEY)
    monkeypatch.setattr(settings, "ENCRYPTION_SALT", "test-preserved-vault-salt")
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", "")
    monkeypatch.setattr(crypto, "_fernet", None)
    monkeypatch.setattr(security_utils, "_fernet_instance", None)
    monkeypatch.setattr(
        "app.core.token_blacklist.is_token_blacklisted", AsyncMock(return_value=False)
    )


def issue(kind):
    if kind == "refresh":
        return security.create_refresh_token("test-user", expires_delta=timedelta(days=30))
    return security.create_access_token("test-user", extra_claims={"type": kind})


@pytest.mark.parametrize("kind", ["access", "refresh", "password_reset", "ws_stream"])
async def test_rotation_rejects_old_key_without_legacy_verification_fallback(
    keys, monkeypatch, kind
):
    old = issue(kind)
    assert await security.decode_token(old) is not None
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", SIGNING_KEY)
    assert await security.decode_token(old) is None
    new = issue(kind)
    assert await security.decode_token(new) is not None
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(new, VAULT_KEY, algorithms=["HS256"], audience="freesdn-api")


def test_rotation_preserves_both_vault_key_derivations_after_process_restart(keys, monkeypatch):
    credential = crypto.encrypt_credential("test-device-password")
    config = crypto.encrypt_dict({"password": "test-controller-password"})
    field = security_utils.encrypt_field("test-mfa-or-webhook-secret")
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", SIGNING_KEY)
    # A fresh process has no cached Fernet objects to mask accidental derivation changes.
    crypto._fernet = None
    security_utils._fernet_instance = None
    assert crypto.decrypt_credential(credential) == "test-device-password"
    assert crypto.decrypt_dict(config) == {"password": "test-controller-password"}
    assert security_utils.decrypt_field(field) == "test-mfa-or-webhook-secret"


def test_rate_limit_identity_uses_current_signing_key(keys, monkeypatch):
    def subject(token):
        request = Request(
            {"type": "http", "headers": [(b"cookie", f"{ACCESS_COOKIE}={token}".encode())]}
        )
        return RateLimitMiddleware._verified_subject(request)

    old = issue("access")
    assert subject(old) == "test-user"
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", SIGNING_KEY)
    assert subject(old) is None
    assert subject(issue("access")) == "test-user"


async def test_mfa_route_rejects_old_signature_and_reaches_claim_check_with_new_key(
    keys, monkeypatch
):
    from app.api.v1.endpoints import auth
    from app.schemas.core import MfaLoginRequest

    monkeypatch.setattr(auth, "check_auth_rate_limit", AsyncMock())
    revoked = AsyncMock(return_value=True)
    monkeypatch.setattr("app.core.token_blacklist.is_token_blacklisted", revoked)

    def challenge():
        return security.create_access_token(
            "test-user", extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"}
        )

    old = challenge()
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", SIGNING_KEY)
    request = Request(
        {"type": "http", "headers": [], "path": "/api/v1/auth/login/mfa", "client": ("test", 1)}
    )
    with pytest.raises(HTTPException) as exc:
        await auth.login_mfa(
            request, Response(), MfaLoginRequest(mfa_token=old, code="123456"), None
        )
    assert exc.value.status_code == 401
    revoked.assert_not_awaited()
    with pytest.raises(HTTPException) as exc:
        await auth.login_mfa(
            request, Response(), MfaLoginRequest(mfa_token=challenge(), code="123456"), None
        )
    assert exc.value.status_code == 401
    revoked.assert_awaited_once()


@pytest.mark.parametrize(
    "key", ["short", " " * 64, "x" * 31, "x" * 32 + "\n", "CHANGE_ME_generate_a_random_signing_key"]
)
def test_explicit_invalid_signing_key_is_refused_even_in_development(key):
    with pytest.raises(ValidationError, match="JWT_SIGNING_KEY"):
        Settings(_env_file=None, JWT_SIGNING_KEY=key)


def test_env_selects_one_active_key_and_omission_preserves_legacy(monkeypatch):
    monkeypatch.delenv("JWT_SIGNING_KEY", raising=False)
    legacy = Settings(_env_file=None, SECRET_KEY=VAULT_KEY)
    assert legacy.jwt_signing_key == VAULT_KEY
    monkeypatch.setenv("JWT_SIGNING_KEY", SIGNING_KEY)
    rotated = Settings(_env_file=None, SECRET_KEY=VAULT_KEY)
    assert rotated.jwt_signing_key == SIGNING_KEY
    assert rotated.SECRET_KEY == VAULT_KEY
    assert SIGNING_KEY not in repr(rotated)
