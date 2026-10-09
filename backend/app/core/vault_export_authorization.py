"""Freshness-bounded export proof; private until full endpoint integration.

The signature proves only a server assertion. Issuers must authenticate the
existing account and all applicable factors first. Consumers must refresh
authority and the operation binding, durably consume the JTI, and check again
after waits/I/O. No archive access or durable consumption occurs here.
"""

from __future__ import annotations

import hmac
import re
import time
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from app.core.vault_export_proof import InvalidVaultProof, VaultProofContext

ExportOperation = Literal["create", "download_recorded", "observe_legacy", "download_legacy"]
_AUDIENCE = "freesdn-vault-export-v2"
_TYPE = "vault_export_authorization"
_TTL = 120
_OPERATIONS = {
    "create": "create",
    "download_recorded": "download",
    "observe_legacy": "download",
    "download_legacy": "download",
}
_FIELDS = {
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
    "operation",
    "auth_time",
    "auth_exp",
}
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def _invalid() -> InvalidVaultProof:
    return InvalidVaultProof("Fresh vault export authorization is invalid")


def _expected(context: VaultProofContext, binding: str, operation: str) -> dict[str, str | int]:
    if (
        type(context) is not VaultProofContext
        or type(binding) is not str
        or _DIGEST.fullmatch(binding) is None
        or type(operation) is not str
        or operation not in _OPERATIONS
        or _OPERATIONS[operation] != context.action
    ):
        raise _invalid()
    return {**context.claims(), "binding": binding, "operation": operation}


def _key(value: str | bytes, algorithm: str) -> bytes | RSAPrivateKey | RSAPublicKey:
    if type(algorithm) is not str or algorithm not in {"HS256", "RS256"}:
        raise _invalid()
    if type(value) is str:
        value = value.encode("utf-8")
    if type(value) is not bytes or not 32 <= len(value) <= 16384:
        raise _invalid()
    if algorithm == "RS256":
        prepared = RSAAlgorithm(RSAAlgorithm.SHA256).prepare_key(value)
        if not 2048 <= prepared.key_size <= 8192:
            raise _invalid()
        return prepared
    return value


def _times(claims: dict[str, Any]) -> None:
    now = time.time()
    if any(
        type(claims[name]) is not int
        for name in ("iat", "nbf", "exp", "tv", "auth_time", "auth_exp")
    ):
        raise _invalid()
    if (
        not 0 <= claims["iat"] == claims["nbf"] <= now < claims["exp"]
        or not 0 < claims["exp"] - claims["iat"] <= _TTL
        or not 0 <= claims["auth_time"] <= claims["iat"] + 5
        or claims["exp"] > claims["auth_exp"]
        or claims["auth_exp"] > claims["auth_time"] + _TTL
    ):
        raise _invalid()


@dataclass(frozen=True, repr=False)
class VerifiedExportAuthorization:
    """Signature/binding result only; not consumed permission to access data."""

    jti: str
    expires_at: int
    authenticated_at: int
    authentication_expires_at: int


def create_fresh_export_proof(
    context: VaultProofContext,
    *,
    binding: str,
    operation: ExportOperation,
    authenticated_at: int,
    authentication_expires_at: int,
    credential_expires_at: int | None,
    signing_key: str | bytes,
    algorithm: str,
) -> str:
    """Preserve original factor expiry; never backdate issuance or renew age.

    Expiry inputs must be copied from the server-verified factor/credential,
    never accepted from a client. ``None`` denotes a non-expiring API key,
    not permission to omit the ordinary initiating JWT expiry.
    """
    try:
        expected = _expected(context, binding, operation)
        if type(authenticated_at) is not int or type(authentication_expires_at) is not int:
            raise _invalid()
        if credential_expires_at is not None and (
            type(credential_expires_at) is not int or credential_expires_at < 0
        ):
            raise _invalid()
        if context.credential_kind == "access_jti" and credential_expires_at is None:
            raise _invalid()
        now = int(time.time())
        expiry = min(now + _TTL, authentication_expires_at)
        if credential_expires_at is not None:
            expiry = min(expiry, credential_expires_at)
        claims = {
            **expected,
            "iss": "freesdn",
            "aud": _AUDIENCE,
            "type": _TYPE,
            "iat": now,
            "nbf": now,
            "exp": expiry,
            "jti": "vault-export-v2:" + str(uuid4()),
            "auth_time": authenticated_at,
            "auth_exp": authentication_expires_at,
        }
        _times(claims)
        key = _key(signing_key, algorithm)
        if isinstance(key, RSAPublicKey):
            raise _invalid()
        result = jwt.encode(claims, key, algorithm=algorithm)
        # RSA preparation/signing may take time. Expiry applies at return too.
        _times(claims)
        return result
    except Exception:
        raise _invalid() from None


def verify_fresh_export_proof(
    token: str,
    context: VaultProofContext,
    *,
    binding: str,
    operation: ExportOperation,
    verification_key: str | bytes,
    algorithm: str,
) -> VerifiedExportAuthorization:
    try:
        if type(token) is not str or not 1 <= len(token) <= 8192:
            raise _invalid()
        expected = _expected(context, binding, operation)
        key = _key(verification_key, algorithm)
        if isinstance(key, RSAPrivateKey):
            raise _invalid()
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            audience=_AUDIENCE,
            issuer="freesdn",
            options={"require": sorted(_FIELDS), "strict_aud": True},
        )
        if set(claims) != _FIELDS or claims["type"] != _TYPE:
            raise _invalid()
        _times(claims)
        for name, value in expected.items():
            if type(claims[name]) is not type(value):
                raise _invalid()
            if type(value) is str:
                if not hmac.compare_digest(claims[name].encode(), value.encode()):
                    raise _invalid()
            elif claims[name] != value:
                raise _invalid()
        jti = claims["jti"]
        if type(jti) is not str or not jti.startswith("vault-export-v2:"):
            raise _invalid()
        suffix = jti.removeprefix("vault-export-v2:")
        if str(UUID(suffix)) != suffix:
            raise _invalid()
        return VerifiedExportAuthorization(
            jti, claims["exp"], claims["auth_time"], claims["auth_exp"]
        )
    except Exception:
        raise _invalid() from None
