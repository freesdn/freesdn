# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Short-lived fresh IdP confirmation for the separate local-MFA step.

This is not general authentication or an export proof. The server issues it
only after the existing-account OIDC/LDAP verifier succeeds. Redemption needs
current authority, durable one-time consumption and applicable local MFA.
"""

from __future__ import annotations

import hmac
import re
import time
from dataclasses import dataclass
from uuid import UUID, uuid4

import jwt

from app.core.vault_export_proof import VaultProofContext

_AUDIENCE = "freesdn-vault-identity-confirmation"
_TYPE = "vault_identity_confirmation"
_TTL = 120
_HEX = re.compile(r"[a-f0-9]{64}\Z")
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
    "provider",
    "protocol",
    "auth_time",
}
_ERROR = "Fresh identity confirmation is invalid; start a new confirmation"


class InvalidIdentityConfirmation(ValueError):
    """Fixed error without credentials, signed claims or provider diagnostics."""


def _refuse() -> InvalidIdentityConfirmation:
    return InvalidIdentityConfirmation(_ERROR)


def _key(server_key: bytes) -> bytes:
    if type(server_key) is not bytes or len(server_key) < 32:
        raise _refuse()
    return hmac.digest(server_key, b"FreeSDN/vault-identity/v1", "sha256")


def _binding(
    context: VaultProofContext, request_binding: str, provider_id: UUID, protocol: str
) -> dict[str, str | int]:
    if (
        type(context) is not VaultProofContext
        or type(request_binding) is not str
        or not _HEX.fullmatch(request_binding)
        or type(provider_id) is not UUID
        or type(protocol) is not str
        or protocol not in {"oidc", "ldap"}
    ):
        raise _refuse()
    return {
        **context.claims(),
        "binding": request_binding,
        "provider": str(provider_id),
        "protocol": protocol,
    }


@dataclass(frozen=True, repr=False)
class VerifiedIdentityConfirmation:
    """Verified signature and purpose only; consumption/MFA remain required."""

    jti: str
    authenticated_at: int
    expires_at: int


def create_identity_confirmation(
    context: VaultProofContext,
    *,
    request_binding: str,
    provider_id: UUID,
    protocol: str,
    authenticated_at: int,
    flow_expires_at: int,
    server_key: bytes,
) -> str:
    try:
        binding = _binding(context, request_binding, provider_id, protocol)
        now = int(time.time())
        if (
            type(authenticated_at) is not int
            or type(flow_expires_at) is not int
            or not 0 <= authenticated_at <= now + 5
        ):
            raise _refuse()
        expiry = min(now + _TTL, authenticated_at + _TTL, flow_expires_at)
        if expiry <= time.time():
            raise _refuse()
        return jwt.encode(
            {
                **binding,
                "iss": "freesdn",
                "aud": _AUDIENCE,
                "type": _TYPE,
                "iat": now,
                "nbf": now,
                "exp": expiry,
                "jti": "vault-identity:" + str(uuid4()),
                "auth_time": authenticated_at,
            },
            _key(server_key),
            algorithm="HS256",
        )
    except Exception:
        raise _refuse() from None


def verify_identity_confirmation(
    token: str,
    context: VaultProofContext,
    *,
    request_binding: str,
    provider_id: UUID,
    protocol: str,
    server_key: bytes,
) -> VerifiedIdentityConfirmation:
    try:
        if type(token) is not str or not 1 <= len(token) <= 8192:
            raise _refuse()
        expected = _binding(context, request_binding, provider_id, protocol)
        claims = jwt.decode(
            token,
            _key(server_key),
            algorithms=["HS256"],
            audience=_AUDIENCE,
            issuer="freesdn",
            options={"require": sorted(_FIELDS), "strict_aud": True},
        )
        if set(claims) != _FIELDS or claims["type"] != _TYPE:
            raise _refuse()
        if any(type(claims[k]) is not int for k in ("iat", "nbf", "exp", "auth_time", "tv")):
            raise _refuse()
        for name, value in expected.items():
            if type(claims[name]) is not type(value) or claims[name] != value:
                raise _refuse()
        if (
            claims["nbf"] != claims["iat"]
            or not 0 <= claims["auth_time"] <= claims["iat"] + 5
            or not 0 <= claims["iat"] <= time.time() < claims["exp"]
            or not claims["iat"] < claims["exp"] <= claims["iat"] + _TTL
            or claims["exp"] > claims["auth_time"] + _TTL
            or type(claims["jti"]) is not str
            or not claims["jti"].startswith("vault-identity:")
            or str(UUID(claims["jti"][15:])) != claims["jti"][15:]
        ):
            raise _refuse()
        return VerifiedIdentityConfirmation(claims["jti"], claims["auth_time"], claims["exp"])
    except Exception:
        raise _refuse() from None
