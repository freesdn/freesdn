"""Private vault-export proof component; not wired into application endpoints.

Cryptographic binding is NOT account authentication or authorization. A caller
must first validate recent factors, refresh authority after waits, and durably
claim the returned JTI before reading secrets or storage. Those integrations
are deliberately not represented as complete by this component.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import jwt
from jwt.exceptions import PyJWTError

PROOF_AUDIENCE = "freesdn-vault-export"
PROOF_ISSUER = "freesdn"
PROOF_TYPE = "vault_export"
PROOF_TTL_SECONDS = 120
MAX_BINDING_BYTES = 131_072
MAX_TOKEN_BYTES = 8_192
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CLAIMS = frozenset(
    {
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
    }
)


class InvalidVaultProof(ValueError):
    """A deliberately constant error; never include proof or secret inputs."""


def _invalid() -> InvalidVaultProof:
    return InvalidVaultProof("Vault authorization proof is invalid")


def _is_digest(value: object) -> bool:
    return type(value) is str and _HEX_DIGEST.fullmatch(value) is not None


def _canonical_json(value: dict[str, Any]) -> bytes:
    """Bound normalized, already schema-validated JSON without coercion.

    No float/NaN, arbitrary object serialization, repr(), or default=str(). The
    caller supplies the complete validated request, not a hand-selected subset.
    """
    nodes = 0
    estimated_bytes = 0

    def check(item: object, depth: int) -> None:
        nonlocal nodes, estimated_bytes
        nodes += 1
        estimated_bytes += 8
        if nodes > 5_000 or depth > 8:
            raise _invalid()
        if estimated_bytes > MAX_BINDING_BYTES:
            raise _invalid()
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise _invalid()
            return
        if type(item) is str:
            if len(item) > 8_192:
                raise _invalid()
            try:
                estimated_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                raise _invalid() from None
            if estimated_bytes > MAX_BINDING_BYTES:
                raise _invalid()
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or len(key) > 128:
                    raise _invalid()
                try:
                    estimated_bytes += len(key.encode("utf-8"))
                except UnicodeError:
                    raise _invalid() from None
                check(child, depth + 1)
            return
        raise _invalid()

    if type(value) is not dict:
        raise _invalid()
    check(value, 0)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise _invalid() from None
    if len(encoded) > MAX_BINDING_BYTES:
        raise _invalid()
    return encoded


def bind_export_value(value: dict[str, Any], *, key: bytes, domain: str) -> str:
    """Server-keyed commitment; a visible JWT must not enable phrase guessing.

    Domain separation prevents using an account-state commitment as a request
    or artifact commitment. Key material must be a server secret, never a public
    verification key or the archive passphrase. Key storage/rotation is a caller
    integration requirement. Raw values and key material are never returned.
    """
    if type(key) is not bytes or len(key) < 32:
        raise _invalid()
    if type(domain) is not str or domain not in {"request", "authority", "artifact"}:
        raise _invalid()
    body = _canonical_json(value)
    prefix = b"FreeSDN/vault-export/v1/" + domain.encode("ascii") + b"\x00"
    return hmac.new(key, prefix + body, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VaultProofContext:
    user_id: UUID
    organization_id: UUID
    token_version: int
    credential_kind: str
    credential_id: str
    action: str
    authority_digest: str

    def __post_init__(self) -> None:
        if type(self.user_id) is not UUID or type(self.organization_id) is not UUID:
            raise _invalid()
        if type(self.token_version) is not int or not 0 <= self.token_version <= 2**31 - 1:
            raise _invalid()
        if type(self.credential_kind) is not str or self.credential_kind not in {
            "access_jti",
            "api_key_id",
        }:
            raise _invalid()
        if type(self.credential_id) is not str or not 1 <= len(self.credential_id) <= 1_024:
            raise _invalid()
        if self.credential_kind == "api_key_id":
            try:
                if str(UUID(self.credential_id)) != self.credential_id:
                    raise _invalid()
            except (ValueError, TypeError, AttributeError):
                raise _invalid() from None
        if (
            type(self.action) is not str
            or self.action not in {"create", "download"}
            or not _is_digest(self.authority_digest)
        ):
            raise _invalid()

    def claims(self) -> dict[str, str | int]:
        return {
            "sub": str(self.user_id),
            "org": str(self.organization_id),
            "tv": self.token_version,
            "credential_kind": self.credential_kind,
            "credential_id": self.credential_id,
            "action": self.action,
            "authority": self.authority_digest,
        }


@dataclass(frozen=True)
class VerifiedVaultProof:
    """Only a signature/context check; durable consumption is still required."""

    jti: str
    expires_at: int


def create_export_proof(
    context: VaultProofContext,
    *,
    binding: str,
    signing_key: str | bytes,
    algorithm: str,
) -> str:
    if type(context) is not VaultProofContext or not _is_digest(binding):
        raise _invalid()
    if type(algorithm) is not str or algorithm not in {"HS256", "RS256"}:
        raise _invalid()
    now = int(time.time())
    claims = {
        **context.claims(),
        "iss": PROOF_ISSUER,
        "aud": PROOF_AUDIENCE,
        "type": PROOF_TYPE,
        "iat": now,
        "nbf": now,
        "exp": now + PROOF_TTL_SECONDS,
        "jti": "vault-export:" + str(uuid4()),
        "binding": binding,
    }
    try:
        return jwt.encode(claims, signing_key, algorithm=algorithm)
    except (PyJWTError, TypeError, ValueError):
        raise _invalid() from None


def verify_export_proof(
    token: str,
    context: VaultProofContext,
    *,
    binding: str,
    verification_key: str | bytes,
    algorithm: str,
) -> VerifiedVaultProof:
    if type(token) is not str or not 1 <= len(token) <= MAX_TOKEN_BYTES:
        raise _invalid()
    if type(context) is not VaultProofContext or not _is_digest(binding):
        raise _invalid()
    if type(algorithm) is not str or algorithm not in {"HS256", "RS256"}:
        raise _invalid()
    try:
        claims = jwt.decode(
            token,
            verification_key,
            algorithms=[algorithm],
            audience=PROOF_AUDIENCE,
            issuer=PROOF_ISSUER,
            options={"require": sorted(_CLAIMS), "strict_aud": True},
        )
        now = int(time.time())
        if set(claims) != _CLAIMS or claims["type"] != PROOF_TYPE:
            raise _invalid()
        if any(type(claims[name]) is not int for name in ("iat", "nbf", "exp", "tv")):
            raise _invalid()
        if not (0 <= claims["iat"] == claims["nbf"] <= now < claims["exp"]):
            raise _invalid()
        if claims["exp"] - claims["iat"] != PROOF_TTL_SECONDS:
            raise _invalid()
        if any(claims[name] != value for name, value in context.claims().items()):
            raise _invalid()
        if not _is_digest(claims["binding"]) or not hmac.compare_digest(claims["binding"], binding):
            raise _invalid()
        jti = claims["jti"]
        if type(jti) is not str or not jti.startswith("vault-export:"):
            raise _invalid()
        suffix = jti.removeprefix("vault-export:")
        if str(UUID(suffix)) != suffix:
            raise _invalid()
        return VerifiedVaultProof(jti=jti, expires_at=claims["exp"])
    except (PyJWTError, ValueError, TypeError, KeyError, OverflowError):
        raise _invalid() from None
