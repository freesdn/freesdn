# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fresh OIDC identity verification for a purpose-bound vault operation.

This private integration component does not authorize archive access. The caller
must capture a current, existing account/provider/credential binding, supply a
real current-authority checkpoint, and verify any required local second factor.
The returned receipt is not a bearer credential. No JIT, userinfo enrichment,
ordinary SSO session or login token is created here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import time
from collections.abc import Awaitable, Buffer, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid4

import anyio
import jwt

from app.core.security_utils import safe_http_request
from app.core.vault_export_proof import VaultProofContext, bind_export_value

_STATE_AUDIENCE = "freesdn-vault-oidc-reauthentication"
_STATE_TYPE = "vault_oidc_reauthentication"
_FLOW_SECONDS = 300
_FRESH_SECONDS = 120
_CLOCK_SKEW_SECONDS = 5
_DOCUMENT_BYTES = 262_144
_ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_STATE_FIELDS = {"iss", "aud", "type", "iat", "nbf", "exp", "jti", "binding"}
_ERROR = "Fresh identity confirmation failed; start a new confirmation"


class OIDCConfirmationError(ValueError):
    """Safe fixed error: never expose provider bodies, codes or token claims."""


def _refuse() -> OIDCConfirmationError:
    return OIDCConfirmationError(_ERROR)


def _text(value: Any, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise _refuse()
    return value


def _https_url(value: object, *, query: bool = True) -> str:
    value = _text(value, 4096)
    try:
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or "\\" in value
            or (not query and parts.query)
            or parts.port == 0
        ):
            raise _refuse()
    except ValueError:
        raise _refuse() from None
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@dataclass(frozen=True, repr=False)
class OIDCExportBinding:
    """Copied server inputs, never a user-submitted provider configuration.

    ``provider_digest`` must cover the complete current security configuration;
    ``context`` binds account, organization, initiating credential and action.
    Reconstruct and compare these inputs after database waits in the caller.
    """

    context: VaultProofContext
    request_binding: str
    provider_id: UUID
    provider_digest: str
    issuer: str
    discovery_url: str
    client_id: str
    client_secret: str = field(repr=False)
    subject: str = field(repr=False)
    redirect_uri: str
    allowed_redirect_uris: tuple[str, ...]
    client_auth_method: str = "client_secret_post"

    def __post_init__(self) -> None:
        if type(self.context) is not VaultProofContext or type(self.provider_id) is not UUID:
            raise _refuse()
        for value in (self.request_binding, self.provider_digest):
            if type(value) is not str or not _HEX.fullmatch(value):
                raise _refuse()
        _https_url(self.issuer, query=False)
        _https_url(self.discovery_url)
        _https_url(self.redirect_uri)
        _text(self.client_id, 255)
        if self.client_auth_method not in {"client_secret_post", "client_secret_basic", "none"}:
            raise _refuse()
        if self.client_auth_method == "none":
            if self.client_secret != "":
                raise _refuse()
        else:
            _text(self.client_secret, 8192)
        _text(self.subject, 512)
        if (
            type(self.allowed_redirect_uris) is not tuple
            or self.redirect_uri not in self.allowed_redirect_uris
        ):
            raise _refuse()

    def commitment(self, key: bytes) -> str:
        return bind_export_value(
            {
                "stage": "oidc-reauthentication",
                "context": self.context.claims(),
                "request": self.request_binding,
                "provider_id": str(self.provider_id),
                "provider": self.provider_digest,
                "issuer": self.issuer,
                "discovery": self.discovery_url,
                "client": self.client_id,
                "secret": self.client_secret,
                "client_auth_method": self.client_auth_method,
                "subject": self.subject,
                "redirect": self.redirect_uri,
                "allowlist": list(self.allowed_redirect_uris),
            },
            key=key,
            domain="authority",
        )


@dataclass(frozen=True, repr=False)
class OIDCConfirmationStart:
    authorize_url: str
    state: str
    expires_at: int


@dataclass(frozen=True, repr=False)
class OIDCConfirmationReceipt:
    """Internal result only; not sufficient for a vault proof or download."""

    provider_id: UUID
    authenticated_at: int
    completed_at: int
    flow_expires_at: int
    request_binding: str


class _BoundedDocument(io.BytesIO):
    def write(self, value: Buffer) -> int:
        if self.tell() + memoryview(value).nbytes > _DOCUMENT_BYTES:
            raise _refuse()
        return super().write(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _refuse()
        result[key] = value
    return result


async def _durable_claim(jti: str, expiry: int) -> bool:
    # Independent committing transaction; never commit the caller's session.
    from app.core.token_blacklist import claim_token_jti

    return await claim_token_jti(jti, expiry)


class VaultOIDCReauthentication:
    """Own one bounded exchange; checkpoints cannot be omitted by the caller.

    The injected interfaces make transport and genuine database waits testable.
    A mocked checkpoint or claim is not production authority or replay evidence.
    Server key material must be independently secret even when login uses RSA.
    """

    def __init__(
        self,
        *,
        binding: OIDCExportBinding,
        server_key: bytes,
        check_current: Callable[[], Awaitable[None]],
        request_http: Callable[..., Awaitable[Any]] = safe_http_request,
        claim: Callable[[str, int], Awaitable[bool]] = _durable_claim,
    ) -> None:
        if type(server_key) is not bytes or len(server_key) < 32 or not callable(check_current):
            raise _refuse()
        self.binding = binding
        self._key = hmac.digest(server_key, b"FreeSDN/vault-oidc/v1", "sha256")
        self._check_current = check_current
        self._http = request_http
        self._claim = claim

    def _derived(self, jti: str, purpose: str) -> str:
        return _b64(hmac.digest(self._key, (purpose + "\x00" + jti).encode(), "sha256"))

    def _state(self, raw: str) -> dict[str, Any]:
        _text(raw, 8192)
        try:
            claims = jwt.decode(
                raw,
                self._key,
                algorithms=["HS256"],
                audience=_STATE_AUDIENCE,
                issuer="freesdn",
                options={"require": sorted(_STATE_FIELDS), "strict_aud": True},
            )
            if set(claims) != _STATE_FIELDS or claims["type"] != _STATE_TYPE:
                raise _refuse()
            if any(type(claims[k]) is not int for k in ("iat", "nbf", "exp")):
                raise _refuse()
            if not (0 <= claims["iat"] == claims["nbf"] <= time.time() < claims["exp"]):
                raise _refuse()
            if claims["exp"] - claims["iat"] != _FLOW_SECONDS:
                raise _refuse()
            identifier = _text(claims["jti"], 100)
            prefix = "vault-oidc:"
            if (
                not identifier.startswith(prefix)
                or str(UUID(identifier[len(prefix) :])) != identifier[len(prefix) :]
            ):
                raise _refuse()
            if type(claims["binding"]) is not str or not hmac.compare_digest(
                claims["binding"], self.binding.commitment(self._key)
            ):
                raise _refuse()
            return claims
        except Exception:
            raise _refuse() from None

    async def _json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        _https_url(url)
        hosts = frozenset(
            {urlsplit(self.binding.issuer).hostname, urlsplit(self.binding.discovery_url).hostname}
        )
        with _BoundedDocument() as body:
            response = await self._http(
                method,
                url,
                timeout=10.0,
                allowed_schemes=frozenset({"https"}),
                verify_tls=True,
                follow_redirects=False,
                allow_hosts=hosts,
                download_to=body,
                max_response_bytes=_DOCUMENT_BYTES,
                **kwargs,
            )
            if response.status_code != 200:
                raise _refuse()
            data = json.loads(
                body.getvalue(),
                object_pairs_hook=_unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(_refuse()),
            )
        if type(data) is not dict:
            raise _refuse()
        return data

    async def _discovery(self) -> dict[str, Any]:
        document = await self._json("GET", self.binding.discovery_url)
        if document.get("issuer") != self.binding.issuer:
            raise _refuse()
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            _https_url(document.get(name))
        # OIDC Discovery specifies Basic when this optional field is absent.
        methods = document.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
        if (
            type(methods) is not list
            or not methods
            or len(methods) > 32
            or any(type(method) is not str for method in methods)
            or self.binding.client_auth_method not in methods
        ):
            raise _refuse()
        return document

    async def begin(self) -> OIDCConfirmationStart:
        try:
            await self._check_current()
            with anyio.fail_after(30):
                document = await self._discovery()
            await self._check_current()
            now = int(time.time())
            jti = "vault-oidc:" + str(uuid4())
            claims = {
                "iss": "freesdn",
                "aud": _STATE_AUDIENCE,
                "type": _STATE_TYPE,
                "iat": now,
                "nbf": now,
                "exp": now + _FLOW_SECONDS,
                "jti": jti,
                "binding": self.binding.commitment(self._key),
            }
            state = jwt.encode(claims, self._key, algorithm="HS256")
            verifier = self._derived(jti, "pkce")
            params = {
                "client_id": self.binding.client_id,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": self.binding.redirect_uri,
                "state": state,
                "nonce": self._derived(jti, "nonce"),
                "max_age": "0",
                "prompt": "login",
                "code_challenge_method": "S256",
                "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
            }
            parts = urlsplit(document["authorization_endpoint"])
            existing = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
            if any(key in params for key, _ in existing):
                raise _refuse()
            url = urlunsplit(parts._replace(query=urlencode(existing + list(params.items()))))
            return OIDCConfirmationStart(url, state, now + _FLOW_SECONDS)
        except Exception:
            raise _refuse() from None

    def _verify_id_token(
        self, token: object, keys: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any]:
        token = _text(token, 32768)
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        kid = _text(header.get("kid"), 255)
        if algorithm not in _ALLOWED_ALGORITHMS or header.get("crit"):
            raise _refuse()
        jwks = keys.get("keys")
        if type(jwks) is not list or not 1 <= len(jwks) <= 32:
            raise _refuse()
        matching = [key for key in jwks if type(key) is dict and key.get("kid") == kid]
        if len(matching) != 1:
            raise _refuse()
        key = matching[0]
        if (
            key.get("use", "sig") != "sig"
            or key.get("alg", algorithm) != algorithm
            or ("key_ops" in key and key["key_ops"] != ["verify"])
        ):
            raise _refuse()
        parsed = jwt.PyJWK.from_dict(key, algorithm=algorithm)
        if algorithm.startswith("RS") and parsed.key.key_size < 2048:
            raise _refuse()
        claims = jwt.decode(
            token,
            parsed.key,
            algorithms=[algorithm],
            audience=self.binding.client_id,
            issuer=self.binding.issuer,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce", "auth_time"]},
        )
        audience = claims["aud"]
        if type(audience) is list and (
            not audience
            or len(audience) != len(set(audience))
            or any(type(a) is not str for a in audience)
        ):
            raise _refuse()
        if ((type(audience) is list and len(audience) > 1) or "azp" in claims) and claims.get(
            "azp"
        ) != self.binding.client_id:
            raise _refuse()
        if claims["sub"] != self.binding.subject or claims["nonce"] != self._derived(
            state["jti"], "nonce"
        ):
            raise _refuse()
        self._fresh(claims, state)
        return claims

    @staticmethod
    def _fresh(claims: dict[str, Any], state: dict[str, Any]) -> None:
        now = time.time()
        if any(type(claims[k]) is not int for k in ("iat", "exp", "auth_time")):
            raise _refuse()
        authenticated = claims["auth_time"]
        if (
            now >= state["exp"]
            or now >= claims["exp"]
            or claims["iat"] > now
            or claims["exp"] <= claims["iat"]
            or authenticated > claims["iat"] + _CLOCK_SKEW_SECONDS
            or not state["iat"] - _CLOCK_SKEW_SECONDS <= authenticated <= now + _CLOCK_SKEW_SECONDS
            or now - authenticated > _FRESH_SECONDS
        ):
            raise _refuse()

    async def complete(self, *, state: str, code: str) -> OIDCConfirmationReceipt:
        try:
            flow = self._state(state)
            _text(code, 8192)
            await self._check_current()
            self._state(state)
            # Consume before the first exchange. Failure/lost response does not
            # permit another exchange using this challenge, even after rollback.
            if not await self._claim(flow["jti"], flow["exp"]):
                raise _refuse()
            self._state(state)
            await self._check_current()
            self._state(state)
            with anyio.fail_after(30):
                document = await self._discovery()
                data = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self.binding.client_id,
                    "redirect_uri": self.binding.redirect_uri,
                    "code_verifier": self._derived(flow["jti"], "pkce"),
                }
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if self.binding.client_auth_method == "client_secret_post":
                    data["client_secret"] = self.binding.client_secret
                elif self.binding.client_auth_method == "client_secret_basic":
                    # RFC6749 encodes both values before joining with a colon.
                    pair = (
                        quote_plus(self.binding.client_id, safe="")
                        + ":"
                        + quote_plus(self.binding.client_secret, safe="")
                    )
                    headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
                tokens = await self._json(
                    "POST",
                    document["token_endpoint"],
                    data=data,
                    headers=headers,
                )
                keys = await self._json("GET", document["jwks_uri"])
                claims = self._verify_id_token(tokens.get("id_token"), keys, flow)
            await self._check_current()
            # Both the flow and signed authentication freshness must survive the
            # entire exchange AND the final current-authority read/close wait.
            self._state(state)
            self._fresh(claims, flow)
            return OIDCConfirmationReceipt(
                self.binding.provider_id,
                claims["auth_time"],
                int(time.time()),
                flow["exp"],
                self.binding.request_binding,
            )
        except Exception:
            raise _refuse() from None
