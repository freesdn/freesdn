# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Malformed signed claims must be invalid authentication, not uncaught errors."""

import base64
import hmac
import json
import secrets
import time

import pytest
from starlette.requests import Request

from app.core import security
from app.core.config import settings
from app.core.dependencies import get_current_user_optional


@pytest.fixture
def signing_key(monkeypatch):
    key = secrets.token_urlsafe(48)
    monkeypatch.setattr(settings, "JWT_SIGNING_KEY", key)
    monkeypatch.setattr(settings, "ALGORITHM", "HS256")
    return key


def signed_claims(key, claims):
    # Construct the JWS directly so an encoder's input validation cannot hide
    # malformed JSON value types before the real application decoder sees them.
    def segment(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    body = segment(b'{"alg":"HS256","typ":"JWT"}') + b"." + segment(json.dumps(claims).encode())
    return (body + b"." + segment(hmac.digest(key.encode(), body, "sha256"))).decode()


def valid_claims():
    now = int(time.time())
    return {
        "sub": "synthetic-claim-boundary-user",
        "type": "access",
        "exp": now + 600,
        "iat": now - 1,
        "nbf": now - 1,
        "iss": "freesdn",
        "aud": "freesdn-api",
    }


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
@pytest.mark.parametrize("value", [None, [], {}, "not-a-number"], ids=["null", "list", "object", "text"])
async def test_malformed_time_claim_is_rejected_before_any_user_lookup(signing_key, claim, value):
    token = signed_claims(signing_key, {**valid_claims(), claim: value})
    assert await security.decode_token(token) is None
    assert await security.verify_token(token) is None
    request = Request({"type": "http", "headers": []})
    # This sentinel has no database methods. Invalid credentials must never
    # reach a database lookup, and API-key fallback is deliberately absent.
    assert await get_current_user_optional(request, token=token, api_key=None, session=object()) is None


@pytest.mark.parametrize("string_times", [False, True])
async def test_valid_time_claims_still_decode(signing_key, string_times):
    claims = valid_claims()
    if string_times:
        claims.update({name: str(claims[name]) for name in ("exp", "iat", "nbf")})
    payload = await security.verify_token(signed_claims(signing_key, claims))
    assert payload is not None and payload["sub"] == claims["sub"]


async def test_wrong_signature_is_rejected_even_with_valid_claims(signing_key):
    token = signed_claims(secrets.token_urlsafe(48), valid_claims())
    assert await security.decode_token(token) is None
