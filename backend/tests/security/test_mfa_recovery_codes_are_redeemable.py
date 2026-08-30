# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A recovery code the system issues must be a code the system accepts.

``POST /auth/mfa/setup`` mints ten recovery codes as
``secrets.token_hex(5).upper()`` (auth.py:1832) -- TEN hex characters -- and
stores their hashes. ``MfaLoginRequest.code`` was ``Field(min_length=6,
max_length=8)`` with the comment "8 for backup".

So every recovery code this system has ever issued was rejected by request
validation with a 422, before any verification ran. The one mechanism that gets
an operator back in after losing their authenticator could not be redeemed at
all -- and the failure looks like a wrong code, not a broken endpoint.

The mint and the stored hashes agreed with each other; only the input schema
disagreed with both, which is why nothing else caught it.
"""

from __future__ import annotations

import secrets

import pytest
from pydantic import ValidationError

from app.schemas.core import MfaLoginRequest

_TOKEN = "t" * 40


def _mint() -> str:
    """Exactly what /auth/mfa/setup does."""
    return secrets.token_hex(5).upper()


def test_a_minted_recovery_code_passes_request_validation() -> None:
    """The core regression. Fails before the fix with a ValidationError."""
    code = _mint()
    assert len(code) == 10, f"the mint changed shape: {code!r}"
    MfaLoginRequest(mfa_token=_TOKEN, code=code)


def test_the_schema_bound_matches_what_the_mint_produces() -> None:
    """Pin the two together so a change to either fails here.

    A shorter mint would still pass the test above; this catches drift in the
    other direction too.
    """
    bound = MfaLoginRequest.model_fields["code"].metadata
    max_len = next((m.max_length for m in bound if hasattr(m, "max_length")), None)
    assert max_len == len(_mint()), (
        f"MfaLoginRequest.code caps at {max_len} but /auth/mfa/setup mints "
        f"{len(_mint())}-character codes. Every issued recovery code would be "
        "rejected by validation before verification runs."
    )


def test_a_totp_digit_code_is_still_accepted() -> None:
    """Widening the bound must not break the ordinary path."""
    MfaLoginRequest(mfa_token=_TOKEN, code="123456")


def test_an_over_long_code_is_still_rejected() -> None:
    """The bound must still bound something."""
    with pytest.raises(ValidationError):
        MfaLoginRequest(mfa_token=_TOKEN, code="A" * 11)
