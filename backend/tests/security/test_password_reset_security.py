# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test password reset token security properties.

These are static source-level checks that guard against regressions in the
`reset_password` and `change_password` endpoints. The token_version ("tv")
claim mechanism only works if:

  1. `request_password_reset` mints the reset token bound to the user's
     current token_version.
  2. `reset_password` verifies `payload['tv'] == user.token_version` before
     mutating the password.
  3. `change_password` (and logout/password-reset themselves) bump
     `user.token_version` so that any prior reset links become stale.
"""

import re
from pathlib import Path

AUTH_FILE = (
    Path(__file__).resolve().parents[2]
    / "app"
    / "api"
    / "v1"
    / "endpoints"
    / "auth.py"
)


def _extract_function(source: str, name: str) -> str:
    """Return the body of `async def <name>` up to the next `async def` or EOF."""
    match = re.search(
        rf"async def {re.escape(name)}\b.*?(?=\nasync def |\Z)",
        source,
        re.DOTALL,
    )
    assert match, f"{name} function not found in auth.py"
    return match.group(0)


def test_request_password_reset_mints_with_token_version():
    """The reset token MUST be minted with the user's current token_version.

    Otherwise the tv claim defaults to 0 and the verification in
    reset_password becomes trivially bypassable for users whose
    token_version has never been bumped, or unusably broken for users
    whose has.
    """
    source = AUTH_FILE.read_text(encoding="utf-8")
    func_body = _extract_function(source, "request_password_reset")

    # Must pass token_version to create_access_token when minting the reset
    # token. We look for the call and a token_version kwarg appearing near it
    # (the call spans several lines and may contain nested parens, so a simple
    # [^)]* regex won't work).
    call_idx = func_body.find("create_access_token(")
    assert call_idx != -1, "request_password_reset must call create_access_token"
    # Scan a reasonable window after the call opener for the kwarg.
    window = func_body[call_idx : call_idx + 800]
    assert re.search(r"token_version\s*=", window), (
        "request_password_reset must pass token_version=user.token_version "
        "to create_access_token"
    )


def test_reset_password_checks_token_version():
    """reset_password must verify the token's tv claim matches user.token_version."""
    source = AUTH_FILE.read_text(encoding="utf-8")
    func_body = _extract_function(source, "reset_password")

    # Must compare payload tv to user token_version (in either order)
    assert re.search(
        r'(\btv\b.*token_version|token_version.*\btv\b)',
        func_body,
        re.DOTALL,
    ), (
        "reset_password must compare payload['tv'] to user.token_version "
        ""
    )

    # Must raise on mismatch (401)
    assert "401" in func_body or "HTTP_401_UNAUTHORIZED" in func_body, (
        "reset_password must return 401 when the tv claim does not match"
    )


def test_reset_password_bumps_token_version():
    """After a successful reset, token_version must be bumped to kill all
    other outstanding sessions (and prevent reset-token replay)."""
    source = AUTH_FILE.read_text(encoding="utf-8")
    func_body = _extract_function(source, "reset_password")
    assert "token_version" in func_body and "+ 1" in func_body, (
        "reset_password must bump user.token_version on success"
    )


def test_change_password_bumps_token_version():
    """change_password must increment user.token_version on success so
    that any previously-issued reset link is invalidated."""
    source = AUTH_FILE.read_text(encoding="utf-8")
    func_body = _extract_function(source, "change_password")
    assert "token_version" in func_body and "+ 1" in func_body, (
        "change_password must bump token_version on success"
    )
