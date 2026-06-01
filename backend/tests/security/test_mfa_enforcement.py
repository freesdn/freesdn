# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test MFA enforcement across all authentication endpoints.

the OAuth2-compatible POST /auth/token endpoint previously
omitted the MFA check that /auth/login applies, letting an attacker who
already knew a password walk past MFA with a single form-encoded POST.
These tests are source-level guards: they fail if a future edit ever
removes the MFA gate from either endpoint.
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


def _function_body(source: str, pattern: str) -> str:
    """Extract an async function body by regex from source text."""
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"function matching {pattern!r} not found in auth.py"
    return match.group(0)


def test_token_endpoint_blocks_mfa_users() -> None:
    """POST /auth/token must not mint access tokens for MFA-enabled users."""
    source = AUTH_FILE.read_text(encoding="utf-8")

    func_body = _function_body(
        source,
        r"async def login_for_access_token.*?(?=\nasync def|\n@router|\Z)",
    )

    assert "mfa_enabled" in func_body, (
        "login_for_access_token must check user.mfa_enabled — CRITICAL"
    )

    # The gate must precede the token-mint call, otherwise an
    # MFA-enabled user would already have been issued a bearer token.
    # Per-device sessions route mint via the new
    # ``_create_access_with_jti`` helper that internally calls
    # ``create_access_token``; accept either name so the test isn't
    # brittle against future refactors.
    mfa_pos = func_body.find("mfa_enabled")
    token_pos = func_body.find("create_access_token")
    if token_pos == -1:
        token_pos = func_body.find("_create_access_with_jti")
    assert mfa_pos != -1 and token_pos != -1, (
        "expected to find both mfa_enabled gate and a token-mint call"
    )
    assert mfa_pos < token_pos, (
        "MFA gate in login_for_access_token must run BEFORE token mint"
    )


def test_login_endpoint_blocks_mfa_users() -> None:
    """POST /auth/login must gate MFA-enabled users."""
    source = AUTH_FILE.read_text(encoding="utf-8")

    func_body = _function_body(
        source,
        r"async def login\s*\(.*?(?=\nasync def|\n@router|\Z)",
    )

    assert "mfa_enabled" in func_body, "/auth/login must check user.mfa_enabled"
    # /login returns an mfa_pending token instead of a full access token
    assert "mfa_pending" in func_body or "require_mfa" in func_body, (
        "/auth/login must return an MFA challenge for MFA-enabled users"
    )


def test_token_endpoint_mfa_gate_runs_after_password_verification() -> None:
    """The MFA gate must run AFTER verify_password so the dummy-hash timing
    normalization still protects the no-user / wrong-password
    branches from enumeration via response-time measurements.
    """
    source = AUTH_FILE.read_text(encoding="utf-8")

    func_body = _function_body(
        source,
        r"async def login_for_access_token.*?(?=\nasync def|\n@router|\Z)",
    )

    verify_pos = func_body.find("verify_password(form_data.password")
    mfa_pos = func_body.find("mfa_enabled")
    assert verify_pos != -1, "verify_password call not found in /auth/token"
    assert mfa_pos != -1
    assert verify_pos < mfa_pos, (
        "MFA gate must run AFTER verify_password so timing normalization holds"
    )


def test_verify_mfa_login_checks_account_state() -> None:
    """/login/mfa must re-check every account-state gate that
    /login applies — is_active, locked_until, deleted_at, token_version.

    Otherwise /login/mfa becomes a bypass path: a user who was disabled
    or whose tokens were all revoked after the mfa_pending challenge was
    issued (but before it expired) could still complete MFA and receive
    a full access+refresh token pair.
    """
    source = AUTH_FILE.read_text(encoding="utf-8")

    func_body = _function_body(
        source,
        r"async def (?:verify_mfa_login|login_mfa|mfa_verify|verify_mfa)\b.*?(?=\nasync def |\n@router|\Z)",
    )

    assert "is_active" in func_body, (
        "/login/mfa must check user.is_active"
    )
    assert "locked_until" in func_body, (
        "/login/mfa must check user.locked_until"
    )
    assert "deleted_at" in func_body, (
        "/login/mfa must check user.deleted_at"
    )
    assert re.search(r"\btv\b|token_version", func_body), (
        "/login/mfa must verify the tv / token_version claim"
    )


def test_login_mfa_pending_token_includes_token_version() -> None:
    """The mfa_pending token issued by /login must embed the current
    token_version. Without it the token_version check in /login/mfa is
    meaningless (any value in the token would compare equal to zero).
    """
    source = AUTH_FILE.read_text(encoding="utf-8")

    func_body = _function_body(
        source,
        r"async def login\s*\(.*?(?=\nasync def|\n@router|\Z)",
    )

    # Locate the mfa_pending block and confirm token_version is passed.
    mfa_block_start = func_body.find('"type": "mfa_pending"')
    assert mfa_block_start != -1, "mfa_pending token block not found in /login"
    # Look at a ~300-char window around the block for the token_version kwarg.
    window = func_body[max(0, mfa_block_start - 300) : mfa_block_start + 300]
    assert "token_version" in window, (
        "mfa_pending token must be created with token_version=..."
    )
