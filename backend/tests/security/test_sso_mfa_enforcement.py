# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test that SSO callback paths enforce local MFA.

These are source-level guardrail tests: they scan ``app/services/sso.py``
and ``app/api/v1/endpoints/sso.py`` to confirm that the ``_issue_tokens``
helper checks the user's local MFA state, returns an MFA challenge
rather than a full token pair when MFA is enabled, and that all three
SSO callback paths (OIDC, SAML, LDAP) forward the provider so the
``trust_idp_mfa`` opt-in works.
"""
from __future__ import annotations

import re
from pathlib import Path

SERVICE_FILE = (
    Path(__file__).resolve().parents[2] / "app" / "services" / "sso.py"
)
ENDPOINTS_FILE = (
    Path(__file__).resolve().parents[2]
    / "app"
    / "api"
    / "v1"
    / "endpoints"
    / "sso.py"
)


def _service_source() -> str:
    return SERVICE_FILE.read_text(encoding="utf-8")


def _endpoints_source() -> str:
    return ENDPOINTS_FILE.read_text(encoding="utf-8")


def _extract_issue_tokens(source: str) -> str:
    """Return the body of the ``_issue_tokens`` method."""
    match = re.search(
        r"def _issue_tokens\b.*?(?=\n    def |\nclass |\Z)",
        source,
        re.DOTALL,
    )
    assert match, "_issue_tokens method not found in sso.py"
    return match.group(0)


def test_issue_tokens_checks_mfa_enabled() -> None:
    """``_issue_tokens`` must inspect ``user.mfa_enabled``."""
    body = _extract_issue_tokens(_service_source())
    assert "mfa_enabled" in body, (
        "_issue_tokens must check user.mfa_enabled"
    )
    assert "mfa_secret" in body, (
        "_issue_tokens must also check user.mfa_secret"
    )


def test_issue_tokens_returns_mfa_challenge() -> None:
    """``_issue_tokens`` must mint an ``mfa_pending`` token when MFA is on."""
    body = _extract_issue_tokens(_service_source())
    assert "mfa_pending" in body, (
        "_issue_tokens must issue a token with type='mfa_pending' when MFA "
        "is enabled"
    )
    assert "require_mfa" in body or "mfa_required" in body, (
        "_issue_tokens must surface require_mfa=True on the MFA branch"
    )


def test_issue_tokens_honors_trust_idp_mfa_optin() -> None:
    """The provider-level ``trust_idp_mfa`` opt-in must be respected."""
    body = _extract_issue_tokens(_service_source())
    assert "trust_idp_mfa" in body, (
        "_issue_tokens must honour provider.extra_settings.trust_idp_mfa "
        "so IdPs that already enforce MFA can opt out of the local gate"
    )


def test_all_callers_pass_provider() -> None:
    """SAML, OIDC, and LDAP callback paths must pass the provider."""
    source = _service_source()
    # Find every real ``self._issue_tokens(...)`` invocation. Requiring the
    # ``self.`` receiver prefix excludes both the ``def _issue_tokens(...)``
    # signature AND prose references in comments (e.g. "_issue_tokens() would
    # mint a token") that would otherwise be captured as bogus empty-arg calls.
    invocation_args = re.findall(r"self\._issue_tokens\s*\(([^)]*)\)", source)
    assert len(invocation_args) >= 3, (
        f"Expected at least 3 _issue_tokens calls (SAML/OIDC/LDAP); "
        f"found {len(invocation_args)}: {invocation_args}"
    )
    for args in invocation_args:
        # Each call must reference `provider` — either positionally as a
        # second arg or via keyword.
        assert "provider" in args, (
            f"_issue_tokens call missing provider argument: {args!r} "
            "(needed so trust_idp_mfa opt-in works)"
        )


def test_sso_callback_response_carries_mfa_fields() -> None:
    """The response schema must be able to carry an MFA challenge."""
    schema_file = (
        Path(__file__).resolve().parents[2] / "app" / "schemas" / "sso.py"
    )
    source = schema_file.read_text(encoding="utf-8")
    assert "require_mfa" in source, (
        "SSOCallbackResponse must expose require_mfa so callers can "
        "distinguish MFA challenges from full sessions"
    )
    assert "mfa_token" in source, (
        "SSOCallbackResponse must expose mfa_token so clients can "
        "exchange it via /auth/login/mfa"
    )


def test_endpoints_skip_cookies_on_mfa_challenge() -> None:
    """Callback endpoints must not set auth cookies on the MFA branch."""
    source = _endpoints_source()
    # There are three callback endpoints (oidc/saml/ldap) — each should
    # check require_mfa and short-circuit before set_auth_cookies().
    occurrences = source.count("result.require_mfa")
    assert occurrences >= 3, (
        "Each SSO callback endpoint (OIDC, SAML, LDAP) must check "
        f"result.require_mfa before setting auth cookies; found {occurrences}"
    )
