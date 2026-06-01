# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unit tests for OIDC discovery-URL derivation + trusted-IdP-host resolution.

These lock in two hardening fixes proven live against a real Keycloak:

* A provider configured with only issuer + client_id + secret must work out of
  the box, by deriving the standard ``{issuer}/.well-known/openid-configuration``
  discovery URL (instead of the non-standard ``{issuer}/authorize`` guess that
  fails against every real IdP).
* The admin-configured IdP host(s) must be trusted so SSO can reach an on-prem /
  internal IdP on a private address, without weakening the SSRF block for
  anything else.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.sso import SSOService


def _svc() -> SSOService:
    # The helpers under test are pure (no DB), so skip __init__.
    return SSOService.__new__(SSOService)


def _provider(
    issuer: str | None = None,
    discovery: str | None = None,
    saml_sso: str | None = None,
    saml_slo: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        oidc_issuer=issuer,
        oidc_discovery_url=discovery,
        saml_sso_url=saml_sso,
        saml_slo_url=saml_slo,
    )


def test_discovery_derived_from_issuer() -> None:
    p = _provider(issuer="https://idp.example.com")
    assert (
        _svc()._effective_discovery_url(p)
        == "https://idp.example.com/.well-known/openid-configuration"
    )


def test_discovery_strips_trailing_slash() -> None:
    p = _provider(issuer="https://idp.example.com/")
    assert (
        _svc()._effective_discovery_url(p)
        == "https://idp.example.com/.well-known/openid-configuration"
    )


def test_explicit_discovery_url_wins() -> None:
    p = _provider(issuer="https://idp.example.com", discovery="https://idp.example.com/c/disco")
    assert _svc()._effective_discovery_url(p) == "https://idp.example.com/c/disco"


def test_discovery_none_without_issuer() -> None:
    assert _svc()._effective_discovery_url(_provider()) is None


def test_trusted_hosts_from_issuer_and_discovery() -> None:
    p = _provider(
        issuer="http://keycloak:8080/realms/x",
        discovery="http://disco.internal/.well-known/openid-configuration",
    )
    assert _svc()._trusted_idp_hosts(p) == frozenset({"keycloak", "disco.internal"})


def test_trusted_hosts_issuer_only() -> None:
    assert _svc()._trusted_idp_hosts(_provider(issuer="https://idp.example.com")) == frozenset(
        {"idp.example.com"}
    )


def test_trusted_hosts_empty_without_config() -> None:
    assert _svc()._trusted_idp_hosts(_provider()) == frozenset()


def test_trusted_hosts_includes_saml_endpoints() -> None:
    # The Test-Connection fix relies on the helper being protocol-complete so an
    # internal SAML IdP is reachable too (not just OIDC).
    p = _provider(saml_sso="https://saml.example.com/sso", saml_slo="https://saml.example.com/slo")
    assert _svc()._trusted_idp_hosts(p) == frozenset({"saml.example.com"})


def test_schema_validator_rejects_bad_idp_url() -> None:
    # A typo'd issuer must fail at config time, not silently widen the SSRF
    # allow-list (the issuer/discovery host is trusted for the private-IP bypass).
    import pytest
    from pydantic import ValidationError

    from app.schemas.sso import SSOProviderUpdate

    assert (
        SSOProviderUpdate(oidc_issuer="https://idp.example.com").oidc_issuer
        == "https://idp.example.com"
    )
    with pytest.raises(ValidationError):
        SSOProviderUpdate(oidc_issuer="not-a-url")
    with pytest.raises(ValidationError):
        SSOProviderUpdate(oidc_discovery_url="file:///etc/passwd")
