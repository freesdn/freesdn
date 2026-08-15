# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.v1.endpoints.credentials import test_credential as run_credential_test
from app.api.v1.endpoints.discovery import TestCredentialRequest as DiscoveryCredentialRequest
from app.api.v1.endpoints.discovery import (
    test_credentials as run_discovery_credential_test,
)
from app.schemas.credentials import CredentialTestRequest


class _ScalarResult:
    def __init__(self, record: object | None) -> None:
        self._record = record

    def scalar_one_or_none(self) -> object | None:
        return self._record


class _FakeCredentialSession:
    def __init__(self, credential: object) -> None:
        self.credential = credential
        self.commits = 0

    async def execute(self, _query: object) -> _ScalarResult:
        return _ScalarResult(self.credential)

    async def commit(self) -> None:
        self.commits += 1


class _FakeDiscoverySession:
    async def execute(self, _query: object) -> _ScalarResult:
        return _ScalarResult(None)


class _FakeResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers = {"server": "test-server"}


class _CapturingAsyncClient:
    created_verify: list[bool] = []
    calls: list[dict[str, object]] = []

    def __init__(self, *, verify: bool, timeout: int) -> None:
        self.verify = verify
        self.timeout = timeout
        type(self).created_verify.append(verify)

    async def __aenter__(self) -> _CapturingAsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str, **kwargs: object) -> _FakeResponse:
        type(self).calls.append(
            {
                "verify": self.verify,
                "timeout": self.timeout,
                "url": url,
                "kwargs": kwargs,
            }
        )
        return _FakeResponse()

    @classmethod
    def reset(cls) -> None:
        cls.created_verify = []
        cls.calls = []


@pytest.mark.asyncio
async def test_credential_test_uses_tls_verification_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    _CapturingAsyncClient.reset()
    monkeypatch.setattr(httpx, "AsyncClient", _CapturingAsyncClient)

    credential = SimpleNamespace(
        username="admin",
        encrypted_password="secret",
        deleted_at=None,
        last_used=None,
        last_test_result=None,
        site_id=None,
    )
    session = _FakeCredentialSession(credential)
    result = await run_credential_test(
        uuid4(),
        CredentialTestRequest(target_ip="192.168.1.10"),
        SimpleNamespace(is_superuser=False, organization_id=uuid4()),
        session,
    )

    assert result.success is True
    assert _CapturingAsyncClient.created_verify == [True]
    assert result.device_info is not None
    assert result.device_info["verify_ssl"] is True
    assert session.commits == 1


@pytest.mark.asyncio
async def test_credential_test_allows_explicit_tls_opt_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    _CapturingAsyncClient.reset()
    monkeypatch.setattr(httpx, "AsyncClient", _CapturingAsyncClient)

    credential = SimpleNamespace(
        username="admin",
        encrypted_password="secret",
        deleted_at=None,
        last_used=None,
        last_test_result=None,
        site_id=None,
    )
    result = await run_credential_test(
        uuid4(),
        CredentialTestRequest(target_ip="192.168.1.10", verify_ssl=False),
        SimpleNamespace(is_superuser=False, organization_id=uuid4()),
        _FakeCredentialSession(credential),
    )

    assert result.success is True
    assert _CapturingAsyncClient.created_verify == [False]
    assert result.device_info is not None
    assert result.device_info["verify_ssl"] is False


def _patch_safe_http(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Capture calls to the IP-pinned safe_http_request the probe now uses.

    SSRF-04: the discovery credential probe routes through
    ``app.core.security_utils.safe_http_request`` (imported inside the endpoint,
    so patching the module attribute is picked up at call time) instead of raw
    httpx — pinning the resolved IP. These tests assert TLS-verify is honored AND
    that redirects are never followed.
    """
    import app.core.security_utils as su

    calls: list[dict[str, object]] = []

    async def _fake_shr(
        method: str,
        url: str,
        *,
        verify_tls: bool = True,
        follow_redirects: bool = False,
        timeout: float = 10,
        auth: object = None,
        **_kw: object,
    ) -> _FakeResponse:
        calls.append(
            {"verify_tls": verify_tls, "follow_redirects": follow_redirects, "url": url}
        )
        return _FakeResponse(200)

    monkeypatch.setattr(su, "safe_http_request", _fake_shr)
    return calls


@pytest.mark.asyncio
async def test_discovery_credential_test_uses_tls_verification_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_safe_http(monkeypatch)

    result = await run_discovery_credential_test(
        DiscoveryCredentialRequest(
            ip_address="8.8.8.8",
            username="admin",
            password="secret",
        ),
        SimpleNamespace(),
        _FakeDiscoverySession(),
    )

    assert result.success is True
    assert calls and calls[0]["verify_tls"] is True
    assert calls[0]["follow_redirects"] is False  # SSRF-04: never follow redirects
    assert result.device_info is not None
    assert result.device_info["verify_ssl"] is True


@pytest.mark.asyncio
async def test_discovery_credential_test_allows_explicit_tls_opt_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_safe_http(monkeypatch)

    result = await run_discovery_credential_test(
        DiscoveryCredentialRequest(
            ip_address="8.8.8.8",
            username="admin",
            password="secret",
            verify_ssl=False,
        ),
        SimpleNamespace(),
        _FakeDiscoverySession(),
    )

    assert result.success is True
    assert calls and calls[0]["verify_tls"] is False
    assert calls[0]["follow_redirects"] is False  # SSRF-04: never follow redirects
    assert result.device_info is not None
    assert result.device_info["verify_ssl"] is False
