# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test SSRF protection with DNS rebinding mitigation.

Covers the helpers introduced in ``app.core.security_utils``:
    - ``_is_ip_safe``
    - ``_resolve_and_validate``
    - ``safe_http_request``

These tests never touch the real network — all DNS resolution is patched.
"""
from __future__ import annotations

import ipaddress
import socket
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security_utils import (
    _is_ip_safe,
    _resolve_and_validate,
    safe_http_request,
)


class TestIPSafety:
    """Test the _is_ip_safe IP-class validator."""

    @pytest.mark.parametrize(
        "ip,safe",
        [
            # Public routable
            ("1.1.1.1", True),
            ("8.8.8.8", True),
            ("93.184.216.34", True),  # example.com
            # Loopback
            ("127.0.0.1", False),
            ("127.0.0.53", False),
            # RFC1918
            ("10.0.0.1", False),
            ("10.255.255.255", False),
            ("172.16.0.1", False),
            ("172.31.255.255", False),
            ("192.168.0.1", False),
            ("192.168.1.1", False),
            # Link-local / cloud metadata
            ("169.254.169.254", False),  # AWS / GCP / Azure IMDS
            ("169.254.0.1", False),
            # Multicast / unspecified
            ("224.0.0.1", False),
            ("239.255.255.250", False),
            ("0.0.0.0", False),
            # IPv6
            ("::1", False),               # loopback
            ("fc00::1", False),           # ULA
            ("fe80::1", False),           # link-local
            ("ff02::1", False),           # multicast
            ("2606:4700:4700::1111", True),  # Cloudflare public DNS
        ],
    )
    def test_is_ip_safe(self, ip: str, safe: bool) -> None:
        ip_obj = ipaddress.ip_address(ip)
        assert _is_ip_safe(ip_obj) is safe


class TestResolveAndValidate:
    """Test DNS resolution validation."""

    def test_rejects_private_resolution(self) -> None:
        """Hostname that resolves to loopback must be rejected."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                _resolve_and_validate("evil.example.com")

    def test_rejects_rfc1918_resolution(self) -> None:
        """Hostname that resolves to an RFC1918 address must be rejected."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                _resolve_and_validate("router.lan")

    def test_rejects_aws_metadata_resolution(self) -> None:
        """Hostname that resolves to 169.254.169.254 must be rejected."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                _resolve_and_validate("metadata.attacker.com")

    def test_rejects_mixed_resolution(self) -> None:
        """If ANY resolved IP is unsafe, reject the whole hostname.

        This is the core DNS-rebinding defence: an attacker cannot bypass
        the check by returning one public + one private address.
        """
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0)),       # safe
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),     # unsafe
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                _resolve_and_validate("evil.example.com")

    def test_accepts_public_resolution(self) -> None:
        """Hostname that resolves to a single public IP is accepted."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0)),
            ]
            result = _resolve_and_validate("one.one.one.one")
            assert result == "1.1.1.1"

    def test_accepts_multiple_public_resolutions(self) -> None:
        """Multiple public IPs are fine — returns the first one."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
            ]
            result = _resolve_and_validate("example.com")
            assert result == "1.1.1.1"

    def test_rejects_unresolvable(self) -> None:
        """Unresolvable hostname raises ValueError."""
        with patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror("no such host"),
        ):
            with pytest.raises(ValueError, match="Cannot resolve"):
                _resolve_and_validate("nonexistent.example.invalid")

    def test_rejects_empty_addrinfo(self) -> None:
        """Empty addrinfo list raises ValueError."""
        with patch("socket.getaddrinfo", return_value=[]):
            with pytest.raises(ValueError, match="No addresses"):
                _resolve_and_validate("nothing.example.com")


class TestSafeHttpRequest:
    """Test the safe_http_request function."""

    @pytest.mark.asyncio
    async def test_rejects_ftp_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            await safe_http_request("GET", "ftp://example.com/foo")

    @pytest.mark.asyncio
    async def test_rejects_file_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            await safe_http_request("GET", "file:///etc/passwd")

    @pytest.mark.asyncio
    async def test_rejects_gopher_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            await safe_http_request("GET", "gopher://example.com/")

    @pytest.mark.asyncio
    async def test_rejects_direct_loopback_url(self) -> None:
        with pytest.raises(ValueError, match="blocked IP"):
            await safe_http_request("GET", "http://127.0.0.1/admin")

    @pytest.mark.asyncio
    async def test_rejects_direct_aws_metadata_url(self) -> None:
        with pytest.raises(ValueError, match="(blocked IP|metadata)"):
            await safe_http_request("GET", "http://169.254.169.254/latest/meta-data/")

    @pytest.mark.asyncio
    async def test_rejects_rfc1918(self) -> None:
        with pytest.raises(ValueError, match="blocked IP"):
            await safe_http_request("GET", "http://192.168.1.1/config")

    @pytest.mark.asyncio
    async def test_rejects_ipv6_loopback(self) -> None:
        with pytest.raises(ValueError, match="blocked IP"):
            await safe_http_request("GET", "http://[::1]/")

    @pytest.mark.asyncio
    async def test_rejects_empty_url(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            await safe_http_request("GET", "")

    @pytest.mark.asyncio
    async def test_rejects_hostname_resolving_to_loopback(self) -> None:
        """The core DNS-rebinding test: a hostname that resolves to 127.0.0.1
        must be rejected even though the URL string looks innocent."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                await safe_http_request("GET", "http://evil.attacker.com/")

    @pytest.mark.asyncio
    async def test_rejects_hostname_mixed_resolution(self) -> None:
        """Hostname returning both public and private IPs must be rejected."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                await safe_http_request("GET", "http://rebind.attacker.com/")

    @pytest.mark.asyncio
    async def test_rejects_metadata_hostname(self) -> None:
        """metadata.google.internal must be blocked by name."""
        with pytest.raises(ValueError, match="metadata"):
            await safe_http_request("GET", "http://metadata.google.internal/")

    @pytest.mark.asyncio
    async def test_https_requests_preserve_sni_for_verified_tls(self) -> None:
        """Verified HTTPS must pin the TCP socket to the IP but keep TLS
        hostname validation bound to the original hostname."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            ]
            with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
                mock_request.return_value = object()

                await safe_http_request("GET", "https://example.com/sso/callback")

        args, kwargs = mock_request.call_args
        assert args[0] == "GET"
        assert args[1] == "https://93.184.216.34/sso/callback"
        assert kwargs["headers"]["Host"] == "example.com"
        assert kwargs["extensions"]["sni_hostname"] == "example.com"

    @pytest.mark.asyncio
    async def test_non_default_port_is_preserved_in_host_header(self) -> None:
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            ]
            with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
                mock_request.return_value = object()

                await safe_http_request("POST", "https://example.com:8443/webhook", content="{}")

        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1] == "https://93.184.216.34:8443/webhook"
        assert kwargs["headers"]["Host"] == "example.com:8443"
        assert kwargs["extensions"]["sni_hostname"] == "example.com"


class TestValidateUrlSsrfDeprecation:
    """Ensure the old helper warns on use."""

    def test_emits_deprecation_warning(self) -> None:
        from app.core.security_utils import validate_url_ssrf

        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0)),
            ]
            with pytest.warns(DeprecationWarning, match="DNS rebinding"):
                validate_url_ssrf("http://example.com/")
