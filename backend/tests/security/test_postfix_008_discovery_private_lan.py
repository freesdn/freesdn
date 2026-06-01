# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for private-LAN targets blocked by transport.

Before this fix the ``/discovery/test-credentials`` endpoint called
``validate_target_host`` (which correctly allows RFC-1918 addresses for
device-management probes) and then called ``safe_http_request`` WITHOUT
``allow_hosts``.  Because ``safe_http_request`` blocks private IPs by default
(``trusted=False``), every legitimate LAN target (10/8, 172.16/12, 192.168/16)
was silently rejected at the transport layer with a ``ValueError`` — the same
exception class used for unreachable hosts — so the caller received a generic
"Could not connect" response instead of being able to reach the device.

Fix (discovery.py ~1374): ``allow_hosts=frozenset({target})`` is now passed to
``safe_http_request``.  This makes the validated target "trusted" so its private
IP is not re-blocked, while the never-bypassable set (loopback, link-local,
cloud-metadata) remains enforced regardless.

These are pure-unit tests — no DB, no real network sockets.
"""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security_utils import safe_http_request


class TestPrivateLanAllowedWithAllowHosts:
    """safe_http_request must reach private-LAN IP literals when allow_hosts is set."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "192.168.0.200",
            "10.0.0.1",
            "10.255.255.1",
            "172.16.0.1",
            "172.31.254.254",
        ],
    )
    async def test_private_ip_reaches_transport_with_allow_hosts(self, ip: str) -> None:
        """A private-range IP that is in allow_hosts must NOT raise ValueError.

        The fix passes allow_hosts=frozenset({target}) so safe_http_request
        treats the validated device target as trusted.  We mock httpx so no real
        socket is opened; the test asserts that we reach the httpx call rather
        than raising ValueError before it.
        """
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "FakeDevice/1.0"}

        with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_resp

            # Must NOT raise — the target should reach the httpx transport layer.
            await safe_http_request(
                "GET",
                f"http://{ip}:443/",
                verify_tls=False,
                follow_redirects=False,
                timeout=10,
                allow_hosts=frozenset({ip}),
            )

        # Confirm the transport was actually invoked (we passed the SSRF gate).
        mock_req.assert_called_once()
        # The URL supplied to httpx must use the IP literal (no hostname to re-resolve).
        call_url: str = mock_req.call_args.args[1]
        assert ip in call_url, f"Expected IP {ip!r} in transport URL, got {call_url!r}"


class TestNeverBypassableStillBlocked:
    """Loopback, link-local, and cloud-metadata must be blocked even with allow_hosts.

    The never-bypassable set is enforced by _ip_block_reason regardless of the
    trusted flag, so passing allow_hosts={target} for a dangerous address must
    still raise ValueError.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "dangerous_ip",
        [
            "127.0.0.1",  # loopback
            "127.1.2.3",  # loopback range
            "169.254.169.254",  # AWS/Azure/GCP cloud-metadata (link-local)
            "169.254.0.1",  # other link-local
            "0.0.0.0",  # unspecified
        ],
    )
    async def test_dangerous_ip_rejected_even_in_allow_hosts(self, dangerous_ip: str) -> None:
        """Even if a caller adds a loopback / metadata IP to allow_hosts it must
        still be rejected.  This is the invariant that prevents SSRF regardless
        of the transport-allowance mechanism."""
        with pytest.raises(ValueError):
            await safe_http_request(
                "GET",
                f"http://{dangerous_ip}/",
                follow_redirects=False,
                # Deliberately add the dangerous IP to allow_hosts to prove the
                # never-bypassable block cannot be defeated by this parameter.
                allow_hosts=frozenset({dangerous_ip}),
            )

    @pytest.mark.asyncio
    async def test_ipv6_loopback_rejected_even_in_allow_hosts(self) -> None:
        """IPv6 loopback (::1) must remain blocked regardless of allow_hosts."""
        with pytest.raises(ValueError):
            await safe_http_request(
                "GET",
                "http://[::1]/",
                follow_redirects=False,
                allow_hosts=frozenset({"::1"}),
            )

    @pytest.mark.asyncio
    async def test_metadata_hostname_rejected(self) -> None:
        """Cloud-metadata hostname must be blocked by name before DNS resolution."""
        with pytest.raises(ValueError, match="metadata"):
            await safe_http_request(
                "GET",
                "http://metadata.google.internal/",
                follow_redirects=False,
                allow_hosts=frozenset({"metadata.google.internal"}),
            )

    @pytest.mark.asyncio
    async def test_aws_imds_ip_rejected(self) -> None:
        """169.254.169.254 is in _METADATA_IPS and must be blocked unconditionally."""
        with pytest.raises(ValueError):
            await safe_http_request(
                "GET",
                "http://169.254.169.254/latest/meta-data/",
                follow_redirects=False,
                allow_hosts=frozenset({"169.254.169.254"}),
            )


class TestDnsRebindingStillBlockedWithAllowHosts:
    """DNS rebinding protection is not weakened by allow_hosts.

    allow_hosts only trusts the specified hostname-or-IP.  A different hostname
    (not in allow_hosts) that resolves to a private IP must still be rejected.
    """

    @pytest.mark.asyncio
    async def test_untrusted_hostname_resolving_to_private_blocked(self) -> None:
        """A hostname NOT in allow_hosts that resolves to a private IP must be
        rejected even when allow_hosts contains a different trusted device."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.99", 0)),
            ]
            with pytest.raises(ValueError, match="blocked IP"):
                await safe_http_request(
                    "GET",
                    "http://evil.rebind.attacker.com/",
                    follow_redirects=False,
                    # "192.168.1.1" is trusted, but the URL hostname is different.
                    allow_hosts=frozenset({"192.168.1.1"}),
                )

    @pytest.mark.asyncio
    async def test_trusted_hostname_resolving_to_private_allowed(self) -> None:
        """A hostname that IS in allow_hosts and resolves to a private IP must
        reach the transport layer — this is the LAN-device use-case."""
        with patch("socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.5.10", 0)),
            ]
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.headers = {}

            with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
                mock_req.return_value = mock_resp

                await safe_http_request(
                    "GET",
                    "http://mydevice.lan/",
                    follow_redirects=False,
                    allow_hosts=frozenset({"mydevice.lan"}),
                )

            mock_req.assert_called_once()
