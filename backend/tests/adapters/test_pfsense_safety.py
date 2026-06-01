# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the pfSense adapter.

Same invariants as Omada / OPNsense / Proxmox — the dual-gate is the
keystone of FreeSDN's vendor-agnostic safety. pfSense is a BSD
firewall (sibling to OPNsense) so a misfired write here can
disconnect entire networks.

Mocked HTTP layer — **no live pfSense controller is contacted at any
point**.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.pfsense.client import PfSenseClient, _validate_path

# ── Path validation ──────────────────────────────────────────────


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/firewall/rule",
            "/firewall/rule",  # without /api prefix (auto-prefixed)
            "/services/dhcpd",
            "/diagnostics/arp_table",
            "interface",  # bare relative
        ],
    )
    def test_accepts_legitimate_paths(self, path: str) -> None:
        _validate_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "/api/v2/../etc/passwd",
            "/firewall/rule/../../system",
            "/firewall/rule with spaces",
            "/firewall/rule;rm -rf",
            "/firewall/rule\x00",
            "/firewall/rule\nX-Header: x",
            # Query-param injection — the previous lax regex permitted
            # ``?``/``=``/``&`` in path strings, which let callers
            # smuggle additional query selectors through f-string
            # interpolation (e.g. ``delete_alias(name="legit&id=99")``).
            # Hardened regex now rejects these; query parameters MUST
            # be passed via ``httpx`` ``params=`` kwarg.
            "/firewall/alias?name=admin-block",
            "/firewall/alias?name=x&id=99",
            "/services/dhcpd?force=true",
            "/firewall/rule%2e%2e/etc",
        ],
    )
    def test_rejects_bad_paths(self, path: str) -> None:
        with pytest.raises(AdapterError):
            _validate_path(path)


def _make_client() -> PfSenseClient:
    return PfSenseClient(
        host="192.0.2.1",
        api_key="k",
        api_secret="s",
        port=443,
        verify_ssl=False,
    )


class TestReadOnlyGate:
    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_refuses_writes_when_read_only(self, method: str) -> None:
        client = _make_client()
        with pytest.raises(AdapterError) as exc:
            await client._request(method, "/firewall/rule")
        assert "ADAPTER_READ_ONLY" in str(exc.value)

    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_refuses_apply_firewall_changes_by_default(self) -> None:
        """The pf apply commits the running ruleset — most consequential
        firewall write."""
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.apply_firewall_changes()

    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_refuses_delete_firewall_rule_by_default(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.delete_firewall_rule(42)

    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_allows_writes_when_force_true(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"data": "ok"}')
        mock_response.json.return_value = {"data": "ok"}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request(
            "POST", "/firewall/rule", data={}, force=True
        )
        assert result == "ok"

    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_allows_reads_when_read_only(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"data": []}')
        mock_response.json.return_value = {"data": []}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request("GET", "/firewall/rule")
        assert result == []


class TestForcePropagation:
    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_add_firewall_rule_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.add_firewall_rule({"description": "test"})

    @pytest.mark.asyncio
    @patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True)
    async def test_add_alias_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.add_alias({"name": "test"})


class TestTaggedBreaker:
    def test_breaker_starts_closed_with_labels(self) -> None:
        client = _make_client()
        assert client._breaker.state == "closed"
        assert client._breaker.name == "pfsense"
        assert client._breaker.host.startswith("https://192.0.2.1")
