# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for Omada adapter error handling and idempotency contracts.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.exceptions import (
    OmadaApiError,
    OmadaAuthError,
    OmadaAuthorizationError,
    OmadaConnectionError,
    OmadaNotFoundError,
    OmadaRateLimitError,
    OmadaSessionExpiredError,
    OmadaTimeoutError,
    OmadaValidationError,
)

# ============================================================================
# _fail_from_exception translations
# ============================================================================


class TestErrorTranslation:
    """Verify each Omada exception maps to the correct AdapterResult error code."""

    def _adapter(self) -> OmadaAdapter:
        return OmadaAdapter("10.0.0.1", "admin", "secret")

    def test_validation_error(self):
        r = self._adapter()._fail_from_exception(
            OmadaValidationError("bad input"), default_error_code="DEFAULT"
        )
        assert r.error_code == "VALIDATION_ERROR"
        assert r.error == "invalid_configuration"

    def test_authorization_error(self):
        r = self._adapter()._fail_from_exception(
            OmadaAuthorizationError("forbidden"), default_error_code="DEFAULT"
        )
        assert r.error_code == "PERMISSION_DENIED"
        assert r.error == "insufficient_permissions"

    def test_auth_error(self):
        r = self._adapter()._fail_from_exception(
            OmadaAuthError("wrong password"), default_error_code="DEFAULT"
        )
        assert r.error_code == "AUTHENTICATION_FAILED"

    def test_session_expired(self):
        r = self._adapter()._fail_from_exception(
            OmadaSessionExpiredError("expired"), default_error_code="DEFAULT"
        )
        assert r.error_code == "AUTHENTICATION_FAILED"

    def test_not_found(self):
        r = self._adapter()._fail_from_exception(
            OmadaNotFoundError("missing"), default_error_code="DEFAULT"
        )
        assert r.error_code == "NOT_FOUND"
        assert r.error == "resource_not_found"

    def test_rate_limited(self):
        r = self._adapter()._fail_from_exception(
            OmadaRateLimitError("too fast"), default_error_code="DEFAULT"
        )
        assert r.error_code == "RATE_LIMITED"
        assert r.error == "rate_limited"

    def test_timeout(self):
        r = self._adapter()._fail_from_exception(
            OmadaTimeoutError("timed out"), default_error_code="DEFAULT"
        )
        assert r.error_code == "CONNECTION_ERROR"
        assert r.error == "controller_unreachable"

    def test_connection_error(self):
        r = self._adapter()._fail_from_exception(
            OmadaConnectionError("unreachable"), default_error_code="DEFAULT"
        )
        assert r.error_code == "CONNECTION_ERROR"

    def test_generic_api_error(self):
        r = self._adapter()._fail_from_exception(
            OmadaApiError("something went wrong"), default_error_code="MY_CODE"
        )
        assert r.error_code == "MY_CODE"
        assert r.error == "controller_error"

    def test_unknown_exception_uses_default_code(self):
        r = self._adapter()._fail_from_exception(
            RuntimeError("unexpected"), default_error_code="OPERATION_FAILED"
        )
        assert r.error_code == "OPERATION_FAILED"
        assert r.error == "unexpected"


# ============================================================================
# Idempotency Contracts
# ============================================================================


class TestIdempotency:
    """Verify all idempotency rules from spec §0.5."""

    @pytest.mark.asyncio
    async def test_create_vlan_existing_returns_ok(self, adapter: OmadaAdapter):
        """VLAN with same ID → ok(existing)."""
        result = await adapter.create_vlan(1, "LAN")
        assert result.success
        assert "already exists" in result.message.lower()

    @pytest.mark.asyncio
    async def test_delete_vlan_absent_returns_ok(self, adapter: OmadaAdapter):
        """Delete non-existent VLAN → ok(None)."""
        result = await adapter.delete_vlan(999)
        assert result.success
        assert "absent" in result.message.lower()

    @pytest.mark.asyncio
    async def test_create_ssid_duplicate_name_returns_fail(self, adapter: OmadaAdapter):
        """SSID duplicate name → fail("duplicate_name")."""
        result = await adapter.create_ssid({"name": "Guest-WiFi"})
        assert not result.success
        assert result.error_code == "DUPLICATE_SSID"

    @pytest.mark.asyncio
    async def test_delete_ssid_absent_returns_ok(self, adapter: OmadaAdapter):
        """Delete non-existent SSID → ok(None)."""
        adapter._client.delete_ssid = AsyncMock(side_effect=OmadaNotFoundError("gone"))
        result = await adapter.delete_ssid("nonexistent")
        assert result.success

    @pytest.mark.asyncio
    async def test_unblock_already_unblocked_returns_ok(self, adapter: OmadaAdapter):
        """Unblock non-blocked client → ok."""
        adapter._client.unblock_client = AsyncMock(side_effect=OmadaNotFoundError("not blocked"))
        result = await adapter.unblock_client("11:22:33:44:55:66")
        assert result.success

    @pytest.mark.asyncio
    async def test_block_already_blocked_returns_ok(self, adapter: OmadaAdapter):
        """Block already-blocked client → ok."""
        adapter._client.block_client = AsyncMock(side_effect=OmadaNotFoundError("already"))
        result = await adapter.block_client("11:22:33:44:55:66")
        assert result.success

    @pytest.mark.asyncio
    async def test_reboot_rate_limit(self, adapter: OmadaAdapter):
        """Same device reboot within cooldown → fail(RATE_LIMITED)."""
        r1 = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert r1.success

        r2 = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert not r2.success
        assert r2.error_code == "RATE_LIMITED"

    @pytest.mark.asyncio
    async def test_reboot_different_device_not_rate_limited(self, adapter: OmadaAdapter):
        """Different devices can reboot independently."""
        r1 = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert r1.success

        r2 = await adapter.reboot_device("AA-BB-CC-DD-EE-02")
        assert r2.success


# ============================================================================
# No-Site Handling
# ============================================================================


class TestNoSite:
    """Methods requiring a site should fail gracefully when no site is available."""

    @pytest.fixture()
    def no_site_adapter(self, adapter: OmadaAdapter) -> OmadaAdapter:
        adapter._site_id = None
        adapter._client.get_sites = AsyncMock(return_value=[])
        return adapter

    @pytest.mark.asyncio
    async def test_set_port_poe_no_site(self, no_site_adapter: OmadaAdapter):
        r = await no_site_adapter.set_port_poe("AA:BB:CC:DD:EE:01", 1, True)
        assert not r.success
        assert r.error_code == "NO_SITE"

    @pytest.mark.asyncio
    async def test_create_vlan_no_site(self, no_site_adapter: OmadaAdapter):
        r = await no_site_adapter.create_vlan(50, "Test")
        assert not r.success
        assert r.error_code == "NO_SITE"

    @pytest.mark.asyncio
    async def test_get_ports_no_site(self, no_site_adapter: OmadaAdapter):
        ports = await no_site_adapter.get_ports("AA:BB:CC:DD:EE:01")
        assert ports == []

    @pytest.mark.asyncio
    async def test_get_vlans_no_site(self, no_site_adapter: OmadaAdapter):
        vlans = await no_site_adapter.get_vlans()
        assert vlans == []

    @pytest.mark.asyncio
    async def test_get_clients_no_site(self, no_site_adapter: OmadaAdapter):
        clients = await no_site_adapter.get_clients()
        assert clients == []

    @pytest.mark.asyncio
    async def test_get_ssids_no_site(self, no_site_adapter: OmadaAdapter):
        ssids = await no_site_adapter.get_ssids()
        assert ssids == []

    @pytest.mark.asyncio
    async def test_toggle_ssid_no_site(self, no_site_adapter: OmadaAdapter):
        r = await no_site_adapter.toggle_ssid("ssid-1", False)
        assert not r.success
        assert r.error_code == "NO_SITE"
