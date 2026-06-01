# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression + invariant tests for the core-verification remediation chapter.

Each test pins a security invariant that was found either BROKEN (a live defect,
now fixed) or UNPROVEN (correct but untested) during security review. A failure
here is a regression of a known security property.

This module is deliberately DB-free (unit-level) so it runs everywhere; the
endpoint/DB-level tenant-isolation invariants (TI-04/TI-16/WP-08 over the wire)
live alongside the existing API tests.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


# ── / the central redactor covers camelCase + the UniFi x_* keys
class TestSecretRedaction:
    def test_redacts_camelcase_vendor_keys(self) -> None:
        """the v6 leak class — camelCase vendor secret keys must mask."""
        from app.core.redaction import redact_secrets

        out = redact_secrets({"preSharedKey": "s", "clientSecret": "s", "bindPassword": "s"})
        assert out == {"preSharedKey": "***", "clientSecret": "***", "bindPassword": "***"}

    def test_redacts_unifi_x_password_and_x_authkey(self) -> None:
        """UniFi RADIUS account secret (x_password) + x_authkey."""
        from app.core.redaction import redact_secrets

        out = redact_secrets({"name": "u", "x_password": "radius-secret", "x_authkey": "k"})
        assert out["x_password"] == "***"
        assert out["x_authkey"] == "***"
        assert out["name"] == "u"  # non-secret preserved

    def test_redacts_nested_dicts_and_lists(self) -> None:
        from app.core.redaction import redact_secrets

        out = redact_secrets({"peer": {"private_key": "x"}, "items": [{"password": "p"}]})
        assert out["peer"]["private_key"] == "***"
        assert out["items"][0]["password"] == "***"


# ── VPN extra_data now uses the central recursive redactor ──
class TestVpnExtraDataRedaction:
    def test_nested_and_camelcase_secrets_masked(self) -> None:
        from app.api.v1.endpoints.vpn import _redact_extra_data

        out = _redact_extra_data(
            {
                "wg": {"preshared_key": "x"},  # nested — old flat redactor missed
                "clientSecret": "y",  # camelCase — old redactor missed
                "setup_key": "z",
                "note": "ok",
            }
        )
        assert out is not None
        assert out["wg"]["preshared_key"] == "***"
        assert out["clientSecret"] == "***"
        assert out["setup_key"] == "***"
        assert out["note"] == "ok"

    def test_none_passes_through(self) -> None:
        from app.api.v1.endpoints.vpn import _redact_extra_data

        assert _redact_extra_data(None) is None


# ── VoIP PBX read response drops every encrypted secret column ──
class TestPbxResponseSanitization:
    def test_drops_api_client_secret_enc(self) -> None:
        from app.modules.voip.api import _sanitize_pbx_response

        pbx = SimpleNamespace(
            name="pbx-1",
            ami_secret_enc="ct",
            ari_password_enc="ct",
            web_password_enc="ct",
            api_client_secret_enc="LEAK",  # the gap
            settings={},
        )
        out = _sanitize_pbx_response(pbx)
        for col in (
            "api_client_secret_enc",
            "ami_secret_enc",
            "ari_password_enc",
            "web_password_enc",
        ):
            assert col not in out, f"{col} leaked in PBX response"


# ── SSRF-04: the IP-pin helper blocks loopback/link-local/metadata ──
class TestSsrfResolveAndPin:
    def test_blocks_loopback_literal(self) -> None:
        from app.core.security_utils import resolve_and_pin_host

        with pytest.raises(ValueError):
            resolve_and_pin_host("127.0.0.1")

    def test_blocks_cloud_metadata_literal(self) -> None:
        from app.core.security_utils import resolve_and_pin_host

        with pytest.raises(ValueError):
            resolve_and_pin_host("169.254.169.254")

    def test_returns_public_ip_literal_unchanged(self) -> None:
        from app.core.security_utils import resolve_and_pin_host

        assert resolve_and_pin_host("8.8.8.8") == "8.8.8.8"

    def test_allows_private_lan_by_default(self) -> None:
        # Discovery probes LAN devices; private is allowed, only loopback/
        # link-local/metadata are blocked.
        from app.core.security_utils import resolve_and_pin_host

        assert resolve_and_pin_host("192.168.1.150") == "192.168.1.150"


# ── INJ-04: CSV/spreadsheet formula injection is neutralized ──
class TestCsvSafe:
    def test_prefixes_formula_triggers(self) -> None:
        from app.core.security_utils import csv_safe

        assert csv_safe("=cmd|' /C calc'!A1").startswith("'=")
        assert csv_safe("+1").startswith("'+")
        assert csv_safe("-1").startswith("'-")
        assert csv_safe("@SUM(A1)").startswith("'@")

    def test_leaves_benign_values(self) -> None:
        from app.core.security_utils import csv_safe

        assert csv_safe("device-01") == "device-01"
        assert csv_safe("") == ""


# ── INJ-02: LIKE/ILIKE search terms are wildcard-escaped ──
class TestEscapeLike:
    def test_neutralizes_like_metacharacters(self) -> None:
        from app.core.security_utils import escape_like

        out = escape_like("50%_x\\")
        assert "\\%" in out  # % escaped
        assert "\\_" in out  # _ escaped
        assert "\\\\" in out  # backslash escaped


# ── PS-11 (CRITICAL): a plugin AI tool can never run ungated ──
class TestPluginAiToolPermissionGate:
    def test_bridge_coerces_undeclared_permission_to_sentinel(self) -> None:
        from app.modules.ai.tools import TOOL_REGISTRY, AITool
        from app.plugins.bridges import _UNDECLARED_PLUGIN_TOOL_PERMISSION, PluginAIBridge

        async def _h(**_kw: object) -> dict:
            return {}

        bridge = PluginAIBridge()
        try:
            bridge.register_plugin_tool(
                "acme",
                AITool(name="t1", description="d", parameters={}, handler=_h, permission=None),
            )
            reg = TOOL_REGISTRY.get("plugin_acme_t1")
            assert reg is not None
            # No declared permission → forced to the super_admin-only sentinel,
            # NEVER left None (which _execute_tool would treat as ungated).
            assert reg.permission == _UNDECLARED_PLUGIN_TOOL_PERMISSION
        finally:
            bridge.unregister_plugin_tools("acme")

    def test_bridge_preserves_declared_permission(self) -> None:
        from app.modules.ai.tools import TOOL_REGISTRY, AITool
        from app.plugins.bridges import PluginAIBridge

        async def _h(**_kw: object) -> dict:
            return {}

        bridge = PluginAIBridge()
        try:
            bridge.register_plugin_tool(
                "acme",
                AITool(
                    name="t2", description="d", parameters={}, handler=_h, permission="cameras:read"
                ),
            )
            assert TOOL_REGISTRY["plugin_acme_t2"].permission == "cameras:read"
        finally:
            bridge.unregister_plugin_tools("acme")

    @pytest.mark.asyncio
    async def test_executor_denies_plugin_tool_without_permission(self) -> None:
        """Defense-in-depth: even if a plugin_* tool reaches the registry with no
        permission, the executor refuses it (does not run the handler)."""
        from app.modules.ai.providers.base import ToolCall
        from app.modules.ai.service import _execute_tool
        from app.modules.ai.tools import TOOL_REGISTRY, AITool, register_tool

        ran = {"called": False}

        async def _h(**_kw: object) -> dict:
            ran["called"] = True
            return {"ok": True}

        register_tool(
            AITool(
                name="plugin_evil_danger",
                description="d",
                parameters={},
                handler=_h,
                permission=None,
            )
        )
        try:
            # Even a superuser must be refused — the plugin_*-without-permission
            # guard fires before the permission check.
            user = SimpleNamespace(has_permission=lambda _p: True, is_superuser=True)
            res = await _execute_tool(
                ToolCall(id="1", name="plugin_evil_danger", arguments={}), user, None
            )
            assert "Permission denied" in res.get("error", "")
            assert ran["called"] is False
        finally:
            TOOL_REGISTRY.pop("plugin_evil_danger", None)
