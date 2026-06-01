# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the MikroTik adapter.

Same dual-gate as Omada / OPNsense / Proxmox / pfSense. RouterOS
writes touch firewall rules, BGP neighbors, switch configs — bad
writes can disconnect the device or its downstream networks.

Mocked HTTP layer — **no live MikroTik device is contacted**.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.mikrotik.client import MikroTikClient, _validate_path
from app.services.adapter_redaction import redact_secrets


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/rest/system/resource",
            "/rest/ip/firewall/filter",
            "/rest/ip/firewall/filter/*1A",  # RouterOS ID
            "/rest/interface/vlan",
            "/rest/ipv6/address",
            "interface",  # bare relative
        ],
    )
    def test_accepts_legitimate_paths(self, path: str) -> None:
        _validate_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "/rest/../etc/passwd",
            "/rest/system/resource/../../",
            "/rest/system with spaces",
            "/rest/system;rm -rf",
            "/rest/system?q=1",  # query smuggling
            "/rest/system\x00",
            "/rest/system\nX-Header: x",
        ],
    )
    def test_rejects_bad_paths(self, path: str) -> None:
        with pytest.raises(AdapterError):
            _validate_path(path)


def _make_client() -> MikroTikClient:
    return MikroTikClient(
        host="192.0.2.1",
        username="admin",
        password="x",
        port=443,
        verify_ssl=False,
    )


class TestReadOnlyGate:
    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_refuses_writes_when_read_only(self, method: str) -> None:
        client = _make_client()
        with pytest.raises(AdapterError) as exc:
            await client._request(method, "/ip/firewall/filter")
        assert "ADAPTER_READ_ONLY" in str(exc.value)

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    async def test_refuses_firewall_filter_add_by_default(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.add_firewall_filter_rule({"chain": "input", "action": "drop"})

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    async def test_refuses_disable_interface_by_default(self) -> None:
        """Disabling the WAN interface would disconnect the device."""
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.disable_interface("*1A")

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    async def test_allows_writes_when_force_true(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"ok": true}')
        mock_response.json.return_value = {"ok": True}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request(
            "POST", "/ip/firewall/filter", data={}, force=True
        )
        assert result == {"ok": True}

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    async def test_allows_reads_when_read_only(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='[]')
        mock_response.json.return_value = []
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request("GET", "/ip/firewall/filter")
        assert result == []


class TestTaggedBreaker:
    def test_breaker_starts_closed_with_labels(self) -> None:
        client = _make_client()
        assert client._breaker.state == "closed"
        assert client._breaker.name == "mikrotik"
        assert client._breaker.host.startswith("https://192.0.2.1")


class TestPathLengthCap:
    """The _validate_path guard must reject paths exceeding 256 chars."""

    def test_rejects_path_over_256_chars(self) -> None:
        # Build a path that's 280 chars total — well over the cap.
        # Use only safe chars so we know the rejection comes from the
        # length check, not the regex.
        long_path = "/rest/" + ("a" * 280)
        assert len(long_path) > 256
        with pytest.raises(AdapterError) as exc:
            _validate_path(long_path)
        assert "too long" in str(exc.value).lower()

    def test_accepts_path_at_or_below_256(self) -> None:
        # 250 chars including the /rest/ prefix.
        path = "/rest/" + ("a" * 240)
        assert len(path) <= 256
        # Should not raise.
        _validate_path(path)


class TestSecretRedaction:
    """Sanity-check that ``redact_secrets`` masks the typical
    RouterOS-shaped fields the adapter shells back."""

    def test_redacts_routeros_user_password(self) -> None:
        rows = [
            {"name": "admin", "password": "supersecret", "group": "full"},
            {"name": "ops", "password": "another", "group": "read"},
        ]
        redacted = redact_secrets(rows)
        assert all(row["password"] == "***" for row in redacted)
        # Non-secret fields should round-trip unchanged.
        assert [row["name"] for row in redacted] == ["admin", "ops"]
        assert [row["group"] for row in redacted] == ["full", "read"]

    def test_redacts_nested_token_field(self) -> None:
        payload = {
            "config": {"token": "abc123", "name": "ok"},
            "items": [{"api_key": "leak", "host": "1.1.1.1"}],
        }
        redacted = redact_secrets(payload)
        assert redacted["config"]["token"] == "***"
        assert redacted["config"]["name"] == "ok"
        assert redacted["items"][0]["api_key"] == "***"
        assert redacted["items"][0]["host"] == "1.1.1.1"


class TestApplyMethodsAcceptForce:
    """Each MikroTik service `_APPLY` entry must dispatch to a client
    method that accepts a ``force`` keyword argument; otherwise the
    distribution-engine's force=True semantics are silently dropped."""

    def _check_apply_map(self, module_name: str) -> None:
        # Import the service module dynamically so this test class
        # doesn't have to enumerate them at the top.
        import importlib

        from app.adapters.mikrotik.client import MikroTikClient

        mod = importlib.import_module(module_name)
        apply_map = getattr(mod, "_APPLY", None)
        assert apply_map is not None, f"{module_name} has no _APPLY"
        for (feature, op), method_name in apply_map.items():
            method = getattr(MikroTikClient, method_name, None)
            assert method is not None, (
                f"{module_name}: {feature}/{op} → MikroTikClient has no "
                f"method {method_name!r}"
            )
            sig = inspect.signature(method)
            assert "force" in sig.parameters, (
                f"{module_name}: {feature}/{op} dispatches to "
                f"{method_name!r} which has no `force` parameter — the "
                "dual-gate would silently drop force=True"
            )

    @pytest.mark.parametrize(
        "module_name",
        [
            "app.services.adapter_mikrotik_capsman",
            "app.services.adapter_mikrotik_dhcp",
            "app.services.adapter_mikrotik_dns",
            "app.services.adapter_mikrotik_firewall",
            "app.services.adapter_mikrotik_hotspot",
            "app.services.adapter_mikrotik_interfaces",
            "app.services.adapter_mikrotik_ip",
            "app.services.adapter_mikrotik_ppp",
            "app.services.adapter_mikrotik_queues",
            "app.services.adapter_mikrotik_routing",
            "app.services.adapter_mikrotik_security",
            "app.services.adapter_mikrotik_system",
            "app.services.adapter_mikrotik_vpn",
        ],
    )
    def test_every_apply_target_accepts_force(self, module_name: str) -> None:
        self._check_apply_map(module_name)


class TestToolFetchUrlValidation:
    """``mikrotik.system.tool_fetch`` must refuse cloud metadata
    targets even though the controller-tier gate already requires
    ``site_admin``. The URL is operator-controlled so a malicious or
    distracted operator would otherwise have a SSRF primitive that
    routes via the device's network position."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost/admin",
            "http://127.0.0.1/x",
        ],
    )
    def test_rejects_metadata_and_loopback(self, url: str) -> None:
        from fastapi import HTTPException

        from app.services.adapter_mikrotik_system import (
            _validate_tool_fetch_payload,
        )

        with pytest.raises(HTTPException) as exc:
            _validate_tool_fetch_payload({"url": url, "mode": "http"})
        assert exc.value.status_code == 400

    def test_rejects_disallowed_payload_keys(self) -> None:
        from fastapi import HTTPException

        from app.services.adapter_mikrotik_system import (
            _validate_tool_fetch_payload,
        )

        with pytest.raises(HTTPException) as exc:
            _validate_tool_fetch_payload(
                {
                    "url": "https://example.com/x",
                    "http-method": "POST",  # not allowlisted
                    "http-data": "secret=1",
                }
            )
        assert exc.value.status_code == 400
        assert "disallowed" in str(exc.value.detail).lower()

    def test_rejects_disallowed_scheme(self) -> None:
        from fastapi import HTTPException

        from app.services.adapter_mikrotik_system import (
            _validate_tool_fetch_payload,
        )

        with pytest.raises(HTTPException) as exc:
            _validate_tool_fetch_payload(
                {"url": "file:///etc/passwd", "mode": "http"}
            )
        assert exc.value.status_code == 400

    def test_accepts_legitimate_lan_fetch(self) -> None:
        from app.services.adapter_mikrotik_system import (
            _validate_tool_fetch_payload,
        )

        # LAN-side artefact server — RouterOS legitimately fetches
        # from RFC1918, so this must not be rejected.
        _validate_tool_fetch_payload(
            {
                "url": "http://10.0.0.5/firmware.npk",
                "mode": "http",
                "dst-path": "firmware.npk",
            }
        )


class TestExportConfigForcesHideSensitive:
    """The /export applier must overwrite operator-supplied
    ``hide-sensitive`` to ``yes`` regardless of intent — the staging
    table persists ``applied_response`` and we don't want plaintext
    credentials sitting in that audit trail."""

    def test_overwrites_hide_sensitive_no(self) -> None:
        from app.services.adapter_mikrotik_system import (
            _validate_export_config_payload,
        )

        cleaned = _validate_export_config_payload(
            {"hide-sensitive": "no", "file": "backup"}
        )
        assert cleaned["hide-sensitive"] == "yes"

    def test_sets_hide_sensitive_when_absent(self) -> None:
        from app.services.adapter_mikrotik_system import (
            _validate_export_config_payload,
        )

        cleaned = _validate_export_config_payload({})
        assert cleaned["hide-sensitive"] == "yes"

    @pytest.mark.parametrize(
        "filename",
        [
            "../etc/passwd",
            "/abs/path/x",
            "sub\\path",
            "..",
        ],
    )
    def test_rejects_path_traversal_in_filename(
        self, filename: str
    ) -> None:
        from fastapi import HTTPException

        from app.services.adapter_mikrotik_system import (
            _validate_export_config_payload,
        )

        with pytest.raises(HTTPException) as exc:
            _validate_export_config_payload({"file": filename})
        assert exc.value.status_code == 400


class TestPayloadSpreadDoesNotCollideWithForce:
    """The ``extra = {k: v ...}`` spread in DHCP / interfaces / IP /
    DNS / firewall appliers must drop ``force`` before ``**extra``;
    otherwise a payload that includes ``force`` raises TypeError
    (``got multiple values for 'force'``)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "module_name,service_attr,feature,payload",
        [
            (
                "app.services.adapter_mikrotik_dhcp",
                "GatewayMikrotikDHCPService",
                "mikrotik.dhcp.lease_static",
                {
                    "mac-address": "aa:bb:cc:dd:ee:ff",
                    "address": "10.0.0.10",
                    "force": "true",  # collision attempt
                },
            ),
            (
                "app.services.adapter_mikrotik_interfaces",
                "GatewayMikrotikInterfacesService",
                "mikrotik.interfaces.vlan",
                {
                    "name": "vlan10",
                    "vlan-id": 10,
                    "interface": "ether1",
                    "force": "true",
                },
            ),
            (
                "app.services.adapter_mikrotik_ip",
                "GatewayMikrotikIPService",
                "mikrotik.ip.address",
                {
                    "address": "10.0.0.1/24",
                    "interface": "ether1",
                    "force": "true",
                },
            ),
            (
                "app.services.adapter_mikrotik_ip",
                "GatewayMikrotikIPService",
                "mikrotik.ip.pool",
                {
                    "name": "pool1",
                    "ranges": "10.0.0.10-10.0.0.20",
                    "force": "true",
                },
            ),
            (
                "app.services.adapter_mikrotik_dns",
                "GatewayMikrotikDNSService",
                "mikrotik.dns.static",
                {
                    "name": "x.local",
                    "address": "10.0.0.1",
                    "force": "true",
                },
            ),
            (
                "app.services.adapter_mikrotik_firewall",
                "GatewayMikrotikFirewallService",
                "mikrotik.firewall.address_list",
                {
                    "list": "blocklist",
                    "address": "1.2.3.4",
                    "force": "true",
                },
            ),
        ],
    )
    async def test_force_in_payload_does_not_collide(
        self,
        module_name: str,
        service_attr: str,
        feature: str,
        payload: dict[str, Any],
    ) -> None:
        import importlib

        mod = importlib.import_module(module_name)
        cls = getattr(mod, service_attr)
        svc = cls.__new__(cls)

        async def _ctrl(*a: Any, **kw: Any) -> Any:
            return SimpleNamespace(host="1.2.3.4")

        # Capture how the applier dispatches into the underlying
        # client method. AsyncMock stands in for every client method
        # the dispatcher might pick — we just need to verify the
        # call actually invoked without TypeError.
        captured: dict[str, Any] = {}

        async def _client(*a: Any, **kw: Any) -> Any:
            mock = AsyncMock()

            def _wrap(name: str) -> Any:
                async def _inner(*args: Any, **kwargs: Any) -> Any:
                    captured["method"] = name
                    captured["args"] = args
                    captured["kwargs"] = kwargs
                    return {"ok": True}

                return _inner

            # Common methods used across all 6 cases
            for m in (
                "add_dhcp_static_lease",
                "add_vlan_interface",
                "add_ip_address",
                "add_ip_pool",
                "add_dns_static_entry",
                "add_firewall_address_list",
            ):
                setattr(mock, m, _wrap(m))
            return mock

        svc._get_controller = _ctrl  # type: ignore[attr-defined]
        # Vendor services now resolve via the polymorphic helper
        # introduced by; stub both names so the rename is
        # transparent to this test.
        svc._resolve_controller_or_gateway = _ctrl  # type: ignore[attr-defined]
        svc._get_client = _client    # type: ignore[attr-defined]

        change = SimpleNamespace(
            controller_id=uuid4(),
            organization_id=uuid4(),
            feature=feature,
            operation="create",
            target_id=None,
            payload=payload,
        )
        applier = svc.build_applier(change)
        # No TypeError on the spread is the success criterion.
        await applier(change)
        # Verify ``force`` was NOT in the captured kwargs (the
        # applier passes its own force=True separately).
        assert captured["kwargs"].get("force") is True
        # The mock captured kwargs is the union of the explicit
        # force=True and the **extra spread — ``force`` should not
        # appear twice.


class TestTargetIdGuards:
    """The 5 services patched in item 10 must reject update/delete
    operations missing a target_id — otherwise RouterOS would receive
    a literal ``None`` interpolated into the URL path."""

    def _make_change(self, *, feature: str, op: str, target_id: str | None) -> Any:
        return SimpleNamespace(
            controller_id=uuid4(),
            organization_id=uuid4(),
            feature=feature,
            operation=op,
            target_id=target_id,
            payload={},
        )

    def _patched_service(self, service_cls: type) -> object:
        # Bypass GatewayServiceBase's DB lookup — feed a minimal object
        # whose _get_controller and _get_client are async no-ops.
        svc = service_cls.__new__(service_cls)

        async def _ctrl(*a: Any, **kw: Any) -> Any:
            return SimpleNamespace(host="1.2.3.4")

        async def _client(*a: Any, **kw: Any) -> Any:
            return AsyncMock()

        svc._get_controller = _ctrl  # type: ignore[attr-defined]
        # See gateway_base.py — vendor services migrated to
        # ``_resolve_controller_or_gateway``. Stub both names.
        svc._resolve_controller_or_gateway = _ctrl  # type: ignore[attr-defined]
        svc._get_client = _client    # type: ignore[attr-defined]
        return svc

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "module_name,service_attr,feature",
        [
            (
                "app.services.adapter_mikrotik_dhcp",
                "GatewayMikrotikDHCPService",
                "mikrotik.dhcp.server",
            ),
            (
                "app.services.adapter_mikrotik_ip",
                "GatewayMikrotikIPService",
                "mikrotik.ip.pool",
            ),
            (
                "app.services.adapter_mikrotik_dns",
                "GatewayMikrotikDNSService",
                "mikrotik.dns.static",
            ),
            (
                "app.services.adapter_mikrotik_interfaces",
                "GatewayMikrotikInterfacesService",
                "mikrotik.interfaces.vlan",
            ),
            (
                "app.services.adapter_mikrotik_firewall",
                "GatewayMikrotikFirewallService",
                "mikrotik.firewall.filter_rule",
            ),
        ],
    )
    @pytest.mark.parametrize("op", ["update", "delete"])
    async def test_missing_target_id_rejected(
        self,
        module_name: str,
        service_attr: str,
        feature: str,
        op: str,
    ) -> None:
        import importlib

        from fastapi import HTTPException

        mod = importlib.import_module(module_name)
        cls = getattr(mod, service_attr)
        svc = self._patched_service(cls)

        change = self._make_change(feature=feature, op=op, target_id=None)
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "target_id" in str(exc.value.detail).lower()
