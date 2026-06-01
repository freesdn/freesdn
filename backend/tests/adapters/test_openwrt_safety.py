# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the OpenWrt ubus client read-only gate.

OpenWrt was — alongside Omada — one of two adapters whose request layer
never refused live-device writes while ``ADAPTER_READ_ONLY`` was engaged
(external pre-public review, finding F1). Unlike the REST
adapters (which classify by HTTP verb), ubus tunnels BOTH reads and
writes over the same ``POST /ubus``, so the gate classifies by the ubus
*method verb*.

These tests assert the restored contract:

1. The verb classifier flags every mutating ubus call and no read.
2. ``client.call`` refuses a write while read-only is engaged and we are
   NOT inside an approved staged-apply window.
3. A read is never gated.
4. A staged apply (``apply_window``) is permitted even under read-only —
   that's the sanctioned write path.
5. With read-only cleared the gate is a no-op (live-write deployments).

The session + transport are mocked everywhere, so **no live OpenWrt box
is contacted** by this module.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.apply_context import apply_window
from app.adapters.openwrt.client import (
    OpenWRTAPIError,
    OpenWRTClient,
    _is_adapter_read_only,
    _is_ubus_write,
)


def _make_client() -> OpenWRTClient:
    """Build a client pointed at a TEST-NET-1 (RFC 5737) host so the test
    can never accidentally talk to a real device on the LAN."""
    return OpenWRTClient(host="192.0.2.1", username="root", password="x", port=80)


def _stub_transport(client: OpenWRTClient) -> AsyncMock:
    """Replace the session + raw-call layer so a call that PASSES the gate
    resolves to a sentinel instead of opening a socket. Returns the
    ``_raw_call`` mock so a test can assert it was (not) awaited."""
    client._ensure_session = AsyncMock()  # type: ignore[assignment]
    raw = AsyncMock(return_value={"ok": 1})
    client._raw_call = raw  # type: ignore[assignment]
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Verb classifier
# ─────────────────────────────────────────────────────────────────────────────


class TestUbusWriteClassifier:
    """``_is_ubus_write`` is the heart of the gate — it must catch every
    mutating verb the client's write wrappers emit and never a read."""

    @pytest.mark.parametrize(
        "method",
        [
            "reboot",
            "halt",
            "poweroff",  # system power
            "restart",
            "reload",
            "start",
            "stop",  # service / network control
            "add",
            "set",
            "delete",
            "commit",
            "revert",
            "rename",
            "order",  # uci
            "exec",  # rc exec (service start/stop)
            # case-insensitive
            "SET",
            "Reboot",
            "COMMIT",
        ],
    )
    def test_writes_classified(self, method: str) -> None:
        assert _is_ubus_write(method) is True

    @pytest.mark.parametrize(
        "method",
        [
            "board",
            "info",
            "dump",
            "status",
            "get",
            "changes",
            "list",
            "read",
            "backup",
            "getDHCPLeases",
            "getARPTable",
            "diskfree",
            "process_list",
            "syslog",
            "packagelist",
            "conntrack_count",
            "arp_table",
        ],
    )
    def test_reads_not_classified(self, method: str) -> None:
        assert _is_ubus_write(method) is False


# ─────────────────────────────────────────────────────────────────────────────
# call() read-only gate
# ─────────────────────────────────────────────────────────────────────────────


class TestCallReadOnlyGate:
    @pytest.mark.asyncio
    @patch("app.adapters.openwrt.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize(
        "path,method,params",
        [
            ("uci", "set", {"config": "firewall", "section": "@rule[0]"}),
            ("uci", "add", {"config": "firewall", "type": "rule"}),
            ("uci", "delete", {"config": "firewall", "section": "x"}),
            ("uci", "commit", {"config": "firewall"}),
            ("system", "reboot", None),
            ("system", "halt", None),
            ("network", "restart", None),
            ("rc", "exec", {"name": "firewall", "command": "start"}),
        ],
    )
    async def test_write_refused_under_read_only(
        self, path: str, method: str, params: dict | None
    ) -> None:
        client = _make_client()
        raw = _stub_transport(client)
        with pytest.raises(OpenWRTAPIError) as exc:
            await client.call(path, method, params)
        assert "ADAPTER_READ_ONLY" in str(exc.value)
        # The write must never have reached the transport.
        raw.assert_not_awaited()

    @pytest.mark.asyncio
    @patch("app.adapters.openwrt.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize(
        "path,method",
        [
            ("system", "board"),
            ("system", "info"),
            ("network.interface", "dump"),
            ("uci", "get"),
            ("uci", "changes"),
            ("service", "list"),
            ("luci-rpc", "getDHCPLeases"),
            ("rpc-sys", "backup"),
        ],
    )
    async def test_read_never_gated(self, path: str, method: str) -> None:
        client = _make_client()
        raw = _stub_transport(client)
        result = await client.call(path, method)
        assert result == {"ok": 1}
        raw.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("app.adapters.openwrt.client._is_adapter_read_only", lambda: True)
    async def test_write_permitted_inside_apply_window(self) -> None:
        """A sanctioned staged apply opens ``apply_window`` AFTER the
        staging service's own ADAPTER_READ_ONLY + force gate — the client
        must let the write through there even while read-only is on."""
        client = _make_client()
        raw = _stub_transport(client)
        with apply_window():
            result = await client.call("uci", "commit", {"config": "firewall"})
        assert result == {"ok": 1}
        raw.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("app.adapters.openwrt.client._is_adapter_read_only", lambda: False)
    async def test_write_permitted_when_read_only_off(self) -> None:
        """Operators who deliberately clear ADAPTER_READ_ONLY get direct
        live writes — the gate is a no-op for them."""
        client = _make_client()
        raw = _stub_transport(client)
        result = await client.call("system", "reboot")
        assert result == {"ok": 1}
        raw.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────────────────
# Read-only flag default
# ─────────────────────────────────────────────────────────────────────────────


class TestReadOnlyFlagDefaults:
    def test_default_is_read_only(self) -> None:
        # Shipped default is True — no env override in this test process.
        assert _is_adapter_read_only() is True
