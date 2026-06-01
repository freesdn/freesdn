# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Direct-route read-only parity for the force-gated network adapters.

OPNsense / pfSense / MikroTik gate live writes at the CLIENT layer
(``client._request`` refuses mutating verbs unless ``force=True``). Their
high-level adapter methods (``create_firewall_rule``, ``restart_service``, …)
used to hard-code ``force=True`` when calling the client — which DEFEATED the
gate for any direct API route (gateway-service / device-control / passthrough),
letting an authenticated operator mutate a live device under
``ADAPTER_READ_ONLY=true`` (external pre-public review, "direct live gateway
writes bypass ADAPTER_READ_ONLY").

The fix threads ``self._direct_write_force`` (default False) instead of a
hard-coded ``True``. So:

* a direct-route caller (default construction) → ``force=False`` → the client
  gate refuses the write under read-only;
* the sanctioned staged applier calls the client DIRECTLY with ``force=True``
  (it does not use these adapter methods), so it is unaffected;
* an explicit opt-in (``direct_write_force=True``) threads ``force=True``.

These tests assert the adapter threads the flag (not a hard-coded True). The
client-layer gate behaviour itself (force=False ⇒ refused under read-only) is
covered by each adapter's ``test_*_safety.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.mikrotik.adapter import MikroTikAdapter
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.adapters.pfsense.adapter import PfSenseAdapter

# ───────────────────────── OPNsense ─────────────────────────


class TestOPNsenseDirectWriteForce:
    def _adapter(self, **kw: object) -> OPNsenseAdapter:
        return OPNsenseAdapter(host="192.0.2.1", username="key", password="secret", **kw)

    @pytest.mark.asyncio
    async def test_create_firewall_rule_threads_force_false_by_default(self) -> None:
        a = self._adapter()
        assert a._direct_write_force is False
        a._api = MagicMock()
        a._api.add_firewall_rule = AsyncMock(return_value={"uuid": "x"})
        a._api.apply_firewall_changes = AsyncMock(return_value={})
        await a.create_firewall_rule({"description": "t"})
        # The bug was a hard-coded force=True; it must now be the flag (False).
        assert a._api.add_firewall_rule.await_args.kwargs["force"] is False
        assert a._api.apply_firewall_changes.await_args.kwargs["force"] is False

    @pytest.mark.asyncio
    async def test_create_firewall_rule_threads_force_true_when_opted_in(self) -> None:
        a = self._adapter(direct_write_force=True)
        assert a._direct_write_force is True
        a._api = MagicMock()
        a._api.add_firewall_rule = AsyncMock(return_value={"uuid": "x"})
        a._api.apply_firewall_changes = AsyncMock(return_value={})
        await a.create_firewall_rule({"description": "t"})
        assert a._api.add_firewall_rule.await_args.kwargs["force"] is True


# ───────────────────────── pfSense ──────────────────────────


class TestPfSenseDirectWriteForce:
    def _adapter(self, **kw: object) -> PfSenseAdapter:
        return PfSenseAdapter(host="192.0.2.1", username="key", password="secret", **kw)

    @pytest.mark.asyncio
    async def test_create_firewall_rule_threads_force_false_by_default(self) -> None:
        a = self._adapter()
        assert a._direct_write_force is False
        a._api = MagicMock()
        a._api.add_firewall_rule = AsyncMock(return_value={"id": 1})
        a._api.apply_firewall_changes = AsyncMock(return_value={})
        await a.create_firewall_rule({"descr": "t"})
        assert a._api.add_firewall_rule.await_args.kwargs["force"] is False

    @pytest.mark.asyncio
    async def test_create_firewall_rule_threads_force_true_when_opted_in(self) -> None:
        a = self._adapter(direct_write_force=True)
        a._api = MagicMock()
        a._api.add_firewall_rule = AsyncMock(return_value={"id": 1})
        a._api.apply_firewall_changes = AsyncMock(return_value={})
        await a.create_firewall_rule({"descr": "t"})
        assert a._api.add_firewall_rule.await_args.kwargs["force"] is True

    @pytest.mark.asyncio
    async def test_diagnostic_ping_still_forces(self) -> None:
        """Diagnostic read-POSTs (ping/traceroute/dns) legitimately pass
        force=True so the write-method gate doesn't block a read — that must
        NOT have been changed to the flag."""
        a = self._adapter()  # default flag False
        a._api = MagicMock()
        a._api.run_ping = AsyncMock(return_value={"ok": True})
        await a.run_ping("192.0.2.50")
        # Diagnostics keep force=True regardless of the (False) write flag.
        assert a._api.run_ping.await_args.kwargs.get("force") is True


# ───────────────────────── MikroTik ─────────────────────────


class TestMikroTikDirectWriteForce:
    def _adapter(self, **kw: object) -> MikroTikAdapter:
        return MikroTikAdapter(host="192.0.2.1", username="admin", password="x", **kw)

    def _mock_api(self, a: MikroTikAdapter) -> MagicMock:
        a._api = MagicMock()
        a._api.get_services = AsyncMock(
            return_value=[{"name": "api", ".id": "*1", "disabled": "false"}]
        )
        a._api.update_service = AsyncMock(return_value={})
        return a._api

    @pytest.mark.asyncio
    async def test_restart_service_threads_force_false_by_default(self) -> None:
        a = self._adapter()
        api = self._mock_api(a)
        await a.restart_service("api")
        # restart_service toggles disabled true→false; the FIRST update_service
        # carries the threaded flag (False by default).
        assert api.update_service.await_args_list[0].kwargs["force"] is False

    @pytest.mark.asyncio
    async def test_restart_service_threads_force_true_when_opted_in(self) -> None:
        a = self._adapter(direct_write_force=True)
        api = self._mock_api(a)
        await a.restart_service("api")
        assert api.update_service.await_args_list[0].kwargs["force"] is True

    @pytest.mark.asyncio
    async def test_diagnostic_ping_still_forces(self) -> None:
        a = self._adapter()
        a._api = MagicMock()
        a._api.run_ping = AsyncMock(return_value={"ok": True})
        await a.run_ping("192.0.2.50")
        assert a._api.run_ping.await_args.kwargs.get("force") is True
