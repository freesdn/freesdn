# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the Proxmox adapter.

Critical invariants verified here:

1. Path-traversal in any Proxmox API path is rejected before httpx
   sends a request — VM IDs / node names / volume IDs that contain
   ``..`` cannot walk the cluster API surface.
2. The universal ``ADAPTER_READ_ONLY`` gate is enforced at the
   ``_request`` layer. Default-on. Refuses every POST/PUT/PATCH/
   DELETE unless ``force=True`` is explicitly passed. Proxmox writes
   are the most catastrophic in the platform (VM destroy, node
   shutdown, snapshot delete) so this gate is the single most
   valuable production safety on the entire codebase.
3. The tagged ``CircuitBreaker`` emits the
   ``freesdn_adapter_circuit_state`` Prometheus gauge so dashboards
   see Proxmox alongside Omada / OPNsense.

These tests run against a mocked HTTP layer — **no live Proxmox
controller is contacted at any point**.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.exceptions import (
    AdapterConfirmationRequiredError,
    AdapterError,
    AdapterReadOnlyError,
)
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.client import (
    ProxmoxClient,
    ProxmoxClientConfig,
    _validate_path,
)

# ── Path validation ──────────────────────────────────────────────


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/api2/json/cluster/status",
            "/api2/json/nodes/pve1",
            "/api2/json/nodes/pve1/qemu/100/status/current",
            "/api2/json/nodes/pve1/storage/local-lvm",
            "/api2/json/access/users/admin@pam",
            "/cluster/status",  # without /api2/json prefix (adapter pattern)
            "nodes/pve1/qemu/100",  # bare relative path
        ],
    )
    def test_accepts_legitimate_paths(self, path: str) -> None:
        _validate_path(path)  # does not raise

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "/api2/json/../etc/passwd",
            "/api2/json/nodes/pve1/qemu/100/../../../cluster",
            "/api2/json/nodes/pve1 with spaces",
            "/api2/json/foo;rm -rf",
            "/api2/json/foo?q=1",
            "/api2/json/foo\x00",
            "/api2/json/foo\nbar",
            "/api2/json/foo#frag",
        ],
    )
    def test_rejects_bad_paths(self, path: str) -> None:
        with pytest.raises(AdapterError):
            _validate_path(path)


# ── Read-only gate ───────────────────────────────────────────────


def _make_client() -> ProxmoxClient:
    return ProxmoxClient(
        ProxmoxClientConfig(
            host="192.0.2.1",
            port=8006,
            use_ssl=True,
            verify_ssl=False,
            username="root",
            password="x",
        )
    )


class TestReadOnlyGate:
    """The dual-gate is the keystone of Proxmox production safety.
    A misconfigured destroy-VM call must NOT reach a live cluster
    in default config."""

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_refuses_writes_when_read_only(self, method: str) -> None:
        client = _make_client()
        # Must raise the TYPED AdapterReadOnlyError (not a bare AdapterError):
        # the app-level handler maps that to a clean HTTP 403, so a read-only
        # refusal never surfaces as an opaque 500. AdapterReadOnlyError is an
        # AdapterError subclass, so existing broad catches still work.
        with pytest.raises(AdapterReadOnlyError) as exc:
            await client._request(method, "/cluster/firewall/options")
        assert "ADAPTER_READ_ONLY" in str(exc.value)
        assert isinstance(exc.value, AdapterError)

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_refuses_destroy_vm_by_default(self) -> None:
        """The single most catastrophic write — destroy a VM. Must
        default-refuse so that even a buggy applier or a misclick
        in upstream code doesn't reach a live cluster."""
        client = _make_client()
        with pytest.raises(AdapterError):
            await client._request(
                "DELETE", "/nodes/pve1/qemu/100"
            )

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_refuses_node_shutdown_by_default(self) -> None:
        """Node shutdown takes the entire host offline. Must default-refuse."""
        client = _make_client()
        with pytest.raises(AdapterError):
            await client._request(
                "POST", "/nodes/pve1/status",
                data={"command": "shutdown"},
            )

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_allows_writes_when_force_true(self) -> None:
        """The sanctioned write path: applier passes force=True only
        after the apply endpoint clears its own dual-gate."""
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"data": null}')
        mock_response.json.return_value = {"data": None}
        # Bypass connect — set internal state so _request uses our mock.
        client._http = AsyncMock()
        client._http.is_closed = False
        client._http.request = AsyncMock(return_value=mock_response)
        client._authenticated = True
        # force=True satisfies the client-layer gate (the env+force dual-gate is enforced upstream). Should not raise.
        result = await client._request(
            "POST",
            "/nodes/pve1/qemu/100/status/start",
            force=True,
        )
        assert result is None  # data was None

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: False)
    async def test_allows_writes_when_env_off(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"data": "ok"}')
        mock_response.json.return_value = {"data": "ok"}
        client._http = AsyncMock()
        client._http.is_closed = False
        client._http.request = AsyncMock(return_value=mock_response)
        client._authenticated = True
        result = await client._request(
            "POST", "/nodes/pve1/qemu/100/config",
            data={"memory": 2048},
        )
        assert result == "ok"

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_allows_reads_when_read_only(self) -> None:
        """Reads are unconditionally allowed — only mutations gated."""
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"data": []}')
        mock_response.json.return_value = {"data": []}
        client._http = AsyncMock()
        client._http.is_closed = False
        client._http.request = AsyncMock(return_value=mock_response)
        client._authenticated = True
        result = await client._request("GET", "/cluster/status")
        assert result == []


class TestForcePropagation:
    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_post_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.post("/nodes/pve1/qemu/100/status/start")

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_put_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.put("/nodes/pve1/qemu/100/config", {"memory": 2048})

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_delete_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.delete("/nodes/pve1/qemu/100")


# ── Confirmed direct ops still honor read-only (confirmed ≠ force) ─


def _make_connected_adapter() -> tuple[ProxmoxAdapter, ProxmoxClient]:
    """A ProxmoxAdapter wired to a real client over a mocked HTTP layer, so the
    client-layer read-only gate runs for real (mocking the client would skip it)."""
    adapter = ProxmoxAdapter(host="192.0.2.1", username="root", password="x", port=8006)
    client = _make_client()
    mock_response = MagicMock(status_code=200, text='{"data": "UPID:task"}')
    mock_response.json.return_value = {"data": "UPID:task"}
    client._http = AsyncMock()
    client._http.is_closed = False
    client._http.request = AsyncMock(return_value=mock_response)
    client._authenticated = True
    adapter._client = client
    adapter._connected = True
    return adapter, client


class TestConfirmedDirectDeleteHonorsReadOnly:
    """Regression for the verified read-only bypass (audit: 3/3 verifiers,
    severity HIGH). A CONFIRMED direct ``delete_vm`` must NOT reach the cluster
    while read-only is ON: ``confirmed`` (the type-to-confirm second factor) and
    ``force`` (the staging read-only bypass) are decoupled — confirmed alone
    clears but never sets force, so the client read-only gate still bites."""

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_confirmed_delete_still_refused_under_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.delete_vm("pve1", 100, "qemu", confirmed=True)
        client._http.request.assert_not_called()  # never hit the wire

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_unconfirmed_delete_asks_to_confirm(self) -> None:
        adapter, _ = _make_connected_adapter()
        with pytest.raises(AdapterConfirmationRequiredError):
            await adapter.delete_vm("pve1", 100, "qemu")

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: False)
    async def test_confirmed_delete_proceeds_in_read_write(self) -> None:
        adapter, client = _make_connected_adapter()
        result = await adapter.delete_vm("pve1", 100, "qemu", confirmed=True)
        assert result.success
        client._http.request.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_staging_force_still_bypasses_read_only(self) -> None:
        """The sanctioned staging path (force=True) is unchanged — it writes even
        under read-only because the apply chokepoint enforces read-only upstream."""
        adapter, client = _make_connected_adapter()
        result = await adapter.delete_vm("pve1", 100, "qemu", force=True)
        assert result.success
        client._http.request.assert_awaited_once()


class TestConfirmedNodePowerHonorsReadOnly:
    """Node reboot/shutdown are catastrophic but operator-allowed via the
    type-to-confirm dialog. ``confirmed`` clears but never sets force,
    so the direct path still honors read-only (refused → 403); the staging
    applier's force=True path is unchanged."""

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_confirmed_reboot_refused_under_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.reboot_node("pve1", confirmed=True)
        client._http.request.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_unconfirmed_reboot_asks_to_confirm(self) -> None:
        adapter, _ = _make_connected_adapter()
        with pytest.raises(AdapterConfirmationRequiredError):
            await adapter.reboot_node("pve1")

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: False)
    async def test_confirmed_reboot_proceeds_in_read_write(self) -> None:
        adapter, client = _make_connected_adapter()
        result = await adapter.reboot_node("pve1", confirmed=True)
        assert result.success
        client._http.request.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_confirmed_shutdown_refused_under_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.shutdown_node("pve1", confirmed=True)
        client._http.request.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_staging_force_reboot_still_bypasses_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        result = await adapter.reboot_node("pve1", force=True)
        assert result.success
        client._http.request.assert_awaited_once()


class TestConfirmedGuestAgentHonorsReadOnly:
    """Guest-agent exec/file-write are RCE-class but operator-allowed via an
    explicit confirmed second factor. confirmed clears the gate but never
    sets force, so they are still refused while read-only is ON (monitor-only runs
    no guest commands/writes); the staging force=True path is unchanged."""

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_confirmed_exec_refused_under_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.agent_exec("pve1", 100, "ls /", confirmed=True)
        client._http.request.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_unconfirmed_exec_asks_to_confirm(self) -> None:
        adapter, _ = _make_connected_adapter()
        with pytest.raises(AdapterConfirmationRequiredError):
            await adapter.agent_exec("pve1", 100, "ls /")

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: False)
    async def test_confirmed_exec_proceeds_in_read_write(self) -> None:
        adapter, client = _make_connected_adapter()
        result = await adapter.agent_exec("pve1", 100, "ls /", confirmed=True)
        assert result.success
        client._http.request.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_confirmed_file_write_refused_under_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.agent_file_write("pve1", 100, "/tmp/x", "data", confirmed=True)
        client._http.request.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.adapters.proxmox.client._is_adapter_read_only", lambda: True)
    async def test_staging_force_exec_still_bypasses_read_only(self) -> None:
        adapter, client = _make_connected_adapter()
        result = await adapter.agent_exec("pve1", 100, "ls /", force=True)
        assert result.success
        client._http.request.assert_awaited_once()


# ── Tagged breaker ───────────────────────────────────────────────


class TestTaggedBreaker:
    def test_breaker_starts_closed_with_labels(self) -> None:
        client = _make_client()
        assert client._circuit.state == "closed"
        assert client._circuit.name == "proxmox"
        assert client._circuit.host.startswith("192.0.2.1")


# ── Vendor isolation (no cross-adapter read-only) ──────────────────


class TestReadOnlyVendorIsolation:
    """The Proxmox gate must consult ONLY ``ADAPTER_READ_ONLY`` — never the
    Omada flag. A prior copy-paste OR'd in ``OMADA_READ_ONLY`` (default True),
    so the documented ``ADAPTER_READ_ONLY=false`` toggle could not actually
    enable Proxmox writes (and the refusal message never mentioned it). Matches
    the OPNsense/pfSense/MikroTik gates, which already dropped the cross-OR."""

    def test_omada_flag_does_not_re_engage_read_only(self) -> None:
        from app.adapters.proxmox import client as pc
        from app.core import config

        with (
            patch.object(config.settings, "ADAPTER_READ_ONLY", False),
            patch.object(config.settings, "OMADA_READ_ONLY", True, create=True),
        ):
            # Writes opted-in via ADAPTER_READ_ONLY=false; the Omada flag must
            # NOT drag Proxmox back into read-only.
            assert pc._is_adapter_read_only() is False

    def test_adapter_read_only_true_engages(self) -> None:
        from app.adapters.proxmox import client as pc
        from app.core import config

        with patch.object(config.settings, "ADAPTER_READ_ONLY", True):
            assert pc._is_adapter_read_only() is True
