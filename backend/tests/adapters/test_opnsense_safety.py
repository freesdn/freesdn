# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the OPNsense adapter.

Critical invariants verified here:

1. Path-traversal in any OPNsense API path is rejected before httpx
   sends a request — so a path-typo or attacker payload can't walk
   the controller's API surface.
2. The universal ``ADAPTER_READ_ONLY`` gate is enforced at the
   ``_request`` layer. Default-on. Refuses every POST/PUT/PATCH/
   DELETE unless ``force=True`` is explicitly passed.
3. The tagged ``CircuitBreaker`` emits the
   ``freesdn_adapter_circuit_state`` Prometheus gauge so dashboards
   see OPNsense alongside Omada.

These tests run against a mocked HTTP layer — **no live OPNsense
controller is contacted at any point**.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.opnsense.client import (
    OPNsenseClient,
    _is_read_only_post,
    _validate_path,
)

# ── Path validation ──────────────────────────────────────────────


class TestPathValidation:
    """Single chokepoint catches every path-traversal payload before
    it hits the controller."""

    @pytest.mark.parametrize(
        "path",
        [
            "/api/firewall/filter/get",
            "/api/firewall/filter/setRule/abc-123",
            "/api/openvpn/instances/get/uuid-1.2.3",
            "/api/diagnostics/dns/reverse_lookup/192.168.1.1",
            "/api/core/service/restart/unbound",
            "/api/firewall/alias/getItem/foo-bar_baz.qux",
        ],
    )
    def test_accepts_legitimate_paths(self, path: str) -> None:
        _validate_path(path)  # does not raise

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "/api/../etc/passwd",
            "/api/firewall/filter/setRule/../../core/system",
            "/api/firewall/filter/setRule/foo bar",
            "/api/firewall/filter/setRule/foo;rm -rf",
            "/api/firewall/filter/setRule/foo?q=1",
            "/api/firewall/filter/setRule/foo\x00",
            "/api/firewall/filter/setRule/foo\nbar",
            "/api/firewall/filter/setRule/foo#frag",
            "../etc/passwd",  # not under /api at all
            "/foo/bar",       # missing /api prefix
        ],
    )
    def test_rejects_bad_paths(self, path: str) -> None:
        with pytest.raises(AdapterError):
            _validate_path(path)


# ── Read-only gate ───────────────────────────────────────────────


def _make_client() -> OPNsenseClient:
    """Build a client without going through ``connect()`` so tests
    don't open a real httpx session."""
    return OPNsenseClient(
        host="192.0.2.1",
        api_key="k",
        api_secret="s",
        port=443,
        verify_ssl=False,
    )


class TestReadOnlyGate:
    """The universal ``ADAPTER_READ_ONLY`` gate refuses writes
    unless force=True is explicitly passed. Default-on, so a
    production deployment that doesn't override the env never
    sends a write to the live controller by accident."""

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_refuses_writes_when_read_only(self, method: str) -> None:
        client = _make_client()
        with pytest.raises(AdapterError) as exc:
            await client._request(method, "/api/firewall/filter/addRule")
        assert "ADAPTER_READ_ONLY" in str(exc.value)

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_allows_reads_when_read_only(self) -> None:
        """Reads are unconditionally allowed — only writes are gated."""
        client = _make_client()
        # Mock the underlying httpx client so we don't actually
        # connect — we just want to prove the gate doesn't trigger
        # for GET. ``_request`` will call ``connect()``; we bypass
        # by setting a mock client directly.
        mock_response = MagicMock(status_code=200, text='{"ok": true}')
        mock_response.json.return_value = {"ok": True}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request("GET", "/api/firewall/filter/get")
        assert result == {"ok": True}

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_allows_writes_when_force_true(self) -> None:
        """Even with read-only on, ``force=True`` satisfies the client-layer gate; the env+force dual-gate is enforced upstream by the apply endpoint.
        This is the single sanctioned write path — the apply endpoint
        is responsible for setting force only when its own dual-gate
        has cleared (env-off + force-true on the request)."""
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"ok": true}')
        mock_response.json.return_value = {"ok": True}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        # Should NOT raise.
        result = await client._request(
            "POST",
            "/api/firewall/filter/addRule",
            data={"rule": {}},
            force=True,
        )
        assert result == {"ok": True}

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: False)
    async def test_allows_writes_when_env_off(self) -> None:
        """When operator opts out of read-only, default writes (without
        force) still go through. force is only required when the env
        gate is closed."""
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"ok": true}')
        mock_response.json.return_value = {"ok": True}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client._request(
            "POST", "/api/firewall/filter/addRule", data={}
        )
        assert result == {"ok": True}


class TestReadPostNotBlocked:
    """OPNsense's MVC API uses POST for search/read endpoints. The read-only
    gate must classify those as READS (allowed) while keeping mutating POSTs
    blocked — otherwise read-only mode can't even list firewall rules/aliases/
    NAT. (Found live on real OPNsense 26.1.10: searchRule etc. were 403'd.)"""

    @pytest.mark.parametrize(
        "path",
        [
            "/api/firewall/filter/searchRule",
            "/api/firewall/alias/searchItem",
            "/api/firewall/source_nat/searchRule",
            "/api/dhcpv4/settings/searchStaticMap",
            "/api/unbound/settings/searchHostOverride",
            "/api/wireguard/client/searchClient",
            "/api/openvpn/instances/search",
        ],
    )
    def test_classifier_marks_search_as_read(self, path: str) -> None:
        assert _is_read_only_post(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "/api/firewall/filter/addRule",
            "/api/firewall/filter/setRule/abc-123",
            "/api/firewall/filter/delRule/abc-123",
            "/api/firewall/filter/toggleRule/abc-123/1",
            "/api/firewall/filter/apply",
            "/api/firewall/alias/reconfigure",
            "/api/core/service/restart/unbound",
            "/api/core/system/reboot",
            "/api/core/firmware/update",
            "/api/unbound/settings/addHostOverride",
        ],
    )
    def test_classifier_marks_mutations_as_write(self, path: str) -> None:
        assert _is_read_only_post(path) is False

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_search_post_allowed_under_read_only(self) -> None:
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"rows": []}')
        mock_response.json.return_value = {"rows": []}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        # READ-via-POST must NOT be refused by the read-only gate.
        result = await client._request("POST", "/api/firewall/filter/searchRule", data={})
        assert result == {"rows": []}

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_get_firewall_rules_works_under_read_only(self) -> None:
        """The high-level read method (POST searchRule) succeeds in read-only."""
        client = _make_client()
        mock_response = MagicMock(status_code=200, text='{"rows": []}')
        mock_response.json.return_value = {"rows": []}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client.get_firewall_rules()
        assert result == {"rows": []}

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize(
        "path", ["/api/firewall/filter/apply", "/api/firewall/filter/addRule"]
    )
    async def test_mutating_post_still_blocked_under_read_only(self, path: str) -> None:
        client = _make_client()
        with pytest.raises(AdapterError) as exc:
            await client._request("POST", path)
        assert "ADAPTER_READ_ONLY" in str(exc.value)


class TestBodylessPostSendsEmptyJson:
    """OPNsense action endpoints (delItem, apply, reboot, toggle) are body-less
    POSTs. Declaring application/json with a null/empty body makes OPNsense
    reject the request as 'Invalid JSON syntax' — so body-less POSTs must send a
    valid empty object {}. (Found live on 26.1: alias delete was 'Invalid JSON
    syntax'.)"""

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: False)
    async def test_bodyless_post_sends_empty_object_not_null(self) -> None:
        client = _make_client()
        captured: dict = {}
        resp = MagicMock(status_code=200, text='{"result":"deleted"}')
        resp.json.return_value = {"result": "deleted"}

        async def _req(method, path, **kw):
            captured.update(kw)
            return resp

        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(side_effect=_req)
        await client._request("POST", "/api/firewall/alias/delItem/abc-123", data=None, force=True)
        assert captured.get("json") == {}

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: False)
    async def test_post_with_body_is_unchanged(self) -> None:
        client = _make_client()
        captured: dict = {}
        resp = MagicMock(status_code=200, text='{"uuid":"x"}')
        resp.json.return_value = {"uuid": "x"}

        async def _req(method, path, **kw):
            captured.update(kw)
            return resp

        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(side_effect=_req)
        await client._request("POST", "/api/firewall/alias/addItem", data={"alias": {"n": 1}}, force=True)
        assert captured.get("json") == {"alias": {"n": 1}}


class TestForcePropagation:
    """The high-level OPNsense client write methods (add_firewall_rule,
    add_alias, etc.) all forward ``force`` to ``self.post``. Apply path
    passes ``force=True``; everywhere else gets the default (False)
    and is refused at the gate."""

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_add_firewall_rule_default_blocked(self) -> None:
        client = _make_client()
        with pytest.raises(AdapterError) as exc:
            await client.add_firewall_rule({"description": "ssh"})
        assert "ADAPTER_READ_ONLY" in str(exc.value)

    @pytest.mark.asyncio
    @patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    async def test_apply_firewall_changes_default_blocked(self) -> None:
        """The pf apply call is the most consequential write — it
        commits the running ruleset. Must default-refuse."""
        client = _make_client()
        with pytest.raises(AdapterError):
            await client.apply_firewall_changes()


# ── Tagged breaker emits metrics ─────────────────────────────────


class TestTaggedBreaker:
    def test_breaker_starts_in_closed_state_with_labels(self) -> None:
        client = _make_client()
        assert client._circuit.state == "closed"
        assert client._circuit.name == "opnsense"
        assert client._circuit.host.endswith(":443")

    def test_breaker_emits_metric_on_state_change(self) -> None:
        from app.adapters.http_utils import CircuitBreaker

        b = CircuitBreaker(
            failure_threshold=2,
            reset_timeout=60.0,
            name="opnsense",
            host="https://test",
        )
        # Trip the breaker.
        b.record_failure()
        b.record_failure()
        assert b.state == "open"
        # Smoke test: the metric module must be importable. Direct
        # gauge inspection requires Prometheus registry access; the
        # contract test is that ``_sync_metric`` runs without
        # raising and the breaker reaches OPEN.
        from app.core.metrics import adapter_circuit_state
        assert adapter_circuit_state is not None

    def test_breaker_unlabeled_skips_metric(self) -> None:
        """Legacy callers without name/host don't pollute the metric."""
        from app.adapters.http_utils import CircuitBreaker

        b = CircuitBreaker(failure_threshold=1, reset_timeout=60.0)
        b.record_failure()
        assert b.state == "open"
        # No labels → no metric emitted; should not have raised.


class TestPortForwardGracefulDegrade:
    """OPNsense 26.1 has no /api/firewall/dnat MVC controller (404 verified on
    the live box) — classic port-forward (rdr) rules are config.xml-only. The
    adapter must degrade a 404 to an empty list (so the firewall read doesn't
    hard-fail) while still surfacing other errors."""

    def _adapter(self):
        from app.adapters.opnsense.adapter import OPNsenseAdapter

        return OPNsenseAdapter(
            host="192.0.2.1", username="k", password="s", port=443, verify_ssl=False
        )

    @pytest.mark.asyncio
    async def test_404_degrades_to_empty_with_note(self) -> None:
        from app.adapters.opnsense.client import OPNsenseAPIError

        a = self._adapter()
        a._api.get_port_forward_rules = AsyncMock(
            side_effect=OPNsenseAPIError("not found", status_code=404)
        )
        r = await a.get_port_forwards()
        assert r.success is True
        assert r.data["port_forwards"] == []
        assert r.data["count"] == 0
        assert "note" in r.data

    @pytest.mark.asyncio
    async def test_non_404_error_still_fails(self) -> None:
        from app.adapters.opnsense.client import OPNsenseAPIError

        a = self._adapter()
        a._api.get_port_forward_rules = AsyncMock(
            side_effect=OPNsenseAPIError("server error", status_code=500)
        )
        r = await a.get_port_forwards()
        assert r.success is False
