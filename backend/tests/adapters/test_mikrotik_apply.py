# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
apply-path tests for the three previously stage-only MikroTik
features:

- ``mikrotik.system.identity`` (update)  → ``set_system_identity``
- ``mikrotik.system.ntp`` (update)        → ``set_ntp_client``
- ``mikrotik.firewall.filter_reorder``    → ``move_firewall_filter_rule``

The tests cover three angles per feature:

1. Client method shape — exists on ``MikroTikClient`` and accepts
   ``force=`` (the dual-gate would silently drop force=True otherwise).
2. Apply dispatch — the service's ``build_applier`` resolves the
   feature to the right client method via ``_APPLY``.
3. Validation — the service rejects malformed payloads with HTTP 400
   instead of forwarding garbage to the router.

The HTTP layer is mocked at the ``client._client.request`` boundary so
no live router is touched.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.mikrotik.client import MikroTikClient
from app.services.adapter_mikrotik_firewall import (
    _APPLY as FIREWALL_APPLY,
)
from app.services.adapter_mikrotik_firewall import (
    GatewayMikrotikFirewallService,
)
from app.services.adapter_mikrotik_system import (
    _APPLY as SYSTEM_APPLY,
)
from app.services.adapter_mikrotik_system import (
    GatewayMikrotikSystemService,
)

# ────────────────────────────────────────────────────────────────────
# Client method existence + signature shape
# ────────────────────────────────────────────────────────────────────


class TestClientMethodsExist:
    """Each new apply target must exist on ``MikroTikClient`` and
    accept ``force``. ``test_mikrotik_safety.TestApplyMethodsAcceptForce``
    already loops over all services; these are explicit per-method
    sanity checks for the additions."""

    @pytest.mark.parametrize(
        "method_name",
        [
            "set_system_identity",
            "set_ntp_client",
            "move_firewall_filter_rule",
        ],
    )
    def test_method_exists_and_takes_force(self, method_name: str) -> None:
        method = getattr(MikroTikClient, method_name, None)
        assert method is not None, (
            f"MikroTikClient is missing {method_name!r} — wiring "
            "incomplete"
        )
        sig = inspect.signature(method)
        assert "force" in sig.parameters, (
            f"{method_name!r} must accept ``force=`` so the dual-gate at "
            "the client layer doesn't refuse the sanctioned write"
        )

    def test_apply_table_includes_identity(self) -> None:
        assert ("mikrotik.system.identity", "update") in SYSTEM_APPLY
        assert SYSTEM_APPLY[("mikrotik.system.identity", "update")] == (
            "set_system_identity"
        )

    def test_apply_table_includes_ntp(self) -> None:
        assert ("mikrotik.system.ntp", "update") in SYSTEM_APPLY
        assert SYSTEM_APPLY[("mikrotik.system.ntp", "update")] == (
            "set_ntp_client"
        )

    def test_apply_table_includes_filter_reorder(self) -> None:
        assert (
            "mikrotik.firewall.filter_reorder",
            "update",
        ) in FIREWALL_APPLY
        assert FIREWALL_APPLY[
            ("mikrotik.firewall.filter_reorder", "update")
        ] == "move_firewall_filter_rule"


# ────────────────────────────────────────────────────────────────────
# Apply-path dispatch
# ────────────────────────────────────────────────────────────────────


def _make_change(feature: str, operation: str, **kw: Any) -> SimpleNamespace:
    """Build a change-shaped object the applier accepts. The applier
    only reads ``feature``, ``operation``, ``payload``, ``target_id``,
    ``controller_id``, and ``organization_id`` off the model, so a
    namespace is sufficient."""
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _make_system_service_with_mock_client() -> tuple[
    GatewayMikrotikSystemService, MagicMock
]:
    """Build a system service with stubbed controller-lookup + client."""
    svc = GatewayMikrotikSystemService(MagicMock())
    mock_client = MagicMock()
    # The applier calls these via ``client.<method>(args..., force=True)``.
    mock_client.set_system_identity = AsyncMock(return_value={"ok": True})
    mock_client.set_ntp_client = AsyncMock(return_value={"ok": True})

    async def _resolve(*_args: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_client(*_args: Any, **_kw: Any) -> Any:
        return mock_client

    # The vendor services were migrated to ``_resolve_controller_or_gateway``
    # in; stub both names so test mocks survive the rename and
    # remain effective whether the production code path took the legacy
    # or the new method.
    svc._get_controller = _resolve  # type: ignore[assignment]
    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_client = _get_client  # type: ignore[assignment]
    return svc, mock_client


def _make_firewall_service_with_mock_client() -> tuple[
    GatewayMikrotikFirewallService, MagicMock
]:
    svc = GatewayMikrotikFirewallService(MagicMock())
    mock_client = MagicMock()
    mock_client.move_firewall_filter_rule = AsyncMock(return_value={"ok": True})
    # IDOR guard calls ``get_firewall_filter_rules``
    # to verify each target_id before dispatching update/delete/move.
    # Tests pre-populate the list with the rids they exercise.
    mock_client.get_firewall_filter_rules = AsyncMock(return_value=[
        {".id": "*1"}, {".id": "*2"}, {".id": "*3"},
    ])
    mock_client.get_firewall_nat_rules = AsyncMock(return_value=[
        {".id": "*1"}, {".id": "*2"},
    ])
    mock_client.get_firewall_mangle_rules = AsyncMock(return_value=[
        {".id": "*1"}, {".id": "*2"},
    ])
    mock_client.get_firewall_address_lists = AsyncMock(return_value=[
        {".id": "*1"}, {".id": "*2"},
    ])

    async def _resolve(*_args: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_client(*_args: Any, **_kw: Any) -> Any:
        return mock_client

    svc._get_controller = _resolve  # type: ignore[assignment]
    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_client = _get_client  # type: ignore[assignment]
    return svc, mock_client


class TestSystemIdentityApply:
    @pytest.mark.asyncio
    async def test_dispatches_to_set_system_identity_with_force(self) -> None:
        svc, client = _make_system_service_with_mock_client()
        change = _make_change(
            "mikrotik.system.identity",
            "update",
            payload={"name": "edge-01"},
        )
        applier = svc.build_applier(change)
        result = await applier(change)
        assert result == {"ok": True}
        client.set_system_identity.assert_awaited_once_with(
            "edge-01", force=True
        )

    @pytest.mark.asyncio
    async def test_rejects_missing_name(self) -> None:
        svc, _ = _make_system_service_with_mock_client()
        change = _make_change(
            "mikrotik.system.identity", "update", payload={}
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_control_chars_in_name(self) -> None:
        svc, _ = _make_system_service_with_mock_client()
        change = _make_change(
            "mikrotik.system.identity",
            "update",
            payload={"name": "evil\nname"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "control" in str(exc.value.detail).lower()

    @pytest.mark.asyncio
    async def test_rejects_overlong_name(self) -> None:
        svc, _ = _make_system_service_with_mock_client()
        change = _make_change(
            "mikrotik.system.identity",
            "update",
            payload={"name": "x" * 40},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "too long" in str(exc.value.detail).lower()


class TestSystemNtpApply:
    @pytest.mark.asyncio
    async def test_dispatches_to_set_ntp_client_with_force(self) -> None:
        svc, client = _make_system_service_with_mock_client()
        payload = {
            "primary-ntp": "10.0.0.1",
            "secondary-ntp": "10.0.0.2",
            "enabled": "yes",
        }
        change = _make_change(
            "mikrotik.system.ntp", "update", payload=payload
        )
        applier = svc.build_applier(change)
        result = await applier(change)
        assert result == {"ok": True}
        client.set_ntp_client.assert_awaited_once_with(payload, force=True)

    @pytest.mark.asyncio
    async def test_rejects_unknown_payload_key(self) -> None:
        svc, _ = _make_system_service_with_mock_client()
        change = _make_change(
            "mikrotik.system.ntp",
            "update",
            payload={"primary-ntp": "10.0.0.1", "evil-key": "x"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "disallowed" in str(exc.value.detail).lower()


class TestFirewallFilterReorderApply:
    @pytest.mark.asyncio
    async def test_dispatches_moves_in_order(self) -> None:
        svc, client = _make_firewall_service_with_mock_client()
        change = _make_change(
            "mikrotik.firewall.filter_reorder",
            "update",
            payload={"order": ["*1", "*2", "*3"]},
        )
        applier = svc.build_applier(change)
        result = await applier(change)
        assert result["moved"] == 3
        # The first two moves carry the next rule as destination; the
        # last move drops destination so RouterOS lands it at the end.
        calls = client.move_firewall_filter_rule.await_args_list
        assert len(calls) == 3
        # Move 1: *1 before *2
        assert calls[0].args == ("*1", "*2")
        assert calls[0].kwargs == {"force": True}
        # Move 2: *2 before *3
        assert calls[1].args == ("*2", "*3")
        assert calls[1].kwargs == {"force": True}
        # Move 3: *3 → end (destination=None)
        assert calls[2].args == ("*3", None)
        assert calls[2].kwargs == {"force": True}

    @pytest.mark.asyncio
    async def test_rejects_empty_order_array(self) -> None:
        svc, _ = _make_firewall_service_with_mock_client()
        change = _make_change(
            "mikrotik.firewall.filter_reorder",
            "update",
            payload={"order": []},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_non_string_ids(self) -> None:
        svc, _ = _make_firewall_service_with_mock_client()
        change = _make_change(
            "mikrotik.firewall.filter_reorder",
            "update",
            payload={"order": ["*1", 42]},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400


# ────────────────────────────────────────────────────────────────────
# Client-level dual-gate (write_refused) for the new methods
# ────────────────────────────────────────────────────────────────────


class TestClientLevelGate:
    """The new client methods must refuse writes when the read-only
    gate is engaged AND force=False — same as every other write method
    in the adapter. The applier passes force=True; this verifies the
    gate would catch any caller that forgot to."""

    def _make_client(self) -> MikroTikClient:
        return MikroTikClient(
            host="192.0.2.1",
            username="admin",
            password="x",
            port=443,
            verify_ssl=False,
        )

    @pytest.mark.asyncio
    @patch(
        "app.adapters.mikrotik.client._is_adapter_read_only",
        lambda: True,
    )
    async def test_set_system_identity_refused_without_force(self) -> None:
        from app.adapters.exceptions import AdapterError

        client = self._make_client()
        with pytest.raises(AdapterError):
            await client.set_system_identity("evil-rename")

    @pytest.mark.asyncio
    @patch(
        "app.adapters.mikrotik.client._is_adapter_read_only",
        lambda: True,
    )
    async def test_set_ntp_client_refused_without_force(self) -> None:
        from app.adapters.exceptions import AdapterError

        client = self._make_client()
        with pytest.raises(AdapterError):
            await client.set_ntp_client({"primary-ntp": "10.0.0.1"})

    @pytest.mark.asyncio
    @patch(
        "app.adapters.mikrotik.client._is_adapter_read_only",
        lambda: True,
    )
    async def test_move_firewall_filter_rule_refused_without_force(
        self,
    ) -> None:
        from app.adapters.exceptions import AdapterError

        client = self._make_client()
        with pytest.raises(AdapterError):
            await client.move_firewall_filter_rule("*1", "*2")

    @pytest.mark.asyncio
    @patch(
        "app.adapters.mikrotik.client._is_adapter_read_only",
        lambda: True,
    )
    async def test_set_system_identity_allowed_with_force(self) -> None:
        client = self._make_client()
        mock_response = MagicMock(status_code=200, text='{"ok": true}')
        mock_response.json.return_value = {"ok": True}
        client._client = AsyncMock()
        client._client.is_closed = False
        client._client.request = AsyncMock(return_value=mock_response)
        result = await client.set_system_identity("renamed", force=True)
        assert result == {"ok": True}
        # Verify the wire format: RouterOS REST uses POST /<path>/set
        # for singleton updates (NOT PATCH — verified against real CHR
        # 7.21.3, which returns 400 "missing or invalid resource
        # identifier" for PATCH on singletons).
        call = client._client.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/system/identity/set")
        assert call.kwargs["json"] == {"name": "renamed"}
