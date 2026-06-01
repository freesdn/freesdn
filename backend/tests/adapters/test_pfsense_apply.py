# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for pfSense staged-write services.

These cover the pfSense firewall apply path, which had safety tests
but no dispatch tests. Mirrors ``test_openwrt_apply.py`` shape.

Coverage:
- ``_APPLY`` table completeness
- Applier dispatches each (feature, op) to the right client method
  with ``force=True`` (pfSense client's dual-gate requires it)
- ``firewall.rule`` auto-applies after create/update/delete so a
  single staged change takes effect without a separate
  ``firewall.apply`` change
- ``firewall.apply`` only accepts ``operation=create``
- target_id must be numeric for rule update/delete
- Aliases addressed by name (string)
- Unknown feature → 400
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services.adapter_pfsense_firewall import (
    _APPLY as FW_APPLY,
    GatewayPfsenseFirewallService,
)


def _make_change(
    feature: str, operation: str, **kw: Any,
) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _make_service() -> tuple[GatewayPfsenseFirewallService, MagicMock]:
    svc = GatewayPfsenseFirewallService(MagicMock())
    mock_client = MagicMock()
    for name in (
        "add_firewall_rule", "update_firewall_rule", "delete_firewall_rule",
        "add_alias", "update_alias", "delete_alias",
        "apply_firewall_changes",
    ):
        setattr(mock_client, name, AsyncMock(return_value={"ok": True}))

    async def _resolve(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_client(*_a: Any, **_kw: Any) -> Any:
        return mock_client

    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_client = _get_client  # type: ignore[assignment]
    return svc, mock_client


# ─── _APPLY completeness ────────────────────────────────────────────


class TestApplyTableCompleteness:
    @pytest.mark.parametrize(
        "feature,op",
        [
            ("pfsense.firewall.rule", "create"),
            ("pfsense.firewall.rule", "update"),
            ("pfsense.firewall.rule", "delete"),
            ("pfsense.firewall.alias", "create"),
            ("pfsense.firewall.alias", "update"),
            ("pfsense.firewall.alias", "delete"),
            ("pfsense.firewall.apply", "create"),
        ],
    )
    def test_apply_table_has_pair(self, feature: str, op: str) -> None:
        assert (feature, op) in FW_APPLY


# ─── Rule dispatch ──────────────────────────────────────────────────


class TestRuleDispatch:
    @pytest.mark.asyncio
    async def test_create_dispatches_and_auto_applies(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.rule", "create",
            payload={"action": "pass", "interface": "wan"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.add_firewall_rule.assert_awaited_once_with(
            {"action": "pass", "interface": "wan"}, force=True,
        )
        # Auto-apply runs after create (pfSense rules invisible until
        # filter ruleset commits).
        client.apply_firewall_changes.assert_awaited_once_with(force=True)

    @pytest.mark.asyncio
    async def test_update_dispatches_with_numeric_id(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.rule", "update",
            target_id="42",
            payload={"descr": "renamed"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.update_firewall_rule.assert_awaited_once_with(
            42, {"descr": "renamed"}, force=True,
        )
        client.apply_firewall_changes.assert_awaited_once_with(force=True)

    @pytest.mark.asyncio
    async def test_delete_dispatches_with_numeric_id(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.rule", "delete",
            target_id="7",
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.delete_firewall_rule.assert_awaited_once_with(7, force=True)
        client.apply_firewall_changes.assert_awaited_once_with(force=True)

    @pytest.mark.asyncio
    async def test_update_without_target_id_raises_400(self) -> None:
        svc, _ = _make_service()
        change = _make_change(
            "pfsense.firewall.rule", "update",
            target_id=None,
            payload={"descr": "x"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "target_id" in exc.value.detail.lower()

    @pytest.mark.asyncio
    async def test_update_with_non_numeric_target_id_raises_400(self) -> None:
        svc, _ = _make_service()
        change = _make_change(
            "pfsense.firewall.rule", "update",
            target_id="not-a-number",
            payload={"descr": "x"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "numeric" in exc.value.detail.lower()


# ─── Alias dispatch ─────────────────────────────────────────────────


class TestAliasDispatch:
    @pytest.mark.asyncio
    async def test_create_alias_dispatches(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.alias", "create",
            payload={"name": "blocked_ips", "type": "host", "address": "1.2.3.4"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.add_alias.assert_awaited_once()
        client.apply_firewall_changes.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_alias_addresses_by_name(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.alias", "update",
            target_id="blocked_ips",  # alias addressed by name, not numeric id
            payload={"address": "5.6.7.8"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.update_alias.assert_awaited_once_with(
            "blocked_ips", {"address": "5.6.7.8"}, force=True,
        )

    @pytest.mark.asyncio
    async def test_delete_alias_without_target_id_raises_400(self) -> None:
        svc, _ = _make_service()
        change = _make_change(
            "pfsense.firewall.alias", "delete",
            target_id=None,
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400


# ─── Apply feature (one-shot commit) ────────────────────────────────


class TestApplyFeature:
    @pytest.mark.asyncio
    async def test_apply_create_dispatches_commit(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "pfsense.firewall.apply", "create",
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.apply_firewall_changes.assert_awaited_once_with(force=True)

    @pytest.mark.asyncio
    async def test_apply_with_wrong_operation_raises_400(self) -> None:
        svc, _ = _make_service()
        for bad_op in ("update", "delete"):
            change = _make_change("pfsense.firewall.apply", bad_op)
            applier = svc.build_applier(change)
            with pytest.raises(HTTPException) as exc:
                await applier(change)
            assert exc.value.status_code == 400


# ─── Unknown features ───────────────────────────────────────────────


class TestUnknownFeatures:
    @pytest.mark.asyncio
    async def test_unknown_feature_raises_400(self) -> None:
        svc, _ = _make_service()
        change = _make_change("pfsense.firewall.not_real", "create")
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "no applier" in exc.value.detail.lower()
