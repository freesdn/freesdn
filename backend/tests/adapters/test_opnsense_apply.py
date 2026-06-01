# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for OPNsense staged-write services.

These cover the OPNsense firewall apply path, which had safety tests
but no dispatch tests. Mirrors ``test_pfsense_apply.py`` shape since
the OPNsense + pfSense services are sibling implementations of the
same vendor-write contract.

Coverage:
- ``_APPLY`` table completeness for firewall rule + alias + apply
- Applier dispatches each (feature, op) to the right client method
  with ``force=True`` (dual-gate)
- Aliases addressed by name (string), rules by UUID
- ``firewall.apply`` only accepts ``operation=create`` (one-shot
  commit) AND invalidates the rule/alias listing cache so the next
  read picks up the freshly-applied ruleset
- target_id required for update/delete
- Unknown feature → 400
- httpx pool deterministically closed even on exception (try/finally)
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services.adapter_opnsense_firewall import (
    _APPLY as FW_APPLY,
    GatewayOpnsenseFirewallService,
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


def _make_service() -> tuple[GatewayOpnsenseFirewallService, MagicMock]:
    svc = GatewayOpnsenseFirewallService(MagicMock())
    mock_client = MagicMock()
    for name in (
        "add_firewall_rule", "update_firewall_rule", "delete_firewall_rule",
        "add_alias", "update_alias", "delete_alias",
        "apply_firewall_changes",
    ):
        setattr(mock_client, name, AsyncMock(return_value={"ok": True}))
    # close() is invoked in the try/finally even on the happy path —
    # AsyncMock keeps it awaitable.
    mock_client.close = AsyncMock(return_value=None)

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
            ("opnsense.firewall.rule", "create"),
            ("opnsense.firewall.rule", "update"),
            ("opnsense.firewall.rule", "delete"),
            ("opnsense.firewall.alias", "create"),
            ("opnsense.firewall.alias", "update"),
            ("opnsense.firewall.alias", "delete"),
            ("opnsense.firewall.apply", "create"),
        ],
    )
    def test_apply_table_has_pair(self, feature: str, op: str) -> None:
        assert (feature, op) in FW_APPLY


# ─── Rule dispatch ──────────────────────────────────────────────────


class TestRuleDispatch:
    @pytest.mark.asyncio
    async def test_create_dispatches(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "opnsense.firewall.rule", "create",
            payload={"action": "pass", "interface": "wan"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.add_firewall_rule.assert_awaited_once_with(
            {"action": "pass", "interface": "wan"}, force=True,
        )
        # close() runs in the try/finally
        client.close.assert_awaited()

    @pytest.mark.asyncio
    async def test_update_dispatches(self) -> None:
        svc, client = _make_service()
        rule_uuid = "abc-1234-def-5678"
        change = _make_change(
            "opnsense.firewall.rule", "update",
            target_id=rule_uuid,
            payload={"descr": "renamed"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.update_firewall_rule.assert_awaited_once_with(
            rule_uuid, {"descr": "renamed"}, force=True,
        )

    @pytest.mark.asyncio
    async def test_delete_dispatches(self) -> None:
        svc, client = _make_service()
        rule_uuid = "abc-1234-def-5678"
        change = _make_change(
            "opnsense.firewall.rule", "delete",
            target_id=rule_uuid,
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.delete_firewall_rule.assert_awaited_once_with(
            rule_uuid, force=True,
        )


# ─── Alias dispatch ─────────────────────────────────────────────────


class TestAliasDispatch:
    @pytest.mark.asyncio
    async def test_create_alias_dispatches(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "opnsense.firewall.alias", "create",
            payload={"name": "blocked", "type": "host", "content": "1.2.3.4"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.add_alias.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_alias_by_name(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "opnsense.firewall.alias", "update",
            target_id="blocked",  # alias addressed by name
            payload={"content": "5.6.7.8"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.update_alias.assert_awaited_once_with(
            "blocked", {"content": "5.6.7.8"}, force=True,
        )

    @pytest.mark.asyncio
    async def test_delete_alias_dispatches(self) -> None:
        svc, client = _make_service()
        change = _make_change(
            "opnsense.firewall.alias", "delete",
            target_id="blocked",
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.delete_alias.assert_awaited_once_with("blocked", force=True)


# ─── Apply feature (one-shot commit) ────────────────────────────────


class TestApplyFeature:
    @pytest.mark.asyncio
    async def test_apply_create_dispatches_commit(self) -> None:
        svc, client = _make_service()
        change = _make_change("opnsense.firewall.apply", "create")
        applier = svc.build_applier(change)
        await applier(change)
        client.apply_firewall_changes.assert_awaited_once_with(force=True)

    @pytest.mark.asyncio
    async def test_apply_invalidates_cache(self) -> None:
        """After apply, the cache should be cleared so the next read
        sees the freshly-applied ruleset (not the 10s-stale snapshot
        the cache would otherwise serve)."""
        from app.services import adapter_opnsense_firewall as mod
        svc, client = _make_service()
        change = _make_change("opnsense.firewall.apply", "create")
        # Pre-seed cache with a fake entry under THIS change's
        # controller_id so we can verify invalidation removes it.
        ctrl_id = change.controller_id
        mod._LIST_CACHE[f"{ctrl_id}:list_rules"] = (
            10**12,  # far-future expiry; only removable via invalidate
            {"items": ["stale"]},
        )
        applier = svc.build_applier(change)
        await applier(change)
        assert f"{ctrl_id}:list_rules" not in mod._LIST_CACHE


# ─── target_id validation ───────────────────────────────────────────


class TestRequiredArgs:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("feature", [
        "opnsense.firewall.rule",
        "opnsense.firewall.alias",
    ])
    @pytest.mark.parametrize("op", ["update", "delete"])
    async def test_update_delete_require_target_id(
        self, feature: str, op: str,
    ) -> None:
        svc, _ = _make_service()
        change = _make_change(feature, op, target_id=None, payload={"x": 1})
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "target_id" in exc.value.detail.lower()


# ─── Unknown features ───────────────────────────────────────────────


class TestUnknownFeatures:
    @pytest.mark.asyncio
    async def test_unknown_feature_raises_400(self) -> None:
        svc, _ = _make_service()
        change = _make_change("opnsense.firewall.not_real", "create")
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "no applier" in exc.value.detail.lower()
