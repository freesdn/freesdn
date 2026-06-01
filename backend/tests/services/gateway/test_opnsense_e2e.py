# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""End-to-end stage -> apply -> verify for OPNsense firewall writes.

Exercises the FULL sanctioned write path through the real apply chokepoint
(``AdapterStagingService.apply_change`` building the firewall service's applier):
the dual-gate, the NEW catastrophic-op preflight gate, force=True propagation to
the client, status transition to ``applied``, cache invalidation on commit, and a
verify-read reflecting the change. Mocked session + client — no live device.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.staging import AdapterPendingChange
from app.services.adapter_opnsense_firewall import (
    _LIST_CACHE,
    GatewayOpnsenseFirewallService,
    _cache_key,
    _cache_put,
)
from app.services.adapter_staging import AdapterStagingService


def _make_session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    count = MagicMock()
    count.scalar.return_value = 0
    session.execute = AsyncMock(return_value=count)
    session.get = AsyncMock(return_value=None)
    return session


def _make_change(*, feature, operation, payload=None, target_id=None) -> AdapterPendingChange:
    return AdapterPendingChange(
        id=uuid4(), organization_id=uuid4(), controller_id=uuid4(), site_id=None,
        omada_site_id="s", feature=feature, operation=operation,
        target_id=target_id, payload=payload or {}, status="pending", notes=None,
    )


def _fw_service(client: MagicMock) -> GatewayOpnsenseFirewallService:
    fw = GatewayOpnsenseFirewallService(MagicMock())

    async def _resolve(*_a, **_k):
        return MagicMock()

    async def _get_client(*_a, **_k):
        return client

    fw._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    fw._get_client = _get_client  # type: ignore[assignment]
    return fw


def _staging_for(change: AdapterPendingChange) -> AdapterStagingService:
    session = _make_session()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=change)
    )
    return AdapterStagingService(session)


@pytest.fixture(autouse=True)
def _gate_open(monkeypatch):
    # Env gate opened (operator opted in); the per-call force + preflight gate
    # are what these tests actually exercise.
    from app.services import adapter_staging

    monkeypatch.setattr(
        adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
    )


class TestOpnsenseFirewallE2E:
    @pytest.mark.asyncio
    async def test_rule_create_stage_apply_verify(self) -> None:
        client = MagicMock()
        client.add_firewall_rule = AsyncMock(return_value={"uuid": "rule-1", "result": "saved"})
        client.get_firewall_rules = AsyncMock(
            return_value={"rows": [{"uuid": "rule-1", "description": "allow ssh"}]}
        )
        client.close = AsyncMock()
        fw = _fw_service(client)
        change = _make_change(
            feature="opnsense.firewall.rule", operation="create",
            payload={"description": "allow ssh"},
        )
        applied = await _staging_for(change).apply_change(
            change.id, force=True, applier=fw.build_applier(change)
        )
        # Safe create passes the preflight gate; write dispatched with force=True.
        client.add_firewall_rule.assert_awaited_once_with({"description": "allow ssh"}, force=True)
        assert applied.status == "applied"
        # verify-read reflects the new rule.
        rules = await client.get_firewall_rules()
        assert any(r["uuid"] == "rule-1" for r in rules["rows"])

    @pytest.mark.asyncio
    async def test_rule_delete_blocked_without_confirmation(self) -> None:
        # The preflight gate is enforced INSIDE apply_change — a delete without
        # confirmed=true is 409'd before the applier touches the device.
        client = MagicMock()
        client.delete_firewall_rule = AsyncMock(return_value={"result": "deleted"})
        client.close = AsyncMock()
        fw = _fw_service(client)
        change = _make_change(
            feature="opnsense.firewall.rule", operation="delete", target_id="rule-1", payload={}
        )
        with pytest.raises(HTTPException) as exc:
            await _staging_for(change).apply_change(
                change.id, force=True, applier=fw.build_applier(change)
            )
        assert exc.value.status_code == 409
        client.delete_firewall_rule.assert_not_awaited()
        assert change.status == "pending"

    @pytest.mark.asyncio
    async def test_rule_delete_with_confirmation_applies(self) -> None:
        client = MagicMock()
        client.delete_firewall_rule = AsyncMock(return_value={"result": "deleted"})
        client.close = AsyncMock()
        fw = _fw_service(client)
        change = _make_change(
            feature="opnsense.firewall.rule", operation="delete",
            target_id="rule-1", payload={},
        )
        # Confirmation is an apply-time decision (the request flag), not staged data.
        applied = await _staging_for(change).apply_change(
            change.id, force=True, confirmed=True, applier=fw.build_applier(change)
        )
        client.delete_firewall_rule.assert_awaited_once_with("rule-1", force=True)
        assert applied.status == "applied"

    @pytest.mark.asyncio
    async def test_apply_commit_invalidates_cache(self) -> None:
        client = MagicMock()
        client.apply_firewall_changes = AsyncMock(return_value={"status": "ok"})
        client.close = AsyncMock()
        fw = _fw_service(client)
        change = _make_change(feature="opnsense.firewall.apply", operation="create", payload={})
        _cache_put(change.controller_id, "get_firewall_rules", [{"uuid": "stale"}])
        assert _cache_key(change.controller_id, "get_firewall_rules") in _LIST_CACHE
        applied = await _staging_for(change).apply_change(
            change.id, force=True, applier=fw.build_applier(change)
        )
        client.apply_firewall_changes.assert_awaited_once_with(force=True)
        assert applied.status == "applied"
        # The commit invalidates this controller's cached listings.
        assert _cache_key(change.controller_id, "get_firewall_rules") not in _LIST_CACHE
