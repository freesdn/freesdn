# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A second authorization lookup must not widen a previously approved operation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.fabric.execution import OperationResult
from app.core.fabric.negotiator import Connection, ConnectionStep, Negotiator
from app.core.fabric.operations import Operation, OperationTier
from app.core.site_access import resolve_actor_site_grants
from app.services.automation import Action, ActionType, AutomationEngine


def session_for(user=None, error=False):
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    db.execute = AsyncMock(return_value=result)
    if error:
        db.execute.side_effect = RuntimeError("synthetic-private-scope-lookup-detail")
    db.commit = AsyncMock()
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    return db


def active_author():
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        role="org_admin",
        is_active=True,
        deleted_at=None,
        site_access=[],
    )


@pytest.mark.parametrize("failure", ["database", "missing", "inactive", "deleted"])
async def test_unresolved_authority_never_becomes_unrestricted(failure, caplog):
    author = active_author()
    if failure == "inactive":
        author.is_active = False
    elif failure == "deleted":
        author.deleted_at = object()
    db = session_for(None if failure == "missing" else author, error=failure == "database")
    with pytest.raises(PermissionError) as caught:
        await resolve_actor_site_grants(db, author.id)
    assert "synthetic-private-scope-lookup-detail" not in str(caught.value)
    assert "synthetic-private-scope-lookup-detail" not in caplog.text


async def test_missing_identity_remains_neutral_for_explicit_permission_free_operations():
    db = session_for(error=True)
    assert await resolve_actor_site_grants(db, None) is None
    db.execute.assert_not_awaited()


@pytest.mark.parametrize("caller", ["automation", "connection"])
async def test_grant_lookup_outage_refuses_after_permission_success(monkeypatch, caller):
    org, actor = uuid4(), uuid4()
    operation = Operation(
        id="owned.scope-read",
        title="Owned read",
        permission="device:read",
        tier=OperationTier.NATIVE,
        provider_id="owned",
        handler=lambda _ctx: None,
    )
    registry = SimpleNamespace(get_operation=lambda _name: operation)
    execute = AsyncMock(return_value=OperationResult.ok(output={"owned": True}))
    executor = SimpleNamespace(execute=execute, _artifacts=None)
    permission = AsyncMock(return_value=True)
    db = session_for(error=True)
    if caller == "connection":
        negotiator = Negotiator(
            registry, executor, permission_checker=permission, session_factory=lambda: db
        )
        conn = Connection(
            id="owned",
            organization_id=org,
            actor_id=actor,
            name="Owned",
            source_event="owned.event",
            steps=[ConnectionStep(operation_id=operation.id)],
        )
        result = await negotiator.run_once(conn, {})
        success = result["success"]
    else:
        monkeypatch.setattr(
            "app.core.fabric.registry.fabric_registry.get_operation", registry.get_operation
        )
        monkeypatch.setattr("app.core.fabric.executor.operation_executor.execute", execute)
        monkeypatch.setattr("app.core.fabric.runtime.fabric_permission_checker", permission)
        monkeypatch.setattr("app.db.async_session_factory", lambda: db)
        result = await AutomationEngine()._execute_action(
            Action(action_type=ActionType.FABRIC_OPERATION, params={"operation_id": operation.id}),
            {"organization_id": str(org), "actor_id": str(actor)},
        )
        success = result.success
    permission.assert_awaited_once()
    db.execute.assert_awaited_once()
    assert success is False
    execute.assert_not_awaited()


async def test_permission_checker_refuses_soft_deleted_active_author(monkeypatch):
    from app.core.fabric.runtime import fabric_permission_checker

    author = active_author()
    author.deleted_at = object()
    monkeypatch.setattr("app.db.session.async_session_factory", lambda: session_for(author))
    assert (
        await fabric_permission_checker(author.id, "device:read", author.organization_id) is False
    )
