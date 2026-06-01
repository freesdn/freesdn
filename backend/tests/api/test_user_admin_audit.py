# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: admin account-management mutations must write the audit trail.

A capability audit found ``users.py`` (create / update / delete user, including
role changes) wrote NO audit log — the Security Audit page never recorded who
created, modified, or deleted an account, or escalated a role. These lock the
wiring and prove the helper routes through the tamper-evident ``AuditService.log``
chain best-effort.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints import users as users_mod


def _fake_request(method: str = "POST", path: str = "/api/v1/users/"):
    return SimpleNamespace(
        client=SimpleNamespace(host="198.51.100.4"),
        headers={"user-agent": "pytest-agent"},
        url=SimpleNamespace(path=path),
        method=method,
    )


def test_user_mutations_are_wired_to_audit():
    """The exact gap: every account-admin mutation must call the audit helper."""
    for fn in (users_mod.create_user, users_mod.update_user, users_mod.delete_user):
        assert "_audit_user_change" in inspect.getsource(fn), fn.__name__


@pytest.mark.asyncio
async def test_audit_user_change_writes_chained_log(monkeypatch):
    rec = AsyncMock()
    monkeypatch.setattr("app.services.audit.AuditService.log", rec)

    actor = SimpleNamespace(id=uuid4(), email="admin@example.com")
    target = SimpleNamespace(id=uuid4(), email="newhire@example.com", organization_id=uuid4())

    await users_mod._audit_user_change(
        session=MagicMock(),
        request=_fake_request(),
        action="user.create",
        actor=actor,
        target=target,
        changes={"role": "viewer"},
    )

    assert rec.await_count == 1
    kwargs = rec.await_args.kwargs
    assert kwargs["action"] == "user.create"
    assert kwargs["resource_type"] == "user"
    assert kwargs["actor_id"] == actor.id
    assert kwargs["resource_id"] == target.id
    assert kwargs["organization_id"] == target.organization_id
    assert kwargs["changes"] == {"role": "viewer"}


@pytest.mark.asyncio
async def test_audit_user_change_is_best_effort(monkeypatch):
    monkeypatch.setattr(
        "app.services.audit.AuditService.log", AsyncMock(side_effect=RuntimeError("db down"))
    )
    # Must NOT raise — an audit failure can never break the account operation.
    await users_mod._audit_user_change(
        session=MagicMock(),
        request=_fake_request(),
        action="user.delete",
        actor=SimpleNamespace(id=uuid4(), email="a@b.com"),
        target=SimpleNamespace(id=uuid4(), email="c@d.com", organization_id=None),
    )
