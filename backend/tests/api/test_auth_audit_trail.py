# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: the auth flow must populate the persistent security audit trail.

A capability audit found that the ``PersistentSecurityAuditService`` subsystem
(FailedLoginRecord / AuditLogRecord / security_events, surfaced by the Security
Audit page) had NO producer at the auth layer — ``record_failed_login`` and
``create_audit_log`` existed but were never called from login/logout/MFA/
password-change, so every forensic view read empty even though the live
brute-force protection (Redis windows + User.locked_until) worked fine.

These tests lock two things:
  1. the best-effort helpers actually write the right record and never raise; and
  2. each auth entry point is WIRED to the helpers (the precise gap).
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints import auth as auth_mod


class _FakeSession:
    """Stand-in for an AsyncSession context manager."""

    def __init__(self) -> None:
        self.commit = AsyncMock()
        self.rollback = AsyncMock()

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False


def _fake_request(
    ip: str = "203.0.113.7", ua: str = "pytest-agent", path: str = "/api/v1/auth/login"
):
    return SimpleNamespace(
        client=SimpleNamespace(host=ip),
        headers={"user-agent": ua},
        url=SimpleNamespace(path=path),
    )


@pytest.mark.asyncio
async def test_audit_failed_login_writes_record(monkeypatch):
    rec = AsyncMock()
    sess = _FakeSession()
    monkeypatch.setattr(
        "app.services.security_audit.PersistentSecurityAuditService.record_failed_login", rec
    )
    monkeypatch.setattr("app.db.session.audit_session_factory", lambda: sess)

    await auth_mod._audit_failed_login(
        identifier="alice@example.com", request=_fake_request(), reason="invalid_credentials"
    )

    assert rec.await_count == 1
    kwargs = rec.await_args.kwargs
    assert kwargs["username"] == "alice@example.com"
    assert kwargs["ip_address"] == "203.0.113.7"
    assert kwargs["user_agent"] == "pytest-agent"
    assert kwargs["reason"] == "invalid_credentials"
    assert sess.commit.await_count == 1  # the forensic write is committed


@pytest.mark.asyncio
async def test_audit_failed_login_is_best_effort(monkeypatch):
    """A forensic-write failure must never propagate into the auth response."""
    monkeypatch.setattr(
        "app.services.security_audit.PersistentSecurityAuditService.record_failed_login",
        AsyncMock(side_effect=RuntimeError("db down")),
    )
    monkeypatch.setattr("app.db.session.audit_session_factory", lambda: _FakeSession())

    # Must NOT raise.
    await auth_mod._audit_failed_login(identifier="x", request=_fake_request())


@pytest.mark.asyncio
async def test_audit_auth_event_writes_audit_log(monkeypatch):
    rec = AsyncMock()
    sess = _FakeSession()
    # Auth events join the tamper-evident chain via AuditService.log (not a
    # plain insert) — mock that writer.
    monkeypatch.setattr("app.services.audit.AuditService.log", rec)
    monkeypatch.setattr("app.db.session.audit_session_factory", lambda: sess)

    user = SimpleNamespace(id=uuid4(), email="op@example.com", organization_id=uuid4())
    await auth_mod._audit_auth_event(
        action="login", request=_fake_request(), user=user, method="mfa"
    )

    assert rec.await_count == 1
    kwargs = rec.await_args.kwargs
    assert kwargs["action"] == "login"
    assert kwargs["resource_type"] == "auth_session"
    assert kwargs["actor_id"] == user.id  # UUID, not str — AuditService.log expects UUID
    assert kwargs["actor_email"] == "op@example.com"
    assert kwargs["status"] == "success"
    assert kwargs["tags"] == ["auth", "mfa"]
    assert sess.commit.await_count == 1


@pytest.mark.asyncio
async def test_audit_auth_event_is_best_effort(monkeypatch):
    monkeypatch.setattr(
        "app.services.audit.AuditService.log",
        AsyncMock(side_effect=RuntimeError("db down")),
    )
    monkeypatch.setattr("app.db.session.audit_session_factory", lambda: _FakeSession())

    # Must NOT raise even with no user.
    await auth_mod._audit_auth_event(action="logout", request=_fake_request(), user=None)


def test_auth_entry_points_are_wired_to_the_trail():
    """The exact regression: every auth entry point must call the producers."""
    login_src = inspect.getsource(auth_mod.login)
    token_src = inspect.getsource(auth_mod.login_for_access_token)
    mfa_src = inspect.getsource(auth_mod.login_mfa)
    logout_src = inspect.getsource(auth_mod.logout)
    pw_src = inspect.getsource(auth_mod.change_password)

    # Failed-login forensic trail on all three credential-verifying paths.
    assert "_audit_failed_login" in login_src
    assert "_audit_failed_login" in token_src
    assert "_audit_failed_login" in mfa_src

    # Audit-log trail for success / logout / password change.
    assert "_audit_auth_event" in login_src
    assert "_audit_auth_event" in token_src
    assert "_audit_auth_event" in mfa_src
    assert "_audit_auth_event" in logout_src
    assert "_audit_auth_event" in pw_src
