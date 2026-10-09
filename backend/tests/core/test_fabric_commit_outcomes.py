# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Do not report persistence success after a failed or uncertain commit."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.fabric.negotiator import Connection, ConnectionStep, Negotiator
from tests.core.fabric_fakes import SharedClaims


def configured(step_success=True, *, commit_error=None, rollback_error=None):
    db = SimpleNamespace(
        commit=AsyncMock(side_effect=commit_error),
        rollback=AsyncMock(side_effect=rollback_error),
    )
    context = SimpleNamespace(__aenter__=AsyncMock(return_value=db), __aexit__=AsyncMock())
    engine = Negotiator(session_factory=lambda: context)
    engine._redis = SharedClaims()
    conn = Connection(
        id=str(uuid4()),
        organization_id=uuid4(),
        name="Persistence check",
        source_event="owned.event",
        steps=[ConnectionStep(operation_id="owned.operation")],
    )
    engine.add_connection(conn)
    step = {
        "operation_id": "owned.operation",
        "success": step_success,
        "effect_receipt": "already-returned-by-handler",
    }
    if not step_success:
        step.update(error="Step refused", error_code="OPERATION_REFUSED")
    engine._run_step = AsyncMock(return_value=step)
    return engine, conn, db, context, step


@pytest.mark.parametrize("error_type", [RuntimeError, ConnectionError, TimeoutError])
@pytest.mark.parametrize("step_success", [True, False])
@pytest.mark.parametrize("rollback_fails", [True, False])
async def test_commit_failure_is_unconfirmed_without_erasing_step_outcome(
    error_type,
    step_success,
    rollback_fails,
    caplog,
):
    secret = "PRIVATE_DATABASE_CREDENTIAL_IN_EXCEPTION"
    engine, conn, db, context, step = configured(
        step_success,
        commit_error=error_type(secret),
        rollback_error=RuntimeError(secret) if rollback_fails else None,
    )
    result = await engine.run_once(conn, {})
    assert result["success"] is False
    assert result["error_code"] == "COMMIT_FAILED"
    assert result["commit_status"] == "unconfirmed"
    assert "effects may already have occurred" in result["error"]
    assert result["steps"] == [step]
    assert result["steps"][0]["success"] is step_success
    assert secret not in repr(result) and secret not in caplog.text
    db.commit.assert_awaited_once()
    db.rollback.assert_awaited_once()
    context.__aexit__.assert_awaited_once()
    engine._run_step.assert_awaited_once()


@pytest.mark.parametrize("step_success", [True, False])
async def test_successful_commit_preserves_prior_operation_result(step_success):
    engine, conn, db, context, step = configured(step_success)
    result = await engine.run_once(conn, {})
    assert result["success"] is step_success
    assert result["steps"] == [step]
    assert "error_code" not in result and "commit_status" not in result
    db.commit.assert_awaited_once()
    db.rollback.assert_not_awaited()
    context.__aexit__.assert_awaited_once()


async def test_cancellation_during_commit_is_not_reported_as_success():
    engine, conn, db, context, _ = configured(commit_error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await engine.run_once(conn, {})
    db.commit.assert_awaited_once()
    context.__aexit__.assert_awaited_once()


async def test_automatic_audit_gets_failure_and_no_replay_after_commit_uncertainty():
    engine, conn, db, _, step = configured(commit_error=TimeoutError("private-commit-reply"))
    recorder = AsyncMock()
    engine._run_recorder = recorder
    event = SimpleNamespace(
        id=str(uuid4()),
        event_type=conn.source_event,
        organization_id=str(conn.organization_id),
        payload={},
    )
    runs = await engine.handle_event(event)
    assert len(runs) == 1 and runs[0]["success"] is False
    assert runs[0]["error_code"] == "COMMIT_FAILED"
    assert runs[0]["steps"] == [step]
    recorder.assert_awaited_once()
    assert recorder.await_args.args[1] is runs[0]
    assert await engine.handle_event(event) == []
    db.commit.assert_awaited_once()
    engine._run_step.assert_awaited_once()


async def test_no_session_for_pure_operation_retains_existing_behavior():
    engine, conn, db, context, step = configured()
    engine._session_factory = lambda: None
    result = await engine.run_once(conn, {})
    assert result["success"] and result["steps"] == [step]
    db.commit.assert_not_awaited()
    context.__aenter__.assert_not_awaited()
