# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Admission, repeated cancellation and failure retrieval for owned operations."""

import asyncio
import contextvars
import logging
import threading

import anyio
import pytest

from app.core.owned_async import complete_before_cancellation


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("cancellation", ["none", "task", "scope"])
async def test_admitted_operation_drains_with_original_context_and_safe_failure(
    caplog, request, failure, cancellation,
):
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    context = contextvars.ContextVar("owned_context", default="missing")
    context.set("owned request identity")
    observations = {}
    error = OSError("owned provider detail must not enter the diagnostic")
    scope_holder = []

    def actual_worker():
        observations["worker_context_preserved"] = context.get() == "owned request identity"
        entered.set()
        try:
            if not release.wait(5):
                observations["escape_fired"] = True
            if failure:
                raise error
            return b"owned exact result"
        finally:
            finished.set()

    @complete_before_cancellation
    async def operation():
        return await anyio.to_thread.run_sync(actual_worker)

    async def owner():
        with anyio.CancelScope() as scope:
            scope_holder.append(scope)
            result = await operation()
            await anyio.lowlevel.checkpoint()
            return result

    with caplog.at_level(logging.WARNING, logger="app.core.owned_async"):
        task = asyncio.create_task(owner())
        try:
            with anyio.fail_after(10):
                while not entered.is_set():
                    await asyncio.sleep(0.005)
            accepted = []
            if cancellation == "task":
                for _ in range(3):
                    accepted.append(task.cancel())
                    await asyncio.sleep(0.01)
            elif cancellation == "scope":
                scope_holder[0].cancel()
            await asyncio.sleep(0.02)
            observations.update(
                owner_ended_while_worker_active=task.done(),
                worker_still_active=not finished.is_set(),
                accepted_cancel_calls=accepted,
            )
        finally:
            release.set()
        result = (await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10))[0]
    observations.update(
        worker_completed=finished.is_set(),
        result_type=type(result).__name__,
        exact_error_instance=result is error,
        safe_diagnostic="owned provider detail" not in caplog.text,
        original_callable_name=operation.__name__ == "operation",
        scope_cancel_called=scope_holder[0].cancel_called,
        scope_cancel_caught=scope_holder[0].cancelled_caught,
    )
    request.node.user_properties.extend(observations.items())
    assert observations["worker_context_preserved"] and observations["worker_still_active"]
    assert not observations.get("escape_fired", False)
    assert not observations["owner_ended_while_worker_active"] and observations["worker_completed"]
    assert observations["safe_diagnostic"] and observations["original_callable_name"]
    if cancellation == "task":
        assert observations["accepted_cancel_calls"] == [True, True, True]
        assert isinstance(result, asyncio.CancelledError)
        if failure:
            assert "Cancelled owned operation ended with OSError" in caplog.text
    elif cancellation == "scope":
        # The owned scope suppresses its own cancellation after work drains.
        # Pending cancellation must win over a captured ordinary worker error.
        assert result is None
        assert observations["scope_cancel_called"] and observations["scope_cancel_caught"]
        if failure:
            assert "Cancelled owned operation ended with OSError" in caplog.text
    elif failure:
        assert result is error
    elif cancellation == "none":
        assert result == b"owned exact result"


@pytest.mark.parametrize("cancellation", ["task", "scope"])
async def test_cancellation_before_admission_does_not_invoke_the_operation(request, cancellation):
    calls = []

    @complete_before_cancellation
    async def operation():
        calls.append("started")

    async def owner():
        with anyio.CancelScope() as scope:
            if cancellation == "task":
                asyncio.current_task().cancel()
            else:
                scope.cancel()
            await operation()

    result = (await asyncio.gather(asyncio.create_task(owner()), return_exceptions=True))[0]
    request.node.user_properties.extend([
        ("operation_never_invoked", not calls), ("caller_result_type", type(result).__name__),
    ])
    assert not calls
    if cancellation == "task":
        assert isinstance(result, asyncio.CancelledError)


async def test_owned_child_cancellation_propagates_without_spinning(request):
    entered = []

    @complete_before_cancellation
    async def operation():
        entered.append(True)
        raise asyncio.CancelledError("owned child cancelled")

    result = (await asyncio.wait_for(asyncio.gather(operation(), return_exceptions=True), 2))[0]
    request.node.user_properties.extend([
        ("operation_invoked_once", entered == [True]),
        ("child_cancellation_propagated", isinstance(result, asyncio.CancelledError)),
    ])
    assert entered == [True] and isinstance(result, asyncio.CancelledError)
