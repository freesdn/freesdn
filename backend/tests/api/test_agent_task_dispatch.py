# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``POST /agents/{id}/tasks`` created a task and never delivered it.

The endpoint INSERTed an AgentTask row and returned 200. The only consumer of a
PENDING AgentTask is ``GET /agents/{id}/tasks/pending``, documented as "called
by the agent process to poll for work" -- and the shipped agent never calls it.
It wires ``ws_client.on_command`` straight to its TaskExecutor and receives work
exclusively over the socket. There is no poller and there never was.

So a task created here sat at PENDING for ever. Confirmed against a live daemon,
connected and heartbeating:

    POST /agents/{id}/tasks  -> 200
    ...36 seconds later      -> still "pending"

This is the SAME bug ``POST /discovery/agent-scan`` had and fixed; the sibling
endpoint was never updated. That fix is the model followed here.

MY FIRST ATTEMPT AT IT WAS ALSO WRONG, in a way worth recording. Sending the
command is not enough: ``register_interactive_task`` is what makes the agent's
action_result and scan_progress reports mirror back into the agent_tasks row.
Without it the command really does run on the agent and the task STILL sits at
PENDING -- indistinguishable from never having been dispatched, which is exactly
the symptom I was trying to fix. After adding it:

    POST /agents/{id}/tasks  -> 200
    ...seconds later         -> "completed", with the agent's result attached
"""

from __future__ import annotations

import inspect


def _src() -> str:
    from app.api.v1.endpoints.agents import create_task

    return inspect.getsource(create_task)


def _body() -> str:
    """Source without comments -- the explanation above names every symbol."""
    return "\n".join(ln for ln in _src().splitlines() if not ln.strip().startswith("#"))


def test_the_task_is_actually_sent():
    body = _body()
    assert "send_command(" in body, "the endpoint still only records the task"
    assert "AgentCommand(" in body


def test_the_result_is_mirrored_back_to_the_row():
    """
    Without this the command runs and the row never leaves PENDING, which looks
    identical to no dispatch at all.
    """
    body = _body()
    assert "register_interactive_task(" in body


def test_registration_happens_before_the_send():
    """
    A result arriving between send and register would be dropped, leaving the
    task pending for a command that already ran.
    """
    body = _body()
    assert body.index("register_interactive_task(") < body.index("send_command(")


def test_a_failed_send_unregisters_and_fails_the_task():
    """
    Leaving it registered leaks the id, and leaving it PENDING tells the caller
    to keep waiting for something that will never arrive.
    """
    body = _body()
    after = body.split("except Exception", 1)[1]
    assert "unregister_interactive_task(" in after
    assert "AgentTaskStatus.FAILED" in after


def test_a_disconnected_agent_is_reported_not_silently_queued():
    """
    409 rather than a 200 and a task id that never moves. The row is left
    PENDING on purpose -- the agent may reconnect, and a scheduled task is not
    late yet -- but the caller is told.
    """
    body = _body()
    assert "HTTP_409_CONFLICT" in body
    assert "no active WebSocket connection" in body


def test_a_task_type_with_no_command_twin_is_refused():
    """
    AgentTaskType and AgentCommandType overlap but are NOT the same set. Sending
    a name the agent has no handler for only earns an "Unknown command type"
    report, so it is refused up front instead.
    """
    body = _body()
    assert "AgentCommandType(" in body
    assert "HTTP_400_BAD_REQUEST" in body


def test_the_two_vocabularies_still_overlap_where_it_matters():
    """
    Pins the actual relationship rather than assuming it. Every command the
    shipped agent implements must exist in AgentCommandType, or the backend
    could not ask for it at all.
    """
    import re
    from pathlib import Path

    from app.services.remote_agent import AgentCommandType

    for parent in Path(__file__).resolve().parents:
        candidate = parent / "agent" / "src" / "freesdn_agent" / "services" / "task_executor.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover - backend-only checkout
        import pytest

        pytest.skip("the agent source is not present in this checkout")

    handlers = set(
        re.findall(r'"([a-z_]+)":', re.search(r"_HANDLERS = \{(.*?)\}", src, re.S).group(1))
    )
    known = {c.value for c in AgentCommandType}
    orphans = sorted(handlers - known)
    assert not orphans, f"the agent handles commands the backend cannot name: {orphans}"
