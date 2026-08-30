# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: the conversation history window must keep the NEWEST messages.

The history query read ``ORDER BY created_at ASC LIMIT 50`` under a comment that
said "Keep last 50 messages for context". Ascending + limit returns the OLDEST
50, so once a conversation passed the cap the model stopped seeing the most
recent turns -- including the user's immediately preceding question and the
assistant's answer -- and reasoned from stale context, repeated actions, or
contradicted the current state. Tool-calling hits the cap sooner because one
turn can persist an assistant tool-call message plus several tool results.

Two behaviours are pinned here:

* the query orders DESC (newest first) and is reversed into chronological order,
  so the window is the newest N;
* a window whose boundary lands mid-tool-exchange does not emit a ``tool``
  message whose originating assistant ``tool_calls`` fell outside it, which a
  provider rejects as an invalid sequence.

No DB, no provider: the statement is captured and compiled for assertion.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.modules.ai.service import (
    HISTORY_MESSAGE_LIMIT,
    AIChatService,
    _drop_orphaned_tool_prefix,
)


class _StopAfterHistory(Exception):
    """Raised by the fake session once the history statement is captured."""


def _compiled(stmt) -> str:
    return str(stmt.compile(compile_kwargs={"literal_binds": False}))


@pytest.mark.asyncio
async def test_history_query_takes_the_newest_messages(monkeypatch) -> None:
    """The history SELECT must be DESC + LIMIT (newest), not ASC + LIMIT (oldest).

    Fails before the fix: the compiled statement carried ``ORDER BY
    ai_messages.created_at ASC``.
    """
    monkeypatch.setattr("app.modules.ai.tools.load_tools", MagicMock())

    conversation = SimpleNamespace(id=uuid4(), provider="openai", model="test-model")
    captured: dict[str, object] = {}
    calls = {"n": 0}

    async def fake_execute(stmt):
        calls["n"] += 1
        if calls["n"] == 1:  # conversation lookup
            return SimpleNamespace(scalar_one_or_none=lambda: conversation)
        captured["stmt"] = stmt  # the history window
        raise _StopAfterHistory

    db = MagicMock()
    db.execute = AsyncMock(side_effect=fake_execute)

    user = SimpleNamespace(id=uuid4(), organization_id=uuid4())

    with pytest.raises(_StopAfterHistory):
        await AIChatService().chat(
            user=user,
            db=db,
            message="what changed since my last question?",
            conversation_id=conversation.id,
        )

    sql = _compiled(captured["stmt"]).upper()
    assert "ORDER BY" in sql, "history query lost its ordering"
    order_clause = sql.split("ORDER BY", 1)[1]
    assert "DESC" in order_clause, (
        "history query must order DESC and be reversed in memory; ASC + LIMIT "
        f"selects the OLDEST {HISTORY_MESSAGE_LIMIT} messages. Got: {order_clause.strip()[:120]}"
    )
    assert "ASC" not in order_clause.split("LIMIT")[0], (
        f"history ordering still ascending: {order_clause.strip()[:120]}"
    )


def test_reversing_a_desc_window_yields_chronological_order() -> None:
    """DESC rows reversed must read oldest -> newest within the window."""
    newest_first = [SimpleNamespace(role="user", content=str(i)) for i in range(60, 10, -1)]
    chronological = list(reversed(newest_first))
    assert [m.content for m in chronological][:3] == ["11", "12", "13"]
    assert [m.content for m in chronological][-1] == "60"
    assert len(chronological) == HISTORY_MESSAGE_LIMIT


def _msg(role: str, content: str = "x"):
    return SimpleNamespace(role=role, content=content, tool_calls=None, tool_call_id="c", tool_name="t")


def test_orphaned_tool_results_at_window_head_are_dropped() -> None:
    """A window starting mid-tool-exchange must not lead with tool results.

    A provider rejects a ``tool`` message not preceded by the assistant message
    carrying the matching ``tool_calls``.
    """
    history = [_msg("tool"), _msg("tool"), _msg("assistant"), _msg("user")]
    trimmed = _drop_orphaned_tool_prefix(history)
    assert [m.role for m in trimmed] == ["assistant", "user"]


def test_intact_history_is_not_trimmed() -> None:
    """A window that already starts on a complete turn is returned unchanged."""
    history = [_msg("user"), _msg("assistant"), _msg("tool"), _msg("assistant")]
    trimmed = _drop_orphaned_tool_prefix(history)
    assert [m.role for m in trimmed] == ["user", "assistant", "tool", "assistant"]
    assert trimmed is history  # no copy when nothing to drop


def test_all_tool_history_collapses_to_empty() -> None:
    """Degenerate window of nothing but orphaned results yields no messages."""
    assert _drop_orphaned_tool_prefix([_msg("tool"), _msg("tool")]) == []
