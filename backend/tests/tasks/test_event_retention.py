# SPDX-License-Identifier: AGPL-3.0-only
"""Guard destructive retention inputs and incomplete/failed sweep reporting.

The companion Docker probe verifies the SQL against actual Timescale chunks.
"""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import event_retention


@pytest.mark.parametrize("days", [False, True, 0, -1, 36501, 1.5, "90", None])
@pytest.mark.asyncio
async def test_invalid_retention_never_opens_database(days):
    factory = MagicMock()
    with pytest.raises(ValueError, match="retention days"):
        await event_retention.prune_event_history(factory, days)
    factory.assert_not_called()


def session_fixture(counts, remaining):
    session = MagicMock()
    session.scalar = AsyncMock(return_value=remaining)
    statements = []
    transactions = []

    @asynccontextmanager
    async def begin():
        try:
            yield
        except BaseException:
            transactions.append("rollback")
            raise
        else:
            transactions.append("commit")

    async def execute(statement):
        statements.append(statement)
        result = MagicMock()
        if statement.is_delete:
            count = next(counts)
            if isinstance(count, BaseException):
                raise count
            result.scalars.return_value.all.return_value = list(range(count))
        return result

    session.begin = begin
    session.execute = AsyncMock(side_effect=execute)
    factory = MagicMock()
    factory.return_value.__aenter__.return_value = session
    return factory, statements, transactions


@pytest.mark.asyncio
async def test_short_batch_with_locked_backlog_is_not_complete():
    factory, _, transactions = session_fixture(iter([0]), "locked-row")
    result = await event_retention.prune_event_history(factory)
    assert result["success"] is True
    assert result["deleted"] == 0
    assert result["remaining_expired"] is True
    assert result["complete"] is False
    assert transactions == ["commit", "commit"]


@pytest.mark.asyncio
async def test_batch_budget_leaves_backlog_visible(monkeypatch):
    monkeypatch.setattr(event_retention, "MAX_BATCHES", 2)
    factory, _, transactions = session_fixture(iter([1000, 1000]), "remaining-row")
    result = await event_retention.prune_event_history(factory)
    assert result["deleted"] == 2000
    assert result["batches"] == 2
    assert result["complete"] is False
    assert transactions == ["commit", "commit", "commit"]


@pytest.mark.asyncio
async def test_failure_does_not_report_success_or_undo_prior_batches():
    factory, _, transactions = session_fixture(iter([1000, RuntimeError("database failure")]), None)
    with pytest.raises(RuntimeError, match="database failure"):
        await event_retention.prune_event_history(factory)
    assert transactions == ["commit", "rollback"]


@pytest.mark.asyncio
async def test_time_budget_does_not_start_another_delete(monkeypatch):
    clock = iter([0, 201])
    monkeypatch.setattr(event_retention, "monotonic", lambda: next(clock))
    factory, statements, _ = session_fixture(iter([]), "expired-row")
    result = await event_retention.prune_event_history(factory)
    assert not any(s.is_delete for s in statements)
    assert result["deleted"] == result["batches"] == 0
    assert result["complete"] is False


@pytest.mark.asyncio
async def test_empty_table_is_complete():
    factory, _, _ = session_fixture(iter([0]), None)
    result = await event_retention.prune_event_history(factory)
    assert result["deleted"] == 0
    assert result["complete"] is True
