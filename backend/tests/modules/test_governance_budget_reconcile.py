# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Budget reservation-reconciliation regression tests.

REGRESSION (correctness review — "pre-increment decoupling"):

The AI budget is enforced with a Redis *reservation*: ``check_token_budget``
pre-increments the org's monthly counter by an ESTIMATE before the LLM call, so
concurrent requests can't race past the cap. After the call we know the ACTUAL
token usage and must reconcile:

* **success** → set the counter to actual: release ``estimated - actual``
  (``_redis_budget_rollback`` with a possibly-negative delta — negative means the
  actual exceeded the estimate, so we *add* the difference).
* **failure** → release the WHOLE reservation (nothing was spent).

The bug: ``execute_structured`` recorded the actual usage to the DB on success
but never reconciled the Redis reservation, so every successful call leaked
``estimated - actual`` into the monthly counter — it inflated unboundedly and
eventually false-rejected a tenant well under their real budget. These tests
pin both arms (success reconcile, failure full-release) so it can't regress.

Everything is mocked — no Redis, no DB, no LLM provider is contacted.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.modules.ai.governance import LLMGovernanceService, LLMOperation


def _patch_governance(monkeypatch, svc: LLMGovernanceService) -> AsyncMock:
    """Stub every governance layer except the budget reconcile under test;
    return the ``_redis_budget_rollback`` spy."""
    monkeypatch.setattr(svc, "check_global_kill_switch", MagicMock())
    monkeypatch.setattr(svc, "get_org_policy", AsyncMock(return_value=object()))
    monkeypatch.setattr(svc, "check_org_policy", MagicMock())
    monkeypatch.setattr(svc, "check_provider_allowed", MagicMock())
    monkeypatch.setattr(svc, "check_token_budget", AsyncMock())  # the reservation
    monkeypatch.setattr(svc, "log_call", AsyncMock())
    monkeypatch.setattr(svc, "record_token_usage", AsyncMock())
    monkeypatch.setattr(svc, "_build_structured_prompt", MagicMock(return_value="prompt"))
    rollback = AsyncMock()
    monkeypatch.setattr(svc, "_redis_budget_rollback", rollback)
    return rollback


def _patch_provider(monkeypatch, *, usage, raises: bool = False) -> None:
    """Point ``AIChatService._get_provider`` at a fake provider whose ``chat``
    either returns a response carrying ``usage`` or raises."""
    import app.modules.ai.service as service_mod

    if raises:
        chat = AsyncMock(side_effect=RuntimeError("provider exploded"))
    else:
        response = SimpleNamespace(content="ok", usage=usage, model="test-model")
        chat = AsyncMock(return_value=response)
    fake_provider = SimpleNamespace(chat=chat)
    monkeypatch.setattr(
        service_mod.AIChatService,
        "_get_provider",
        AsyncMock(return_value=fake_provider),
    )


@pytest.mark.asyncio
async def test_success_reconciles_redis_reservation_down_to_actual(monkeypatch) -> None:
    svc = LLMGovernanceService()
    rollback = _patch_governance(monkeypatch, svc)
    # input_text = "one two three" -> 3 words -> estimated = 3 * 2 = 6.
    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5)  # actual = 15
    _patch_provider(monkeypatch, usage=usage)

    org_id = uuid4()
    await svc.execute_structured(
        MagicMock(),  # db (unused — all DB-touching layers are stubbed)
        org_id=org_id,
        operation=LLMOperation.CLASSIFY,
        input_data={"text": "one two three"},
        provider_id="openai",
    )

    # Actual (15) recorded to the DB...
    svc.record_token_usage.assert_awaited_once()
    assert svc.record_token_usage.await_args.args[2] == 15
    # ...and the reservation reconciled by (estimated - actual) = 6 - 15 = -9
    # (negative delta -> the actual exceeded the estimate, so the counter is
    # bumped UP by 9 rather than leaking the estimate).
    rollback.assert_awaited_once_with(org_id, 6 - 15)


@pytest.mark.asyncio
async def test_failure_releases_full_reservation(monkeypatch) -> None:
    svc = LLMGovernanceService()
    rollback = _patch_governance(monkeypatch, svc)
    _patch_provider(monkeypatch, usage=None, raises=True)

    org_id = uuid4()
    with pytest.raises(RuntimeError):
        await svc.execute_structured(
            MagicMock(),
            org_id=org_id,
            operation=LLMOperation.CLASSIFY,
            input_data={"text": "one two three"},  # estimated = 6
            provider_id="openai",
        )

    # Nothing was spent -> no DB usage recorded, full reservation released.
    svc.record_token_usage.assert_not_awaited()
    rollback.assert_awaited_once_with(org_id, 6)
