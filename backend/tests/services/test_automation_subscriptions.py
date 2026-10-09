# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Repeated reads and rule edits must not keep duplicate or obsolete patterns."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.automation import (
    AutomationEngine,
    AutomationRule,
    AutomationService,
    RuleStatus,
    TriggerType,
)


def rule(pattern="owned.old"):
    return AutomationRule(
        id=uuid4(),
        name="Owned subscription",
        description=None,
        organization_id=uuid4(),
        trigger_type=TriggerType.EVENT,
        trigger_config={"event_pattern": pattern},
        conditions=None,
        actions=[],
        status=RuleStatus.ACTIVE,
        cooldown_seconds=0,
    )


def service_for(engine, item):
    record = SimpleNamespace(
        **{
            **vars(item),
            "trigger_type": item.trigger_type.value,
            "status": item.status.value,
            "actions": [],
        }
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = record
    db = SimpleNamespace(execute=AsyncMock(return_value=result), flush=AsyncMock())
    return AutomationService(db, engine), record


async def test_repeated_reads_dispatch_one_action_chain():
    engine = AutomationEngine()
    item = rule()
    service, _ = service_for(engine, item)
    for _ in range(4):
        await service.get_rule(item.id)
    engine._check_throttle = AsyncMock(return_value=True)
    engine._execute_rule = AsyncMock(return_value=SimpleNamespace(id=uuid4()))
    result = await engine.process_event("owned.old", {}, event_org_id=str(item.organization_id))
    assert len(result) == 1
    engine._execute_rule.assert_awaited_once()


@pytest.mark.parametrize("pattern", ["owned.old", "owned.new"])
async def test_replacement_removes_the_previous_pattern(pattern):
    engine = AutomationEngine()
    item = rule()
    await engine.register_rule(item)
    changed = replace(item, trigger_config={"event_pattern": pattern})
    await engine.register_rule(changed)
    assert engine._find_matching_rules("owned.old") == ([changed] if pattern == "owned.old" else [])
    assert engine._find_matching_rules(pattern) == [changed]


@pytest.mark.parametrize("new_config", [{}, {"event_pattern": ""}])
async def test_blank_replacement_cannot_keep_old_actions_subscribed(new_config):
    engine = AutomationEngine()
    item = rule()
    await engine.register_rule(item)
    await engine.register_rule(replace(item, trigger_config=new_config))
    assert engine._find_matching_rules("owned.old") == []
    assert engine._unsubscribed_rules[item.id] == item.name


async def test_fixing_blank_pattern_clears_broken_rule_diagnostic():
    engine = AutomationEngine()
    item = rule("")
    await engine.register_rule(item)
    await engine.register_rule(replace(item, trigger_config={"event_pattern": "owned.new"}))
    assert item.id not in engine._unsubscribed_rules
    assert len(engine._find_matching_rules("owned.new")) == 1


async def test_changing_trigger_type_removes_event_subscription():
    engine = AutomationEngine()
    item = rule()
    await engine.register_rule(item)
    await engine.register_rule(replace(item, trigger_type=TriggerType.MANUAL))
    assert engine._find_matching_rules("owned.old") == []


async def test_unregister_cleans_legacy_duplicates_without_removing_other_rules():
    engine = AutomationEngine()
    item, other = rule(), rule()
    await engine.register_rule(item)
    await engine.register_rule(other)
    engine._event_subscriptions["owned.old"].extend([item.id, item.id])
    assert await engine.unregister_rule(item.id)
    assert engine._event_subscriptions == {"owned.old": [other.id]}
    await engine.register_rule(replace(item, trigger_config={"event_pattern": "owned.new"}))
    assert engine._find_matching_rules("owned.old") == [other]
    assert not await engine.unregister_rule(uuid4())


async def test_service_edit_refreshes_event_index_after_database_flush():
    engine = AutomationEngine()
    item = rule()
    service, record = service_for(engine, item)
    await service.get_rule(item.id)
    changed = await service.update_rule(
        item.id, organization_id=item.organization_id, trigger_config={"event_pattern": "owned.new"}
    )
    service.db.flush.assert_awaited_once()
    assert record.trigger_config == {"event_pattern": "owned.new"}
    assert engine._find_matching_rules("owned.old") == []
    assert engine._find_matching_rules("owned.new") == [changed]
