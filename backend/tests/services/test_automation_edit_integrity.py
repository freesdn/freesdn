# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Updates must remain executable and a failed write cannot corrupt cached rules."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints.automation import AutomationRuleUpdate, _rule_to_response
from app.services.automation import (
    Action,
    ActionType,
    AutomationEngine,
    AutomationService,
    ConditionGroup,
    handle_delay,
)
from tests.services.test_automation_hydration import _record


async def setup():
    engine = AutomationEngine()
    engine.register_action_handler(ActionType.DELAY, handle_delay)
    record = _record(
        author=uuid4(),
        rule_id=uuid4(),
        org=uuid4(),
        actions=[{"action_type": "delay", "params": {"seconds": 0}}],
    )
    record.trigger_config = {"event_pattern": "owned.old"}
    result = MagicMock()
    result.scalar_one_or_none.return_value = record
    db = SimpleNamespace(execute=AsyncMock(return_value=result), flush=AsyncMock())
    service = AutomationService(db, engine)
    initial = await service.get_rule(record.id)
    return service, record, initial, result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"actions": [{"action_type": "delay", "params": {"seconds": 0}}]},
        {
            "conditions": {
                "logic": "and",
                "conditions": [{"field": "state", "operator": "eq", "value": "up"}],
            }
        },
        {
            "actions": [{"action_type": "delay", "params": {"seconds": 0}}],
            "conditions": {
                "logic": "and",
                "conditions": [{"field": "state", "operator": "eq", "value": "up"}],
            },
        },
        {"name": "Owned renamed control"},
        {"trigger_type": "manual"},
    ],
)
async def test_normal_api_edits_remain_serializable_and_executable(change):
    service, record, _, _ = await setup()
    request = AutomationRuleUpdate(**change)
    updates = request.model_dump(exclude_unset=True)
    if "actions" in updates and request.actions:
        updates["actions"] = [a.model_dump() for a in request.actions]
    if "conditions" in updates and request.conditions:
        updates["conditions"] = request.conditions.model_dump()
    updated = await service.update_rule(
        record.id, organization_id=record.organization_id, **updates
    )
    assert updated
    response = _rule_to_response(updated)
    assert response.id == str(record.id)
    assert all(isinstance(action, Action) for action in updated.actions)
    for action in updated.actions:
        result = await service.engine._execute_action(action, {})
        assert result.success
    if updated.conditions:
        assert isinstance(updated.conditions, ConditionGroup)
        assert updated.conditions.evaluate({"state": "up"})
        assert not updated.conditions.evaluate({"state": "down"})
    service.db.flush.assert_awaited_once()
    assert isinstance(record.actions[0], dict)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["lookup", "flush"])
async def test_failed_write_does_not_modify_live_rule_or_subscription(failure):
    service, record, initial, _ = await setup()
    before = deepcopy(initial.to_dict())
    subscriptions = deepcopy(service.engine._event_subscriptions)
    if failure == "lookup":
        service.db.execute.side_effect = RuntimeError("synthetic lookup failure")
    else:
        service.db.flush.side_effect = RuntimeError("synthetic flush failure")
    with pytest.raises(RuntimeError):
        await service.update_rule(
            record.id,
            organization_id=record.organization_id,
            name="must-not-publish",
            trigger_config={"event_pattern": "owned.new"},
            actions=[{"action_type": "delay", "params": {"seconds": 0}}],
        )
    assert service.engine.get_rule(record.id).to_dict() == before
    assert service.engine._event_subscriptions == subscriptions


@pytest.mark.asyncio
async def test_deleted_persistent_row_does_not_report_a_successful_edit():
    service, record, _, result = await setup()
    result.scalar_one_or_none.return_value = None
    updated = await service.update_rule(
        record.id, organization_id=record.organization_id, name="missing"
    )
    assert updated is None
    service.db.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrong_organization_does_not_mutate_rule():
    service, record, initial, _ = await setup()
    before = deepcopy(initial.to_dict())
    assert await service.update_rule(record.id, organization_id=uuid4(), name="wrong") is None
    assert service.engine.get_rule(record.id).to_dict() == before
    service.db.flush.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["id", "created_by", "trigger_count"])
async def test_protected_fields_cannot_be_edited_through_service(key):
    service, record, initial, _ = await setup()
    before = deepcopy(initial.to_dict())
    with pytest.raises(ValueError):
        await service.update_rule(
            record.id,
            organization_id=record.organization_id,
            **{key: 99 if key == "trigger_count" else uuid4()},
        )
    assert service.engine.get_rule(initial.id).to_dict() == before
    service.db.flush.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "updates",
    [
        {"actions": [{"action_type": "does.not.exist"}]},
        {
            "conditions": {
                "logic": "and",
                "conditions": [{"field": "state", "operator": "invalid", "value": "up"}],
            }
        },
    ],
)
async def test_invalid_runtime_shapes_are_refused_before_persistent_or_live_mutation(updates):
    service, record, initial, _ = await setup()
    before = deepcopy(initial.to_dict())
    stored = deepcopy(vars(record))
    with pytest.raises(ValueError):
        await service.update_rule(record.id, organization_id=record.organization_id, **updates)
    assert service.engine.get_rule(record.id).to_dict() == before
    assert vars(record) == stored
    service.db.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_unedited_fields_come_from_current_database_definition():
    service, record, initial, _ = await setup()
    record.actions = [{"action_type": "delay", "params": {"seconds": 1}}]
    updated = await service.update_rule(
        record.id, organization_id=record.organization_id, name="current"
    )
    assert updated.actions[0].params == {"seconds": 1}
    assert initial.actions[0].params == {"seconds": 0}


@pytest.mark.asyncio
async def test_replacement_does_not_mutate_an_existing_execution_snapshot():
    service, record, initial, _ = await setup()
    before = deepcopy(initial.to_dict())
    updated = await service.update_rule(
        record.id, organization_id=record.organization_id, name="replacement"
    )
    assert updated.name == "replacement"
    assert initial.to_dict() == before


@pytest.mark.asyncio
async def test_typed_internal_updates_round_trip_to_json_and_runtime_objects():
    service, record, _, _ = await setup()
    conditions = ConditionGroup.from_dict(
        {"logic": "and", "conditions": [{"field": "state", "operator": "eq", "value": "up"}]}
    )
    action = Action(ActionType.DELAY, params={"seconds": 0})
    updated = await service.update_rule(
        record.id, organization_id=record.organization_id, actions=[action], conditions=conditions
    )
    assert updated.actions[0].to_dict() == action.to_dict()
    assert updated.conditions.to_dict() == conditions.to_dict()
    assert record.actions == [action.to_dict()] and record.conditions == conditions.to_dict()


@pytest.mark.parametrize(
    "key",
    [
        "name",
        "trigger_type",
        "trigger_config",
        "actions",
        "priority",
        "cooldown_seconds",
        "max_triggers_per_hour",
    ],
)
def test_explicit_null_is_invalid_for_required_patch_fields(key):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AutomationRuleUpdate(**{key: None})


@pytest.mark.parametrize("key", ["description", "conditions"])
def test_optional_fields_can_still_be_cleared(key):
    assert AutomationRuleUpdate(**{key: None}).model_dump(exclude_unset=True) == {key: None}
