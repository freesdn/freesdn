# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Every event rule created in the UI fired on every event in the organisation.

``register_rule`` read the pattern as::

    event_pattern = rule.trigger_config.get("event_pattern", "*")

and the rule form had no field for it, so it posted ``trigger_config: {}``.
The two together mean an operator who wrote "notify me when a device goes
offline" got a rule subscribed to ``*``: device updates, controller syncs,
discovery runs, every alert, every camera event. The 60-second cooldown was the
only thing between them and a notification per event.

Reproduced before the fix, with exactly what the form posts::

    rule(trigger_type=EVENT, trigger_config={})
    -> subscriptions: {'*': [<rule>]}
    -> device.status.changed     matches 1
       alert.fired               matches 1
       controller.sync.completed matches 1
       collector.syslog.received matches 1

The last line is why this stopped being theoretical. The collector now
publishes a bus event for every warning-or-worse syslog message, so a fleet
that logs is a fleet that fires every UI-created rule continuously -- including
``notify.webhook`` rules pointed at somebody else's endpoint.

A missing pattern is not a lenient default, it is the loudest possible one. It
is refused at creation now, and a rule already in the database that has no
pattern is registered but subscribes to nothing and says so. ``*`` is still
valid; it just has to be asked for.
"""

from __future__ import annotations

import inspect
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.v1.endpoints.automation import AutomationRuleCreate
from app.services.automation import (
    AutomationEngine,
    AutomationRule,
    RuleStatus,
    TriggerType,
)

_FIELDS = list(inspect.signature(AutomationRule.__init__).parameters)[1:]
_ACTIONS = [{"action_type": "notify.in_app", "params": {}}]


def _rule(trigger_config: dict, name: str = "a rule") -> AutomationRule:
    kwargs = dict.fromkeys(_FIELDS)
    kwargs.update(
        id=uuid4(),
        organization_id=uuid4(),
        name=name,
        description="",
        trigger_type=TriggerType.EVENT,
        trigger_config=trigger_config,
        conditions=None,
        actions=[],
        status=RuleStatus.ACTIVE,
        priority=0,
    )
    return AutomationRule(**kwargs)


# ── the engine ──────────────────────────────────────────────────


async def test_a_rule_with_no_pattern_does_not_subscribe_to_everything():
    """
    The regression itself, driven with exactly what the form posts.
    """
    engine = AutomationEngine()

    await engine.register_rule(_rule({}))

    assert "*" not in engine._event_subscriptions, "still subscribed to every event"
    for event_type in (
        "device.status.changed",
        "alert.fired",
        "controller.sync.completed",
        "collector.syslog.received",
    ):
        assert engine._find_matching_rules(event_type) == [], f"fired on {event_type}"


async def test_a_rule_with_no_pattern_is_reported_rather_than_silently_dead():
    """
    Not firing is safer than firing on everything, and it is still wrong. An
    operator has no way to tell "my rule does not fire" from "nothing has
    happened yet", so the engine keeps a list.
    """
    engine = AutomationEngine()
    rule = _rule({}, name="notify me when a device goes offline")

    await engine.register_rule(rule)

    assert engine.unsubscribed_rules == {rule.id: "notify me when a device goes offline"}


async def test_an_explicit_pattern_subscribes_to_exactly_that():
    engine = AutomationEngine()

    await engine.register_rule(_rule({"event_pattern": "device.status.changed"}))

    assert len(engine._find_matching_rules("device.status.changed")) == 1
    assert engine._find_matching_rules("alert.fired") == []
    assert engine.unsubscribed_rules == {}


async def test_an_explicit_wildcard_still_works():
    """
    ``*`` is a legitimate pattern -- an audit or logging rule genuinely wants
    every event. The fix removes it as a DEFAULT, not as an option.
    """
    engine = AutomationEngine()

    await engine.register_rule(_rule({"event_pattern": "*"}))

    assert len(engine._find_matching_rules("collector.syslog.received")) == 1
    assert engine.unsubscribed_rules == {}


async def test_a_prefix_wildcard_still_works():
    engine = AutomationEngine()

    await engine.register_rule(_rule({"event_pattern": "collector.*"}))

    assert len(engine._find_matching_rules("collector.syslog.received")) == 1
    assert engine._find_matching_rules("device.status.changed") == []


@pytest.mark.parametrize("blank", ["", "   ", None])
async def test_a_blank_pattern_counts_as_no_pattern(blank):
    """
    An empty string reaching ``get(..., "*")`` would miss the default and
    subscribe to the empty pattern instead -- a rule that matches nothing, with
    nothing reported. Both blanks take the same path.
    """
    engine = AutomationEngine()

    await engine.register_rule(_rule({"event_pattern": blank}))

    assert engine._event_subscriptions == {}
    assert len(engine.unsubscribed_rules) == 1


async def test_unregistering_clears_the_not_firing_list():
    """
    Otherwise a deleted rule is reported as broken for the life of the process,
    and the list stops being worth reading.
    """
    engine = AutomationEngine()
    rule = _rule({})
    await engine.register_rule(rule)

    await engine.unregister_rule(rule.id)

    assert engine.unsubscribed_rules == {}


# ── the API ─────────────────────────────────────────────────────


def test_creating_an_event_rule_without_a_pattern_is_refused():
    """
    Refused at creation, not merely inert at registration. A rule that is
    accepted and then never fires is its own confusing failure -- the operator
    saw a success toast.
    """
    with pytest.raises(ValidationError) as exc:
        AutomationRuleCreate(
            name="notify me when a device goes offline",
            trigger_type="event",
            trigger_config={},
            actions=_ACTIONS,
        )

    assert "event_pattern" in str(exc.value)


def test_the_refusal_names_what_to_do():
    """
    "field required" would send someone to the source. The message has to carry
    an example, because the pattern grammar is not guessable.
    """
    with pytest.raises(ValidationError) as exc:
        AutomationRuleCreate(
            name="x", trigger_type="event", trigger_config={}, actions=_ACTIONS
        )

    message = str(exc.value)
    assert "device.status.changed" in message
    assert "'*'" in message


@pytest.mark.parametrize("pattern", ["device.status.changed", "collector.*", "*"])
def test_a_named_pattern_is_accepted(pattern):
    AutomationRuleCreate(
        name="x",
        trigger_type="event",
        trigger_config={"event_pattern": pattern},
        actions=_ACTIONS,
    )


def test_a_manual_rule_needs_no_pattern():
    """
    Only EVENT rules subscribe. Demanding a pattern from a manual rule would
    make the button-triggered case impossible to create.
    """
    AutomationRuleCreate(
        name="run by hand", trigger_type="manual", trigger_config={}, actions=_ACTIONS
    )


def test_the_engine_and_the_api_agree_on_which_triggers_exist():
    """
    The UI offered schedule, threshold and webhook. None has a driver --
    ``IMPLEMENTED_TRIGGER_TYPES`` excludes them and the create endpoint refuses
    them -- so picking one filled in a form and earned a 400.
    """
    from app.services.automation import IMPLEMENTED_TRIGGER_TYPES

    assert frozenset({TriggerType.EVENT, TriggerType.MANUAL}) == IMPLEMENTED_TRIGGER_TYPES


def test_the_collector_events_are_selectable():
    """
    The end of the vertical. The rule form reads its options from
    ``EVENT_CATEGORIES``, so an event the collector publishes has to be in
    there or an operator cannot build the rule that consumes it -- and the
    whole syslog-to-fabric chain stops at a dropdown.
    """
    from app.api.v1.endpoints.integrations import EVENT_CATEGORIES

    offered = {event for events in EVENT_CATEGORIES.values() for event in events}

    assert "collector.syslog.received" in offered
    assert "collector.trap.received" in offered


# ── the update path, closed for the same reason ─────────────────


def test_updating_an_event_rule_without_a_pattern_is_refused():
    """
    The firehose is already closed at registration, so this is not a security
    gap -- but without it an update could set an event rule's trigger_config to
    one with no pattern and the rule would go silently dead, while create
    refuses exactly that. The two paths must agree.
    """
    from app.api.v1.endpoints.automation import AutomationRuleUpdate

    with pytest.raises(ValidationError):
        AutomationRuleUpdate(trigger_type="event", trigger_config={})


def test_a_partial_update_that_does_not_touch_the_trigger_is_allowed():
    """
    Updates are partial. Renaming a rule must not require re-supplying the
    event pattern; the check only fires when the trigger is being set.
    """
    from app.api.v1.endpoints.automation import AutomationRuleUpdate

    AutomationRuleUpdate(name="just a rename")
    AutomationRuleUpdate(priority=5)


def test_an_update_with_an_explicit_pattern_is_accepted():
    from app.api.v1.endpoints.automation import AutomationRuleUpdate

    AutomationRuleUpdate(trigger_type="event", trigger_config={"event_pattern": "alert.*"})
