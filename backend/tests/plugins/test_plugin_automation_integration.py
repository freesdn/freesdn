# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Do the plugin system and the if-this-then-that rule engine work together?

They meet in two places, and the two halves are deliberately asymmetric.

PLUGIN -> RULE (a plugin's event fires a rule) — fully wired.
    ``ctx.events.emit("x")`` publishes ``plugin.{id}.x``; the engine subscribes
    to ``*`` on the bus; an EVENT rule whose ``event_pattern`` is
    ``plugin.{id}.*`` matches it. Verified end to end on a live instance:
    plugin emitted, rule fired, action ran, alert row appeared.

RULE -> PLUGIN (a rule invokes a plugin's action) — deliberately closed.
    A plugin operation is a CATALOGUE PROJECTION. It is advertised so an
    operator or the assistant can discover it, and it is executed by the
    plugin's own per-(plugin, organization) runtime — never by the shared
    registry.

    The reason is tenancy. A plugin has ONE runtime instance PER ORGANIZATION,
    while the Fabric registry is process-wide and holds one Operation per id. A
    handler captured at registration belongs to whichever organization started
    the plugin first, so invoking it from a rule in a different organization
    runs one tenant's plugin against another tenant's context.

    I removed that gate once, taking it for incomplete wiring, and immediately
    produced exactly that on a live instance: a rule in org 6b96a36e ran a
    handler bound to org 2fecdb40's runtime. These tests exist so nobody repeats
    it, and so the reason is written down next to the gate.

    Five callers can reach the Fabric executor: the invoke endpoint, the AI
    tool projection, the automation engine, the Connection builder's validator,
    and the Negotiator that runs Connections. Each refuses a plugin operation
    independently, and each refusal is covered below -- because a gate that
    holds on four paths and not the fifth is not a gate.

Two real defects surfaced during the verification, and both are fixed:

1. ``_execute_action`` reported success whenever a handler RETURNED without
   raising, ignoring ``{"success": False}``. Not plugin-specific: all four
   camera actions and every ``fabric.operation`` failure path report by return
   value, so a camera that refused a PTZ move was recorded as a successful rule
   run. A green execution that did nothing is worse than an error, because it
   removes the signal that something needs attention.

2. ``alert.create``, a built-in action, violated NOT NULL on ``rule_id`` and
   then on ``fingerprint``. Two independent constraint violations is as close to
   proof as it gets that the action had never once run successfully.
"""

from __future__ import annotations

import inspect
import pathlib

import pytest


def _automation_module():
    from app.services import automation

    return automation


# ── the false success ───────────────────────────────────────────


def test_a_handler_that_returns_failure_is_recorded_as_a_failure():
    """The bug that made every other failure here invisible."""
    from app.services.automation import AutomationEngine

    src = inspect.getsource(AutomationEngine._execute_action)
    assert 'output.get("success") is False' in src, (
        "the engine ignores a handler's returned failure again; every graceful "
        "failure will be recorded as a successful action"
    )
    assert "success=succeeded" in src, "ActionResult is hardcoded to success again"


def test_handlers_still_report_failure_by_return_value():
    """
    Premise for the check above. If every handler switched to raising, that
    assertion would be dead weight rather than load-bearing.
    """
    src = pathlib.Path(inspect.getfile(_automation_module())).read_text(encoding="utf-8")
    assert src.count('return {"success": False') >= 5, (
        "handlers no longer report failure by return value; revisit _execute_action"
    )


# ── the tenancy gate ────────────────────────────────────────────


def test_a_rule_cannot_reach_a_plugin_operation():
    """
    Opening this lets a rule in one organization run another organization's
    plugin runtime. Verified live, not theorised.
    """
    from app.services.automation import AutomationEngine

    src = inspect.getsource(AutomationEngine)
    assert "op.tier is not OperationTier.NATIVE" in src, (
        "fabric.operation accepts non-native operations again; a rule in org A "
        "can now run org B's plugin runtime"
    )


def test_the_gate_records_why_it_exists():
    """
    A restriction with no stated reason invites removal. It was removed once for
    exactly that reason.
    """
    from app.services.automation import AutomationEngine

    src = inspect.getsource(AutomationEngine)
    assert "PER" in src and "ORGANIZATION" in src, (
        "the tenancy rationale next to the tier gate is gone"
    )


def test_a_plugin_operation_carries_no_executable_handler():
    """
    Belt to the gate's braces. Even past a tier check there is nothing to call:
    the registry projects plugin operations for DISCOVERY and leaves the handler
    unset on purpose.
    """
    from app.core.fabric import registry

    src = pathlib.Path(inspect.getfile(registry)).read_text(encoding="utf-8")
    block = src.split("def _plugin(", 1)[1].split("\n    def ", 1)[0]
    assert "handler=" not in block, (
        "the registry attaches a handler to plugin operations; that handler "
        "belongs to whichever organization started the plugin first"
    )


def test_the_two_string_gated_paths_still_check_tier():
    """
    Five callers can reach a Fabric operation. Three refuse a plugin one
    behaviourally and are exercised as such below; these two are HTTP-shaped
    enough that a source check is the honest way to cover them.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    for module_path, label in (
        ("app/api/v1/endpoints/fabric.py", "the invoke endpoint"),
        ("app/core/fabric/ai_bridge.py", "the AI tool projection"),
    ):
        src = (root / module_path).read_text(encoding="utf-8")
        assert "OperationTier.NATIVE" in src, f"{label} no longer gates on tier"


def _plugin_op():
    from app.core.fabric.operations import Operation, OperationTier

    return Operation(
        id="plugin.probe.do_thing",
        title="Do Thing",
        description="",
        input_schema={},
        tier=OperationTier.PLUGIN,
        provider_id="probe",
    )


def test_a_connection_cannot_be_authored_against_a_plugin_step(monkeypatch):
    """
    The Fabric Connection builder is the OTHER if-this-then-that surface, and
    the one most likely to acquire this bug: it lists compatible targets from
    the same catalogue the plugin operations are projected into.

    Authoring must refuse, not merely fail at run time. A step that saves and
    then quietly returns NOT_SUPPORTED on every firing is the silent-failure
    shape this whole file exists to prevent.
    """
    from app.core.fabric import registry as registry_mod
    from app.services.fabric_connections import (
        ConnectionPermissionError,
        FabricConnectionService,
    )

    op = _plugin_op()
    monkeypatch.setattr(
        registry_mod.fabric_registry, "get_operation", lambda oid: op if oid == op.id else None
    )

    class MaximallyPrivileged:
        def has_permission(self, _permission):
            return True

    with pytest.raises(ConnectionPermissionError):
        FabricConnectionService.__new__(FabricConnectionService)._validate_spec(
            source_event="device.status.changed",
            steps=[{"operation_id": op.id, "params": {}}],
            conditions=None,
            current_user=MaximallyPrivileged(),
        )


async def test_the_negotiator_denies_a_plugin_step_even_for_a_privileged_author():
    """
    The run-time twin of the check above, for a Connection authored before the
    gate existed. The permission checker here says yes to everything; the tier
    must still deny.
    """
    import uuid

    from app.core.fabric.negotiator import Negotiator

    negotiator = Negotiator.__new__(Negotiator)

    async def _grant_everything(_actor, _permission, _org):
        return True

    negotiator._permission_checker = _grant_everything

    allowed = await negotiator._check_permission(_plugin_op(), uuid.uuid4(), uuid.uuid4())
    assert allowed is False, "the negotiator would run a plugin op from a Connection"


async def test_the_executor_has_nothing_to_call_anyway():
    """
    Last line: even reached, a projected plugin operation carries no handler, so
    it fails closed rather than running something belonging to another tenant.
    """
    import uuid

    from app.core.fabric.execution import OperationContext
    from app.core.fabric.executor import operation_executor

    result = await operation_executor.execute(
        _plugin_op(),
        OperationContext(organization_id=uuid.uuid4(), actor_id=None, params={}),
    )
    assert result.success is False
    assert result.error_code == "NOT_SUPPORTED"


def test_the_action_listing_never_leaks_a_callable():
    """``get_plugin_actions()`` feeds API responses; a handler belongs in neither."""
    from app.plugins.bridges import PluginAutomationBridge

    listing = inspect.getsource(PluginAutomationBridge.get_plugin_actions)
    assert 'if k != "handler"' in listing, "the listing leaks callables into responses"


def test_the_sdk_does_not_promise_rule_invocation():
    """
    The real defect on this side. The docstring said "when an automation rule
    uses this action type, the handler ...", which no rule could do -- so an
    author would write a handler, wire a rule, and watch nothing happen with no
    error anywhere.
    """
    from app.plugins.sdk import FreeSDNPlugin

    doc = " ".join((FreeSDNPlugin.register_automation_action.__doc__ or "").split())
    assert "An automation rule cannot currently invoke it" in doc, (
        "the SDK promises rule invocation again"
    )
    assert "event_pattern" in doc, "the docstring does not point at what DOES work"


def test_a_plugin_write_operation_is_still_categorically_refused():
    """
    Defence in depth for a path that should not be reachable anyway. If a
    per-organization dispatch is ever built, this is the gate that keeps a rule
    from driving a device write around native staging.
    """
    from app.core.fabric.executor import OperationExecutor

    src = inspect.getsource(OperationExecutor._execute_plugin)
    assert "PLUGIN_WRITE_FORBIDDEN" in src
    assert src.index("if op.write:") < src.index("op.handler(ctx.params)"), (
        "the write refusal no longer precedes the handler call"
    )


def test_the_rule_authors_permission_is_rechecked_at_fire_time():
    """
    A rule authored by an admin later demoted or moved out of the organization
    must stop working, rather than continuing under the stored actor.
    """
    from app.services.automation import AutomationEngine

    assert "fabric_permission_checker" in inspect.getsource(AutomationEngine)


# ── the second door, now closed ───────────────────────


def test_registering_a_plugin_action_does_not_touch_the_engine():
    """
    The bridge used to write ``automation_engine._action_handlers[full_type] =
    handler``. Dead on arrival -- a rule names actions through ``ActionType``,
    a closed enum, so ``plugin.x.y`` can never be the key looked up -- but not
    harmless: see the two tests below.

    It was also the second door onto the cross-tenant hazard the Fabric tier
    gate closes. One process-wide handler, captured from whichever organization
    started the plugin first. It stayed shut only because the enum happened to
    reject the key.
    """
    from app.plugins import bridges

    # Strip comments: the note explaining why this must not come back names the
    # very expression being searched for.
    code = "\n".join(
        line
        for line in inspect.getsource(bridges).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "_action_handlers" not in code, (
        "the plugin bridge touches the automation engine's handler dict again"
    )


def test_the_engine_refuses_a_handler_key_that_is_not_an_action_type():
    """
    Fail at the poke, not three layers away in an error message.
    """
    from app.services.automation import AutomationEngine

    async def _handler(_params):
        return {}

    with pytest.raises(TypeError):
        AutomationEngine().register_action_handler("plugin.x.y", _handler)


def test_the_rule_create_rejection_message_still_formats():
    """
    The damage the dead write actually did. ``implemented_action_types()``
    returns the handler dict's keys, and the rule-create endpoint renders them
    with ``t.value`` when refusing an unsupported action. One plain-string key
    made that AttributeError -- so installing a plugin that registered a single
    action turned a helpful 422 into a 500 for every rule in the process.
    """
    from app.plugins.bridges import automation_bridge
    from app.services.automation import automation_engine

    async def _handler(_params):
        return {}

    automation_bridge.register_plugin_action(
        plugin_id="formatting-probe",
        action_type="do_thing",
        handler=_handler,
        description="",
        params_schema={},
    )
    try:
        supported = automation_engine.implemented_action_types()
        assert supported, "no action handlers registered; this test proves nothing"
        # The endpoint's exact expression. With the old bridge this raised
        # AttributeError, and the caller got a 500.
        ", ".join(sorted(t.value for t in supported))
    finally:
        automation_bridge.unregister_plugin("formatting-probe")


# ── alert.create ────────────────────────────────────────────────


def _alert_create_block() -> str:
    from app.services.automation import AutomationEngine

    src = inspect.getsource(AutomationEngine._register_builtin_handlers)
    return src.split("_handle_alert_create", 1)[1].split("_handle_alert_resolve", 1)[0]


@pytest.mark.parametrize("column", ["rule_id", "fingerprint"])
def test_alert_create_supplies_every_not_null_column(column: str):
    """
    It omitted both and died on the constraint. Two independent NOT NULL
    violations in a built-in action means nobody had ever run it successfully.
    """
    assert f"{column}=" in _alert_create_block(), (
        f"alert.create does not set {column}, which is NOT NULL"
    )


def test_the_alert_fingerprint_is_derived_not_random():
    """
    fingerprint is the dedup key. A random value per firing makes every repeat
    of the same rule a brand new alert -- the alert-storm bug one layer down.
    """
    block = _alert_create_block()
    assert "sha256" in block
    assert "uuid4" not in block, "the alert fingerprint is random, defeating dedup"


def test_the_system_alert_rule_is_per_organization():
    """
    ``Alert.rule_id`` is a foreign key into an organization's own rules. One
    shared row across organizations would be a cross-tenant reference.
    """
    from app.services.automation import _system_alert_rule_id

    assert "AlertRule.organization_id == org_id" in inspect.getsource(_system_alert_rule_id)


# ── plugin -> rule: the half that works ─────────────────────────


def test_the_engine_subscribes_to_the_whole_bus():
    """
    This is why a plugin-emitted event can fire a rule at all. If the engine
    ever narrows its subscription, plugin events stop matching and nothing
    raises -- the rules simply never fire.
    """
    from app.services.automation import AutomationEngine

    assert 'event_bus.subscribe("*"' in inspect.getsource(AutomationEngine), (
        "the automation engine no longer subscribes to every event; "
        "plugin-emitted events will silently stop triggering rules"
    )


def test_event_patterns_are_free_form_not_an_enum():
    """
    A rule's ``event_pattern`` must stay an arbitrary string. The moment it is
    validated against an enum of known event types, ``plugin.{id}.*`` becomes
    unwritable -- which is precisely what happened to ACTION types and is why
    that half does not work.
    """
    from app.services.automation import AutomationEngine

    src = inspect.getsource(AutomationEngine.register_rule)
    assert 'trigger_config.get("event_pattern"' in src
    assert "TriggerType(" not in src, "the event pattern is being coerced to an enum"


def test_a_plugin_emits_under_its_own_namespace():
    """
    ``plugin.{id}.{event}`` is what makes ``plugin.my-plugin.*`` a usable rule
    pattern, and what stops a plugin emitting an event that impersonates a
    platform one and trips rules written for ``device.status.changed``.
    """
    from app.plugins.sdk import EventSDK

    assert "plugin." in inspect.getsource(EventSDK.emit), "plugin events are no longer namespaced"
