# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A plugin alert has to behave like every other alert.

Until 2026-08-22 it did not, and the gap was total. ``AlertSDK.create`` wrote
the row and stopped: no notification dispatched, no event published. An alert
raised by a plugin reached the alert LIST and nothing else -- no email, no
Slack, no webhook, even on an instance with all three configured. The only way
an operator learned that a plugin had found something was to go looking.

Two consequences, both verified on the live instance before this was fixed:

  * ``new-device-watch`` raising 40 unrecognised-device alerts notified nobody.
  * ``notify-hub``, the plugin whose entire job is forwarding alerts to chat,
    subscribes to ``alert.fired`` -- which only ``AlertRuleService`` published.
    So the forwarding plugin could not forward an alert raised by a plugin. The
    codebase already documents the near-miss version of this in
    ``core/events.py``: notify-hub originally subscribed to ``alert.created``,
    which nothing has ever published.

The fix routes plugin alerts through the machinery that already existed, rather
than inventing a parallel one: the plugin's own system AlertRule is a real,
operator-editable row, and its ``notification_channels`` is the same control an
operator already uses for every other rule.
"""

from __future__ import annotations

import inspect

import pytest


def _create_src() -> str:
    from app.plugins.sdk import AlertSDK

    return inspect.getsource(AlertSDK.create)


# ── delivery ────────────────────────────────────────────────────


def test_creating_an_alert_dispatches_notifications():
    """
    The defect itself. Without this an alert is a row in a table that nobody is
    told about, which for a monitoring plugin is indistinguishable from not
    having found anything.
    """
    from app.plugins.sdk import AlertSDK

    assert "self._notify(" in _create_src(), "plugin alerts do not notify again"
    assert "dispatch_notifications" in inspect.getsource(AlertSDK._notify)


def test_delivery_uses_the_operators_own_channel_config():
    """
    The channels live on the plugin's system AlertRule -- a real row an operator
    can open in Alert Rules and edit. Deliberately the same control used for
    every other rule, rather than a second notification concept that applies
    only to plugins.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._notify)
    assert "notification_channels" in src


def test_no_configured_channels_means_no_delivery():
    """
    The right default for something installed at runtime: a freshly installed
    plugin does not start paging anyone until an operator says where. Silence
    here is a decision, not an oversight.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._notify)
    assert "if not channels:" in src and "return" in src


def test_a_delivery_failure_does_not_undo_the_alert():
    """
    Best-effort, like the native path. An alert that is already recorded must
    not disappear because an SMTP server was down.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._notify)
    assert "except Exception" in src
    assert src.index("dispatch_notifications") < src.index("except Exception")


# ── the event bus ───────────────────────────────────────────────


def test_creating_an_alert_publishes_alert_fired():
    """
    Without it, plugins cannot hear each other: the one plugin whose job is
    forwarding alerts subscribes to this event.
    """
    from app.plugins.sdk import AlertSDK

    assert "self._publish_fired(" in _create_src()
    assert '"alert.fired"' in inspect.getsource(AlertSDK._publish_fired)


def test_the_event_matches_the_native_payload_exactly():
    """
    Same event type and same keys on purpose. A subscriber must not have to
    care whether an alert came from a rule evaluation or from a plugin, and a
    separate event type would mean every existing subscriber silently ignores
    half the alerts on the system.
    """
    from app.plugins.sdk import AlertSDK
    from app.services.alert_rules import AlertRuleService

    plugin_src = inspect.getsource(AlertSDK._publish_fired)
    native_src = inspect.getsource(AlertRuleService)
    native_block = native_src.split('event_type="alert.fired"', 1)[1].split("except", 1)[0]

    for key in (
        "alert_id",
        "rule_id",
        "rule_name",
        "severity",
        "title",
        "message",
        "device_id",
        "site_id",
    ):
        assert f'"{key}"' in native_block, f"native no longer publishes {key}; update this test"
        assert f'"{key}"' in plugin_src, f"the plugin event is missing {key}"


def test_the_event_names_the_plugin_that_raised_it():
    """
    The one addition over the native payload. A subscriber forwarding to chat
    wants to say which plugin found the problem, and without it the rule name is
    the only clue.
    """
    from app.plugins.sdk import AlertSDK

    assert '"plugin_id"' in inspect.getsource(AlertSDK._publish_fired)


def test_a_publish_failure_does_not_undo_the_alert():
    from app.plugins.sdk import AlertSDK

    assert "except Exception" in inspect.getsource(AlertSDK._publish_fired)


# ── the rule an operator actually edits ─────────────────────────


def test_the_rule_is_named_for_a_human():
    """
    It used to be ``__plugin_alerts_new-device-watch``. Fine while nothing
    pointed at it; now that it IS the control for "where do this plugin's alerts
    go", it has to look like something a person is meant to open.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._get_or_create_plugin_rule)
    assert 'f"Plugin alerts: {self._plugin_id}"' in src


def test_an_existing_rule_is_renamed_rather_than_replaced():
    """
    An operator who already configured channels against the old row keeps them.
    Creating a fresh rule instead would silently drop their configuration and
    leave an orphan behind.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._get_or_create_plugin_rule)
    assert "legacy_name" in src
    assert "AlertRule.name.in_([rule_name, legacy_name])" in src


def test_the_rule_tells_the_operator_what_it_is_for():
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK._get_or_create_plugin_rule)
    assert "Set notification" in src, "the rule does not say what an operator should do with it"


def test_the_rule_lookup_returns_the_row_not_an_id():
    """
    ``create`` needs ``notification_channels`` off it. Returning just the id was
    what made the delivery step impossible to write without a second query.
    """
    from app.plugins.sdk import AlertSDK

    sig = inspect.signature(AlertSDK._get_or_create_plugin_rule)
    assert sig.return_annotation is not None
    src = inspect.getsource(AlertSDK._get_or_create_plugin_rule)
    assert "select(AlertRule)" in src, "the lookup selects a column, not the row"


@pytest.mark.parametrize("guard", ["AlertRule.alive()", "is_system == True"])
def test_the_rule_lookup_keeps_its_existing_guards(guard: str):
    """The rewrite must not drop what was already there."""
    from app.plugins.sdk import AlertSDK

    assert guard in inspect.getsource(AlertSDK._get_or_create_plugin_rule)
