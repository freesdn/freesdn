# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The Integrations page offered events the platform has never published.

Every integration type defaulted to ``alert.created``. That name is not merely
absent  -  ``app/core/events.py`` carries a comment recording that it is
deliberately absent:

    # ALERT_CREATED = "alert.created" is intentionally absent: nothing has ever
    # published it. The alert lifecycle publishes alert.fired.

So an operator could open Integrations, pick any type, accept the defaults, see
the integration listed and enabled, and receive nothing, for ever, with no error
anywhere. ``alert.fired``  -  the event that actually fires  -  was not on the
menu to choose instead: it appeared zero times in the whole file.

Eighteen of the twenty-three names offered were in that state. This test is the
ratchet: a name in that catalogue is a promise the UI makes on the platform's
behalf, and it now has to be one the platform can keep.

Deliberately structural rather than a live-dispatch test. The failure being
guarded is a NAME that never matches, which no amount of exercising the delivery
path would reveal  -  the delivery path works perfectly, it is simply never
triggered.
"""

from __future__ import annotations

import pathlib
import re

import pytest


def _published_event_names() -> set[str]:
    """Every event name the platform can actually emit.

    Two sources, because the platform uses both: the ``EventType`` enum, and
    literal strings passed to publish()/emit() by subsystems that never added an
    enum member.
    """
    app = pathlib.Path(__file__).resolve().parents[2] / "app"

    events_src = (app / "core" / "events.py").read_text(encoding="utf-8")
    enum_block = re.search(r"class EventType\(StrEnum\):(.*?)(?=\nclass |\Z)", events_src, re.S)
    assert enum_block, "EventType enum not found; this test cannot judge anything"

    names: set[str] = set()
    for line in enum_block.group(1).splitlines():
        # Skip comments. ``alert.created`` lives in one, and counting it would
        # make this test bless the exact name it exists to catch.
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.search(r'=\s*"([a-z_.]+)"', stripped)
        if m:
            names.add(m.group(1))

    for path in app.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        src = path.read_text(encoding="utf-8", errors="ignore")
        # Two call shapes, because the app uses both: a positional first
        # argument, and the ``event_type=`` keyword. Matching only the first
        # under-detects -- an earlier version of this did exactly that and
        # reported ``device.adopted`` as a phantom, when discovery.py publishes
        # it by keyword. Under-detection fails a name that is perfectly real,
        # which is the more damaging direction for a ratchet to be wrong in.
        for pattern in (
            r'(?:publish|emit|emit_event|publish_event)\s*\(\s*["\']([a-z_]+\.[a-z_.]+)["\']',
            r'event_type\s*=\s*["\']([a-z_]+\.[a-z_.]+)["\']',
        ):
            for m in re.finditer(pattern, src):
                names.add(m.group(1))

    return names


def _offered_event_names() -> set[str]:
    from app.api.v1.endpoints.integrations import EVENT_CATEGORIES, INTEGRATION_TYPES

    offered: set[str] = set()
    for events in EVENT_CATEGORIES.values():
        offered.update(events)
    for spec in INTEGRATION_TYPES.values():
        offered.update(spec.get("default_events") or [])
    return offered


def test_the_platform_publishes_something():
    """Premise. If this collapses to nothing the test below passes vacuously."""
    published = _published_event_names()
    assert len(published) >= 10, f"only found {len(published)} published events"
    assert "alert.fired" in published


def test_alert_created_is_still_not_a_real_event():
    """
    The specific name this whole test exists for. If it ever becomes real, the
    assertion below stops mattering and this file should be revisited rather
    than deleted.
    """
    assert "alert.created" not in _published_event_names()


def test_every_offered_event_is_one_the_platform_publishes():
    offered = _offered_event_names()
    published = _published_event_names()
    phantom = sorted(offered - published)
    assert not phantom, (
        "the Integrations page offers events nothing publishes, so anyone who "
        f"selects one receives nothing for ever: {phantom}"
    )


def test_the_alert_event_that_fires_is_actually_offered():
    """
    The other half. Removing the phantom names would satisfy the test above
    while leaving no way to subscribe to an alert at all.
    """
    assert "alert.fired" in _offered_event_names()


@pytest.mark.parametrize(
    "integration_type", ["n8n", "slack", "teams", "pagerduty", "jira", "servicenow"]
)
def test_no_type_defaults_to_something_that_never_fires(integration_type: str):
    """
    Defaults matter more than the menu. Most people accept them, and a default
    that cannot fire turns "it is enabled" into a lie on first use.
    """
    from app.api.v1.endpoints.integrations import INTEGRATION_TYPES

    published = _published_event_names()
    defaults = INTEGRATION_TYPES[integration_type].get("default_events") or []
    assert defaults, f"{integration_type} has no default events at all"
    phantom = [e for e in defaults if e not in published]
    assert not phantom, f"{integration_type} defaults to events that never fire: {phantom}"


def test_types_needing_their_own_credentials_are_marked():
    """
    An integration is a webhook: a URL, event types and an HMAC secret. There is
    no auth field and no payload templating, so a vendor API needing its own
    credentials cannot be reached this way at all  -  it cannot even
    authenticate. Those types must say so rather than accept a configuration
    that fails on every delivery.
    """
    from app.api.v1.endpoints.integrations import INTEGRATION_TYPES

    for name in ("jira", "servicenow", "pagerduty"):
        spec = INTEGRATION_TYPES[name]
        assert spec.get("requires_plugin"), f"{name} still presents itself as working"
        assert "plugin" in spec["description"].lower(), (
            f"{name}'s description does not tell the operator what to do instead"
        )
