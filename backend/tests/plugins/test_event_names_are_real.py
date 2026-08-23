# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A subscription to an event that is never published is accepted in silence.

The manifest validates, the plugin installs, the plugin enables, and it simply
never hears anything. Nothing in the platform reports it, because there is no
list of valid names to check against: roughly 57 event types are published
across the service layer and the closest thing to a catalogue was an enum
naming 17 of them.

The shipped notify-hub example, the one the SDK holds up as the flagship,
subscribed to six events. FOUR of them could never fire:

    alert.created            never published; the lifecycle fires alert.fired
    sla.breach_created       one character off the real sla.breach.created
    vpn.connection_down      a WebSocket message type, not a bus event
    vpn.connection_restored  same

A near-miss is worse than an obvious mistake. `sla.breach_created` reads as
correct at a glance and the plugin stays quiet forever.

The enum was the root cause rather than carelessness in the example: it carried
ALERT_CREATED = "alert.created" while nothing had ever published that name, so
an author reading it as the catalogue was misled by the platform itself.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest


def _event_factories(events_py: pathlib.Path) -> dict[str, tuple[str, int, str]]:
    """Helpers in core/events.py that build an event name from an argument.

    ``device_event()`` returns ``Event(event_type=f"device.{event_type}")``, so
    the name is only half-written at the definition; the other half arrives at
    each call site. Reading the definition alone yields the literal string
    ``device.{event_type}``, which is not a name anything can subscribe to.

    Returns ``{function_name: (prefix, arg_index, arg_keyword)}``.
    """
    tree = ast.parse(events_py.read_text(encoding="utf-8"))
    factories: dict[str, tuple[str, int, str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
                continue
            if call.func.id != "Event":
                continue
            for kw in call.keywords:
                if kw.arg != "event_type" or not isinstance(kw.value, ast.JoinedStr):
                    continue
                parts = kw.value.values
                if len(parts) != 2:
                    continue
                head, tail = parts
                if not (isinstance(head, ast.Constant) and isinstance(tail, ast.FormattedValue)):
                    continue
                if not isinstance(tail.value, ast.Name) or tail.value.id not in params:
                    continue
                factories[node.name] = (
                    str(head.value),
                    params.index(tail.value.id),
                    tail.value.id,
                )
    return factories


def _resolve_factory_calls(tree: ast.AST, factories: dict[str, tuple[str, int, str]]) -> set[str]:
    """Expand every call to a known factory into the name it actually publishes."""
    names: set[str] = set()
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        fname = (
            call.func.id
            if isinstance(call.func, ast.Name)
            else call.func.attr
            if isinstance(call.func, ast.Attribute)
            else None
        )
        if fname not in factories:
            continue
        prefix, index, keyword = factories[fname]
        bound: ast.AST | None = None
        if len(call.args) > index:
            bound = call.args[index]
        else:
            for kw in call.keywords:
                if kw.arg == keyword:
                    bound = kw.value
        resolved = _string_values(bound)
        if resolved:
            names |= {prefix + v for v in resolved}
        else:
            # Not resolvable statically. Keep the placeholder so a wildcard
            # subscription can still match it, but do not invent a name.
            names.add(f"{prefix}{{{keyword}}}")
    return names


def _string_values(node: ast.AST | None) -> set[str]:
    """Every string an expression can evaluate to, when that is knowable.

    A ternary is the common case and it publishes BOTH names, so collapsing it
    to "unresolvable" would leave a placeholder that re-opens the prefix
    amnesty:

        device_event("action_completed" if ok else "action_failed", ...)
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        both = _string_values(node.body) | _string_values(node.orelse)
        # Only trust it if BOTH arms resolved; a half-known ternary would
        # under-report and flag a live event as dead.
        return both if _string_values(node.body) and _string_values(node.orelse) else set()
    return set()


def _published_event_types() -> set[str]:
    """Every event type the app can actually publish.

    Three spellings count, because all three really do reach the bus:

    * a literal ``event_type="device.updated"``
    * an enum member handed to a publish helper, e.g.
      ``publish_controller_event(EventType.CONTROLLER_SYNC_STARTED, ...)``
    * a factory call whose argument completes an f-string, e.g.
      ``discovery_event("failed", ...)`` -> ``discovery.failed``

    The third was originally handled by treating the unexpanded
    ``discovery.{event_type}`` as a prefix that blessed anything beneath it.
    That is not a detector, it is an amnesty: it reported ``alert.created`` as
    live against ``alert.{severity}``, whose factory has no production caller at
    all. Resolving the argument at each call site gives a real answer instead,
    and only genuinely unresolvable calls fall back to a placeholder.
    """
    app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
    events_py = app_dir / "core" / "events.py"
    names: set[str] = set()
    literal = re.compile(r'event_type="([a-z_]+\.[a-z_.]+)"')
    member = re.compile(r"EventType\.([A-Z_]+)")

    from app.core.events import EventType

    by_name = {e.name: e.value for e in EventType}
    factories = _event_factories(events_py)

    for py in app_dir.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        for m in literal.finditer(text):
            names.add(m.group(1))
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - app must parse
            continue
        names |= _resolve_factory_calls(tree, factories)
        if py.name == "events.py" and py.parent.name == "core":
            continue  # the definition itself is not a publish site
        for m in member.finditer(text):
            if m.group(1) in by_name:
                names.add(by_name[m.group(1)])
    return names


def _subscriptions_in(manifest: pathlib.Path) -> list[str]:
    """The event_subscriptions block of a plugin manifest.

    Read as text rather than through yaml.safe_load so the check still works in
    a checkout without PyYAML, and so a manifest that fails to parse for some
    unrelated reason cannot quietly skip the check.
    """
    body = manifest.read_text(encoding="utf-8")
    if "event_subscriptions:" not in body:
        return []
    subs: list[str] = []
    for line in body.split("event_subscriptions:", 1)[1].splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            subs.append(stripped[2:].strip())
        elif stripped and not stripped.startswith("#"):
            break  # the next top-level key ends the block
    return subs


def _example_manifests() -> list[pathlib.Path]:
    """Every shipped example manifest, not only the flagship.

    Pinning this to notify-hub was itself a miss. hello-world is the FIRST
    example an author opens, and it carried the same dead ``alert.created``
    subscription for the entire time notify-hub was being fixed. Anything under
    examples/plugins/ counts from here on.
    """
    for parent in pathlib.Path(__file__).resolve().parents:
        root = parent / "freesdn-sdk" / "examples" / "plugins"
        if root.is_dir():
            return sorted(root.glob("*/plugin.yaml"))
    return []


def _matches_any(subscription: str, published: set[str]) -> bool:
    """Is this subscription capable of ever firing?

    An f-string publish site such as ``event_type=f"alert.{severity}"`` proves
    only that SOME name under ``alert.`` can fire, never which. The first
    version of this helper gave an exact subscription credit for that, and the
    hole was wide enough to swallow the bug the module exists to catch:
    ``alert.created`` "matched" the placeholder ``alert.{severity}`` and was
    reported live. Worse, ``alert_event()`` has no production call site at all,
    so that placeholder is not even published.

    So the two cases are treated differently, because the evidence differs:

    * An EXACT subscription needs an exact published literal. A placeholder is
      not proof, and accepting it silently blesses every near-miss under the
      prefix.
    * A WILDCARD subscription may match a placeholder, because it genuinely
      catches whatever that placeholder expands to.
    """
    if subscription in published:
        return True
    if not subscription.endswith(".*"):
        return False

    prefix = subscription[:-1]
    if any(p.startswith(prefix) for p in published):
        return True
    for p in published:
        if "{" not in p:
            continue
        head = p.split("{", 1)[0]
        # Either direction is a real overlap: device.* covers device.{x}, and
        # device.status.* is a possible expansion of device.{x}.
        if head.startswith(prefix) or prefix.startswith(head):
            return True
    return False


def test_the_app_publishes_a_lot_more_than_the_enum_names():
    """
    Premise for the docstring on EventType. If these ever converge, the enum
    could become the catalogue and this warning can be revisited.
    """
    from app.core.events import EventType

    published = _published_event_types()
    assert len(published) > 40, f"only found {len(published)} published event types"
    assert len(set(EventType)) < len(published)


def test_the_enum_no_longer_names_an_event_nobody_publishes():
    """
    ALERT_CREATED sat in the enum while the alert lifecycle published
    alert.fired. That is where the example got the wrong name.
    """
    from app.core.events import EventType

    values = {e.value for e in EventType}
    assert "alert.created" not in values, "the enum names an event nothing publishes"
    assert "alert.fired" in values, "the enum omits the event that actually fires"


def test_the_enum_only_names_events_that_are_published():
    """Every remaining member must correspond to something real."""
    from app.core.events import EventType

    published = _published_event_types()
    unpublished = sorted(e.value for e in EventType if not _matches_any(e.value, published))
    assert not unpublished, f"enum names events nothing publishes: {unpublished}"


def test_every_shipped_example_subscribes_only_to_real_events():
    """
    The examples are what authors copy. notify-hub had four of six
    subscriptions that could never fire; hello-world had one of two. Nothing in
    the platform would have told either author.
    """
    manifests = _example_manifests()
    if not manifests:  # pragma: no cover - backend-only checkout
        pytest.skip("SDK examples not present")

    published = _published_event_types()
    dead: dict[str, list[str]] = {}
    for manifest in manifests:
        subs = _subscriptions_in(manifest)
        missed = [s for s in subs if not _matches_any(s, published)]
        if missed:
            dead[manifest.parent.name] = missed
    assert not dead, f"examples subscribe to events nothing publishes: {dead}"


def test_a_placeholder_publish_site_does_not_bless_an_exact_near_miss():
    """
    Guards the hole that let the headline bug through this module's own check.

    ``alert_event()`` builds ``event_type=f"alert.{severity}"``, so the scan
    records the literal string ``alert.{severity}`` as publishable. A matcher
    that let an exact subscription claim a placeholder by prefix reported
    ``alert.created`` as LIVE -- the precise name this file was written to
    catch. It has no production call site either, so nothing under that prefix
    is published by it at all.

    A wildcard may still claim a placeholder, because a wildcard really does
    catch whatever the placeholder expands to.
    """
    placeholder = {"alert.{severity}", "device.{event_type}"}

    assert not _matches_any("alert.created", placeholder)
    assert not _matches_any("alert.fired", placeholder)
    assert not _matches_any("device.anything", placeholder)

    assert _matches_any("alert.*", placeholder)
    assert _matches_any("device.status.*", placeholder)


def test_the_scaffold_default_subscription_is_real():
    """The generated manifest ships a subscription too; it must also be real."""
    tpl = None
    for parent in pathlib.Path(__file__).resolve().parents:
        cand = (
            parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk" / "templates" / "plugin.yaml.j2"
        )
        if cand.is_file():
            tpl = cand
            break
    if tpl is None:  # pragma: no cover - backend-only checkout
        pytest.skip("SDK source not present")

    body = tpl.read_text(encoding="utf-8")
    block = body.split("event_subscriptions:", 1)[1].split("\n\n", 1)[0]
    subs = [
        line.strip()[2:].strip() for line in block.splitlines() if line.strip().startswith("- ")
    ]
    published = _published_event_types()
    dead = [s for s in subs if not _matches_any(s, published)]
    assert not dead, f"the scaffold subscribes to events nothing publishes: {dead}"


def test_the_n8n_trigger_only_offers_events_that_can_fire():
    """
    The n8n Trigger node presents a dropdown of FreeSDN events. TEN of its
    sixteen options could never fire: device.online, device.offline,
    alert.created, alert.escalated, controller.connected,
    controller.disconnected, backup.complete, backup.failed,
    discovery.complete and security.anomaly are published nowhere.

    Several were near-misses -- discovery.complete for discovery.completed,
    alert.created for alert.fired -- which is the worst kind here. The workflow
    saves, activates, reports no error, and simply never runs. Neither n8n nor
    FreeSDN reports a subscription that cannot match, so the user's only signal
    is silence.

    This lives in the backend suite on purpose: the list of real event names is
    derived HERE, from the app, and a check that ships with the node could only
    ever compare against a copy.
    """
    node = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = (
            parent
            / "integrations"
            / "n8n-nodes-freesdn"
            / "nodes"
            / "FreeSDN"
            / "FreeSdnTrigger.node.ts"
        )
        if candidate.is_file():
            node = candidate
            break
    if node is None:  # pragma: no cover - backend-only checkout
        pytest.skip("the n8n node is not present in this checkout")

    body = node.read_text(encoding="utf-8")
    assert "const EVENT_TYPE_OPTIONS = [" in body, "the trigger's event list moved or was renamed"
    block = body.split("const EVENT_TYPE_OPTIONS = [", 1)[1].split("];", 1)[0]
    offered = re.findall(r"value:\s*'([a-z0-9_.*]+)'", block)
    assert offered, "the trigger offers no events"

    published = _published_event_types()
    dead = [event for event in offered if not _matches_any(event, published)]
    assert not dead, (
        f"the n8n trigger offers events nothing publishes: {dead}. "
        "A user selecting one gets a workflow that never fires, silently."
    )
