# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pin: nothing outside ``DeviceControlService`` may choose the ``ActionType``.

WHY THIS EXISTS. ``DeviceControlService._execute_action`` gates
``ActionType.FACTORY_RESET`` like this
(``app/services/device_control.py``)::

    case ActionType.FACTORY_RESET:
        confirm = params.get("confirm", False)
        if not confirm:
            return AdapterResult(success=False, error="Factory reset requires confirmation")

``params`` is an untyped ``dict[str, Any]``, and every non-empty string is
truthy in Python -- so ``{"confirm": "false"}`` (and ``"no"``, ``"off"``,
``"0"``) is an explicit DECLINE that PASSES the gate and wipes the device. It is
the same bug class that was live on ``POST /agents/{id}/tasks`` and is now
forbidden by ``tests/services/test_confirmed_antipattern_guard.py``; that guard
matches ``bool(...confirmed)`` and cannot see this ``if not confirm:`` shape.

It is NOT live today, and this test is the reason it stays that way. Every
consumer of the service goes through a typed convenience wrapper
(``reboot_device`` / ``locate_device`` / ``cycle_poe`` / ...), each of which
hardcodes its own ``ActionType``. The only entry points that accept a
caller-chosen ``ActionType`` are ``execute_action`` and ``bulk_execute``, and
neither is called from outside the module. So the FACTORY_RESET branch is
unreachable, and widening the textual anti-pattern guard to cover it would be a
detector for something that cannot happen.

The moment someone wires one of those two up -- an endpoint that takes an
action string, a new ``factory_reset_device`` wrapper, a plugin action -- the
gate becomes live and bypassable. This test fails at that moment, before the
bypass ships. **If it fails, fix the confirm gate first**::

    from app.services.adapter_preflight_common import payload_confirmed
    ...
    case ActionType.FACTORY_RESET:
        if not payload_confirmed({"confirmed": params.get("confirm")}):
            return AdapterResult(success=False, error="Factory reset requires confirmation")

then relax this pin in the same commit.
"""

from __future__ import annotations

import ast
from pathlib import Path

_APP = Path(__file__).resolve().parents[2] / "app"
_OWNER = _APP / "services" / "device_control.py"

#: The two methods that take a caller-supplied ``ActionType``. Everything else
#: on the service hardcodes one, so a denylist stays correct when a new typed
#: wrapper is added.
_UNTYPED_ENTRYPOINTS = {"execute_action", "bulk_execute"}


def _sources() -> list[Path]:
    return [f for f in sorted(_APP.rglob("*.py")) if f != _OWNER]


def _service_variables(tree: ast.Module) -> set[str]:
    """Names bound to a ``DeviceControlService(...)`` construction."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        func = value.func
        constructed = (isinstance(func, ast.Name) and func.id == "DeviceControlService") or (
            isinstance(func, ast.Attribute) and func.attr == "DeviceControlService"
        )
        if not constructed:
            continue
        names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def test_scan_actually_covers_the_app() -> None:
    """Guard the guard: a broken scan root must not read as a clean result.

    Mutation this catches: mistyping ``_APP``, which makes both assertions
    below pass over an empty file list -- indistinguishable from "no callers".
    """
    assert _APP.is_dir(), f"scan root not found: {_APP}"
    assert _OWNER.is_file(), f"the service moved: {_OWNER}"
    files = _sources()
    assert len(files) > 500, f"the scan looks truncated -- only {len(files)} files under {_APP}"
    # The two modules that DO consume the service must be in scope, or the
    # denylist below is being checked against nothing.
    consumers = [f for f in files if "DeviceControlService" in f.read_text(encoding="utf-8")]
    assert any(f.name == "api.py" and f.parent.name == "network" for f in consumers), (
        "app/modules/network/api.py no longer references DeviceControlService -- "
        "confirm the consumers moved rather than that the scan broke"
    )


def test_no_caller_outside_the_service_picks_its_own_action_type() -> None:
    """``execute_action`` / ``bulk_execute`` must stay internal.

    Mutation this catches: an endpoint that forwards a client-supplied action
    string into ``execute_action``, which is what makes the truthy
    ``if not confirm:`` gate on FACTORY_RESET reachable.
    """
    offenders: list[str] = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        if "DeviceControlService" not in text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - fails louder elsewhere
            continue
        variables = _service_variables(tree)
        if not variables:
            continue
        rel = path.relative_to(_APP.parent).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            receiver = func.value
            if not isinstance(receiver, ast.Name) or receiver.id not in variables:
                continue
            if func.attr in _UNTYPED_ENTRYPOINTS:
                offenders.append(f"{rel}:{node.lineno} {receiver.id}.{func.attr}(...)")

    assert not offenders, (
        "A caller outside DeviceControlService now chooses its own ActionType. "
        "That makes ActionType.FACTORY_RESET reachable, and its confirm gate "
        '(app/services/device_control.py, `confirm = params.get("confirm", '
        'False); if not confirm:`) accepts the string "false" as consent. Fix '
        "the gate with payload_confirmed() before landing this:\n" + "\n".join(offenders)
    )


def test_factory_reset_action_type_is_named_nowhere_else() -> None:
    """A second, cheaper tripwire on the same invariant.

    Mutation this catches: reaching the branch without going through a variable
    the AST walk above can follow -- a partial, a dict dispatch table, a
    ``getattr(svc, name)`` -- any of which would still have to name
    ``ActionType.FACTORY_RESET`` somewhere.
    """
    offenders = [
        f.relative_to(_APP.parent).as_posix()
        for f in _sources()
        if "ActionType.FACTORY_RESET" in f.read_text(encoding="utf-8")
    ]

    assert not offenders, (
        "ActionType.FACTORY_RESET is referenced outside app/services/"
        "device_control.py. Its confirm gate is truthiness-based and the "
        'string "false" passes it -- switch the gate to payload_confirmed() '
        "before wiring this up:\n" + "\n".join(offenders)
    )
