# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The most destructive device action must not accept the string "false".

``DeviceControlService`` gated FACTORY_RESET with::

    confirm = params.get("confirm", False)
    if not confirm:

In Python every non-empty string is truthy, so ``"false"`` -- what a JSON client
sends when it serialises a boolean badly, and what an attacker sends on purpose --
passed the gate and factory-reset the device.

The branch is currently UNREACHABLE: nothing outside device_control.py names
``ActionType.FACTORY_RESET``, and the two entry points that take a caller-supplied
ActionType (``execute_action`` / ``bulk_execute``) have no callers outside the
module -- every external consumer uses a typed wrapper that hardcodes its action.
So this was a landmine, not a live bypass. It is still the single most destructive
operation the service exposes, and it should not be armed the day someone wires it.

The repo already had the strict rule, as ``payload_confirmed``, written after the
same ``bool("false")`` bypass was found on the staged-change path. It reads the key
``confirmed``; device_control's flag is spelled ``confirm``, so the two never met.
The rule is now shared rather than duplicated.
"""

from __future__ import annotations

import pytest

from app.services.adapter_preflight_common import affirmative, payload_confirmed


@pytest.mark.parametrize(
    "value",
    ["false", "False", "FALSE", "no", "off", "0", "", "nope", "null", "undefined"],
)
def test_a_negative_or_junk_value_is_not_confirmation(value: str) -> None:
    """The core regression. Every one of these is truthy to ``bool()``."""
    assert bool(value) or value == "", "sanity: these are the truthy-string cases"
    assert affirmative(value) is False, (
        f"{value!r} must not count as confirmation -- bool({value!r}) is "
        f"{bool(value)}, which is how the original gate let it through"
    )


@pytest.mark.parametrize("value", [True, "true", "True", "1", "yes", "on", 1])
def test_a_genuine_affirmative_is_accepted(value: object) -> None:
    """The gate must still be satisfiable, or the action is simply dead."""
    assert affirmative(value) is True


@pytest.mark.parametrize("value", [False, None, 0, [], {}])
def test_absent_and_falsey_values_are_not_confirmation(value: object) -> None:
    assert affirmative(value) is False


def test_factory_reset_uses_the_strict_check_not_truthiness() -> None:
    """Pin the call site, not just the helper.

    Mutation this catches: reverting device_control.py to
    ``if not params.get("confirm")``. The helper would still be correct and every
    test above would still pass, while the destructive path went back to
    accepting "false".
    """
    import inspect

    from app.services.device_control import DeviceControlService

    src = inspect.getsource(DeviceControlService)
    assert "affirmative(params.get(\"confirm\"))" in src, (
        "the FACTORY_RESET gate no longer uses the strict affirmative check, so "
        'the string "false" confirms a factory reset again'
    )


def test_the_two_spellings_share_one_implementation() -> None:
    """``payload_confirmed`` must delegate, not carry a second copy of the rule.

    A duplicated rule is how this bypass reached the codebase twice.
    """
    import inspect

    assert "affirmative(" in inspect.getsource(payload_confirmed)
    assert payload_confirmed({"confirmed": "false"}) is False
    assert payload_confirmed({"confirmed": True}) is True
