# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Recording a SUCCESSFUL apply must never be able to fail.

Background
----------
``AdapterPendingChange.applied_response`` is a JSONB column. The apply path
stored::

    change.applied_response = response if isinstance(response, dict) else {"data": response}

Most appliers do not return a dict -- they return an ``AdapterResult``
dataclass. The success check on the line directly above literally reads
``getattr(response, "success", None) is False``, so the code already knew that.

``{"data": AdapterResult(...)}`` is not JSON serialisable, so the commit raised
AFTER the write had already landed on the live device. The operator was told the
apply FAILED for a VLAN that exists on the controller, the audit row rolled back
with the transaction, and the change was left mis-recorded. That is the single
worst outcome available to a staged-write system: the database and the device
disagree, and the disagreement is invisible.

``asdict()`` alone does not fix it either -- ``AdapterResult`` carries a
``datetime`` field, and ``data`` can hold anything the vendor returned.

So the normaliser coerces to a plain dict and then forces a real json round-trip
with ``default=str`` as a backstop. The property these tests protect is not
"produces pretty output"; it is **never raises**.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from app.adapters.base import AdapterResult
from app.services.adapter_staging import _jsonable_applied_response


def _assert_storable(value: object) -> dict:
    """The result must be a dict that a JSONB column can actually take."""
    out = _jsonable_applied_response(value)
    assert isinstance(out, dict)
    json.dumps(out)  # would raise if anything non-serialisable survived
    return out


# ── The regression ───────────────────────────────────────────────


def test_adapter_result_is_stored_rather_than_exploding() -> None:
    """The exact failure: a successful AdapterResult broke the commit."""
    result = AdapterResult.ok({"vlan_id": 42, "name": "guest"})

    assert not isinstance(result, dict), "precondition: appliers return a dataclass"
    with pytest.raises(TypeError):
        json.dumps({"data": result})  # the old behaviour

    stored = _assert_storable(result)
    assert stored["success"] is True
    assert stored["data"]["vlan_id"] == 42


def test_the_datetime_field_does_not_defeat_it() -> None:
    """
    AdapterResult carries a timestamp, so a bare asdict() still would not
    serialise. This is why there is a json round-trip with default=str.
    """
    result = AdapterResult(success=True, data=None, message="ok")
    stored = _assert_storable(result)
    assert "timestamp" in stored


def test_exotic_values_nested_in_data_are_coerced_not_fatal() -> None:
    """
    ``data`` holds whatever the vendor returned. A UUID or datetime in there
    must not be able to fail the bookkeeping for a write that already happened.
    """
    result = AdapterResult.ok(
        {
            "id": uuid.uuid4(),
            "when": datetime.now(UTC),
            "nested": {"more": {uuid.uuid4().hex: datetime.now(UTC)}},
        }
    )
    _assert_storable(result)


# ── Shapes that must keep working ────────────────────────────────


def test_a_plain_dict_passes_through_unchanged() -> None:
    payload = {"ok": True, "rows": [1, 2, 3], "msg": "done"}
    assert _jsonable_applied_response(payload) == payload


def test_none_and_scalars_are_wrapped() -> None:
    assert _assert_storable(None) == {"data": None}
    assert _assert_storable("saved") == {"data": "saved"}
    assert _assert_storable(7) == {"data": 7}
    assert _assert_storable(True) == {"data": True}


def test_a_list_response_is_wrapped_not_dropped() -> None:
    stored = _assert_storable([{"uuid": "a"}, {"uuid": "b"}])
    assert stored["data"] == [{"uuid": "a"}, {"uuid": "b"}]


def test_a_pydantic_style_object_is_dumped() -> None:
    class _Model:
        def model_dump(self):
            return {"a": 1}

    assert _assert_storable(_Model()) == {"a": 1}


def test_an_arbitrary_dataclass_is_handled() -> None:
    @dataclass
    class _Custom:
        x: int
        y: str

    assert _assert_storable(_Custom(1, "two")) == {"x": 1, "y": "two"}


# ── The load-bearing property ────────────────────────────────────


def test_it_never_raises_even_on_hostile_input() -> None:
    """
    By the time this runs the device has already taken the write. Raising here
    does not prevent a bad write -- it corrupts the record of a good one. So
    there is no input for which raising is acceptable.
    """

    class _Hostile:
        def __repr__(self):
            return "hostile"

        def model_dump(self):
            raise RuntimeError("nope")

    class _Recursive:
        pass

    recursive = _Recursive()
    recursive.self_ref = recursive  # type: ignore[attr-defined]

    for value in (_Hostile(), recursive, object(), {1, 2, 3}, lambda: None):
        out = _jsonable_applied_response(value)
        assert isinstance(out, dict)
        json.dumps(out)


def test_a_dict_containing_unserialisable_values_still_stores() -> None:
    """A dict passes the isinstance check but can still be unserialisable."""
    stored = _assert_storable({"when": datetime.now(UTC), "who": uuid.uuid4()})
    assert set(stored) == {"when", "who"}
