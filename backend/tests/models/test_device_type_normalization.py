# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Device types written by adapters must survive the trip back out of the DB.

Background
----------
``Device.device_type`` is a plain ``String(50)`` column, but the API response
models declare ``device_type: DeviceType``. So the column accepts anything and
the reader accepts almost nothing, and nothing sat in between.

The adapter contract is not at fault: ``DiscoveredDevice.device_type`` is
declared ``str`` with the comment "# ap, switch, router, camera, nvr, phone,
etc." -- deliberately loose. The defect was that the PERSIST boundary never
translated it. Two distinct failures came out of that:

1. ``DeviceType(data.device_type)`` in the adapter-sync path raised ValueError
   for every value that was not literally an enum member -- "ap" (UniFi maps
   both uap AND ubb to it), "phone" (FreePBX, Grandstream), "storage"
   (TrueNAS), "camera_ptz" (Hikvision, ONVIF). The sync loop caught the
   exception per-device, so the device was SILENTLY SKIPPED: a UniFi access
   point, the most common UniFi device there is, simply never appeared in
   inventory, and the only trace was one entry in ``stats["errors"]``.

2. ``DeviceType.UNKNOWN`` did not exist. Any device an adapter reported with no
   type at all hit ``AttributeError`` instead. Meanwhile four import paths wrote
   the literal string ``"unknown"`` straight into the column, which then broke
   serialisation for every subsequent read of that row.

``normalize_device_type`` is now the single translation point and never raises.
These tests pin both halves: the specific strings the shipped adapters emit,
and the property that nothing can get through unnormalised.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from app.models.devices import DeviceType, normalize_device_type


class _Response(BaseModel):
    """Stand-in for the API response models, which type this field strictly."""

    device_type: DeviceType


# ── The enum gap that caused the AttributeError ──────────────────


def test_device_type_has_an_unknown_member() -> None:
    """
    Code referenced ``DeviceType.UNKNOWN`` before it existed. ``DeviceStatus``
    has always had one; this is the sibling that was missing.
    """
    assert hasattr(DeviceType, "UNKNOWN")
    assert DeviceType.UNKNOWN.value == "unknown"


def test_unknown_is_distinct_from_other() -> None:
    """"We could not determine it" is not the same as "a type we do not model"."""
    assert DeviceType.UNKNOWN != DeviceType.OTHER


# ── The strings the shipped adapters actually emit ───────────────


@pytest.mark.parametrize(
    ("emitted", "expected"),
    [
        # UniFi: _UNIFI_TYPE_MAP sends both uap and ubb here.
        ("ap", DeviceType.ACCESS_POINT),
        # FreePBX / Grandstream handsets.
        ("phone", DeviceType.VOIP_PHONE),
        # TrueNAS.
        ("storage", DeviceType.SERVER),
        # Hikvision / ONVIF.
        ("camera_ptz", DeviceType.CAMERA),
        # Already-valid members must pass through untouched.
        ("switch", DeviceType.SWITCH),
        ("router", DeviceType.ROUTER),
        ("camera", DeviceType.CAMERA),
        ("access_point", DeviceType.ACCESS_POINT),
    ],
)
def test_adapter_emitted_types_normalise(emitted: str, expected: DeviceType) -> None:
    assert normalize_device_type(emitted) is expected


def test_the_regression_ap_used_to_raise() -> None:
    """
    The exact failure: DeviceType("ap") raises, which is what silently dropped
    every UniFi access point from inventory. Normalisation must absorb it.
    """
    with pytest.raises(ValueError):
        DeviceType("ap")
    assert normalize_device_type("ap") is DeviceType.ACCESS_POINT


# ── Never raises, whatever it is handed ──────────────────────────


@pytest.mark.parametrize(
    "value",
    ["", "   ", None, "unknown", "wat", "Access Point", "ACCESS_POINT", 42, object()],
)
def test_normalisation_never_raises(value: object) -> None:
    """
    A raise here re-creates the original bug in a new place: the caller is a
    per-device loop that swallows exceptions, so raising means the device
    silently disappears rather than failing loudly.
    """
    assert isinstance(normalize_device_type(value), DeviceType)


def test_missing_type_is_unknown_not_other() -> None:
    for empty in (None, "", "   "):
        assert normalize_device_type(empty) is DeviceType.UNKNOWN


def test_unrecognised_type_falls_back_to_other() -> None:
    assert normalize_device_type("some-new-vendor-thing") is DeviceType.OTHER


def test_case_and_separator_variants_are_absorbed() -> None:
    for variant in ("AP", "Ap", "Access Point", "access-point", "ACCESS_POINT"):
        assert normalize_device_type(variant) is DeviceType.ACCESS_POINT


def test_passing_an_enum_member_through_is_idempotent() -> None:
    for member in DeviceType:
        assert normalize_device_type(member) is member
        assert normalize_device_type(member.value) is member


# ── The round trip that was actually broken ──────────────────────


@pytest.mark.parametrize("emitted", ["ap", "phone", "storage", "camera_ptz", "unknown", ""])
def test_normalised_values_survive_the_response_model(emitted: str) -> None:
    """
    The end-to-end property that matters: whatever an adapter emits, once
    normalised it must serialise through a response model declaring the strict
    enum. Unnormalised, these are exactly the values that 500 the endpoint.
    """
    ok = _Response(device_type=normalize_device_type(emitted))
    assert ok.device_type in set(DeviceType)


def test_unnormalised_values_would_still_break_the_response_model() -> None:
    """
    Negative control for the test above: proves the round-trip test is not
    vacuous, and documents why the normaliser has to exist at all.
    """
    for raw in ("ap", "phone", "storage", "camera_ptz"):
        with pytest.raises(ValidationError):
            _Response(device_type=raw)  # type: ignore[arg-type]


# ── Guard against a new adapter reintroducing the gap ────────────


def test_every_unifi_mapped_type_normalises() -> None:
    """
    UniFi is where this was found. Pin its whole map rather than the two
    entries that happened to be broken, so a new hardware family added to
    _UNIFI_TYPE_MAP cannot reintroduce a silently-dropped device.
    """
    from app.adapters.unifi.adapter import _UNIFI_TYPE_MAP

    assert _UNIFI_TYPE_MAP, "UniFi type map is empty - did it move?"
    for unifi_type, emitted in _UNIFI_TYPE_MAP.items():
        result = normalize_device_type(emitted)
        assert result in set(DeviceType), f"{unifi_type} -> {emitted} does not normalise"
        assert result is not DeviceType.OTHER, (
            f"UniFi {unifi_type!r} emits {emitted!r}, which falls through to OTHER. "
            "Add an explicit alias in _DEVICE_TYPE_ALIASES so the device is not "
            "quietly mis-typed in inventory."
        )


def test_no_persist_site_calls_the_bare_enum_constructor() -> None:
    """
    The original defect was `DeviceType(data.device_type)` at a persist site.
    Fail the build if that idiom returns, since its symptom is a device that
    silently never appears rather than an error anyone sees.
    """
    import inspect

    from app.services import discovery

    src = inspect.getsource(discovery)
    assert "DeviceType(data.device_type)" not in src, (
        "discovery.py is constructing DeviceType directly again; route it "
        "through normalize_device_type()"
    )
    assert "normalize_device_type(" in src
