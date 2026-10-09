# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded public projections preserve categories without exposing legacy bodies."""

import copy

import pytest

from app.core.controller_diagnostics import (
    CONTROLLER_ERROR,
    public_controller_error,
    public_controller_history,
)


@pytest.mark.parametrize("value", [None, ""])
def test_absent_error_remains_absent(value):
    assert public_controller_error(value) is None


@pytest.mark.parametrize(
    "value",
    [
        False,
        0,
        123,
        {},
        [],
        "owned-private-password",
        "https://owned.invalid/?token=private",
        "SQL parameters: owned-private-password",
    ],
)
def test_unknown_error_is_a_fixed_category(value):
    assert public_controller_error(value) == CONTROLLER_ERROR


@pytest.mark.parametrize(
    "value",
    [
        "Connection failed",
        "Connection test failed",
        "Discovery failed; verify controller connectivity and configuration.",
        "Previous discovery failure",
        "Proxmox API request failed (HTTP 500).",
        "Proxmox API request failed (HTTP 429).",
    ],
)
def test_known_safe_local_error_retains_useful_category(value):
    assert public_controller_error(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "Proxmox API request failed (HTTP 999).",
        "Proxmox API request failed (HTTP True).",
        "Proxmox API request failed (HTTP 500). private",
        "Proxmox API request failed (HTTP 0500).",
        "Proxmox API request failed (HTTP 500).\nprivate",
    ],
)
def test_status_projection_is_exact_and_bounded(value):
    assert public_controller_error(value) == CONTROLLER_ERROR


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        "private",
        [None, "private", {}, {"timestamp": "private", "error": "private"}],
        [{"timestamp": "x" * 41, "error": "private"}],
    ],
)
def test_malformed_history_never_exposes_provider_text(value):
    assert public_controller_history(value) == []


def test_history_is_bounded_to_ten_safe_copies_and_does_not_mutate_input():
    value = [
        {"timestamp": "2026-09-24T00:00:00+00:00", "error": "private", "opaque": "private"}
        for _ in range(100)
    ]
    original = copy.deepcopy(value)
    result = public_controller_history(value)
    assert len(result) == 10
    assert all(
        row == {"timestamp": "2026-09-24T00:00:00+00:00", "error": CONTROLLER_ERROR}
        for row in result
    )
    assert value == original


def test_history_retains_known_safe_category_and_canonical_time():
    value = [{"timestamp": "2026-09-24T00:00:00Z", "error": "Connection failed"}]
    assert public_controller_history(value) == [
        {"timestamp": "2026-09-24T00:00:00+00:00", "error": "Connection failed"}
    ]
