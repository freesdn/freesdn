# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada controller version handling.

The "fully supported" floor (5.9) is a property of the 5.x line. A bare
``minor < 9`` check ignored the major, so v6.2 (newer than 5.14) was wrongly
flagged ``unsupported_version`` — exactly the spurious log noise seen against
the live OC300 on v6.2.10. The floor must be scoped to its own major.
"""
from __future__ import annotations

import pytest

from app.adapters.omada.utils import is_version_below_fully_supported, parse_version


@pytest.mark.parametrize(
    "version,expected",
    [
        ("5.14.30.7", (5, 14, 30)),
        ("6.2.10.18", (6, 2, 10)),
        ("5.9", (5, 9, 0)),
        ("", (0, 0, 0)),
        (None, (0, 0, 0)),
    ],
)
def test_parse_version(version, expected) -> None:
    assert parse_version(version) == expected


@pytest.mark.parametrize(
    "major,minor,below",
    [
        (5, 8, True),    # legacy 5.x below the floor → warn
        (5, 0, True),
        (5, 9, False),   # exactly the floor → fully supported
        (5, 14, False),
        (6, 2, False),   # v6.2 is NEWER than 5.14 — must NOT be flagged (the bug)
        (6, 0, False),
        (7, 1, False),   # any future major is above the 5.x floor
    ],
)
def test_is_version_below_fully_supported(major, minor, below) -> None:
    assert is_version_below_fully_supported(major, minor) is below


def test_live_controller_version_not_flagged() -> None:
    # The owner's live OC300 runs 6.2.10.18 — it must parse and NOT warn.
    major, minor, _ = parse_version("6.2.10.18")
    assert (major, minor) == (6, 2)
    assert is_version_below_fully_supported(major, minor) is False
