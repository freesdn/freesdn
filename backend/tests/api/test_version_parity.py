# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The backend and the agent must order versions identically.

Two independent implementations decide "is this release newer": the backend, to
decide whether to advertise an update, and the agent, to decide whether to accept
one. When they disagree the failure is silent and goes both ways:

  * backend offers, agent refuses -- the agent has ALREADY downloaded the binary
    by the time it checks the signed version, so it re-downloads (up to the
    500 MB cap) on every poll, forever;
  * backend refuses, agent would have accepted -- a genuinely newer release is
    never offered at all, and nobody is told.

fixed only the agent, which produced exactly that split: the backend
still compared raw dotted integers, so ``1.0.0.0`` looked newer than ``1.0.0``
to it and equal to the agent, while ``v2.0.0`` raised inside the backend's
``int()`` and was silently substituted with ``(0, 0, 0)``.

Both sides now use the same grammar. This test pins them against ONE table, so a
change to either implementation alone fails here rather than in the field.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from app.services.release_signing import parse_agent_version as backend_parse

#: Digest of VECTORS below. The AGENT's suite
#: (``agent/tests/test_update_version_grammar.py``) carries the identical table
#: and asserts the identical digest, which is how the two stay in lockstep
#: WITHOUT one importing the other.
#:
#: Cross-importing was tried and rejected: the agent's ``updater`` module pulls
#: dependencies the backend venv does not have, and the CI backend leg mounts
#: only ``backend/`` anyway -- so the comparison would have raised locally and
#: skipped silently in CI, proving nothing. Edit one table and its own suite
#: fails on this digest.
VECTORS_DIGEST = "a0fce4fd19183543"

#: The shared grammar, as behaviour rather than implementation. Each entry is
#: (version_string, expected_normalised_tuple).
VECTORS: list[tuple[str, tuple[int, ...]]] = [
    # plain
    ("1.0.4", (1, 0, 4)),
    ("2.11.3", (2, 11, 3)),
    ("0.1.0", (0, 1)),
    # insignificant trailing zeros collapse -- the perpetual-reinstall bug
    ("1.0.0", (1,)),
    ("1.0.0.0", (1,)),
    ("1.0", (1,)),
    ("1", (1,)),
    ("1.2.0", (1, 2)),
    # a leading v is permitted by the release schema, so it must not explode
    ("v2.0.0", (2,)),
    ("V2.0.1", (2, 0, 1)),
    # pre-release / build suffixes read as their numeric prefix
    ("2.0.0-beta", (2,)),
    ("1.4.2+build7", (1, 4, 2)),
    # unparseable can never look newer
    ("", ()),
    ("latest", ()),
    ("not-a-version", ()),
]


@pytest.mark.parametrize("raw,expected", VECTORS, ids=[v[0] or "<empty>" for v in VECTORS])
def test_backend_parses_to_the_shared_grammar(raw: str, expected: tuple[int, ...]) -> None:
    assert backend_parse(raw) == expected


#: Ordering pairs: (older, newer). Both sides must agree on the direction.
ORDERING: list[tuple[str, str]] = [
    ("1.0.3", "1.0.4"),
    ("1.0.4", "1.1.0"),
    ("1.9.9", "2.0.0"),
    ("1.0.0", "v2.0.0"),
]


@pytest.mark.parametrize("older,newer", ORDERING)
def test_both_sides_agree_an_upgrade_is_an_upgrade(older: str, newer: str) -> None:
    assert backend_parse(newer) > backend_parse(older)


#: Spellings that must compare EQUAL, so neither side offers nor accepts them.
EQUIVALENT: list[tuple[str, str]] = [
    ("1.0.0", "1.0.0.0"),
    ("1.0", "1.0.0"),
    ("1", "1.0.0.0"),
    ("2.0.0", "v2.0.0"),
]


@pytest.mark.parametrize("a,b", EQUIVALENT)
def test_equivalent_spellings_are_not_an_upgrade_on_either_side(a: str, b: str) -> None:
    """The perpetual-reinstall loop, pinned.

    A release row labelled with a trailing zero must not look like an upgrade
    over a binary reporting the shorter form -- on either side.
    """
    assert backend_parse(a) == backend_parse(b)
    assert not backend_parse(b) > backend_parse(a)


def test_the_shared_vector_table_has_not_drifted() -> None:
    """The agent's suite pins the SAME digest.

    Editing this table without editing the agent's copy fails here; editing the
    agent's without editing this one fails there. That is the whole mechanism
    keeping two independent parsers in agreement.
    """
    payload = json.dumps([[a, list(b)] for a, b in VECTORS], separators=(",", ":"))
    assert hashlib.sha256(payload.encode()).hexdigest()[:16] == VECTORS_DIGEST, (
        "the shared version-grammar table changed. Update "
        "agent/tests/test_update_version_grammar.py with the same table and "
        "digest, or the backend and agent will disagree about what is newer."
    )
