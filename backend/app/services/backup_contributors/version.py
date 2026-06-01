# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Strict semver compatibility for backup contributor schemas.

Each contributor declares a ``schema_version`` semver string (e.g.
``"1.0.0"``). On restore, the running code's schema_version is compared
against the schema_version embedded in the backup manifest:

- **Same major** → compatible. Restore proceeds. Minor/patch increases
  inside the same major must remain backwards-compatible (additive
  field changes only — no rename, no remove, no type change).
- **Different major** → incompatible. Restore for that contributor
  is skipped with ``status="schema_mismatch"``. Other contributors
  proceed independently. Operator gets a clear error message in the
  restore report.

This matches the readiness-audit scoping decision (strict semver,
refuse incompatible major). The alternative — best-effort with
unknown-field-skipping — masks real shape changes and leads to silent
data corruption; we deliberately rejected that option.

Industry parallel: pfSense's config.xml schema_version is the same
pattern. UniFi's looser "try and warn" approach is what we're
explicitly NOT doing.
"""

from __future__ import annotations

import re

# semver: <major>.<minor>.<patch> with optional pre-release / build metadata.
# Match the production-leaning subset used by all contributors today
# (no pre-release tags in contributor schemas — those are for software
# versions, not data shapes).
_SEMVER_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$",
)


class InvalidSchemaVersion(ValueError):
    """Raised when a contributor declares a non-semver schema_version."""


def parse(version: str) -> tuple[int, int, int]:
    """Parse a strict X.Y.Z semver into ``(major, minor, patch)``.

    Raises ``InvalidSchemaVersion`` on anything that doesn't fit the
    bare X.Y.Z shape. We deliberately reject pre-release tags
    (``1.0.0-beta``) and build metadata (``1.0.0+abc123``) — these are
    for software versions, and a contributor's schema_version should
    bump cleanly when the data shape changes.
    """
    m = _SEMVER_RE.match(version)
    if m is None:
        raise InvalidSchemaVersion(
            f"contributor schema_version {version!r} is not strict semver "
            f"(expected '<major>.<minor>.<patch>', e.g. '1.0.0')"
        )
    return int(m["major"]), int(m["minor"]), int(m["patch"])


def is_compatible(payload_version: str, code_version: str) -> bool:
    """True iff the running code can restore a payload of ``payload_version``.

    Rules:
      - Same major → compatible. Restore proceeds.
      - Code major newer than payload (e.g. payload 1.4.2 → code 2.0.0)
        → incompatible. Restore for that contributor is skipped.
      - Code major OLDER than payload (downgrade) → also incompatible.
        The operator is restoring a backup taken on a newer instance;
        we cannot safely interpret fields the running code doesn't know.

    Minor / patch differences within the same major are always allowed
    — the contributor is responsible for tolerating new optional fields
    (additive) and ignoring fields the running code doesn't recognize.

    Raises ``InvalidSchemaVersion`` if either version string is malformed.
    """
    payload = parse(payload_version)
    code = parse(code_version)
    return payload[0] == code[0]


def describe_mismatch(payload_version: str, code_version: str) -> str:
    """Human-readable explanation for a refused restore, used in the
    per-contributor RestoreResult ``errors`` list so the operator sees
    why a module was skipped."""
    payload = parse(payload_version)
    code = parse(code_version)
    if payload[0] < code[0]:
        return (
            f"backup payload schema is v{payload_version} (older major); "
            f"running code expects v{code_version}. Upgrade required: the "
            f"contributor must implement ``migrate_from`` to convert the "
            f"older payload. Restore for this contributor skipped."
        )
    if payload[0] > code[0]:
        return (
            f"backup payload schema is v{payload_version} (newer major); "
            f"running code is at v{code_version}. Downgrade refused — the "
            f"backup was taken on a newer instance and may carry fields "
            f"this code can't safely interpret. Restore for this "
            f"contributor skipped."
        )
    # Same major (compatible) — should not be called.
    return f"schemas are compatible ({payload_version} ↔ {code_version})"


__all__ = [
    "InvalidSchemaVersion",
    "describe_mismatch",
    "is_compatible",
    "parse",
]
