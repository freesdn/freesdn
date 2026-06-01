# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Shared helpers for the per-vendor catastrophic-op preflight gates."""

from typing import Any


def payload_confirmed(payload: dict[str, Any] | None) -> bool:
    """Strict affirmative check for a staged change's ``confirmed`` flag.

    The historical ``bool(payload.get("confirmed"))`` was unsafe: in Python every
    non-empty string is truthy, so ``bool("false")`` is ``True`` — an operator (or
    attacker) could bypass the catastrophic-op confirmation gate by sending the
    STRING ``"false"`` instead of the boolean ``false``. Accept ONLY a genuine
    affirmative: boolean ``True`` or the canonical truthy string/number forms a
    JSON client might send. Everything else (``False``, ``"false"``, ``""``, ``0``,
    ``None``, arbitrary strings) is treated as NOT confirmed.
    """
    v = (payload or {}).get("confirmed")
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes", "on"}
    return v == 1
