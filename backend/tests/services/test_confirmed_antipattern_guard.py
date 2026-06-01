# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Structural guard against the catastrophic-op confirmation bypass.

``bool(payload.get("confirmed"))`` is unsafe: every non-empty string is truthy in
Python, so ``bool("false")`` is ``True`` and ``{"confirmed": "false"}`` bypasses the
gate. The fix routes every confirm check through ``payload_confirmed`` (strict).
This test fails the build if anyone reintroduces the ``bool(...confirmed...)``
anti-pattern, so the whole bug class can't come back."""

from __future__ import annotations

import re
from pathlib import Path

# bool( ... confirmed within a short window — catches both the one-line
# bool(payload.get("confirmed")) and the multi-line bool(\n (payload).get("confirmed")) forms.
_ANTIPATTERN = re.compile(r"bool\([\s\S]{0,80}?confirmed", re.IGNORECASE)


def test_no_bool_confirmed_antipattern() -> None:
    services = Path(__file__).resolve().parents[2] / "app" / "services"
    offenders: list[str] = []
    for f in sorted(services.rglob("*.py")):
        # The helper module documents the anti-pattern in its own docstring.
        if f.name == "adapter_preflight_common.py":
            continue
        text = f.read_text(encoding="utf-8")
        if _ANTIPATTERN.search(text):
            # Report the offending line(s) for a useful failure message.
            for i, line in enumerate(text.splitlines(), 1):
                if "confirmed" in line.lower() and ("bool(" in line or line.strip().startswith("bool(")):
                    offenders.append(f"{f.name}:{i}: {line.strip()}")
            if not any(f.name in o for o in offenders):  # multi-line match
                offenders.append(f"{f.name}: multi-line bool(...confirmed) match")
    assert not offenders, (
        "Confirmation gates must use payload_confirmed() "
        "(app.services.adapter_preflight_common), NOT bool(...confirmed) — "
        "bool('false') is True, a catastrophic-op confirmation bypass:\n"
        + "\n".join(offenders)
    )
