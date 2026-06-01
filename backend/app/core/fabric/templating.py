# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — safe template resolution for data passing.

Lets a Connection step reference the trigger payload and prior steps' outputs in
its params, e.g. ``{"camera_id": "{{trigger.camera_id}}", "note": "snap
{{steps.0.output.bytes}}"}``. This is the mechanism that flows one app's output
into another app's input.

**Not a templating language — a dotted-path resolver.** There is no expression
evaluation, no function calls, no attribute access on Python objects; only
lookups into the (JSON-shaped) context dict via ``a.b.c`` / ``list.0.x`` paths.
This makes server-side template injection impossible by construction. Hardened
with a recursion-depth cap and a rendered-string-length cap.
"""

from __future__ import annotations

import json
import re
from typing import Any

# A reference is the whole string (``"{{trigger.x}}"``) or embedded
# (``"got {{steps.0.output.n}} frames"``). Path chars: alnum, _, -, .
_REF_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")
_WHOLE_RE = re.compile(r"^\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}$")

_MAX_DEPTH = 12
_MAX_RENDERED_STR = 16 * 1024  # 16 KiB per rendered string
_MAX_REF_OBJECT_BYTES = 256 * 1024  # whole-reference object (dict/list) ceiling


def _cap_object(value: Any) -> Any:
    """Bound a whole-reference OBJECT (dict/list) pulled from an untrusted payload
    before it flows into a step/staged-write param. Strings are capped separately;
    without this an event field that is a large object would be copied verbatim.
    """
    try:
        if len(json.dumps(value, default=str)) <= _MAX_REF_OBJECT_BYTES:
            return value
    except (TypeError, ValueError):
        return None
    return {"__truncated__": f"resolved value exceeded {_MAX_REF_OBJECT_BYTES} bytes"}


def _lookup(path: str, context: dict[str, Any]) -> Any:
    """Walk a dotted path into the context. Integer segments index lists.

    Returns ``None`` if any segment is missing — a missing reference resolves to
    null rather than raising, so a partially-populated trigger doesn't blow up a
    Connection.
    """
    cur: Any = context
    for seg in path.split("."):
        if isinstance(cur, dict):
            if seg not in cur:
                return None
            cur = cur[seg]
        elif isinstance(cur, (list, tuple)):
            if not seg.isdigit():
                return None
            idx = int(seg)
            if idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur


def resolve_template(value: Any, context: dict[str, Any], _depth: int = 0) -> Any:
    """Recursively resolve ``{{...}}`` references in ``value`` against ``context``.

    * A string that is *exactly* one reference returns the resolved value with
      its native type preserved (so ``"{{trigger.count}}"`` yields an int, and
      ``"{{trigger.obj}}"`` yields a dict) — important for typed params.
    * A string with embedded reference(s) is rendered to a string (each ref
      stringified), length-capped.
    * Dicts/lists are resolved element-wise; scalars pass through unchanged.
    """
    # Strings are leaves (no recursion) — resolve them at ANY depth so a deep
    # reference never leaks as a literal ``{{trigger.x}}`` into the params.
    if isinstance(value, str):
        whole = _WHOLE_RE.match(value)
        if whole:
            resolved = _lookup(whole.group(1), context)
            # Bound a whole-reference STRING too (an untrusted, e.g. plugin-sourced,
            # event field must not push an unbounded value into a step param).
            # Non-string types preserve their native shape for typed params.
            if isinstance(resolved, str):
                return resolved[:_MAX_RENDERED_STR]
            if isinstance(resolved, (dict, list)):
                return _cap_object(resolved)
            return resolved

        def _sub(m: re.Match[str]) -> str:
            resolved = _lookup(m.group(1), context)
            return "" if resolved is None else str(resolved)

        rendered = _REF_RE.sub(_sub, value)
        return rendered[:_MAX_RENDERED_STR]

    # Container recursion is depth-bounded (DoS guard). Past the cap, DROP the
    # over-deep subtree (return None) rather than returning it verbatim with
    # unresolved ``{{...}}`` literals inside — leaf strings above already resolve.
    if _depth > _MAX_DEPTH:
        return None

    if isinstance(value, dict):
        return {k: resolve_template(v, context, _depth + 1) for k, v in value.items()}

    if isinstance(value, list):
        return [resolve_template(v, context, _depth + 1) for v in value]

    return value
