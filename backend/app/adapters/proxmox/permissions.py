# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Interpret PVE's effective privileges without confusing grants and inheritance.

GET /access/permissions?path=... returns {path: {privilege: propagation}}.
A present privilege with propagation 0 is still granted at that exact path.
Do not infer child access from a parent response: query each concrete path, or
explicitly require propagation as a minimum visibility check. Child ACL/pool
overrides can still restrict visibility even when the parent flag is 1.
"""

from typing import Any


def propagation_flag(value: Any) -> bool | None:
    """Return the strict native flag; None means malformed, not denied."""
    if type(value) in (int, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value in ("0", "1"):
        return value == "1"
    return None


def permissions_at_path(response: Any, path: str) -> dict[str, Any]:
    """Validate a path-filtered response; an empty response means no grants.

    Reject unrelated paths instead of merging them into separately fetched
    permissions. Never reconstruct inheritance or token/user ACL intersections
    locally; the provider returns the effective permissions for its caller.
    """
    if not isinstance(response, dict) or set(response) - {path}:
        raise ValueError("Malformed effective permission response")
    granted = response.get(path, {})
    if not isinstance(granted, dict) or any(
        not isinstance(privilege, str) or propagation_flag(flag) is None
        for privilege, flag in granted.items()
    ):
        raise ValueError("Malformed effective privilege map")
    return granted


def has_privileges(granted: Any, *required: str, propagate: bool = False) -> bool:
    """Check exact-path grants, optionally requiring inheritance for visibility."""
    if not isinstance(granted, dict):
        return False
    for privilege in required:
        flag = propagation_flag(granted.get(privilege))
        if flag is None or (propagate and not flag):
            return False
    return True
