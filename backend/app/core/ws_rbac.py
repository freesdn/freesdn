# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""WebSocket subscription RBAC helpers.

Kept in a dependency-free module so unit tests can import it directly
without dragging in FastAPI, SQLAlchemy, Celery, Prometheus, etc.

The WebSocket endpoint re-exports these names.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

# Map event prefixes to required permissions. A pattern must start with one
# of these prefixes (optionally preceded by ``*.``). Unknown prefixes are
# denied by default. ``None`` means super_admin only.
SUBSCRIPTION_PERMISSIONS: dict[str, str | None] = {
    "device.": "device:read",
    "alert.": "alert:read",
    "sla.": "analytics:read",
    "controller.": "controller:read",
    "discovery.": "device:read",
    "vpn.": "vpn:read",
    "pbx.": "device:read",  # PBX sync progress + state events
    "camera.": "device:read",  # camera events / health updates
    "nvr.": "device:read",  # NVR-level events (reboot, status)
    "audit.": "audit:read",  # restricted
    "security.": "audit:read",  # restricted
    "settings.": "settings:read",  # restricted
    "user.": "user:read",  # restricted
    "admin.": None,  # super_admin only
    "system.": None,  # super_admin only
}


def user_can_subscribe(user: Any, pattern: str) -> bool:
    """Return True iff ``user`` is allowed to subscribe to ``pattern``.

    ``user`` is duck-typed: it must expose ``is_superuser: bool`` and a
    ``has_permission(permission: str) -> bool`` callable. The JWT-claim
    principal used by the WebSocket endpoint satisfies this shape, and so
    does the full ``CurrentUser`` used elsewhere.
    """
    if not isinstance(pattern, str) or not pattern:
        return False

    # "*" is a firehose — only super_admins get everything.
    if pattern == "*":
        return bool(getattr(user, "is_superuser", False))

    for prefix, required_perm in SUBSCRIPTION_PERMISSIONS.items():
        if pattern.startswith(prefix) or pattern.startswith(f"*.{prefix}"):
            if required_perm is None:
                return bool(getattr(user, "is_superuser", False))
            has_perm = getattr(user, "has_permission", None)
            if callable(has_perm):
                return bool(has_perm(required_perm))
            return False

    # Unknown pattern — default deny.
    return False


class ConnectionRateLimiter:
    """Per-connection sliding-window rate limiter for inbound WS messages."""

    def __init__(self, max_per_second: int = 5, window: float = 1.0) -> None:
        self.max = max_per_second
        self.window = window
        # ``maxlen`` makes the bound explicit. The sliding window
        # in ``check()`` already evicts old entries, so the deque
        # was already bounded in practice, but spelling it out
        # documents the invariant and protects against a future
        # refactor that forgets to prune.
        self.timestamps: deque[float] = deque(maxlen=max_per_second)

    def check(self) -> bool:
        """Return True if within the rate limit, False if over."""
        now = time.monotonic()
        while self.timestamps and (now - self.timestamps[0]) > self.window:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max:
            return False
        self.timestamps.append(now)
        return True
