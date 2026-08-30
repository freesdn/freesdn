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
    # Observability. The collector now publishes syslog/trap events, and
    # without an entry here they fell through to the default-deny at the bottom
    # -- fail-closed, but it also meant the only subscriber who could ever see
    # them was a super_admin on the "*" firehose, so the feature was invisible
    # to exactly the operators it is for. Mapped to the SAME permission that
    # already gates reading these logs over REST, so this grants nobody
    # anything they could not already read.
    "collector.": "collector.logs.read",
    # Same defect as ``collector.`` above, five more families deep. Each of
    # these event types is published org-scoped by the backend and routed by
    # the frontend's handleMessage, but none had an entry here, so every
    # ``subscribe`` request for them fell through to the default-deny at the
    # bottom of ``user_can_subscribe`` and the server answered
    # ``subscription_denied``. The only principal who could ever receive them
    # was a super_admin on the ``"*"`` firehose. Each maps to the permission
    # that already gates the SAME data over REST, so this grants nobody
    # anything they could not already fetch.
    #
    # Checked one family at a time that the PUBLISHER sets
    # ``Event.organization_id``: ``ConnectionManager._should_receive`` drops
    # any event without one (websocket.py:468), so a mapping on a family whose
    # publisher leaves it None would be inert.
    #   gateway.distribution.*  -> distribution_service.py:560   org set
    #   fabric.connection.changed -> fabric.py:300               org set
    #   backup.validation.failed -> tasks/backup.py:511          org set
    #   overlay.*               -> overlay_monitor.py:70,
    #                              overlay_discovery.py:205      org set
    #   omada.event.*           -> omada_monitor.py:95           org set
    "gateway.": "gateway.view",  # brain/limb sync + VLAN distribution lifecycle
    "fabric.": "event:read",  # /fabric reads take no permission beyond auth
    "backup.": "backup.view",  # scheduled restore-validation failures
    "overlay.": "vpn:read",  # overlay mesh peers/status — same gate as vpn.
    "omada.": "controller:read",  # controller reach transitions — as controller.
    # ``network.`` is the one family in that group that is NOT deliverable yet,
    # and the blocker is not here: modules/network/service.py builds its events
    # through ``_emit()`` and none of its six call sites (lines 311/335/352/
    # 473/497/514) pass ``organization_id``, so ``_network_event`` leaves
    # ``Event.organization_id`` None and ``_should_receive`` drops it before
    # any subscription is consulted. The mapping is correct and belongs here
    # regardless -- without it, fixing those six emits would still deliver
    # nothing and the next reader would look in the wrong file. Mirrors the
    # REST gate: the whole network module is behind ``device:read``
    # (modules/network/api.py:455).
    "network.": "device:read",
    # NOT mapped, deliberately: ``notification.``. Its events carry the whole
    # in-app notification plus the target ``user_id`` (services/notification.py:
    # 2356) and ``_should_receive`` enforces per-user targeting ONLY for
    # site-limited connections (websocket.py:480-492). Permitting the prefix
    # would hand every non-site-limited member of an org every other member's
    # notifications. It needs a user_id check in ``_should_receive`` first.
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
