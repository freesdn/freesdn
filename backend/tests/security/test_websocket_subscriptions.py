# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test WebSocket subscription RBAC.

Covers the pattern-level permission check applied when a client sends a
``subscribe`` message. The check must:

  * Deny admin/system patterns to non-superusers.
  * Allow users with the mapped permission (e.g. ``device:read``) to
    subscribe to the corresponding prefix (``device.*``).
  * Allow super_admins to subscribe to admin-only patterns.
  * Default-deny any unknown pattern.

The helpers live in ``app.core.ws_rbac`` (a tiny dependency-free module) and
are re-exported from ``app.api.v1.endpoints.websocket`` under the same names
used in the acceptance spec (``_user_can_subscribe``,
``SUBSCRIPTION_PERMISSIONS``, ``ConnectionRateLimiter``).
"""

from unittest.mock import MagicMock

from app.core.ws_rbac import (
    SUBSCRIPTION_PERMISSIONS,
    ConnectionRateLimiter,
)
from app.core.ws_rbac import user_can_subscribe as _user_can_subscribe


class TestSubscriptionPermissions:
    def test_viewer_cannot_subscribe_to_admin(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission.return_value = False
        assert not _user_can_subscribe(user, "admin.*")

    def test_viewer_cannot_subscribe_to_system(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission.return_value = False
        assert not _user_can_subscribe(user, "system.health")

    def test_viewer_can_subscribe_to_device(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission = lambda p: p == "device:read"
        assert _user_can_subscribe(user, "device.*")

    def test_viewer_without_audit_denied_audit(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission = lambda p: p == "device:read"
        assert not _user_can_subscribe(user, "audit.log")

    def test_super_admin_can_subscribe_to_admin(self) -> None:
        user = MagicMock()
        user.is_superuser = True
        user.has_permission.return_value = True
        assert _user_can_subscribe(user, "admin.*")

    def test_super_admin_can_subscribe_to_system(self) -> None:
        user = MagicMock()
        user.is_superuser = True
        user.has_permission.return_value = True
        assert _user_can_subscribe(user, "system.*")

    def test_unknown_pattern_denied(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission.return_value = True
        assert not _user_can_subscribe(user, "random_pattern.*")

    def test_empty_pattern_denied(self) -> None:
        user = MagicMock()
        user.is_superuser = True
        user.has_permission.return_value = True
        assert not _user_can_subscribe(user, "")

    def test_non_string_pattern_denied(self) -> None:
        user = MagicMock()
        user.is_superuser = True
        user.has_permission.return_value = True
        assert not _user_can_subscribe(user, 123)  # type: ignore[arg-type]

    def test_firehose_denied_for_non_superuser(self) -> None:
        user = MagicMock()
        user.is_superuser = False
        user.has_permission.return_value = True
        assert not _user_can_subscribe(user, "*")

    def test_firehose_allowed_for_superuser(self) -> None:
        user = MagicMock()
        user.is_superuser = True
        user.has_permission.return_value = True
        assert _user_can_subscribe(user, "*")

    def test_permission_map_contains_restricted_prefixes(self) -> None:
        # Regression guard so a refactor can't silently drop admin/system gates
        assert SUBSCRIPTION_PERMISSIONS["admin."] is None
        assert SUBSCRIPTION_PERMISSIONS["system."] is None
        assert SUBSCRIPTION_PERMISSIONS["audit."] == "audit:read"
        assert SUBSCRIPTION_PERMISSIONS["security."] == "audit:read"
        assert SUBSCRIPTION_PERMISSIONS["settings."] == "settings:read"
        assert SUBSCRIPTION_PERMISSIONS["user."] == "user:read"


class TestConnectionRateLimiter:
    def test_allows_up_to_limit(self) -> None:
        rl = ConnectionRateLimiter(max_per_second=5, window=60.0)
        for _ in range(5):
            assert rl.check() is True

    def test_rejects_over_limit(self) -> None:
        rl = ConnectionRateLimiter(max_per_second=3, window=60.0)
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is False
        assert rl.check() is False

    def test_window_expiry_releases_budget(self) -> None:
        rl = ConnectionRateLimiter(max_per_second=2, window=0.05)
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is False
        import time

        time.sleep(0.08)
        assert rl.check() is True
