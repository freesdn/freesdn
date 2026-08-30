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


class _Principal:
    """Minimal duck-typed principal with the real wildcard semantics.

    ``user_can_subscribe`` only needs ``is_superuser`` + ``has_permission``.
    The matching rules are copied from ``CurrentUser.has_permission``
    (app/core/dependencies.py:628) because the point of
    ``test_every_mapped_permission_is_granted_to_some_role`` below is to catch
    a MISSPELLED permission -- e.g. ``backup:view`` instead of ``backup.view``
    -- and a stub that answers "yes" to a set membership test would miss the
    dot/colon confusion entirely.
    """

    def __init__(self, permissions: set[str], is_superuser: bool = False) -> None:
        self.permissions = permissions
        self.is_superuser = is_superuser

    def has_permission(self, permission: str) -> bool:
        if self.is_superuser or "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        colon = permission.split(":")
        if len(colon) == 2 and f"{colon[0]}:*" in self.permissions:
            return True
        dot = permission.split(".")
        if len(dot) == 2 and f"{dot[0]}.*" in self.permissions:
            return True
        return False


#: The families that were published, routed by the frontend, and denied by the
#: default-deny at the bottom of ``user_can_subscribe`` because they had no
#: entry in the map. Pattern -> the permission that gates the same data at REST.
_NEWLY_MAPPED = {
    "gateway.distribution.completed": "gateway.view",
    "fabric.connection.changed": "event:read",
    "backup.validation.failed": "backup.view",
    "overlay.peer.online": "vpn:read",
    "omada.event.controller_unreachable": "controller:read",
    "network.vlan.created": "device:read",
}


class TestPreviouslyUnmappedFamilies:
    """Each of these was ``subscription_denied`` for every non-super_admin."""

    def test_holder_of_the_rest_permission_may_subscribe(self) -> None:
        """Mutation this catches: deleting any of the six new map entries.

        Without the entry the pattern reaches ``# Unknown pattern — default
        deny`` and this is False no matter what the principal holds.
        """
        for pattern, perm in _NEWLY_MAPPED.items():
            assert _user_can_subscribe(_Principal({perm}), pattern) is True, pattern

    def test_wildcard_form_is_permitted_too(self) -> None:
        """The frontend subscribes with ``<family>.*``, not a literal type."""
        for pattern, perm in _NEWLY_MAPPED.items():
            family = pattern.split(".")[0] + ".*"
            assert _user_can_subscribe(_Principal({perm}), family) is True, family

    def test_principal_without_the_permission_is_still_denied(self) -> None:
        """Mutation this catches: mapping a family to ``event:read`` (which
        every role including ``guest`` holds) as a shortcut, which would widen
        the stream past its REST gate."""
        for pattern, perm in _NEWLY_MAPPED.items():
            if perm == "event:read":
                continue  # deliberately auth-only at REST; see the map comment
            assert _user_can_subscribe(_Principal({"site:read"}), pattern) is False, pattern

    def test_notification_family_stays_denied(self) -> None:
        """``notification.created`` carries another user's notification body.

        ``_should_receive`` enforces per-user targeting only for site-LIMITED
        connections, so mapping this prefix would broadcast every member's
        in-app notifications to every other member of the org. It must stay
        unmapped until ``_should_receive`` grows a ``payload.user_id`` check.
        """
        assert "notification." not in SUBSCRIPTION_PERMISSIONS
        assert _user_can_subscribe(_Principal({"*"}), "notification.*") is False

    def test_no_prefix_shadows_another(self) -> None:
        """``user_can_subscribe`` returns on the FIRST matching prefix.

        Mutation this catches: adding e.g. ``"net."`` ahead of ``"network."``,
        which would silently re-gate the whole network family on the wrong
        permission depending on dict insertion order.
        """
        prefixes = list(SUBSCRIPTION_PERMISSIONS)
        shadowed = [(a, b) for a in prefixes for b in prefixes if a != b and b.startswith(a)]
        assert not shadowed, f"prefix collision makes the map order-dependent: {shadowed}"

    def test_every_mapped_permission_is_granted_to_some_role(self) -> None:
        """A typo'd permission fails closed and looks exactly like a denial.

        Mutation this catches: ``"backup.": "backup:view"`` (colon instead of
        dot) or ``"gateway.": "gateway:view"`` -- both parse fine, both make
        the prefix unsubscribable for every non-super_admin, and nothing else
        in the suite would notice.
        """
        from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS

        holders = {role: _Principal(set(perms)) for role, perms in DEFAULT_ROLE_PERMISSIONS.items()}
        orphans = [
            f"{prefix} -> {perm}"
            for prefix, perm in SUBSCRIPTION_PERMISSIONS.items()
            if perm is not None
            and not any(
                p.has_permission(perm) for role, p in holders.items() if role != "super_admin"
            )
        ]
        assert not orphans, (
            "these subscription permissions are held by no role, so the prefix "
            f"is dead for everyone but a super_admin: {orphans}"
        )
