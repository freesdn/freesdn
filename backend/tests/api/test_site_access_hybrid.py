# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the hybrid site-access model.

Hybrid policy:
- super_admin / org_admin → never site-limited (see all org sites).
- a non-admin user with ZERO grants → NOT limited (full role-based
  access, backwards-compatible).
- a non-admin user with >=1 grant → site-limited: only granted sites;
  denied everywhere else.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.core.dependencies import CurrentUser


def _cu(role, org_id, *, grants=None, levels=None):
    user = SimpleNamespace(id=uuid4(), organization_id=org_id, role=role)
    return CurrentUser(
        user=user,
        permissions=["device:read", "device:update", "device:delete"],
        accessible_site_ids=set(grants or []),
        site_access_levels=levels or {},
    )


class TestIsSiteLimited:
    def test_no_grants_not_limited(self):
        u = _cu("operator", uuid4())
        assert u.is_site_limited is False

    def test_with_grants_is_limited(self):
        u = _cu("operator", uuid4(), grants=[uuid4()])
        assert u.is_site_limited is True

    def test_org_admin_never_limited(self):
        u = _cu("org_admin", uuid4(), grants=[uuid4()])
        assert u.is_site_limited is False

    def test_super_admin_never_limited(self):
        u = _cu("super_admin", uuid4(), grants=[uuid4()])
        assert u.is_site_limited is False


class TestCanAccessSite:
    def test_no_grants_allows_any(self):
        u = _cu("operator", uuid4())
        assert u.can_access_site(uuid4()) is True

    def test_limited_allows_only_granted(self):
        granted, other = uuid4(), uuid4()
        u = _cu("operator", uuid4(), grants=[granted])
        assert u.can_access_site(granted) is True
        assert u.can_access_site(other) is False

    def test_org_admin_allows_any(self):
        granted = uuid4()
        u = _cu("org_admin", uuid4(), grants=[granted])
        assert u.can_access_site(uuid4()) is True


class TestHasSitePermission:
    def test_no_grants_inherits_role(self):
        u = _cu("operator", uuid4())
        assert u.has_site_permission("device:update", uuid4()) is True

    def test_limited_denies_non_granted_site(self):
        granted, other = uuid4(), uuid4()
        u = _cu("operator", uuid4(), grants=[granted])
        # granted site → allowed (no per-site level → full)
        assert u.has_site_permission("device:update", granted) is True
        # non-granted site → denied even though role has the permission
        assert u.has_site_permission("device:update", other) is False

    def test_read_level_blocks_write(self):
        granted = uuid4()
        u = _cu(
            "operator", uuid4(),
            grants=[granted], levels={granted: "read"},
        )
        assert u.has_site_permission("device:read", granted) is True
        assert u.has_site_permission("device:update", granted) is False

    def test_no_site_context_unrestricted(self):
        granted = uuid4()
        u = _cu("operator", uuid4(), grants=[granted])
        # site_id=None → no site constraint applied
        assert u.has_site_permission("device:update", None) is True
