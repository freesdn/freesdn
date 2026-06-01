# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: an SSO provider's group->role ``role_mapping`` must be tier-capped
exactly like ``default_role``.

A self-audit found ``_validate_default_role`` guarded ``default_role`` but NOT
``role_mapping``; ``_map_role`` blocks super_admin from group claims yet does not
tier-check the other roles. Not exploitable today (only super_admin/org_admin can
manage providers, and an org_admin granting org_admin is within authority), but a
latent privilege escalation the moment provider management is delegated lower.
``_validate_role_mapping`` closes the asymmetry; these lock it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.sso import _validate_role_mapping
from app.models import UserRole


def _user(role: str):
    return SimpleNamespace(role=role)


def test_none_or_empty_mapping_is_allowed():
    _validate_role_mapping(None, _user(UserRole.ORG_ADMIN.value))
    _validate_role_mapping({}, _user(UserRole.ORG_ADMIN.value))


def test_super_admin_target_rejected_even_for_super_admin_caller():
    for caller in (UserRole.SUPER_ADMIN.value, UserRole.ORG_ADMIN.value):
        with pytest.raises(HTTPException) as ei:
            _validate_role_mapping({"super_admin": ["admins"]}, _user(caller))
        assert ei.value.status_code == 400


def test_targets_at_or_below_caller_tier_allowed():
    # org_admin (tier 1) may map org_admin + operator (same / lower tier)
    _validate_role_mapping({"org_admin": ["a"], "operator": ["b"]}, _user(UserRole.ORG_ADMIN.value))


def test_target_above_caller_tier_rejected():
    # a site_admin must not map a group to org_admin (a higher tier)
    with pytest.raises(HTTPException) as ei:
        _validate_role_mapping({"org_admin": ["admins"]}, _user(UserRole.SITE_ADMIN.value))
    assert ei.value.status_code == 403


def test_invalid_role_name_rejected():
    with pytest.raises(HTTPException) as ei:
        _validate_role_mapping({"wizard": ["g"]}, _user(UserRole.ORG_ADMIN.value))
    assert ei.value.status_code == 400
