# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Residual crown-jewel invariants (core-verification, follow-on wave).

Pins the lower-tier-but-still-CRITICAL invariants the assessment left UNPROVEN:
SSO cross-org takeover + no-super_admin-auto-grant, export org-scoping, and the
plugin install/runtime-dep trust boundary. A failure here is a cross-tenant,
privilege-escalation, or trust-boundary regression.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession


# ── PS-16: runtime python-dep installs are disabled by default ──
def test_runtime_python_dep_installs_disabled_by_default() -> None:
    from app.core.config import settings

    assert settings.PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS is False
    # Direct-URL plugin installs are also opt-in.
    assert settings.PLUGIN_ENABLE_DIRECT_URL_INSTALLS is False


# ── PS-01: plugin install is super_admin-only ──
class TestPluginInstallGate:
    def test_non_superuser_blocked(self) -> None:
        from app.api.v1.endpoints.plugins import _require_plugin_platform_admin

        with pytest.raises(HTTPException) as exc:
            _require_plugin_platform_admin(SimpleNamespace(is_superuser=False))
        assert exc.value.status_code == 403

    def test_superuser_allowed(self) -> None:
        from app.api.v1.endpoints.plugins import _require_plugin_platform_admin

        # No raise == allowed.
        _require_plugin_platform_admin(SimpleNamespace(is_superuser=True))


# ── TI-12: SSO never auto-grants super_admin ──
class TestSsoRoleMapping:
    def test_super_admin_group_does_not_grant_super_admin(self) -> None:
        from app.services.sso import SSOService

        # Provider maps a group to super_admin AND org_admin; the claim carries
        # the super_admin group. _map_role must NEVER return super_admin via SSO.
        provider = SimpleNamespace(
            role_mapping={"super_admin": ["idp-admins"], "org_admin": ["idp-ops"]},
            default_role="viewer",
        )
        role = SSOService(MagicMock())._map_role(provider, {"groups": ["idp-admins"]})
        assert role != "super_admin"
        assert role == "viewer"  # falls through to default (super_admin excluded)

    def test_mapped_org_admin_group_is_honored(self) -> None:
        from app.services.sso import SSOService

        provider = SimpleNamespace(role_mapping={"org_admin": ["idp-ops"]}, default_role="viewer")
        role = SSOService(MagicMock())._map_role(provider, {"groups": ["idp-ops"]})
        assert role == "org_admin"


# ── TI-07: MFA-enabled user cannot get a full token without the 2nd factor ──
class TestMfaNotBypassable:
    @pytest.mark.asyncio
    async def test_mfa_user_gets_challenge_not_full_token(self) -> None:
        from app.services.sso import SSOService

        # An IdP/LDAP-authenticated user who has local MFA enabled must receive a
        # short-lived mfa_pending challenge — NOT a full access+refresh pair —
        # otherwise a compromised IdP/LDAP password bypasses the second factor.
        user = SimpleNamespace(
            id=uuid4(), mfa_enabled=True, mfa_secret="JBSWY3DPEHPK3PXP", token_version=0
        )
        resp = await SSOService(MagicMock())._issue_tokens(user, provider=None)
        assert resp.require_mfa is True
        assert resp.access_token is None
        assert resp.refresh_token is None
        assert resp.mfa_token is not None


# ── Shared two-org DB world (org A user + per-org site/device) ──
@pytest_asyncio.fixture
async def world(db_session: AsyncSession):
    from app.models.core import Organization, Site, User
    from app.models.devices import Device

    org_a = Organization(name=f"A-{uuid4()}", slug=f"a-{uuid4().hex[:8]}")
    org_b = Organization(name=f"B-{uuid4()}", slug=f"b-{uuid4().hex[:8]}")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    site_a = Site(organization_id=org_a.id, name="sa", slug=f"sa-{uuid4().hex[:6]}")
    site_b = Site(organization_id=org_b.id, name="sb", slug=f"sb-{uuid4().hex[:6]}")
    db_session.add_all([site_a, site_b])
    await db_session.flush()

    dev_a = Device(site_id=site_a.id, name="dev-a", device_type="switch")
    dev_b = Device(site_id=site_b.id, name="dev-b", device_type="switch")
    db_session.add_all([dev_a, dev_b])

    user_a = User(
        email=f"alice-{uuid4().hex[:8]}@example.com",
        username=f"alice-{uuid4().hex[:6]}",
        hashed_password="x",
        role="viewer",
        organization_id=org_a.id,
        is_active=True,
    )
    db_session.add(user_a)
    await db_session.flush()

    return SimpleNamespace(
        org_a=org_a,
        org_b=org_b,
        site_a=site_a,
        site_b=site_b,
        dev_a=dev_a,
        dev_b=dev_b,
        user_a=user_a,
    )


# ── TI-11: SSO cannot take over a foreign-org account ──
class TestSsoCrossOrgTakeover:
    @pytest.mark.asyncio
    async def test_foreign_org_email_is_refused(self, db_session, world):
        from app.services.sso import SSOAuthError, SSOService

        # A provider in org B asserts org-A user alice's email. The org-scoped
        # lookup misses (alice is org A), and the foreign-org defense refuses
        # rather than minting a token for / JIT-duplicating the victim.
        provider_b = SimpleNamespace(
            id=uuid4(),
            organization_id=world.org_b.id,
            protocol=SimpleNamespace(value="oidc"),
            jit_provisioning=True,
            role_mapping={},
            default_role="viewer",
        )
        svc = SSOService(db_session)
        with pytest.raises(SSOAuthError):
            await svc._provision_or_update_user(
                provider_b, {"email": world.user_a.email}, {"sub": "x"}
            )


# ── TI-13: full-system export only collects the requesting org's data ──
class TestExportOrgScoping:
    @pytest.mark.asyncio
    async def test_export_excludes_other_org(self, db_session, world):
        from app.services.backup import BackupService

        data = await BackupService(db_session).collect_backup_data(organization_id=world.org_a.id)
        # No org-B site or device may appear in org A's export blob.
        blob = str(data)
        assert str(world.site_b.id) not in blob
        assert "dev-b" not in blob
        # ...and org A's own data IS present (sanity: the export isn't just empty).
        assert "dev-a" in blob or str(world.site_a.id) in blob
