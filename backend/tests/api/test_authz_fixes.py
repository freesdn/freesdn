# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for cross-tenant authorization fixes.

Covers the org-scoping helpers and the in-memory scan visibility check
that close the IDOR findings:
- test-credentials / adopt: a credential or controller from another org
  must not resolve (would otherwise enable cred reuse/exfil).
- _scan_visible_to: a scan owned by org A is invisible to org B.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


def _user(org_id, superuser=False):
    return SimpleNamespace(
        id=uuid4(), organization_id=org_id, is_superuser=superuser,
    )


@pytest_asyncio.fixture
async def two_orgs(db_session: AsyncSession):
    from app.models.core import Controller, Credential, Organization, Site

    a = Organization(name=f"a-{uuid4()}", slug=f"a-{uuid4().hex[:8]}")
    b = Organization(name=f"b-{uuid4()}", slug=f"b-{uuid4().hex[:8]}")
    db_session.add_all([a, b])
    await db_session.flush()

    sa = Site(organization_id=a.id, name="sa", slug=f"sa-{uuid4().hex[:6]}")
    sb = Site(organization_id=b.id, name="sb", slug=f"sb-{uuid4().hex[:6]}")
    db_session.add_all([sa, sb])
    await db_session.flush()

    # A credential + controller owned by org B
    cred_b = Credential(
        organization_id=b.id, name="b-cred", credential_type="password",
        scope="organization", username="root",
    )
    ctrl_b = Controller(
        name="b-ctrl", controller_type="mikrotik", host="10.9.9.9",
        port=443, site_id=sb.id,
    )
    db_session.add_all([cred_b, ctrl_b])
    await db_session.flush()
    return SimpleNamespace(
        org_a=a, org_b=b, site_a=sa, site_b=sb, cred_b=cred_b, ctrl_b=ctrl_b,
    )


class TestOrgScopedResolvers:
    @pytest.mark.asyncio
    async def test_credential_from_other_org_not_resolved(
        self, db_session: AsyncSession, two_orgs
    ) -> None:
        from app.api.v1.endpoints.discovery import _credential_in_org

        # org A user must NOT see org B's credential
        assert await _credential_in_org(
            db_session, two_orgs.cred_b.id, _user(two_orgs.org_a.id),
        ) is False
        # org B user can
        assert await _credential_in_org(
            db_session, two_orgs.cred_b.id, _user(two_orgs.org_b.id),
        ) is True
        # superuser can
        assert await _credential_in_org(
            db_session, two_orgs.cred_b.id, _user(None, superuser=True),
        ) is True
        # None credential_id is a no-op pass
        assert await _credential_in_org(
            db_session, None, _user(two_orgs.org_a.id),
        ) is True

    @pytest.mark.asyncio
    async def test_controller_from_other_org_not_resolved(
        self, db_session: AsyncSession, two_orgs
    ) -> None:
        from app.api.v1.endpoints.discovery import _controller_in_org

        assert await _controller_in_org(
            db_session, two_orgs.ctrl_b.id, _user(two_orgs.org_a.id),
        ) is False
        assert await _controller_in_org(
            db_session, two_orgs.ctrl_b.id, _user(two_orgs.org_b.id),
        ) is True

    @pytest.mark.asyncio
    async def test_site_from_other_org_not_resolved(
        self, db_session: AsyncSession, two_orgs
    ) -> None:
        from app.api.v1.endpoints.discovery import _site_in_org

        assert await _site_in_org(
            db_session, two_orgs.site_b.id, _user(two_orgs.org_a.id),
        ) is False
        assert await _site_in_org(
            db_session, two_orgs.site_b.id, _user(two_orgs.org_b.id),
        ) is True


class TestScanVisibility:
    def test_scan_isolation(self) -> None:
        from app.api.v1.endpoints.discovery import _scan_visible_to

        org_a, org_b = uuid4(), uuid4()
        entry = {"organization_id": str(org_a)}

        assert _scan_visible_to(entry, _user(org_a)) is True
        assert _scan_visible_to(entry, _user(org_b)) is False
        # superuser sees all
        assert _scan_visible_to(entry, _user(None, superuser=True)) is True
        # entry with no owner org is not visible to a regular user
        assert _scan_visible_to({"organization_id": None}, _user(org_a)) is False
