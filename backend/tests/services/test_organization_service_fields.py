# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OrganizationService must write fields Organization has.

``create_organization`` built ``Organization(tier=..., status=...)``; neither is
a column, so it raised ``TypeError`` before any row was written.
``update_organization`` / ``delete_organization`` set ``tier`` / ``status`` with
setattr, which lands on a plain Python attribute that is never persisted. Tier
lives in ``settings["tier"]`` (where ``_check_quota`` reads it) and activity in
``is_active``. Found by tests/models/test_orm_constructor_kwargs.py.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select

from app.models.core import Organization
from app.services.organization import OrganizationService, OrganizationTier


async def _reload(db_session, org_id):
    db_session.expunge_all()
    return (
        await db_session.execute(
            select(Organization)
            .where(Organization.id == org_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()


async def test_create_update_delete_persist_tier_and_activity(db_session):
    svc = OrganizationService(db_session)
    slug = f"org-svc-{uuid4().hex[:8]}"

    org = await svc.create_organization("Org Svc", slug=slug, tier=OrganizationTier.STARTER)
    row = await _reload(db_session, org.id)
    assert row.slug == slug
    assert row.settings["tier"] == "starter"
    assert row.is_active is True

    await svc.update_organization(org.id, tier=OrganizationTier.ENTERPRISE, status="suspended")
    row = await _reload(db_session, org.id)
    assert row.settings["tier"] == "enterprise"
    assert row.is_active is False

    assert await svc.delete_organization(org.id) is True
    row = await _reload(db_session, org.id)
    assert row.deleted_at is not None
    assert row.is_active is False
