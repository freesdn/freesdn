"""
Integration tests — quota enforcement + TOCTOU prevention.

Verifies that ``OrganizationService._check_quota`` actually serializes
concurrent insertions via ``SELECT FOR UPDATE`` so two parallel
"create site" requests cannot race past the same limit.

The TOCTOU window we're testing for:
  T1: SELECT count(sites) WHERE org_id=X         → returns N (= max - 1)
  T2: SELECT count(sites) WHERE org_id=X         → returns N (= max - 1)
  T1: ALLOWED, INSERT site                       → count is now max
  T2: ALLOWED, INSERT site                       → count is now max+1 (BUG)

The fix in services/organization.py uses ``with_for_update()`` on the
Organization row before counting, so T2 blocks until T1's transaction
commits. Then T2 sees the already-incremented count and rejects.

These tests use TWO independent SQLAlchemy sessions backed by separate
asyncpg connections, run them concurrently with ``asyncio.gather``, and
assert the cap is honored.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _enforce_quotas(monkeypatch: pytest.MonkeyPatch) -> None:
    """Quota enforcement is OPT-IN: self-hosted installs are unlimited, so
    ``OrganizationService._check_quota`` returns early unless
    ``settings.ENFORCE_ORG_QUOTAS`` is true (a deliberate product behavior). This
    module specifically exercises enforcement, so turn it on for these tests."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "ENFORCE_ORG_QUOTAS", True, raising=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def quota_org(integration_engine: Any) -> dict[str, Any]:
    """Create an organization on the FREE tier (max_sites=1).

    Uses a dedicated session bound to the integration_engine so the row
    is COMMITTED to the test database — not stuck inside the per-test
    SAVEPOINT-rollback envelope used by ``integration_db``. This is
    required because the concurrent-quota test creates two new sessions
    that need to SEE this org row.

    Cleanup: deletes the org (and its sites via FK cascade) at teardown.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.core import Organization

    Session = async_sessionmaker(
        integration_engine, class_=AsyncSession, expire_on_commit=False
    )

    org_id = uuid4()
    async with Session() as session:
        async with session.begin():
            org = Organization(
                id=org_id,
                name="Quota Test Org",
                slug=f"quota-test-{uuid4().hex[:8]}",
                contact_email="quota@example.com",
                # tier in settings["tier"] — default FREE → max_sites=1
                settings={"tier": "free"},
            )
            session.add(org)

    yield {"id": org_id}

    async with Session() as session:
        async with session.begin():
            obj = await session.get(Organization, org_id)
            if obj is not None:
                await session.delete(obj)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_quota_check_allows_under_limit(
    integration_engine: Any, quota_org: dict[str, Any]
) -> None:
    """At zero sites, _check_quota does NOT raise for ``sites``."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.organization import OrganizationService

    Session = async_sessionmaker(
        integration_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with Session() as session:
        async with session.begin():
            service = OrganizationService(session)
            # FREE tier max_sites = 1; current count = 0; should be allowed
            await service._check_quota(quota_org["id"], "sites", increment=1)


async def test_quota_check_rejects_over_limit(
    integration_engine: Any, quota_org: dict[str, Any]
) -> None:
    """When current sites == max, the next _check_quota raises 403."""
    from fastapi import HTTPException
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.core import Site
    from app.services.organization import OrganizationService

    Session = async_sessionmaker(
        integration_engine, class_=AsyncSession, expire_on_commit=False
    )

    # Pre-populate one site (we're at max)
    site_id = uuid4()
    async with Session() as session:
        async with session.begin():
            session.add(
                Site(
                    id=site_id,
                    organization_id=quota_org["id"],
                    name="Existing Site",
                    slug="existing",
                )
            )

    try:
        async with Session() as session:
            async with session.begin():
                service = OrganizationService(session)
                with pytest.raises(HTTPException) as exc_info:
                    await service._check_quota(quota_org["id"], "sites", increment=1)
                assert exc_info.value.status_code == 403
                assert "Quota exceeded" in exc_info.value.detail
    finally:
        # Cleanup — delete the pre-populated site
        async with Session() as session:
            async with session.begin():
                obj = await session.get(Site, site_id)
                if obj is not None:
                    await session.delete(obj)


async def test_concurrent_quota_check_serializes_via_for_update(
    integration_engine: Any, quota_org: dict[str, Any]
) -> None:
    """TWO concurrent _check_quota + INSERT pairs against the same org
    must NOT both succeed when the org is at max-sites - 1.

    This is the regression test for the TOCTOU bug. Without
    ``SELECT … FOR UPDATE`` on the org row, both transactions see the
    pre-insert count and both pass the check. With FOR UPDATE the second
    transaction blocks on the first's commit, then sees the incremented
    count and rejects.

    Setup:
      - FREE tier (max_sites=1)
      - 0 sites currently (capacity for exactly 1)
      - Two concurrent transactions each try to insert one site

    Expected:
      - Exactly one transaction succeeds
      - The other raises HTTPException(403)
    """
    from fastapi import HTTPException
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.core import Site
    from app.services.organization import OrganizationService

    Session = async_sessionmaker(
        integration_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def attempt_create(name: str) -> dict[str, Any]:
        async with Session() as session:
            try:
                async with session.begin():
                    service = OrganizationService(session)
                    await service._check_quota(quota_org["id"], "sites", increment=1)
                    site = Site(
                        id=uuid4(),
                        organization_id=quota_org["id"],
                        name=name,
                        slug=name.lower().replace(" ", "-"),
                    )
                    session.add(site)
                return {"name": name, "result": "ok"}
            except HTTPException as exc:
                return {"name": name, "result": "rejected", "status": exc.status_code}

    # Fire BOTH attempts at the same time; whichever wins the FOR UPDATE
    # lock gets to insert.
    a, b = await asyncio.gather(
        attempt_create("Site A"),
        attempt_create("Site B"),
    )

    statuses = sorted([a["result"], b["result"]])
    assert statuses == ["ok", "rejected"], (
        f"expected exactly one ok and one rejected; got {a!r} and {b!r}"
    )

    # Verify exactly 1 site exists (no race-induced extra row)
    async with Session() as session:
        count = await session.scalar(
            select(func.count(Site.id)).where(
                Site.organization_id == quota_org["id"],
                Site.deleted_at.is_(None),
            )
        )
    assert count == 1, f"expected 1 site after race, got {count}"


async def test_quota_check_raises_for_unknown_org(
    integration_engine: Any,
) -> None:
    """_check_quota against a non-existent org_id raises a clear error."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.organization import OrganizationNotFoundError, OrganizationService

    Session = async_sessionmaker(
        integration_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with Session() as session:
        async with session.begin():
            service = OrganizationService(session)
            with pytest.raises(OrganizationNotFoundError):
                await service._check_quota(uuid4(), "sites", increment=1)
