"""Owned SQL audit retention and owner-retirement contracts, not HTTP authority."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization, Site
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac
from app.services.security_audit import PersistentSecurityAuditService


async def start(db, org, site):
    async with AsyncSession(db) as session:
        assert await session.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
        session.add(Organization(id=org, name="Owned audit retention", slug="owned-" + org.hex))
        await session.flush()
        session.add(Site(id=site, organization_id=org, name="Owned audit site", slug="owned-" + site.hex))
        await session.commit()


async def finish(db, ids, org, site):
    async with db.begin() as connection:
        await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.id.in_(ids)))
        await connection.execute(delete(Site).where(Site.id == site))
        await connection.execute(delete(Organization).where(Organization.id == org))
    await db.dispose()


@pytest.mark.parametrize("cleaner", ["main", "legacy"])
@pytest.mark.parametrize("layout", ["head", "interior", "tail", "all_old"])
async def test_retention_only_removes_an_authenticated_append_prefix(cleaner, layout, record_property):
    db = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org, site = uuid4(), uuid4()
    ids = [uuid4() for _ in range(4)]
    ages = {"head": [120, 20, 10], "interior": [20, 120, 10],
            "tail": [20, 10, 120], "all_old": [120, 130, 140]}[layout]
    expected_retained = {"head": ids[1:3], "interior": ids[:3],
                         "tail": ids[:3], "all_old": []}[layout]
    stamp = datetime.now(UTC)
    try:
        await start(db, org, site)
        async with AsyncSession(db, expire_on_commit=False) as session:
            for identity, age in zip(ids[:3], ages, strict=True):
                await AuditService(session).persist_record(AuditLogRecord(
                    id=identity, timestamp=stamp - timedelta(days=age), action="owned_retention",
                    resource_type="owned_retention", organization_id=org, site_id=site,
                ))
            await session.commit()
        async with AsyncSession(db) as session:
            before = await AuditService(session).validate_audit_chain()
            tail = await session.get(AuditLogRecord, ids[2])
            original_tail_hash = tail.row_hmac
            assert before["valid"]
            if cleaner == "main":
                removed = await AuditService(session).cleanup_old_entries(retention_days=90)
            else:
                removed = (await PersistentSecurityAuditService.cleanup_old_entries(
                    session, retention_days=90,
                ))["audit_logs"]
            await session.commit()
        async with AsyncSession(db) as session:
            retained = list((await session.scalars(select(AuditLogRecord.id).where(
                AuditLogRecord.organization_id == org,
            ).order_by(AuditLogRecord.append_sequence))).all())
            after_cleanup = await AuditService(session).validate_audit_chain()
            await AuditService(session).persist_record(AuditLogRecord(
                id=ids[3], timestamp=datetime.now(UTC), action="owned_after_retention",
                resource_type="owned_retention", organization_id=org, site_id=site,
            ))
            await session.commit()
        async with AsyncSession(db) as reader:
            new = await reader.get(AuditLogRecord, ids[3])
            verdict = await AuditService(reader).validate_audit_chain()
            record_property("retained_owned_IDs", json.dumps(list(map(str, retained))))
            record_property("actual_removed_count", removed)
            record_property("after_cleanup_verdict", json.dumps(after_cleanup))
            record_property("after_append_verdict", json.dumps(verdict))
            record_property("append_preserves_original_tail_hash", new.prev_hash == original_tail_hash)
            assert retained == expected_retained
            assert removed == 3 - len(expected_retained)
            assert new.prev_hash == original_tail_hash
            assert verdict["valid"] and verdict["boundary_verified"]
    finally:
        await finish(db, ids, org, site)


@pytest.mark.parametrize("owner", ["organization", "site"])
async def test_owner_retirement_does_not_rewrite_signed_context(owner, record_property):
    db = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org, site, identity = uuid4(), uuid4(), uuid4()
    try:
        await start(db, org, site)
        async with AsyncSession(db) as session:
            await AuditService(session).persist_record(AuditLogRecord(
                id=identity, timestamp=datetime.now(UTC), action="owned_owner_retirement",
                resource_type="owned_context", organization_id=org, site_id=site,
            ))
            await session.commit()
        async with db.begin() as connection:
            if owner == "organization":
                await connection.execute(delete(Organization).where(Organization.id == org))
            else:
                await connection.execute(delete(Site).where(Site.id == site))
        async with AsyncSession(db) as reader:
            row = await reader.get(AuditLogRecord, identity)
            exists = await reader.get(Organization if owner == "organization" else Site,
                                      org if owner == "organization" else site)
            body_valid = row.row_hmac == _compute_row_hmac(row.prev_hash, row)
            verdict = await AuditService(reader).validate_audit_chain()
            record_property("owner_deleted", exists is None)
            record_property("signed_organization_snapshot_preserved", row.organization_id == org)
            record_property("signed_site_snapshot_preserved", row.site_id == site)
            record_property("stored_body_HMAC_valid", body_valid)
            record_property("actual_chain_verdict", json.dumps(verdict))
            assert exists is None
            assert row.organization_id == org and row.site_id == site
            assert body_valid and verdict["valid"]
    finally:
        await finish(db, [identity], org, site)
