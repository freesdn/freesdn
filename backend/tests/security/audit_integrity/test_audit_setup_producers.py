"""Actual setup completion and synthetic audit producers, not HTTP setup auth."""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization, Site, User, UserRole
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac
from app.setup.sample_data import _create_audit_logs
from app.setup.schemas import SetupCompleteRequest
from app.setup.service import SetupService


async def seed(engine, org, site, actor, prior):
    async with AsyncSession(engine) as session:
        assert await session.scalar(select(func.count()).select_from(Organization)) == 0
        assert await session.scalar(select(func.count()).select_from(User)) == 0
        session.add(Organization(id=org, name="Owned setup audit", slug="owned-setup-audit-" + org.hex))
        await session.flush()
        session.add(Site(id=site, organization_id=org, name="Owned site", slug="owned-site-" + site.hex))
        session.add(User(id=actor, organization_id=org, email=actor.hex + "@example.invalid",
                         username=actor.hex, role=UserRole.SUPER_ADMIN,
                         hashed_password="disabled-owned-fixture-not-a-login", is_active=True))
        await session.commit()
        if prior:
            await AuditService(session).log(action="owned_genesis", resource_type="setup", organization_id=org)
            await session.commit()


async def cleanup(engine, org, site, actor):
    async with engine.begin() as connection:
        await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org))
        await connection.execute(delete(User).where(User.id == actor))
        await connection.execute(delete(Site).where(Site.id == site))
        await connection.execute(delete(Organization).where(Organization.id == org))
    await engine.dispose()


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize("reject", [False, True])
async def test_actual_setup_completion_audit_and_savepoint(prior, reject, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org, site, actor = uuid4(), uuid4(), uuid4()
    constraint = "owned_setup_audit_reject_" + org.hex
    installed = False
    try:
        await seed(engine, org, site, actor, prior)
        if reject:
            async with engine.begin() as connection:
                await connection.execute(text(
                    f"ALTER TABLE audit.audit_logs ADD CONSTRAINT {constraint} "
                    "CHECK (action <> 'SETUP_COMPLETE')",
                ))
                installed = True
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            response = await SetupService(session).complete_setup(
                SetupCompleteRequest(install_sample_data=False),
                client_ip="127.0.0.1", user_agent="owned-setup-audit-contract",
            )
        async with AsyncSession(engine) as reader:
            org_row = await reader.get(Organization, org)
            rows = list((await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org, AuditLogRecord.action == "SETUP_COMPLETE",
            ))).all())
            verdict = await AuditService(reader).validate_audit_chain()
            valid_bodies = all(r.row_hmac == _compute_row_hmac(r.prev_hash, r) for r in rows)
            record_property("response_success", response.success)
            record_property("durable_completion_hint", bool((org_row.settings or {}).get("setup_completed")))
            record_property("audit_row_count", len(rows))
            record_property("independent_stored_bodies_valid", valid_bodies)
            record_property("actual_chain_verdict", json.dumps(verdict))
            assert response.success
            assert (org_row.settings or {}).get("setup_completed") is True
            assert len(rows) == (0 if reject else 1)
            if rows:
                row = rows[0]
                assert row.actor_id == str(actor) and row.actor_type == "anonymous"
                assert row.actor_email == actor.hex + "@example.invalid"
                assert row.resource_id == str(org) and row.ip_address == "127.0.0.1"
                assert row.user_agent == "owned-setup-audit-contract"
                assert valid_bodies
            assert verdict["valid"] and verdict["checked"] == int(prior) + len(rows)
    finally:
        if installed:
            async with engine.begin() as connection:
                await connection.execute(text(f"ALTER TABLE audit.audit_logs DROP CONSTRAINT {constraint}"))
        await cleanup(engine, org, site, actor)


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize("rollback", [False, True])
async def test_actual_sample_audits_signed_marked_and_transactional(prior, rollback, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org, site, actor = uuid4(), uuid4(), uuid4()
    try:
        await seed(engine, org, site, actor, prior)
        async with AsyncSession(engine, expire_on_commit=False) as session:
            generated = await _create_audit_logs(session, org, [site])
            assert len(generated) == 120
            rows = list((await session.scalars(select(AuditLogRecord).where(
                AuditLogRecord.id.in_([r.id for r in generated]),
            ).execution_options(populate_existing=True))).all())
            marked = all(r.tags == ["sample_data"] and r.extra_metadata == {
                "synthetic": True, "origin": "setup_sample_data",
            } for r in rows)
            valid_bodies = len(rows) == 120 and all(
                r.row_hmac == _compute_row_hmac(r.prev_hash, r) for r in rows
            )
            before = await AuditService(session).validate_audit_chain()
            if rollback:
                await session.rollback()
            else:
                await session.commit()
        async with AsyncSession(engine) as reader:
            count = await reader.scalar(select(func.count()).select_from(AuditLogRecord).where(
                AuditLogRecord.organization_id == org,
            ))
            after = await AuditService(reader).validate_audit_chain()
            record_property("generated_count", len(generated))
            record_property("all_examples_explicitly_marked_synthetic", marked)
            record_property("all_120_row_HMACs_valid", valid_bodies)
            record_property("before_transaction_end_chain", json.dumps(before))
            record_property("after_transaction_end_chain", json.dumps(after))
            record_property("durable_row_count", count)
            assert marked
            assert valid_bodies
            assert count == int(prior) + (0 if rollback else 120)
            assert after["valid"]
            assert after["checked"] == count
    finally:
        await cleanup(engine, org, site, actor)
