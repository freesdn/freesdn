"""Real persisted writer and reader contracts; no HTTP or device operation."""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditQuery, AuditService
from app.services.device_migration import DeviceMigrationService
from app.services.security_audit import PersistentSecurityAuditService


@pytest.mark.parametrize("prior_tail", [False, True])
@pytest.mark.parametrize("writer", ["main", "migration", "security_service"])
async def test_actual_audit_writer_contract(writer, prior_tail, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_id, resource_id, actor_id = uuid4(), uuid4(), uuid4()
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            assert await session.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            session.add(Organization(id=org_id, name="Owned audit writer",
                                     slug="owned-audit-writer-" + org_id.hex))
            await session.commit()
            if prior_tail:
                await AuditService(session).log(action="owned_genesis", resource_type="device",
                                               organization_id=org_id)
                await session.commit()
            metadata = {"note": "owned original metadata", "password": "synthetic-canary"}
            if writer == "main":
                await AuditService(session).log(action="owned_contract", resource_type="device",
                                               resource_id=resource_id, actor_id=actor_id,
                                               organization_id=org_id, extra_metadata=metadata)
            elif writer == "migration":
                await DeviceMigrationService(session, org_id)._write_audit_log(
                    action="owned_contract", resource_type="device", resource_id=str(resource_id),
                    actor_id=actor_id, details=metadata,
                )
            else:
                await PersistentSecurityAuditService.create_audit_log(
                    session, action="owned_contract", resource_type="device",
                    resource_id=str(resource_id), actor_id=str(actor_id),
                    organization_id=org_id, metadata=metadata,
                )
            await session.commit()
        async with AsyncSession(engine, expire_on_commit=False) as reader:
            row = (await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org_id,
                AuditLogRecord.action == "owned_contract",
            ))).one()
            verdict = await AuditService(reader).validate_audit_chain()
            # Observe every field before asserting so a first metadata failure
            # cannot be mistaken for execution of subsequent chain assertions.
            record_property("actual_metadata", json.dumps(row.extra_metadata, sort_keys=True))
            record_property("actual_row_hmac_present", row.row_hmac is not None)
            record_property("actual_chain_verdict", json.dumps(verdict, sort_keys=True))
            assert row.organization_id == org_id
            assert row.resource_id == str(resource_id) and row.actor_id == str(actor_id)
            assert row.extra_metadata == {"note": "owned original metadata", "password": "[REDACTED]"}
            assert row.row_hmac is not None
            assert verdict["valid"] is True and verdict["unchained"] == 0
            assert verdict["checked"] == 1 + int(prior_tail)
    finally:
        async with engine.begin() as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
        await engine.dispose()


@pytest.mark.parametrize("identifier_field", ["resource_id", "actor_id"])
async def test_audit_query_preserves_stored_non_uuid_identifiers(identifier_field, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_id = uuid4()
    external = "owned-vendor-resource/101" if identifier_field == "resource_id" else "owned-service/worker"
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            assert await session.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            session.add(Organization(id=org_id, name="Owned audit identifier",
                                     slug="owned-audit-id-" + org_id.hex))
            await session.commit()
            # This existing service explicitly accepts string identifiers and
            # the actual database columns retain them without UUID constraints.
            await PersistentSecurityAuditService.create_audit_log(
                session, action="owned_identifier", resource_type="device",
                organization_id=org_id, **{identifier_field: external},
            )
            await session.commit()
        async with AsyncSession(engine, expire_on_commit=False) as reader:
            row = (await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org_id,
            ))).one()
            stored = getattr(row, identifier_field)
            record_property("stored_identifier", stored)
            assert stored == external
            entries, total = await AuditService(reader).query(AuditQuery(organization_id=org_id))
            assert total == len(entries) == 1
            assert getattr(entries[0], identifier_field) == external
    finally:
        async with engine.begin() as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
        await engine.dispose()
