"""Real PostgreSQL normalization, transaction and savepoint writer contracts."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac
from app.services.device_migration import DeviceMigrationService
from app.services.security_audit import PersistentSecurityAuditService


async def write(session, writer, org, action="owned_persistence", **fields):
    if writer == "main":
        return await AuditService(session).log(
            action=action, resource_type="device", organization_id=org, **fields,
        )
    if writer == "legacy":
        return await PersistentSecurityAuditService.create_audit_log(
            session, action=action, resource_type="device", organization_id=org, **fields,
        )
    return await DeviceMigrationService(session, org)._write_audit_log(
        action=action, resource_type="device", resource_id="owned-vendor/101",
        actor_id=None, details={"note": "owned migration helper"},
    )


async def seed(engine, org):
    async with AsyncSession(engine) as session:
        session.add(Organization(id=org, name="Owned writer persistence",
                                 slug="owned-writer-persistence-" + org.hex,
                                 description="before"))
        await session.commit()


async def cleanup(engine, org):
    async with engine.begin() as connection:
        await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org))
        await connection.execute(delete(Organization).where(Organization.id == org))
    await engine.dispose()


@pytest.mark.parametrize("duration", [None, 0, 17, 0.25], ids=["none", "zero", "integer", "fraction"])
async def test_main_signature_matches_committed_float_column(duration, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org = uuid4()
    try:
        await seed(engine, org)
        async with AsyncSession(engine) as session:
            entry = await write(session, "main", org, response_time_ms=duration)
            await session.commit()
        async with AsyncSession(engine) as reader:
            row = await reader.get(AuditLogRecord, entry.id)
            valid = row.row_hmac == _compute_row_hmac(row.prev_hash, row)
            verdict = await AuditService(reader).validate_audit_chain()
            record_property("stored_response_duration", json.dumps(row.response_time_ms))
            record_property("independent_stored_body_HMAC_valid", valid)
            record_property("actual_chain_verdict", json.dumps(verdict))
            assert row.response_time_ms == duration
            assert valid
            assert verdict["valid"] and verdict["checked"] == 1
    finally:
        await cleanup(engine, org)


@pytest.mark.parametrize("profile", ["defaults", "offset", "integer", "zero", "fraction", "nested"])
async def test_legacy_writer_normalizes_signs_and_redacts_persisted_body(profile, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org = uuid4()
    metadata = {"note": "owned", "password": "synthetic-canary"}
    expected_metadata = {"note": "owned", "password": "[REDACTED]"}
    stamp = datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    fields = {"timestamp": stamp, "resource_id": "owned-vendor/101", "actor_id": "owned-service/worker"}
    if profile == "offset":
        fields["timestamp"] = stamp.astimezone(timezone(timedelta(hours=5, minutes=30)))
    if profile in ("integer", "zero", "fraction"):
        fields["response_time_ms"] = {"integer": 17, "zero": 0, "fraction": 0.25}[profile]
    if profile == "nested":
        metadata = {"items": [{"access_token": "synthetic-value", "ok": True}]}
        expected_metadata = {"items": [{"access_token": "[REDACTED]", "ok": True}]}
    try:
        await seed(engine, org)
        async with AsyncSession(engine, expire_on_commit=False) as session:
            record = await write(session, "legacy", org, metadata=metadata, **fields)
            identity = record.id
            await session.commit()
        async with AsyncSession(engine) as reader:
            row = await reader.get(AuditLogRecord, identity)
            valid = row.row_hmac == _compute_row_hmac(row.prev_hash, row)
            record_property("stored_metadata", json.dumps(row.extra_metadata, sort_keys=True))
            record_property("stored_timestamp", row.timestamp.isoformat())
            record_property("independent_stored_body_HMAC_valid", valid)
            assert row.extra_metadata == expected_metadata
            assert row.timestamp == stamp
            assert row.resource_id == fields["resource_id"] and row.actor_id == fields["actor_id"]
            assert row.tags == []
            assert valid
    finally:
        await cleanup(engine, org)


@pytest.mark.parametrize("writer", ["main", "legacy", "migration"])
async def test_real_audit_rejection_keeps_callers_transaction_usable(writer, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org = uuid4()
    constraint = "owned_audit_reject_" + org.hex
    installed = False
    try:
        await seed(engine, org)
        async with engine.begin() as connection:
            await connection.execute(text(
                f"ALTER TABLE audit.audit_logs ADD CONSTRAINT {constraint} "
                "CHECK (action <> 'owned_reject')",
            ))
            installed = True
        async with AsyncSession(engine) as session:
            caller = await session.get(Organization, org)
            caller.description = "unrelated caller state"
            error = None
            try:
                await write(session, writer, org, action="owned_reject")
            except IntegrityError as exc:
                error = exc
            record_property("actual_error_type", type(error).__name__ if error else None)
            record_property("session_usable_after_rejection", session.is_active)
            # Main remains best effort; previously strict alternate APIs remain strict.
            assert (error is None) is (writer == "main")
            assert session.is_active
            await session.commit()
        async with AsyncSession(engine) as reader:
            assert (await reader.get(Organization, org)).description == "unrelated caller state"
            assert list((await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org,
            ))).all()) == []
            record_property("caller_state_committed_without_failed_audit", True)
    finally:
        if installed:
            async with engine.begin() as connection:
                await connection.execute(text(f"ALTER TABLE audit.audit_logs DROP CONSTRAINT {constraint}"))
        await cleanup(engine, org)


@pytest.mark.parametrize("writer", ["main", "legacy"])
async def test_noncommitting_writer_preserves_outer_rollback(writer, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org = uuid4()
    try:
        await seed(engine, org)
        async with AsyncSession(engine) as session:
            (await session.get(Organization, org)).description = "must roll back"
            await write(session, writer, org)
            await session.rollback()
        async with AsyncSession(engine) as reader:
            assert (await reader.get(Organization, org)).description == "before"
            assert list((await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org,
            ))).all()) == []
            record_property("outer_state_and_audit_rolled_back_together", True)
    finally:
        await cleanup(engine, org)


async def test_migration_helper_retains_its_existing_commit_boundary(record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org = uuid4()
    try:
        await seed(engine, org)
        async with AsyncSession(engine) as session:
            (await session.get(Organization, org)).description = "committed by existing helper"
            await write(session, "migration", org)
            await session.rollback()
        async with AsyncSession(engine) as reader:
            assert (await reader.get(Organization, org)).description == "committed by existing helper"
            assert len(list((await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org,
            ))).all())) == 1
            record_property("existing_explicit_commit_boundary_preserved", True)
    finally:
        await cleanup(engine, org)
