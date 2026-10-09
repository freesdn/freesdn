"""Exact owned row/anchor equality after real cleanup cancellation."""
import asyncio
import hashlib
import json
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.audit import _AUDIT_CHAIN_LOCK_KEY
from tests.security.audit_integrity.test_audit_retention_contention import owned as owned


async def exact_snapshot(engine):
    async with AsyncSession(engine) as db:
        return await db.scalar(text("""
            SELECT jsonb_build_object(
                'state',(SELECT to_jsonb(s) FROM audit.audit_chain_state s WHERE id=1),
                'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit.audit_logs a),
                'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM audit.security_events e),
                'anomalies',(SELECT jsonb_agg(to_jsonb(n) ORDER BY id) FROM audit.security_anomalies n)
            )
        """))


@pytest.mark.parametrize("boundary", ["chain_lock", "seal_statement"])
async def test_cancelled_cleanup_preserves_exact_signed_state_and_rows(owned, boundary, record_property):
    await owned.seed([owned.old], events=1, anomalies=1)
    before = await exact_snapshot(owned.engine)
    if boundary == "chain_lock":
        async with owned.engine.connect() as locker, owned.engine.connect() as observer:
            tx = await locker.begin()
            try:
                locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
                await locker.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _AUDIT_CHAIN_LOCK_KEY})
                task = owned.start()
                pid = await owned.pid()
                witness = await owned.waits(observer, [pid], locker_pid)
                outcome = await asyncio.wait_for(asyncio.shield(task), 12)
            finally:
                await tx.rollback()
    else:
        name = "owned_seal_sleep_" + uuid4().hex
        async with owned.engine.begin() as db:
            await db.execute(text(f"CREATE FUNCTION audit.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(12); RETURN NEW; END $$"))
            await db.execute(text(f"CREATE TRIGGER {name} BEFORE UPDATE ON audit.audit_chain_state FOR EACH ROW EXECUTE FUNCTION audit.{name}()"))
        owned.triggers.append(("audit_chain_state", name))
        task = owned.start()
        pid = await owned.pid()
        async with owned.engine.connect() as observer:
            async with asyncio.timeout(4):
                while True:
                    witness = await observer.scalar(text("SELECT wait_event FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid})
                    if witness == "PgSleep":
                        break
                    await observer.rollback()
                    await asyncio.sleep(0.02)
        outcome = await asyncio.wait_for(asyncio.shield(task), 15)
    after = await exact_snapshot(owned.engine)
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    record_property("exact_cancelled_cleanup", json.dumps({"boundary": boundary, "witness": witness,
        "before_sha256": digest(before), "after_sha256": digest(after),
        "outcome": outcome, "sqlstates": owned.sqlstates, "state_and_all_owned_rows_equal": before == after}))
    assert outcome["error"]["type"] == "RuntimeError"
    assert owned.sqlstates == ["55P03" if boundary == "chain_lock" else "57014"]
    assert before == after
