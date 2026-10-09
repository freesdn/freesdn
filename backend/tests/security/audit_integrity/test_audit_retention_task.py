"""Real task body and PostgreSQL retention; no worker/broker deployment proof."""
from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.security_audit import (
    AuditLogRecord,
    FailedLoginRecord,
    SecurityAnomalyRecord,
    SecurityEventRecord,
)
from app.services.audit import AuditService
from app.tasks import security_audit as tasks

MODELS = {"audit_logs": AuditLogRecord, "security_events": SecurityEventRecord,
          "failed_logins": FailedLoginRecord, "anomalies": SecurityAnomalyRecord}
SCENARIOS = ["empty", "recent", "audit_logs", "security_events", "failed_logins",
             "anomalies", "blocked_prefix", "corrupt"]


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_actual_cleanup_task_is_bounded_truthful_and_repeatable(scenario, monkeypatch, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(tasks, "AsyncSessionLocal", sessions)
    ids = {name: [] for name in MODELS}
    old = datetime.now(UTC) - timedelta(days=120)
    now = datetime.now(UTC)
    try:
        async with sessions() as seed:
            for model in MODELS.values():
                assert await seed.scalar(select(func.count()).select_from(model)) == 0
            count = 1001 if scenario == "audit_logs" else 2 if scenario == "blocked_prefix" else 1 if scenario in ("recent", "corrupt") else 0
            for index in range(count):
                ident = uuid4()
                ids["audit_logs"].append(ident)
                timestamp = now if scenario == "recent" or (scenario == "blocked_prefix" and index == 0) else old
                await AuditService(seed).persist_record(AuditLogRecord(
                    id=ident, timestamp=timestamp, action="owned_retention_task", resource_type="owned_test"))
            for name, model in MODELS.items():
                if name == "audit_logs":
                    continue
                for _index in range(1001 if scenario == name else 1 if scenario in ("recent", "corrupt") else 0):
                    ident = uuid4()
                    ids[name].append(ident)
                    timestamp = now if scenario == "recent" else old
                    if name == "security_events":
                        row = model(id=ident, timestamp=timestamp, event_type="owned_task")
                    elif name == "failed_logins":
                        row = model(id=ident, timestamp=timestamp, username="owned", ip_address="192.0.2.123")
                    else:
                        row = model(id=ident, detected_at=timestamp, anomaly_type="owned_task", title="Owned", resolved=True)
                    seed.add(row)
            if scenario == "corrupt":
                await seed.execute(update(AuditLogRecord).where(AuditLogRecord.id == ids["audit_logs"][0])
                                   .values(action="owned_tamper_marker"))
            await seed.commit()

        async def counts():
            async with sessions() as reader:
                return {name: await reader.scalar(select(func.count()).select_from(model).where(model.id.in_(ids[name])))
                        for name, model in MODELS.items()}

        before = await counts()
        result, error = None, None
        try:
            result = await asyncio.to_thread(tasks.cleanup_audit_data.run)
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
        after = await counts()
        async with sessions() as reader:
            verdict = await AuditService(reader).validate_audit_chain()
        first = {"before": before, "after": after, "result": result, "error": error,
                 "audit_verdict": verdict}
        record_property("actual_first_cleanup_task", json.dumps(first))
        if scenario == "corrupt":
            assert after == before, "Failed chain cleanup must roll back every security table deletion"
            assert error is not None, "Cleanup failures must reach the task failure boundary"
            assert "owned_tamper_marker" not in error["message"]
            assert not verdict["valid"]
            return
        assert error is None
        for name in MODELS:
            assert before[name] - after[name] <= 1000, "Every cleanup table must have a bounded delete"
            assert result[name] == before[name] - after[name]
        expected_more = scenario in MODELS
        expected_blocked = scenario == "blocked_prefix"
        status = result.get("retention", {})
        assert status.get("complete") is (not expected_more and not expected_blocked)
        assert status.get("more_available") is expected_more
        assert status.get("blocked_prefix") is expected_blocked
        assert status.get("remaining") == ([scenario] if expected_more else ["audit_logs"] if expected_blocked else [])
        assert verdict["valid"]
        if expected_more:
            assert after[scenario] == 1
            second = await asyncio.to_thread(tasks.cleanup_audit_data.run)
            remaining = await counts()
            record_property("actual_repeated_cleanup_task", json.dumps({"result": second, "remaining": remaining}))
            assert remaining == dict.fromkeys(MODELS, 0)
            assert second["retention"]["complete"] is True
            assert second["retention"]["more_available"] is False
            assert second[scenario] == 1
        elif scenario == "recent" or expected_blocked:
            assert after == before
    finally:
        async with engine.begin() as connection:
            for name, model in MODELS.items():
                await connection.execute(delete(model).where(model.id.in_(ids[name])))
        await engine.dispose()
