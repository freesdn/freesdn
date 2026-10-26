"""Actual cleanup task waits, cancellation and Redis progress hooks.

Native owned peers and real task/service code. Session subclass only records its
physical PID. Explicit lifecycle hooks are not a deployed Celery worker proof.
"""
from __future__ import annotations

import asyncio
import json
import os
import queue
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from prometheus_client import REGISTRY
from sqlalchemy import delete, event, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.security_audit import AuditLogRecord, SecurityAnomalyRecord, SecurityEventRecord
from app.services.audit import _AUDIT_CHAIN_LOCK_KEY, AuditService
from app.tasks import base
from app.tasks import security_audit as tasks
from tests.harness_wait import HARNESS_WAIT_SECONDS


class OwnedCase:
    def __init__(self, monkeypatch):
        self.engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
        self.pids = queue.Queue()
        self.sqlstates = []
        self.ids = {"audit": [], "events": [], "anomalies": []}
        self.models = {"audit": AuditLogRecord, "events": SecurityEventRecord, "anomalies": SecurityAnomalyRecord}
        self.calls = []
        self.redis_ids = []
        self.triggers = []
        self.old = datetime.now(UTC) - timedelta(days=120)
        self.recent = datetime.now(UTC)
        owner = self

        class ObservedSession(AsyncSession):
            async def __aenter__(self):
                session = await super().__aenter__()
                owner.pids.put(await session.scalar(text("SELECT pg_backend_pid()")))
                return session

        monkeypatch.setattr(tasks, "AsyncSessionLocal", lambda: ObservedSession(self.engine, expire_on_commit=False))

        def observe_error(context):
            self.sqlstates.append(getattr(context.original_exception, "sqlstate", None))

        event.listen(self.engine.sync_engine, "handle_error", observe_error)

    async def seed(self, audit_times=(), *, events=0, anomalies=0):
        async with AsyncSession(self.engine) as db:
            for model in self.models.values():
                assert await db.scalar(select(func.count()).select_from(model)) == 0
            for timestamp in audit_times:
                ident = uuid4()
                self.ids["audit"].append(ident)
                await AuditService(db).persist_record(AuditLogRecord(
                    id=ident, timestamp=timestamp, action="owned_contention", resource_type="owned_test"))
            for _ in range(events):
                ident = uuid4()
                self.ids["events"].append(ident)
                db.add(SecurityEventRecord(id=ident, timestamp=self.old, event_type="owned_contention"))
            for _ in range(anomalies):
                ident = uuid4()
                self.ids["anomalies"].append(ident)
                db.add(SecurityAnomalyRecord(id=ident, detected_at=self.old, anomaly_type="owned", title="Owned", resolved=True))
            await db.commit()

    async def counts(self):
        async with AsyncSession(self.engine) as db:
            return {name: await db.scalar(select(func.count()).select_from(model).where(model.id.in_(self.ids[name])))
                    for name, model in self.models.items()}

    def call(self, hooks=False):
        task = tasks.cleanup_audit_data
        task_id, org_id = str(uuid4()), str(uuid4())
        if hooks:
            assert base.progress_store.redis.ping()
            assert base.progress_store.seed_progress(task_id, base.TaskProgress(
                task_id=task_id, task_name=task.name, organization_id=org_id))
            self.redis_ids.append(task_id)
            task.push_request(id=task_id, retries=0, called_directly=True)
            task.before_start(task_id, [], {})
        started = time.monotonic()
        try:
            try:
                result = task.run()
            except Exception as exc:
                if hooks:
                    task.on_failure(exc, task_id, [], {}, None)
                outcome = {"result": None, "error": {"type": type(exc).__name__, "message": str(exc)}}
            else:
                if hooks:
                    task.on_success(result, task_id, [], {})
                outcome = {"result": result, "error": None}
            outcome["elapsed"] = time.monotonic() - started
            if hooks:
                progress = base.progress_store.get_progress(task_id)
                assert progress is not None and progress.organization_id == org_id
                outcome["progress"] = progress.model_dump(mode="json")
            return outcome
        finally:
            if hooks:
                task.pop_request()

    def start(self, hooks=False):
        task = asyncio.create_task(asyncio.to_thread(self.call, hooks))
        self.calls.append(task)
        return task

    async def pid(self):
        async with asyncio.timeout(12):
            while True:
                try:
                    return self.pids.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.02)

    async def waits(self, observer, worker_pids, locker_pid):
        async with asyncio.timeout(HARNESS_WAIT_SECONDS):
            while True:
                paths = {pid: await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid})
                         for pid in worker_pids}
                def reaches(pid, paths, seen=()):
                    if pid == locker_pid:
                        return True
                    return pid not in seen and any(reaches(p, paths, (*seen, pid)) for p in paths.get(pid, []))
                if all(reaches(pid, paths) for pid in worker_pids):
                    return paths
                await asyncio.sleep(0.02)

    async def close(self):
        if self.calls:
            await asyncio.gather(*self.calls, return_exceptions=True)
        async with self.engine.begin() as db:
            for table, name in self.triggers:
                await db.execute(text(f"DROP TRIGGER IF EXISTS {name} ON audit.{table}"))
                await db.execute(text(f"DROP FUNCTION IF EXISTS audit.{name}()"))
            for name, model in self.models.items():
                await db.execute(delete(model).where(model.id.in_(self.ids[name])))
        for ident in self.redis_ids:
            base.progress_store.delete_progress(ident)
            assert base.progress_store.get_progress(ident) is None
        await self.engine.dispose()


@pytest_asyncio.fixture
async def owned(monkeypatch):
    value = OwnedCase(monkeypatch)
    try:
        yield value
    finally:
        await value.close()


@pytest.mark.parametrize("target", ["domain", "chain"])
async def test_actual_lock_timeout_releases_all_cleanup_changes(owned, target, record_property):
    await owned.seed([owned.old], events=1, anomalies=1)
    before = await owned.counts()
    async with owned.engine.connect() as locker, owned.engine.connect() as observer:
        tx = await locker.begin()
        try:
            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
            if target == "domain":
                await locker.execute(select(SecurityEventRecord.id).where(SecurityEventRecord.id == owned.ids["events"][0]).with_for_update())
            else:
                await locker.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _AUDIT_CHAIN_LOCK_KEY})
            task = owned.start()
            pid = await owned.pid()
            paths = await owned.waits(observer, [pid], locker_pid)
            outcome = await asyncio.wait_for(asyncio.shield(task), 12)
        finally:
            await tx.rollback()
    after = await owned.counts()
    record_property("actual_lock_timeout", json.dumps({"target": target, "paths": paths, "outcome": outcome,
                    "sqlstates": owned.sqlstates, "before": before, "after": after}))
    assert outcome["error"]["type"] == "RuntimeError"
    assert "55P03" in owned.sqlstates and 4.0 <= outcome["elapsed"] < 12
    assert after == before


@pytest.mark.parametrize("target", ["domain", "seal"])
async def test_actual_statement_timeout_rolls_back_late_cleanup(owned, target, record_property):
    await owned.seed([owned.old], events=1, anomalies=1)
    before = await owned.counts()
    table, operation = ("security_events", "DELETE") if target == "domain" else ("audit_chain_state", "UPDATE")
    name = "owned_sleep_" + uuid4().hex
    async with owned.engine.begin() as connection:
        await connection.execute(text(f"CREATE FUNCTION audit.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(12); RETURN " + ("OLD" if target == "domain" else "NEW") + "; END $$"))
        await connection.execute(text(f"CREATE TRIGGER {name} BEFORE {operation} ON audit.{table} FOR EACH ROW EXECUTE FUNCTION audit.{name}()"))
    owned.triggers.append((table, name))
    task = owned.start()
    pid = await owned.pid()
    async with owned.engine.connect() as observer:
        async with asyncio.timeout(HARNESS_WAIT_SECONDS):
            while True:
                wait = await observer.scalar(text("SELECT wait_event FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid})
                if wait == "PgSleep":
                    break
                await observer.rollback()
                await asyncio.sleep(0.02)
    outcome = await asyncio.wait_for(asyncio.shield(task), 15)
    after = await owned.counts()
    record_property("actual_statement_timeout", json.dumps({"target": target, "observed_wait": wait,
                    "outcome": outcome, "sqlstates": owned.sqlstates, "before": before, "after": after}))
    assert outcome["error"]["type"] == "RuntimeError"
    assert "57014" in owned.sqlstates and 9 <= outcome["elapsed"] < 15
    assert after == before


async def test_two_actual_cleaners_share_a_backlog_without_deadlock(owned, record_property):
    await owned.seed([owned.old] * 1001, events=1001)
    async with owned.engine.connect() as locker, owned.engine.connect() as observer:
        tx = await locker.begin()
        try:
            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
            await locker.execute(select(SecurityEventRecord.id).where(SecurityEventRecord.id == min(owned.ids["events"])).with_for_update())
            calls = [owned.start(), owned.start()]
            pids = [await owned.pid(), await owned.pid()]
            assert len({*pids, locker_pid}) == 3
            paths = await owned.waits(observer, pids, locker_pid)
        finally:
            await tx.rollback()
        outcomes = await asyncio.wait_for(asyncio.gather(*(asyncio.shield(t) for t in calls)), 15)
    counts = await owned.counts()
    async with AsyncSession(owned.engine) as db:
        verdict = await AuditService(db).validate_audit_chain()
    record_property("actual_competing_cleaners", json.dumps({"paths": paths, "outcomes": outcomes,
                    "remaining": counts, "sqlstates": owned.sqlstates, "verdict": verdict}))
    assert all(outcome["error"] is None for outcome in outcomes)
    assert not owned.sqlstates and not any(counts.values())
    for table in ("audit_logs", "security_events"):
        assert sum(outcome["result"][table] for outcome in outcomes) == 1001
        assert all(outcome["result"][table] <= 1000 for outcome in outcomes)
    assert verdict["valid"] and verdict["retained_history_authenticated"]


@pytest.mark.parametrize("target", ["event", "anomaly"])
async def test_cleanup_rechecks_changed_eligibility_after_real_wait(owned, target, record_property):
    await owned.seed([owned.old], events=int(target == "event"), anomalies=int(target == "anomaly"))
    model = SecurityEventRecord if target == "event" else SecurityAnomalyRecord
    ident = owned.ids["events" if target == "event" else "anomalies"][0]
    async with owned.engine.connect() as locker, owned.engine.connect() as observer:
        tx = await locker.begin()
        try:
            locker_pid = await locker.scalar(text("SELECT pg_backend_pid()"))
            await locker.execute(select(model.id).where(model.id == ident).with_for_update())
            task = owned.start()
            pid = await owned.pid()
            paths = await owned.waits(observer, [pid], locker_pid)
            values = {"timestamp": owned.recent} if target == "event" else {"resolved": False}
            await locker.execute(update(model).where(model.id == ident).values(**values))
            await tx.commit()
        finally:
            if tx.is_active:
                await tx.rollback()
        outcome = await asyncio.wait_for(asyncio.shield(task), 12)
    async with AsyncSession(owned.engine) as db:
        row = await db.get(model, ident)
        still_ineligible = row is not None and (row.timestamp == owned.recent if target == "event" else not row.resolved)
    record_property("actual_changed_eligibility", json.dumps({"paths": paths, "outcome": outcome,
                    "row_retained_and_ineligible": still_ineligible, "sqlstates": owned.sqlstates}))
    assert outcome["error"] is None and still_ineligible and not owned.sqlstates
    assert outcome["result"]["retention"]["complete"] is True


@pytest.mark.parametrize("outcome", ["complete", "incomplete", "blocked", "failed"])
async def test_actual_cleanup_lifecycle_reports_batch_scope_and_metric(owned, outcome, record_property):
    times = [owned.recent, owned.old] if outcome == "blocked" else [owned.old] if outcome == "failed" else []
    await owned.seed(times, events=1001 if outcome == "incomplete" else 0)
    if outcome == "failed":
        async with owned.engine.begin() as db:
            await db.execute(update(AuditLogRecord).where(AuditLogRecord.id == owned.ids["audit"][0]).values(action="owned_tamper"))
    metric = "freesdn_audit_retention_batches_total"
    before = REGISTRY.get_sample_value(metric, {"outcome": outcome}) or 0
    value = await owned.start(hooks=True)
    after = REGISTRY.get_sample_value(metric, {"outcome": outcome}) or 0
    record_property("actual_cleanup_lifecycle", json.dumps({"outcome": outcome, "task": value, "metric_before": before, "metric_after": after}))
    assert after == before + 1
    progress = value["progress"]
    if outcome == "failed":
        assert value["error"] is not None and progress["status"] == "failure"
        assert progress["error"] == "task_failed" and progress["result"] is None
    else:
        assert value["error"] is None and progress["status"] == "success"
        assert progress["result"] == value["result"]
        if outcome == "incomplete":
            assert "remaining" in progress["message"].lower(), "Successful batch must not imply completed retention"
        elif outcome == "blocked":
            assert "blocked" in progress["message"].lower(), "Blocked retention needs an actionable progress message"
