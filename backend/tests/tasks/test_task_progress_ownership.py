# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exercise API publication ordering and real Celery request isolation."""

import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from celery import Celery
from fastapi import HTTPException

from app.api.v1.endpoints import tasks as api
from app.models import UserRole
from app.tasks import base


class MemoryRedis:
    """Atomic in-memory transport double; production Valkey is qualified separately."""

    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()

    def set(self, key, value, *, ex, nx):
        assert ex == base.TaskProgressStore.TTL and nx is True
        with self.lock:
            if key in self.rows:
                return None
            self.rows[key] = value
            return True

    def setex(self, key, ttl, value):
        assert ttl == base.TaskProgressStore.TTL
        with self.lock:
            self.rows[key] = value

    def get(self, key):
        with self.lock:
            return self.rows.get(key)

    def delete(self, key):
        with self.lock:
            self.rows.pop(key, None)

    def scan_iter(self, **kwargs):
        with self.lock:
            return iter(list(self.rows))


def row(task_id="run-a", org="org-a", status=base.TaskStatus.PENDING):
    return base.TaskProgress(
        task_id=task_id, task_name="owned.progress", organization_id=org, status=status
    )


@pytest.fixture
def store(monkeypatch):
    value = base.TaskProgressStore()
    value._redis = MemoryRedis()
    monkeypatch.setattr(base, "progress_store", value)
    monkeypatch.setattr(api, "progress_store", value)
    return value


@pytest.fixture
def task():
    class Worker(base.FreeSDNTask):
        name = "owned.progress"

        def run(self):
            self.update_progress(1, 2, "Owned work")
            return {"success": True}

    Worker.bind(
        Celery(
            "owned-progress", broker="memory://", backend="cache+memory://", set_as_current=False
        )
    )
    value = Worker()
    value.app.register_task(value)
    value.update_state = MagicMock()
    return value


@contextmanager
def request(task, task_id):
    task.push_request(id=task_id, retries=0)
    try:
        yield
    finally:
        task.pop_request()


@pytest.mark.parametrize("hook", ["start", "progress", "message", "retry", "success", "failure"])
def test_seeded_owner_survives_worker_lifecycle(store, task, hook):
    store.set_progress("run-a", row())
    with request(task, "run-a"):
        task.before_start("run-a", [], {})
        if hook == "progress":
            task.update_progress(1, 2)
        elif hook == "message":
            task.set_message("Still running")
        elif hook == "retry":
            task.on_retry(RuntimeError("synthetic"), "run-a", [], {}, None)
        elif hook == "success":
            task.on_success({"success": True}, "run-a", [], {})
        elif hook == "failure":
            task.on_failure(RuntimeError("synthetic"), "run-a", [], {}, None)
    progress = store.get_progress("run-a")
    assert progress.organization_id == "org-a"
    assert progress.task_id == "run-a"
    assert progress.started_at is not None


@pytest.mark.parametrize("hook", ["progress", "success", "retry"])
def test_another_request_cannot_inherit_cached_owner(store, task, hook):
    with request(task, "run-a"):
        task._progress = row()
        task._start_time = 1000
    store.set_progress("run-b", row("run-b", "org-b"))
    with request(task, "run-b"):
        if hook == "progress":
            task.update_progress(1, 2)
        elif hook == "success":
            task.on_success("done", "run-b", [], {})
        else:
            task.on_retry(RuntimeError("synthetic"), "run-b", [], {}, None)
    progress = store.get_progress("run-b")
    assert progress.organization_id == "org-b"
    assert progress.started_at is None


def test_nested_request_restores_outer_progress_and_clock(store, task):
    with request(task, "run-a"):
        task._progress = row()
        task._start_time = 1000
        with request(task, "run-b"):
            task._progress = row("run-b", "org-b")
            task._start_time = 2000
            task.set_message("inner")
        task.set_message("outer")
        assert task._start_time == 1000
    assert store.get_progress("run-a").organization_id == "org-a"
    assert store.get_progress("run-a").message == "outer"
    assert store.get_progress("run-b").organization_id == "org-b"
    assert store.get_progress("run-b").message == "inner"


def test_concurrent_requests_do_not_share_mutable_progress(store, task):
    barrier = threading.Barrier(2, timeout=5)

    def worker(name):
        with request(task, name):
            task._progress = row(name, "org-" + name)
            task._start_time = 1000 if name == "a" else 2000
            barrier.wait()
            task.set_message("message-" + name)
            barrier.wait()
            task.on_success(name, name, [], {})

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(worker, ["a", "b"]))
    for name, clock in [("a", 1000), ("b", 2000)]:
        progress = store.get_progress(name)
        assert progress.task_id == name and progress.organization_id == "org-" + name
        assert progress.result == name and progress.started_at.timestamp() == clock


def test_actual_celery_eager_execution_preserves_owner(store, task):
    store.set_progress("run-a", row())
    result = task.apply(task_id="run-a", throw=True)
    assert result.successful()
    progress = store.get_progress("run-a")
    assert progress.status == base.TaskStatus.SUCCESS
    assert progress.organization_id == "org-a" and progress.result == {"success": True}


@pytest.mark.parametrize(
    "existing", [base.TaskStatus.PENDING, base.TaskStatus.STARTED, base.TaskStatus.SUCCESS]
)
def test_reservation_never_replaces_existing_owner_or_completion(store, existing):
    original = row(status=existing)
    store.set_progress("run-a", original)
    assert store.seed_progress("run-a", row(org="other")) is False
    assert store.get_progress("run-a") == original


@pytest.mark.parametrize("invalid", ["identity", "unscoped", "terminal"])
def test_invalid_reservation_is_refused(store, invalid):
    value = row()
    if invalid == "identity":
        value.task_id = "wrong"
    elif invalid == "unscoped":
        value.organization_id = None
    else:
        value.status = base.TaskStatus.SUCCESS
    assert store.seed_progress("run-a", value) is False
    assert store.get_progress("run-a") is None


def test_store_rejects_cross_identity_write(store):
    with pytest.raises(ValueError, match="identity"):
        store.set_progress("other", row())
    assert store.redis.rows == {}


def test_store_refuses_misfiled_identity(store):
    store.redis.rows["task_progress:other"] = row().model_dump_json()
    assert store.get_progress("other") is None
    assert store.get_all_active(organization_id="org-a") == []


def test_retry_remains_visible_only_to_owner(store):
    store.set_progress("run-a", row(status=base.TaskStatus.RETRY))
    assert [p.task_id for p in store.get_all_active(organization_id="org-a")] == ["run-a"]
    assert store.get_all_active(organization_id="org-b") == []


@pytest.mark.parametrize("operation", ["seed", "set", "get", "delete", "scan"])
def test_storage_errors_do_not_log_connection_details(store, caplog, operation):
    marker = "synthetic-private-connection-marker"
    broken = MagicMock()
    for name in ["set", "setex", "get", "delete", "scan_iter"]:
        getattr(broken, name).side_effect = RuntimeError(marker)
    store._redis = broken
    if operation == "seed":
        assert store.seed_progress("run-a", row()) is False
    elif operation == "set":
        store.set_progress("run-a", row())
    elif operation == "get":
        assert store.get_progress("run-a") is None
    elif operation == "delete":
        store.delete_progress("run-a")
    else:
        assert store.get_all_active() == []
    assert caplog.records and marker not in caplog.text


def caller():
    return SimpleNamespace(
        organization_id="org-a",
        user=SimpleNamespace(role=UserRole.SUPER_ADMIN, email="owned@example.test"),
    )


@pytest.fixture
def submission(monkeypatch, store):
    dispatched = []
    task = SimpleNamespace(run=lambda: None)
    task.apply_async = lambda **kwargs: dispatched.append(kwargs)
    monkeypatch.setattr(api.celery_app.tasks, "get", lambda _name: task)
    payload = SimpleNamespace(task_name="backup.run_scheduled", args=[], kwargs={}, queue=None)
    return task, payload, dispatched


@pytest.mark.asyncio
async def test_worker_can_complete_before_publish_returns(store, submission):
    task, payload, _ = submission

    def publish(**options):
        task_id = options["task_id"]
        progress = store.get_progress(task_id)
        assert progress.organization_id == "org-a"
        progress.status = base.TaskStatus.SUCCESS
        progress.result = {"completed": True}
        store.set_progress(task_id, progress)
        return SimpleNamespace(id=task_id)

    task.apply_async = publish
    response = await api.trigger_task(payload, current_user=caller())
    progress = store.get_progress(response.task_id)
    assert progress.status == base.TaskStatus.SUCCESS
    assert progress.result == {"completed": True}


@pytest.mark.parametrize("failure", ["unavailable", "collision"])
@pytest.mark.asyncio
async def test_unreserved_task_is_never_published(store, submission, failure):
    _, payload, dispatched = submission
    if failure == "unavailable":
        store.redis.set = MagicMock(side_effect=RuntimeError("private-redis-detail"))
    else:
        store.redis.set = MagicMock(return_value=False)
    with pytest.raises(HTTPException) as exc:
        await api.trigger_task(payload, current_user=caller())
    assert exc.value.status_code == 503
    assert "not submitted" in exc.value.detail
    assert not dispatched


@pytest.mark.parametrize("worker_completed", [False, True])
@pytest.mark.asyncio
async def test_unknown_broker_ack_preserves_owner_and_any_result(
    store, submission, caplog, worker_completed
):
    task, payload, _ = submission
    published = []

    def publish(**options):
        task_id = options["task_id"]
        published.append(task_id)
        if worker_completed:
            progress = store.get_progress(task_id)
            progress.status = base.TaskStatus.SUCCESS
            store.set_progress(task_id, progress)
        raise RuntimeError("synthetic-broker-private-marker")

    task.apply_async = publish
    with pytest.raises(HTTPException) as exc:
        await api.trigger_task(payload, current_user=caller())
    assert exc.value.status_code == 503
    assert "unknown" in exc.value.detail["message"]
    task_id = exc.value.detail["task_id"]
    assert published == [task_id]
    progress = store.get_progress(task_id)
    assert progress.organization_id == "org-a"
    assert progress.status == (
        base.TaskStatus.SUCCESS if worker_completed else base.TaskStatus.PENDING
    )
    assert "synthetic-broker-private-marker" not in caplog.text + str(exc.value.detail)


def test_unseeded_worker_does_not_trust_tenant_kwargs(store, task):
    with request(task, "run-a"):
        task.before_start("run-a", [], {"organization_id": "untrusted"})
        task.on_success("done", "run-a", [], {})
    assert store.get_progress("run-a").organization_id is None


def test_application_outcome_remains_distinct_from_celery_completion(store, task):
    # This change does not reinterpret arbitrary application result dictionaries.
    with request(task, "run-a"):
        task.before_start("run-a", [], {})
        task.on_success({"success": False}, "run-a", [], {})
    progress = store.get_progress("run-a")
    assert progress.status == base.TaskStatus.SUCCESS
    assert progress.result == {"success": False}
