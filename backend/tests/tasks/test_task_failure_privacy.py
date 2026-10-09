"""Tenant task diagnostics must not expose arbitrary worker exceptions."""

import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import tasks as api
from app.core import celery_app as worker
from app.tasks import base
from tests.tasks.test_task_progress_ownership import request
from tests.tasks.test_task_progress_ownership import store as store
from tests.tasks.test_task_progress_ownership import task as task

MARKER = "synthetic-unstructured-device-credential-no-recognizable-token-prefix"
ORG = "f090cf40-9d70-4af7-8794-a815dd1b8d06"
OTHER_ORG = "109458bb-1e64-4771-bbcb-3723333e59e0"


class UnrenderableError(Exception):
    def __str__(self):
        raise AssertionError("Exception rendering must not run")


def progress(status=base.TaskStatus.FAILURE):
    return base.TaskProgress(
        task_id="owned-run",
        task_name="owned.progress",
        organization_id=ORG,
        status=status,
        message=MARKER,
        error=MARKER,
        result={"diagnostic": [MARKER]},
        progress=25,
        current=1,
        total=4,
        retries=2,
        max_retries=3,
    )


def legacy(store, status):
    value = progress(status)
    store.redis.rows["task_progress:owned-run"] = value.model_dump_json()
    return value


def assert_safe(value, status):
    assert MARKER not in value.model_dump_json()
    assert value.task_id == "owned-run" and value.organization_id == ORG
    assert value.status == status and value.result is None
    assert (value.current, value.total, value.progress) == (1, 4, 25)
    assert (value.retries, value.max_retries) == (2, 3)
    assert (
        value.error
        == {
            base.TaskStatus.FAILURE: "task_failed",
            base.TaskStatus.RETRY: "task_retry",
            base.TaskStatus.REVOKED: None,
        }[status]
    )


@pytest.mark.parametrize("hook", ["failure", "retry"])
@pytest.mark.parametrize("hostile", [False, True])
def test_worker_hook_never_renders_exception_or_copies_it_to_progress(
    store, task, caplog, hook, hostile
):
    store.set_progress("owned-run", progress(base.TaskStatus.PENDING))
    error = UnrenderableError(MARKER) if hostile else RuntimeError(MARKER)
    with request(task, "owned-run"), caplog.at_level(logging.WARNING):
        task.before_start("owned-run", [], {})
        getattr(task, "on_" + hook)(error, "owned-run", [], {}, None)
        assert MARKER not in task._progress.model_dump_json()
    row = store.get_progress("owned-run")
    assert row.error == ("task_failed" if hook == "failure" else "task_retry")
    assert row.organization_id == ORG and row.task_id == "owned-run"
    assert row.status == hook
    assert row.retries == (1 if hook == "retry" else 0)
    assert MARKER not in store.redis.rows["task_progress:owned-run"]
    assert MARKER not in caplog.text and "owned-run" in caplog.text


@pytest.mark.parametrize(
    "status", [base.TaskStatus.FAILURE, base.TaskStatus.RETRY, base.TaskStatus.REVOKED]
)
def test_writer_drops_diagnostic_payload_without_mutating_the_caller(store, status):
    value = progress(status)
    original = value.model_dump_json()
    store.set_progress("owned-run", value)
    assert value.model_dump_json() == original
    assert_safe(
        base.TaskProgress.model_validate_json(store.redis.rows["task_progress:owned-run"]), status
    )


@pytest.mark.parametrize(
    "status", [base.TaskStatus.FAILURE, base.TaskStatus.RETRY, base.TaskStatus.REVOKED]
)
def test_legacy_reader_removes_diagnostics_without_rewriting_the_redis_record(store, status):
    legacy(store, status)
    original = store.redis.rows["task_progress:owned-run"]
    assert_safe(store.get_progress("owned-run"), status)
    assert store.redis.rows["task_progress:owned-run"] == original


def test_active_retry_list_keeps_owner_filter_and_removes_legacy_details(store):
    legacy(store, base.TaskStatus.RETRY)
    rows = store.get_all_active(organization_id=ORG)
    assert len(rows) == 1
    assert_safe(rows[0], base.TaskStatus.RETRY)
    assert store.get_all_active(organization_id=OTHER_ORG) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status", [base.TaskStatus.FAILURE, base.TaskStatus.RETRY, base.TaskStatus.REVOKED]
)
async def test_real_progress_endpoint_serializes_safe_legacy_details(store, status):
    legacy(store, status)
    response = await api.get_task_progress_endpoint(
        "owned-run", SimpleNamespace(organization_id=UUID(ORG))
    )
    assert MARKER not in response.model_dump_json() and response.task_id == "owned-run"
    assert response.status == status and response.result is None


@pytest.mark.asyncio
async def test_real_result_endpoint_does_not_expose_legacy_error_or_traceback(store):
    legacy(store, base.TaskStatus.FAILURE)
    response = await api.get_task_result_endpoint(
        "owned-run", SimpleNamespace(organization_id=UUID(ORG))
    )
    assert (
        response.error == "task_failed" and response.result is None and response.traceback is None
    )
    assert MARKER not in response.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["progress", "result"])
async def test_safe_diagnostics_do_not_bypass_tenant_ownership(store, operation):
    legacy(store, base.TaskStatus.FAILURE)
    endpoint = getattr(api, "get_task_" + operation + "_endpoint")
    with pytest.raises(HTTPException) as error:
        await endpoint("owned-run", SimpleNamespace(organization_id=UUID(OTHER_ORG)))
    assert error.value.status_code == 404
    assert MARKER not in json.dumps(error.value.detail)


@pytest.mark.parametrize("state", [None, base.TaskStatus.PENDING, base.TaskStatus.RETRY])
def test_missing_scoped_completion_never_queries_unowned_celery_result(store, monkeypatch, state):
    if state is not None:
        legacy(store, state)
    backend = MagicMock()
    backend.return_value.ready.return_value = True
    backend.return_value.successful.return_value = False
    backend.return_value.name = "owned.progress"
    backend.return_value.result = RuntimeError(MARKER)
    backend.return_value.traceback = MARKER
    monkeypatch.setattr("celery.result.AsyncResult", backend)
    assert base.get_task_result("owned-run") is None
    backend.assert_not_called()


@pytest.mark.parametrize("hostile", [False, True])
def test_custom_failure_signal_does_not_render_exception(hostile, caplog):
    error = UnrenderableError(MARKER) if hostile else RuntimeError(MARKER)
    worker.on_task_failure(
        SimpleNamespace(name="owned.progress"), "owned-run", error, [], {}, None, None
    )
    assert MARKER not in caplog.text and "owned-run" in caplog.text


@pytest.mark.parametrize("status", [base.TaskStatus.PROGRESS, base.TaskStatus.SUCCESS])
def test_running_messages_and_successful_payload_contracts_are_unchanged(store, status):
    value = progress(status)
    value.message = "Processed one device"
    value.error = None
    value.result = {"devices": 1}
    store.set_progress("owned-run", value)
    assert store.get_progress("owned-run") == value
    if status == base.TaskStatus.SUCCESS:
        assert base.get_task_result("owned-run").result == {"devices": 1}
