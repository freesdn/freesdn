# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.tasks import trigger_task
from app.models import UserRole


def _user(*, role: UserRole = UserRole.SUPER_ADMIN):
    return SimpleNamespace(
        organization_id="org-1",
        user=SimpleNamespace(
            role=role,
            email="admin@example.com",
        ),
    )


def _request(task_name: str, *, args=None, kwargs=None, queue=None):
    return SimpleNamespace(
        task_name=task_name,
        args=args or [],
        kwargs=kwargs or {},
        queue=queue,
    )


@pytest.mark.asyncio
async def test_trigger_task_rejects_unlisted_task() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await trigger_task(
            _request("bulk_operations.execute"),
            current_user=_user(),
        )

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_trigger_task_rejects_queue_override() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await trigger_task(
            _request("backup.run_scheduled", queue="priority"),
            current_user=_user(),
        )

    assert exc_info.value.status_code == 400
    assert "queue 'default'" in exc_info.value.detail


@pytest.mark.asyncio
async def test_trigger_task_rejects_non_superadmin() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await trigger_task(
            _request("backup.run_scheduled"),
            current_user=_user(role=UserRole.ORG_ADMIN),
        )

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_trigger_task_queues_allowed_task_on_fixed_queue() -> None:
    fake_result = SimpleNamespace(id="task-123")
    fake_task = MagicMock()
    fake_task.apply_async.return_value = fake_result

    with patch("app.api.v1.endpoints.tasks.celery_app.tasks.get", return_value=fake_task), patch(
        "app.api.v1.endpoints.tasks.progress_store.set_progress"
    ) as set_progress:
        response = await trigger_task(
            _request("backup.run_scheduled"),
            current_user=_user(),
        )

    assert response.task_id == "task-123"
    assert response.task_name == "backup.run_scheduled"
    # The endpoint injects the caller's organization_id into the task kwargs for
    # tenant scoping (overwriting any caller-supplied value); _user() is org-1.
    fake_task.apply_async.assert_called_once_with(
        args=[], kwargs={"organization_id": "org-1"}, queue="default"
    )
    set_progress.assert_called_once()
