# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.discovery import get_agent_scan_status
from app.tasks.bulk_operations import _resolve_device_ids


@pytest.mark.asyncio
async def test_resolve_device_ids_device_list_filters_to_org() -> None:
    org_id = uuid4()
    owned_device_id = uuid4()
    foreign_device_id = uuid4()

    mock_result = MagicMock()
    mock_result.all.return_value = [(owned_device_id,)]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    resolved = await _resolve_device_ids(
        mock_db,
        {
            "scope": "device_list",
            "device_ids": [str(owned_device_id), str(foreign_device_id)],
        },
        org_id,
    )

    assert resolved == [owned_device_id]
    mock_db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_agent_scan_status_rejects_cross_org_task_access() -> None:
    current_user = SimpleNamespace(is_superuser=False, organization_id=uuid4())
    task = SimpleNamespace(
        id=uuid4(),
        agent_id=uuid4(),
        status="pending",
        progress=10,
        result=None,
        error_message=None,
        started_at=None,
        completed_at=None,
        agent=SimpleNamespace(organization_id=uuid4()),
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = task
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await get_agent_scan_status(task.id, current_user=current_user, session=mock_session)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_agent_scan_status_allows_same_org_task_access() -> None:
    org_id = uuid4()
    task = SimpleNamespace(
        id=uuid4(),
        agent_id=uuid4(),
        status="completed",
        progress=100,
        result={"hosts": 3},
        error_message=None,
        started_at=None,
        completed_at=None,
        agent=SimpleNamespace(organization_id=org_id, site_id=None),
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = task
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    response = await get_agent_scan_status(
        task.id,
        current_user=SimpleNamespace(is_superuser=False, organization_id=org_id),
        session=mock_session,
    )

    assert response["task_id"] == str(task.id)
    assert response["result"] == {"hosts": 3}
