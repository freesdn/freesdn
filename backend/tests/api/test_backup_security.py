# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.backups import get_backup, get_schedule, restore_backup
from app.models import UserRole


@pytest.mark.asyncio
async def test_restore_backup_rejects_foreign_null_site_backup() -> None:
    current_user = SimpleNamespace(
        id=uuid4(),
        role=UserRole.SUPER_ADMIN,
        organization_id=uuid4(),
    )
    request = SimpleNamespace(
        backup_id=uuid4(),
        target_site_id=None,
        restore_devices=True,
        restore_vlans=True,
        restore_ssids=True,
        restore_users=False,
        restore_automation=True,
        overwrite_existing=False,
        dry_run=True,
    )
    mock_session = AsyncMock()
    mock_service = AsyncMock()
    mock_service.get_backup_for_organization.return_value = None

    with patch("app.api.v1.endpoints.backups.BackupService", return_value=mock_service):
        with pytest.raises(HTTPException) as exc_info:
            await restore_backup(
                request,
                session=mock_session,
                current_user=current_user,
            )

    assert exc_info.value.status_code == 404
    mock_service.get_backup_for_organization.assert_awaited_once_with(
        request.backup_id,
        current_user.organization_id,
    )


@pytest.mark.asyncio
async def test_get_backup_rejects_foreign_null_site_backup() -> None:
    backup_id = uuid4()
    current_user = SimpleNamespace(organization_id=uuid4())
    mock_service = AsyncMock()
    mock_service.get_backup_for_organization.return_value = None

    with patch("app.api.v1.endpoints.backups.BackupService", return_value=mock_service):
        with pytest.raises(HTTPException) as exc_info:
            await get_backup(
                backup_id,
                session=AsyncMock(),
                current_user=current_user,
            )

    assert exc_info.value.status_code == 404
    mock_service.get_backup_for_organization.assert_awaited_once_with(
        backup_id,
        current_user.organization_id,
    )


@pytest.mark.asyncio
async def test_get_schedule_allows_null_site_schedule_owned_by_org() -> None:
    schedule_id = uuid4()
    current_user = SimpleNamespace(organization_id=uuid4())
    owned_schedule = SimpleNamespace(id=schedule_id, site_id=None, organization_id=current_user.organization_id)
    mock_service = AsyncMock()
    mock_service.get_schedule_for_organization.return_value = owned_schedule

    with patch("app.api.v1.endpoints.backups.BackupService", return_value=mock_service):
        schedule = await get_schedule(
            schedule_id,
            session=AsyncMock(),
            current_user=current_user,
        )

    assert schedule is owned_schedule
    mock_service.get_schedule_for_organization.assert_awaited_once_with(
        schedule_id,
        current_user.organization_id,
    )
