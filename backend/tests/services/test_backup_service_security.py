# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.backup import BackupService


@pytest.mark.asyncio
async def test_get_backup_for_organization_scopes_by_direct_org_fk() -> None:
    # NOTE: post-016 migration the inferred LEFT-OUTER-JOIN scope was
    # replaced by a direct ``Backup.organization_id`` filter. Strictly
    # better: simpler, faster, and not fragile to NULL creator/schedule
    # rows. The assertion now verifies the new contract.
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    service = BackupService(mock_db)
    await service.get_backup_for_organization(uuid4(), uuid4())

    query = mock_db.execute.await_args.args[0]
    compiled = str(query)

    assert "backup.backups.organization_id" in compiled
    assert "JOIN" not in compiled  # No inferred join needed anymore.


@pytest.mark.asyncio
async def test_get_schedule_for_organization_scopes_by_schedule_org() -> None:
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    service = BackupService(mock_db)
    await service.get_schedule_for_organization(uuid4(), uuid4())

    query = mock_db.execute.await_args.args[0]
    compiled = str(query)

    assert "backup.backup_schedules.organization_id" in compiled


@pytest.mark.asyncio
async def test_get_stats_scopes_queries_to_org_backups() -> None:
    status_result = MagicMock()
    status_result.all.return_value = []

    size_result = MagicMock()
    size_result.scalar.return_value = 0

    enabled_result = MagicMock()
    enabled_result.scalar.return_value = 0

    disabled_result = MagicMock()
    disabled_result.scalar.return_value = 0

    recent_scalars = MagicMock()
    recent_scalars.all.return_value = []
    recent_result = MagicMock()
    recent_result.scalars.return_value = recent_scalars

    mock_db = AsyncMock()
    mock_db.execute.side_effect = [
        status_result,
        size_result,
        enabled_result,
        disabled_result,
        recent_result,
    ]

    service = BackupService(mock_db)
    result = await service.get_stats(organization_id=uuid4())

    compiled = str(mock_db.execute.await_args_list[0].args[0])

    # Post-016 migration: stats query filters directly on
    # ``Backup.organization_id`` instead of joining through
    # users + schedules.
    assert "backup.backups.organization_id" in compiled
    assert result["total_backups"] == 0
    assert result["recent_backups"] == []
