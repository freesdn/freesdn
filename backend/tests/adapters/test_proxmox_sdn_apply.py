# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Legacy SDN intents are inspectable but must never dispatch writes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.services.adapter_proxmox_sdn import GatewayProxmoxSdnService
from app.services.adapter_staging import AdapterStagingService

LEGACY_OPERATIONS = [
    ("proxmox.sdn.zone", "create"),
    ("proxmox.sdn.zone", "delete"),
    ("proxmox.sdn.vnet", "create"),
    ("proxmox.sdn.vnet", "delete"),
    ("proxmox.sdn.apply", "create"),
]


@pytest.mark.parametrize(
    "feature,operation", [*LEGACY_OPERATIONS, ("proxmox.sdn.unknown", "create")]
)
@pytest.mark.parametrize(
    "payload", [{}, {"force": True, "confirmed": True, "lock-token": "foreign"}]
)
async def test_historical_sdn_plan_rejected_before_credentials(feature, operation, payload):
    svc = GatewayProxmoxSdnService(MagicMock())
    svc._get_controller = AsyncMock(side_effect=AssertionError("credentials must not be resolved"))
    svc._build_adapter = AsyncMock(side_effect=AssertionError("no native adapter"))
    change = SimpleNamespace(feature=feature, operation=operation, payload=payload)
    with pytest.raises(HTTPException) as exc:
        await svc.build_applier(change)(change)
    assert exc.value.status_code == 409
    svc._get_controller.assert_not_awaited()
    svc._build_adapter.assert_not_awaited()


@pytest.mark.parametrize("feature,operation", LEGACY_OPERATIONS)
async def test_new_sdn_staging_rejected_even_without_controller(feature, operation):
    db = MagicMock()
    with pytest.raises(HTTPException) as exc:
        await AdapterStagingService(db).stage_change(
            feature=feature,
            operation=operation,
            payload={},
            controller_id=None,
            organization_id=None,
        )
    assert exc.value.status_code == 409
    db.add.assert_not_called()
