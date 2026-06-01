# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Focused tests for network action endpoints wired through DeviceControlService.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.modules.network import api as network_api


@pytest.fixture
def current_user():
    """Build a user-like object for endpoint calls."""
    user = MagicMock()
    user.organization_id = uuid.uuid4()
    user.user = MagicMock()
    user.user.email = "ops@example.com"
    return user


@pytest.fixture
def mock_db():
    """Create a mocked async DB session."""
    return AsyncMock()


def _mock_network_device(name: str = "edge-switch-01") -> MagicMock:
    device = MagicMock()
    device.id = uuid.uuid4()
    device.name = name
    device.external_id = "AA:BB:CC:DD:EE:FF"
    device.mac_address = "AA:BB:CC:DD:EE:FF"
    device.site_id = uuid.uuid4()
    return device


def _scalar_result(value):
    """Build a SQLAlchemy scalar result-like test object."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


class TestActionEndpoints:
    """Focused endpoint tests for reboot/locate/poe/sync wiring."""

    @pytest.mark.asyncio
    async def test_reboot_device_uses_device_control_service(self, mock_db, current_user):
        device_id = uuid.uuid4()
        control_device_id = uuid.uuid4()
        network_device = _mock_network_device()

        nd_service = MagicMock()
        nd_service.get = AsyncMock(return_value=network_device)

        action_result = MagicMock(success=True, message="Reboot initiated", error=None)
        control_service = MagicMock()
        control_service.reboot_device = AsyncMock(return_value=action_result)

        with patch.object(
            network_api,
            "NetworkDeviceService",
            return_value=nd_service,
        ), patch.object(
            network_api,
            "_resolve_control_device_id",
            AsyncMock(return_value=control_device_id),
        ), patch.object(network_api, "DeviceControlService", return_value=control_service):
            payload = await network_api.reboot_device(device_id, mock_db, current_user)

        assert payload["status"] == "accepted"
        assert payload["device_id"] == str(device_id)
        control_service.reboot_device.assert_awaited_once_with(
            device_id=control_device_id,
            initiated_by=current_user.user.email,
        )

    @pytest.mark.asyncio
    async def test_reboot_device_maps_no_adapter_error_to_503(self, mock_db, current_user):
        device_id = uuid.uuid4()
        control_device_id = uuid.uuid4()
        network_device = _mock_network_device()

        nd_service = MagicMock()
        nd_service.get = AsyncMock(return_value=network_device)

        action_result = MagicMock(
            success=False,
            message="No compatible adapter found",
            error="no_adapter",
        )
        control_service = MagicMock()
        control_service.reboot_device = AsyncMock(return_value=action_result)

        with patch.object(
            network_api,
            "NetworkDeviceService",
            return_value=nd_service,
        ), patch.object(
            network_api,
            "_resolve_control_device_id",
            AsyncMock(return_value=control_device_id),
        ), patch.object(network_api, "DeviceControlService", return_value=control_service):
            with pytest.raises(HTTPException) as err:
                await network_api.reboot_device(device_id, mock_db, current_user)

        assert err.value.status_code == 503

    @pytest.mark.asyncio
    async def test_cycle_poe_port_dispatches_real_port_number(self, mock_db, current_user):
        device_id = uuid.uuid4()
        port_id = uuid.uuid4()
        control_device_id = uuid.uuid4()
        network_device = _mock_network_device()

        switch_port_service = MagicMock()
        port = MagicMock()
        port.poe_enabled = True
        port.port_number = 8
        switch_port_service.get = AsyncMock(return_value=port)

        nd_service = MagicMock()
        nd_service.get = AsyncMock(return_value=network_device)

        action_result = MagicMock(success=True, message="PoE cycled", error=None)
        control_service = MagicMock()
        control_service.cycle_poe = AsyncMock(return_value=action_result)

        with patch.object(
            network_api,
            "SwitchPortService",
            return_value=switch_port_service,
        ), patch.object(
            network_api,
            "NetworkDeviceService",
            return_value=nd_service,
        ), patch.object(
            network_api,
            "_resolve_control_device_id",
            AsyncMock(return_value=control_device_id),
        ), patch.object(network_api, "DeviceControlService", return_value=control_service):
            payload = await network_api.cycle_poe_port(
                device_id=device_id,
                port_id=port_id,
                db=mock_db,
                current_user=current_user,
                duration=13,
            )

        assert payload["status"] == "accepted"
        assert payload["port_number"] == 8
        control_service.cycle_poe.assert_awaited_once_with(
            device_id=control_device_id,
            port=8,
            duration=13,
            initiated_by=current_user.user.email,
        )

    @pytest.mark.asyncio
    async def test_sync_device_enqueues_task_with_resolved_control_id(self, mock_db, current_user):
        device_id = uuid.uuid4()
        control_device_id = uuid.uuid4()
        network_device = _mock_network_device(name="distribution-switch-01")

        nd_service = MagicMock()
        nd_service.get = AsyncMock(return_value=network_device)

        task = MagicMock()
        task.id = "task-123"

        with patch.object(
            network_api,
            "NetworkDeviceService",
            return_value=nd_service,
        ), patch.object(
            network_api,
            "_resolve_control_device_id",
            AsyncMock(return_value=control_device_id),
        ), patch(
            "app.tasks.sync.sync_device_status.delay",
            return_value=task,
        ) as delay_task:
            payload = await network_api.sync_device(device_id, mock_db, current_user)

        assert payload["status"] == "accepted"
        assert payload["task_id"] == "task-123"
        delay_task.assert_called_once_with(str(control_device_id))

    @pytest.mark.asyncio
    async def test_sync_all_devices_enqueues_full_sync_task(self, mock_db, current_user):
        task = MagicMock()
        task.id = "task-full-1"

        with patch(
            "app.tasks.sync.sync_all_device_statuses.delay",
            return_value=task,
        ) as delay_task:
            payload = await network_api.sync_all_devices(mock_db, current_user)

        assert payload["status"] == "accepted"
        assert payload["task_id"] == "task-full-1"
        delay_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_resolve_control_device_id_uses_external_id_lookup(self, mock_db):
        """Resolver should map network-device rows to core device rows via external_id."""
        control_id = uuid.uuid4()
        network_device = _mock_network_device()
        network_device.external_id = "omada-device-001"

        mock_db.execute = AsyncMock(
            side_effect=[
                _scalar_result(None),        # direct core.id lookup misses
                _scalar_result(control_id),  # external_id lookup hits
            ]
        )

        resolved = await network_api._resolve_control_device_id(
            mock_db,
            uuid.uuid4(),
            network_device,
        )

        assert resolved == control_id

    @pytest.mark.asyncio
    async def test_resolve_control_device_id_falls_back_to_mac_lookup(self, mock_db):
        """Resolver should fall back to MAC lookup when external_id misses."""
        control_id = uuid.uuid4()
        network_device = _mock_network_device()
        network_device.external_id = "missing-ext-id"
        network_device.mac_address = "aa:bb:cc:dd:ee:ff"

        mock_db.execute = AsyncMock(
            side_effect=[
                _scalar_result(None),        # direct id lookup misses
                _scalar_result(None),        # external_id lookup misses
                _scalar_result(control_id),  # mac lookup hits
            ]
        )

        resolved = await network_api._resolve_control_device_id(
            mock_db,
            uuid.uuid4(),
            network_device,
        )

        assert resolved == control_id
