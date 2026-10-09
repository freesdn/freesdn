# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
DeviceControlService focused dispatch and contract tests.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.base import AdapterResult
from app.services.device_control import (
    ActionRequest,
    ActionType,
    DeviceControlService,
)


@pytest.fixture
def organization_id():
    """Use a concrete tenant identity rather than a mock-derived string."""
    return uuid.uuid4()


@pytest.fixture
def mock_db(organization_id):
    """Async execute returns the synchronous SQLAlchemy result interface."""
    result = MagicMock(spec=["scalar_one_or_none"])
    result.scalar_one_or_none.return_value = organization_id
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.fixture
def service(mock_db):
    """Create DeviceControlService with mocked event bus."""
    svc = DeviceControlService(mock_db)
    svc.event_bus = MagicMock()
    svc.event_bus.publish = AsyncMock()
    return svc


@pytest.fixture
def sample_device():
    """Create a sample device model-like object."""
    device = MagicMock()
    device.id = uuid.uuid4()
    device.external_id = "AA:BB:CC:DD:EE:FF"
    device.device_type = "switch"
    device.controller_id = uuid.uuid4()
    device.site_id = uuid.uuid4()
    device.name = "core-switch-01"
    device.ip_address = "10.0.0.10"
    device.vendor = "tp-link"
    return device


def _make_adapter() -> MagicMock:
    """Build a mock adapter supporting async context manager protocol."""
    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=None)
    return adapter


def _assert_completed_event(service, device, organization_id, action):
    service.event_bus.publish.assert_awaited_once()
    event = service.event_bus.publish.await_args.args[0]
    assert event.organization_id == str(organization_id)
    assert event.payload["site_id"] == str(device.site_id)
    assert event.payload["device_id"] == str(device.id)
    assert event.event_type == "device.action_completed"
    assert event.payload["action"] == action.value
    assert event.payload["success"] is True


class TestDeviceControlService:
    """Focused tests for action dispatch and adapter contract compatibility."""

    @pytest.mark.asyncio
    async def test_get_adapter_for_device_uses_controller_type(self, service, sample_device):
        """Controller-managed devices should resolve adapter ID from controller.type."""
        controller = MagicMock()
        controller.type = "omada"
        controller.host = "10.0.0.2"
        controller.username = "admin"
        controller.password = "secret"

        sample_device.controller_id = uuid.uuid4()
        service.get_controller = AsyncMock(return_value=controller)

        mock_adapter = _make_adapter()
        with patch(
            "app.services.device_control.adapter_registry.create_adapter",
            return_value=mock_adapter,
        ) as create_adapter:
            resolved = await service.get_adapter_for_device(sample_device)

        assert resolved is mock_adapter
        assert create_adapter.call_args.kwargs["adapter_id"] == "omada"

    def test_check_capability_passes_lower_device_type(self, service):
        """Capability check should pass normalized lower-case device type."""
        adapter = MagicMock()
        adapter.has_capability = MagicMock(return_value=True)
        device = MagicMock()
        device.device_type = "ACCESS_POINT"

        ok = service.check_capability(adapter, ActionType.REBOOT, device)

        assert ok is True
        assert adapter.has_capability.call_args.kwargs["device_type"] == "access_point"

    @pytest.mark.asyncio
    async def test_execute_action_dispatches_client_unblock(self, service, sample_device, organization_id):
        """CLIENT_UNBLOCK action should dispatch to adapter.unblock_client."""
        adapter = _make_adapter()
        adapter.unblock_client = AsyncMock(
            return_value=AdapterResult.ok(message="Client unblocked")
        )
        service.get_device = AsyncMock(return_value=sample_device)
        service.get_adapter_for_device = AsyncMock(return_value=adapter)
        service.check_capability = MagicMock(return_value=True)

        request = ActionRequest(
            device_id=sample_device.id,
            action_type=ActionType.CLIENT_UNBLOCK,
            parameters={"client_mac": "11:22:33:44:55:66"},
        )
        response = await service.execute_action(request)

        assert response.success is True
        adapter.unblock_client.assert_awaited_once_with("11:22:33:44:55:66")
        _assert_completed_event(service, sample_device, organization_id, ActionType.CLIENT_UNBLOCK)

    @pytest.mark.asyncio
    async def test_execute_action_poe_cycle_passes_duration(self, service, sample_device, organization_id):
        """POE_CYCLE action should pass duration to adapter.cycle_poe_port."""
        adapter = _make_adapter()
        adapter.cycle_poe_port = AsyncMock(
            return_value=AdapterResult.ok(message="PoE cycled")
        )
        service.get_device = AsyncMock(return_value=sample_device)
        service.get_adapter_for_device = AsyncMock(return_value=adapter)
        service.check_capability = MagicMock(return_value=True)

        request = ActionRequest(
            device_id=sample_device.id,
            action_type=ActionType.POE_CYCLE,
            parameters={"port": 4, "duration": 9},
        )
        response = await service.execute_action(request)

        assert response.success is True
        adapter.cycle_poe_port.assert_awaited_once_with(sample_device.external_id, 4, 9)
        _assert_completed_event(service, sample_device, organization_id, ActionType.POE_CYCLE)

    @pytest.mark.asyncio
    async def test_execute_action_port_configure_dispatch(self, service, sample_device, organization_id):
        """PORT_CONFIGURE should use adapter.configure_switch_port when available."""
        adapter = _make_adapter()
        adapter.configure_switch_port = AsyncMock(
            return_value=AdapterResult.ok(message="Port updated")
        )
        service.get_device = AsyncMock(return_value=sample_device)
        service.get_adapter_for_device = AsyncMock(return_value=adapter)
        service.check_capability = MagicMock(return_value=True)

        request = ActionRequest(
            device_id=sample_device.id,
            action_type=ActionType.PORT_CONFIGURE,
            parameters={"port": 7, "config": {"native_vlan": 120}},
        )
        response = await service.execute_action(request)

        assert response.success is True
        adapter.configure_switch_port.assert_awaited_once_with(
            sample_device.external_id,
            7,
            {"native_vlan": 120},
        )
        _assert_completed_event(service, sample_device, organization_id, ActionType.PORT_CONFIGURE)

    @pytest.mark.asyncio
    async def test_execute_action_firmware_check_returns_data(self, service, sample_device, organization_id):
        """FIRMWARE_CHECK should wrap adapter.get_firmware_info into response data."""
        adapter = _make_adapter()
        adapter.get_firmware_info = AsyncMock(
            return_value={"current": "1.2.3", "available": "1.2.4"}
        )
        service.get_device = AsyncMock(return_value=sample_device)
        service.get_adapter_for_device = AsyncMock(return_value=adapter)
        service.check_capability = MagicMock(return_value=True)

        request = ActionRequest(
            device_id=sample_device.id,
            action_type=ActionType.FIRMWARE_CHECK,
            parameters={},
        )
        response = await service.execute_action(request)

        assert response.success is True
        assert response.data == {"current": "1.2.3", "available": "1.2.4"}
        adapter.get_firmware_info.assert_awaited_once_with(sample_device.external_id)
        _assert_completed_event(service, sample_device, organization_id, ActionType.FIRMWARE_CHECK)


@pytest.mark.asyncio
@pytest.mark.parametrize("lookup", ["no-site", "missing-site", "query-failure"])
async def test_completed_device_event_does_not_invent_a_tenant_on_lookup_failure(
    service, sample_device, mock_db, lookup,
):
    adapter = _make_adapter()
    adapter.unblock_client = AsyncMock(return_value=AdapterResult.ok(message="Client unblocked"))
    service.get_device = AsyncMock(return_value=sample_device)
    service.get_adapter_for_device = AsyncMock(return_value=adapter)
    service.check_capability = MagicMock(return_value=True)
    if lookup == "no-site":
        sample_device.site_id = None
    elif lookup == "missing-site":
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
    else:
        mock_db.execute.side_effect = RuntimeError("Owned synthetic site lookup failure")
    response = await service.execute_action(ActionRequest(
        device_id=sample_device.id,
        action_type=ActionType.CLIENT_UNBLOCK,
        parameters={"client_mac": "11:22:33:44:55:66"},
    ))
    assert response.success is True
    adapter.unblock_client.assert_awaited_once_with("11:22:33:44:55:66")
    service.event_bus.publish.assert_awaited_once()
    event = service.event_bus.publish.await_args.args[0]
    assert event.organization_id is None
    assert event.payload["device_id"] == str(sample_device.id)
    assert event.payload["site_id"] == (str(sample_device.site_id) if sample_device.site_id else None)
    assert event.event_type == "device.action_completed"
    if lookup == "no-site":
        mock_db.execute.assert_not_awaited()
    else:
        mock_db.execute.assert_awaited_once()
