"""Local refusal classification using real device/controller/tenant SQL.

These are direct service probes, including internal actions that public routes
cannot select. External adapter and event sink are synthetic; no hardware or
public factory-reset exposure is claimed.
"""

import pytest

from app.services.device_control import ActionRequest, ActionType, DeviceControlService
from tests.security.test_device_action_error_boundaries import (
    boundary_adapters,
    make_fixture,
    record_observed,
)

REFUSALS = [
    ("reset-no-confirm", "factory_reset", {}, "AdapterConfirmationRequiredError"),
    ("reset-false-string", "factory_reset", {"confirm": "false"}, "AdapterConfirmationRequiredError"),
    ("poe-enable-port", "poe_enable", {}, "ConfigurationError"),
    ("poe-disable-port", "poe_disable", {}, "ConfigurationError"),
    ("poe-cycle-port", "poe_cycle", {}, "ConfigurationError"),
    ("port-enable-port", "port_enable", {}, "ConfigurationError"),
    ("port-disable-port", "port_disable", {}, "ConfigurationError"),
    ("port-config-port", "port_configure", {}, "ConfigurationError"),
    ("port-config-config", "port_configure", {"port": 4}, "ConfigurationError"),
    ("port-config-unsupported", "port_configure", {"port": 4, "config": {}}, "CapabilityNotSupportedError"),
    ("ssid-enable-id", "ssid_enable", {}, "ConfigurationError"),
    ("ssid-disable-id", "ssid_disable", {}, "ConfigurationError"),
    ("ssid-update-id", "ssid_update", {}, "ConfigurationError"),
    ("ssid-update-config", "ssid_update", {"ssid_id": "owned-ssid"}, "ConfigurationError"),
    ("ssid-update-unsupported", "ssid_update", {"ssid_id": "owned-ssid", "config": {}}, "CapabilityNotSupportedError"),
    ("client-disconnect-mac", "client_disconnect", {}, "ConfigurationError"),
    ("client-block-mac", "client_block", {}, "ConfigurationError"),
    ("client-unblock-mac", "client_unblock", {}, "ConfigurationError"),
    ("firmware-check-unsupported", "firmware_check", {}, "CapabilityNotSupportedError"),
    ("firmware-upgrade-unsupported", "firmware_upgrade", {}, "CapabilityNotSupportedError"),
    ("backup-unsupported", "config_backup", {}, "CapabilityNotSupportedError"),
    ("restore-id", "config_restore", {}, "ConfigurationError"),
    ("restore-unsupported", "config_restore", {"backup_id": "owned-backup"}, "CapabilityNotSupportedError"),
]


@pytest.mark.parametrize("label,action,parameters,expected", REFUSALS, ids=[r[0] for r in REFUSALS])
async def test_local_refusal_is_not_an_unknown_device_write(
    db_session, label, action, parameters, expected, record_property,
):
    f = await make_fixture(db_session)
    with boundary_adapters(f):
        response = await DeviceControlService(db_session).execute_action(
            ActionRequest(f.device.id, ActionType(action), parameters=parameters)
        )
    record_observed(f, record_property)
    record_property("service_success", response.success)
    record_property("service_error", response.error)
    record_property("service_mentions_unknown", "unknown" in response.message.lower())
    assert response.error == expected
    assert response.success is False
    assert "unknown" not in response.message.lower()
    assert not f.calls
    assert f.exits == len(f.factories) == len(f.events) == 1
    assert f.events[0].payload["success"] is False
    assert f.events[0].organization_id == str(f.org.id)


@pytest.mark.parametrize("action", ["reboot", "locate", "poe_cycle"])
async def test_valid_local_action_still_dispatches_once(db_session, action, record_property):
    f = await make_fixture(db_session)
    with boundary_adapters(f):
        response = await DeviceControlService(db_session).execute_action(
            ActionRequest(f.device.id, ActionType(action), parameters={"port": 4})
        )
    record_observed(f, record_property)
    assert response.success is True and response.error is None
    assert response.data == {"serial": "owned-public-serial"}
    assert len(f.calls) == f.exits == len(f.factories) == len(f.events) == 1
    assert f.events[0].payload["success"] is True
    assert f.events[0].organization_id == str(f.org.id)
