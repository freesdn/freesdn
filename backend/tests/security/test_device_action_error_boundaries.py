"""Owned SQL/JWT/HTTP probes; only the external device and event sink are synthetic.

No hardware traffic. The normal JWT verifier, permissions, tenant SQL, controller
credential decoding, service dispatch, HTTP exception mapper and log formatters
run unchanged. A fixture-issued token does not qualify password login or an IdP.
"""

import io
import json
import logging
from contextlib import contextmanager
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterConnectionError
from app.core.crypto import encrypt_credential
from app.core.logging import ColoredFormatter, JSONLogFormatter
from app.core.middleware import setup_exception_handlers
from app.core.security import create_access_token, get_password_hash
from app.core.site_access import current_user_var
from app.db import get_session
from app.models.core import Controller, Organization, Site, User
from app.models.devices import Device, DevicePort
from app.modules.network import api as network_api
from app.services import device_control
from app.services.device_control import ActionRequest, ActionType, DeviceControlService


async def make_fixture(db, *, mode="clean-success", action="reboot", actor="owner"):
    marker = "OWNED_PRIVATE_VALUE_" + uuid4().hex
    org = Organization(name="Owned device boundary", slug=uuid4().hex)
    foreign = Organization(name="Owned other tenant", slug=uuid4().hex)
    db.add_all([org, foreign])
    await db.flush()
    site = Site(name="Owned device site", slug=uuid4().hex, organization_id=org.id)
    db.add(site)
    await db.flush()
    controller = Controller(
        name="Owned synthetic adapter", site_id=site.id, controller_type="omada",
        host="127.0.0.1", port=443,
        config={"username": "owned-operator", "password": encrypt_credential(marker)},
    )
    db.add(controller)
    await db.flush()
    device = Device(
        name="Owned controllable switch", site_id=site.id, controller_id=controller.id,
        device_type="switch", external_id=uuid4().hex,
    )
    db.add(device)
    await db.flush()
    port = DevicePort(device_id=device.id, port_number=4, is_poe_enabled=True)
    user = User(
        username=uuid4().hex, email=uuid4().hex + "@owned.example.test",
        hashed_password=get_password_hash("Owned test login password"),
        role="viewer" if actor == "viewer" else "org_admin",
        organization_id=foreign.id if actor == "foreign" else org.id,
        is_active=True, is_verified=True,
    )
    db.add_all([port, user])
    await db.flush()
    app = FastAPI()
    app.include_router(network_api.router, prefix="/network")
    setup_exception_handlers(app)

    async def session():
        yield db

    app.dependency_overrides[get_session] = session
    token = create_access_token(str(user.id), token_version=user.token_version)
    suffix = {"reboot": "/reboot", "locate": "/locate", "poe": f"/ports/{port.id}/poe/cycle"}[action]
    f = SimpleNamespace(
        db=db, app=app, device=device, site=site, org=org, marker=marker,
        mode=mode, action=action, calls=[], factories=[], exits=0, events=[],
        publish_error=None, token=token, path=f"/network/devices/{device.id}{suffix}",
    )

    class Adapter:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            f.exits += 1

        def has_capability(self, capability, device_type):
            assert device_type == "switch"
            return True

        async def run(self, method, *args):
            f.calls.append((method, args))
            if mode == "adapter-exception":
                raise AdapterConnectionError("Upstream rejected credential " + marker)
            if mode == "unexpected-exception":
                raise RuntimeError("Owned transport credential " + marker)
            if mode in {"adapter-result-error", "clean-failure"}:
                return AdapterResult(
                    success=False, error="AdapterConnectionError",
                    message=marker if mode == "adapter-result-error" else "Device unavailable",
                    data={"diagnostic": marker} if mode == "adapter-result-error" else None,
                )
            return AdapterResult.ok(
                data={"serial": "owned-public-serial"},
                message=marker if mode == "adapter-success" else "Owned action completed",
            )

        async def reboot_device(self, *args):
            return await self.run("reboot", *args)

        async def locate_device(self, *args):
            return await self.run("locate", *args)

        async def cycle_poe_port(self, *args):
            return await self.run("poe", *args)

    def factory(**kwargs):
        f.factories.append(kwargs)
        assert kwargs["password"] == marker
        assert kwargs["host"] == "127.0.0.1"
        if mode == "factory-exception":
            raise RuntimeError("Owned factory credential " + marker)
        return Adapter()

    async def publish(event):
        f.events.append(event)
        if f.publish_error:
            raise RuntimeError(f.publish_error)

    f.factory = factory
    f.event_bus = SimpleNamespace(publish=AsyncMock(side_effect=publish))
    return f


@contextmanager
def boundary_adapters(f):
    context = current_user_var.set(None)
    try:
        with patch.object(device_control.adapter_registry, "create_adapter", f.factory), patch.object(
            device_control, "get_event_bus", return_value=f.event_bus
        ):
            yield
    finally:
        current_user_var.reset(context)


async def http_action(f, *, authenticated=True):
    headers = {"Authorization": "Bearer " + f.token} if authenticated else {}
    with boundary_adapters(f):
        async with AsyncClient(transport=ASGITransport(app=f.app), base_url="http://owned.test") as client:
            return await client.post(f.path, headers=headers)


def record_observed(f, record_property, response=None):
    record_property("adapter_calls", len(f.calls))
    record_property("factory_calls", len(f.factories))
    record_property("adapter_context_exits", f.exits)
    record_property("event_attempts", len(f.events))
    record_property("event_has_private_value", f.marker in json.dumps([e.payload for e in f.events], default=str))
    if response is not None:
        record_property("HTTP_status", response.status_code)
        record_property("HTTP_has_private_value", f.marker in response.text)


@pytest.mark.parametrize("action", ["reboot", "locate", "poe"])
@pytest.mark.parametrize("mode", ["adapter-result-error", "adapter-exception", "unexpected-exception", "adapter-success"])
async def test_authenticated_HTTP_does_not_echo_adapter_private_text(db_session, action, mode, record_property):
    f = await make_fixture(db_session, action=action, mode=mode)
    response = await http_action(f)
    record_observed(f, record_property, response)
    expected = 200 if action == "locate" else 202
    if mode != "adapter-success":
        expected = 500 if mode == "unexpected-exception" else 503
    assert response.status_code == expected
    assert len(f.calls) == f.exits == 1
    assert f.marker not in response.text
    assert all(f.marker not in json.dumps(e.payload, default=str) for e in f.events)


@pytest.mark.parametrize("action", ["reboot", "locate", "poe"])
@pytest.mark.parametrize("actor", ["anonymous", "foreign", "viewer"])
async def test_refused_HTTP_never_constructs_or_calls_the_adapter(db_session, action, actor, record_property):
    f = await make_fixture(db_session, action=action, actor=actor)
    response = await http_action(f, authenticated=actor != "anonymous")
    record_observed(f, record_property, response)
    assert response.status_code == {"anonymous": 401, "foreign": 404, "viewer": 403}[actor]
    assert not f.calls and not f.factories and not f.events


@pytest.mark.parametrize("action", ["reboot", "locate", "poe"])
async def test_valid_HTTP_action_control_uses_real_tenant_and_device_lookup(db_session, action, record_property):
    f = await make_fixture(db_session, action=action)
    response = await http_action(f)
    record_observed(f, record_property, response)
    assert response.status_code == (200 if action == "locate" else 202)
    assert len(f.calls) == f.exits == len(f.events) == 1
    assert f.events[0].organization_id == str(f.org.id)
    assert f.events[0].payload["site_id"] == str(f.site.id)
    assert f.events[0].payload["device_id"] == str(f.device.id)
    assert response.json()["message"]


@pytest.mark.parametrize("mode", ["adapter-result-error", "adapter-exception", "unexpected-exception", "adapter-success"])
async def test_service_response_does_not_retain_private_diagnostics(db_session, mode, record_property):
    f = await make_fixture(db_session, mode=mode)
    with boundary_adapters(f):
        response = await DeviceControlService(db_session).execute_action(ActionRequest(f.device.id, ActionType.REBOOT))
    record_observed(f, record_property)
    record_property("service_response_has_private_value", f.marker in json.dumps(asdict(response), default=str))
    assert len(f.calls) == 1 and response.success is (mode == "adapter-success")
    assert f.marker not in json.dumps(asdict(response), default=str)
    if response.success:
        assert response.data == {"serial": "owned-public-serial"}


@pytest.mark.parametrize("format_name", ["JSON", "colored"])
@pytest.mark.parametrize("mode", ["adapter-exception", "unexpected-exception", "factory-exception"])
async def test_device_boundary_uses_safe_diagnostics_in_actual_formatters(db_session, format_name, mode, record_property):
    f = await make_fixture(db_session, mode=mode)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONLogFormatter() if format_name == "JSON" else ColoredFormatter())
    logger = logging.getLogger("app.services.device_control")
    logger.addHandler(handler)
    try:
        with boundary_adapters(f):
            response = await DeviceControlService(db_session).execute_action(ActionRequest(f.device.id, ActionType.REBOOT))
    finally:
        logger.removeHandler(handler)
    rendered = stream.getvalue()
    record_property("formatted_log_has_private_value", f.marker in rendered)
    record_property("formatted_log_nonempty", bool(rendered))
    assert response.success is False
    assert rendered and f.marker not in rendered


@pytest.mark.parametrize("format_name", ["JSON", "colored"])
def test_formatter_existing_bearer_redaction_control(format_name):
    marker = uuid4().hex
    record = logging.LogRecord("owned.control", logging.ERROR, __file__, 1, "Bearer " + marker, (), None)
    formatter = JSONLogFormatter() if format_name == "JSON" else ColoredFormatter()
    formatted = formatter.format(record)
    assert marker not in formatted and "[REDACTED]" in formatted


@pytest.mark.parametrize("mode", ["clean-success", "clean-failure"])
async def test_event_publish_failure_preserves_completed_action_outcome_without_replay(db_session, mode, record_property):
    f = await make_fixture(db_session, mode=mode)
    f.publish_error = "Owned notification credential " + f.marker
    with boundary_adapters(f):
        response = await DeviceControlService(db_session).execute_action(ActionRequest(f.device.id, ActionType.REBOOT))
    record_observed(f, record_property)
    record_property("service_success", response.success)
    record_property("service_response_has_private_value", f.marker in json.dumps(asdict(response), default=str))
    assert len(f.calls) == f.exits == len(f.events) == 1
    assert response.success is (mode == "clean-success")
    assert f.marker not in json.dumps(asdict(response), default=str)
    assert "Action failed" not in response.message
    assert response.error is None if response.success else response.error == "AdapterConnectionError"
