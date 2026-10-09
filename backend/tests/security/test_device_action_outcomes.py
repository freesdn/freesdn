"""Actual SQL/JWT/HTTP boundary, synthetic adapter acknowledgements and real cancellation.

The task cancels itself at controlled adapter/event awaits; no external hardware
or broker is contacted. The original diagnostic fixture/authentication remains
unchanged. A fixture-issued JWT is not password-login or IdP qualification.
"""

import asyncio
import json

import pytest

from app.adapters.base import AdapterResult
from app.adapters.exceptions import (
    AdapterConfirmationRequiredError,
    AdapterOutcomeUnknownError,
    AdapterReadOnlyError,
)
from tests.security.test_device_action_error_boundaries import (
    http_action,
    make_fixture,
    record_observed,
)

HTTP_SCENARIOS = [
    "clean-success", "clean-refusal", "cleanup-after-success", "cleanup-after-refusal",
    "malformed-none", "malformed-dict", "malformed-string", "malformed-one", "malformed-null",
    "untrusted-code-list", "typed-readonly", "typed-confirmation", "vendor-readonly",
    "result-readonly", "result-confirmation", "result-unsupported", "outcome-unknown",
    "enter-failed", "enter-cleanup-failed",
]
CANCEL_SCENARIOS = [
    "command-cancel", "command-cancel-exit-error", "command-cancel-suppressed",
    "enter-cancel", "enter-cancel-cleanup-error", "exit-cancel", "event-cancel",
]


async def cancel_here():
    task = asyncio.current_task()
    assert task is not None
    task.cancel()
    await asyncio.sleep(0)
    pytest.fail("An actual task cancellation was not delivered")


async def make_outcome_fixture(db, scenario, action):
    f = await make_fixture(db, action=action)
    original_factory = f.factory
    f.entered = f.disconnected = 0

    class VendorReadOnlyError(AdapterReadOnlyError):
        pass

    class Adapter:
        async def __aenter__(self):
            f.entered += 1
            if scenario.startswith("enter-cancel"):
                await cancel_here()
            if scenario in {"enter-failed", "enter-cleanup-failed"}:
                raise RuntimeError(f.marker)
            return self

        async def __aexit__(self, *args):
            f.exits += 1
            if scenario == "exit-cancel":
                await cancel_here()
            if scenario in {"cleanup-after-success", "cleanup-after-refusal", "command-cancel-exit-error"}:
                raise RuntimeError(f.marker)
            return scenario == "command-cancel-suppressed"

        async def disconnect(self):
            f.disconnected += 1
            if scenario in {"enter-cleanup-failed", "enter-cancel-cleanup-error"}:
                raise RuntimeError(f.marker)

        def has_capability(self, capability, device_type):
            assert device_type == "switch"
            return True

        async def command(self, method, *args):
            f.calls.append((method, args))
            if scenario.startswith("command-cancel"):
                await cancel_here()
            if scenario == "typed-readonly":
                raise AdapterReadOnlyError(f.marker)
            if scenario == "typed-confirmation":
                raise AdapterConfirmationRequiredError(f.marker)
            if scenario == "vendor-readonly":
                raise VendorReadOnlyError(f.marker)
            if scenario == "outcome-unknown":
                raise AdapterOutcomeUnknownError(f.marker)
            if scenario == "malformed-none":
                return None
            if scenario == "malformed-dict":
                return {"success": True, "message": f.marker}
            if scenario in {"malformed-string", "malformed-one", "malformed-null"}:
                value = {"malformed-string": "yes", "malformed-one": 1, "malformed-null": None}[scenario]
                return AdapterResult(success=value, message=f.marker)
            if scenario == "untrusted-code-list":
                return AdapterResult(success=False, error=f.marker, error_code=[f.marker])
            if scenario.startswith("result-"):
                code = {"result-readonly": "READ_ONLY", "result-confirmation": "CONFIRMATION_REQUIRED", "result-unsupported": "NOT_SUPPORTED"}[scenario]
                return AdapterResult.fail(f.marker, error_code=code, message=f.marker)
            if scenario in {"clean-refusal", "cleanup-after-refusal"}:
                return AdapterResult(success=False, error="AdapterConnectionError", message=f.marker)
            return AdapterResult.ok({"serial": "owned-public-serial"}, message=f.marker)

        async def reboot_device(self, *args):
            return await self.command("reboot", *args)

        async def locate_device(self, *args):
            return await self.command("locate", *args)

        async def cycle_poe_port(self, *args):
            return await self.command("poe", *args)

    def factory(**kwargs):
        # Preserve the real decrypted-controller-credential assertion and count.
        original_factory(**kwargs)
        return Adapter()

    f.factory = factory
    if scenario == "event-cancel":
        async def publish(event):
            f.events.append(event)
            await cancel_here()
        f.event_bus.publish.side_effect = publish
    return f


@pytest.mark.parametrize("action", ["reboot", "locate", "poe"])
@pytest.mark.parametrize("scenario", HTTP_SCENARIOS)
async def test_HTTP_keeps_one_validated_device_outcome(db_session, scenario, action, record_property):
    f = await make_outcome_fixture(db_session, scenario, action)
    response = await http_action(f)
    record_observed(f, record_property, response)
    record_property("entered", f.entered)
    record_property("disconnect_attempts", f.disconnected)
    record_property("HTTP_mentions_unknown", "unknown" in response.text.lower())
    expected = 200 if action == "locate" else 202
    if scenario in {"clean-refusal", "cleanup-after-refusal"}:
        expected = 503
    elif scenario in {"typed-readonly", "vendor-readonly", "result-readonly"}:
        expected = 403
    elif scenario in {"typed-confirmation", "result-confirmation", "result-unsupported"}:
        expected = 409
    elif scenario not in {"clean-success", "cleanup-after-success"}:
        expected = 500
    assert response.status_code == expected
    assert len(f.factories) == f.entered == 1
    assert len(f.calls) == (0 if scenario.startswith("enter-") else 1)
    assert f.exits == (0 if scenario.startswith("enter-") else 1)
    assert f.disconnected == (1 if scenario.startswith("enter-") else 0)
    assert f.marker not in response.text
    assert all(f.marker not in json.dumps(e.payload, default=str) for e in f.events)
    if scenario.startswith("malformed-") or scenario in {"untrusted-code-list", "outcome-unknown"}:
        assert "unknown" in response.text.lower()
        assert "before retrying" in response.text.lower()
    if scenario in {"clean-success", "cleanup-after-success", "clean-refusal", "cleanup-after-refusal"}:
        assert len(f.events) == 1
        assert f.events[0].payload["success"] is (scenario in {"clean-success", "cleanup-after-success"})


@pytest.mark.parametrize("action", ["reboot", "locate", "poe"])
@pytest.mark.parametrize("scenario", CANCEL_SCENARIOS)
async def test_real_request_cancellation_survives_adapter_cleanup(db_session, scenario, action, record_property):
    f = await make_outcome_fixture(db_session, scenario, action)
    task = asyncio.create_task(http_action(f))
    cancelled = False
    returned_status = None
    try:
        returned_status = (await task).status_code
    except asyncio.CancelledError:
        cancelled = True
    record_observed(f, record_property)
    record_property("cancellation_propagated", cancelled)
    record_property("request_task_cancelled", task.cancelled())
    record_property("returned_status", returned_status)
    record_property("entered", f.entered)
    record_property("disconnect_attempts", f.disconnected)
    assert cancelled and task.cancelled()
    assert returned_status is None
    assert len(f.factories) == f.entered == 1
    assert len(f.calls) == (0 if scenario.startswith("enter-") else 1)
    assert f.exits == (0 if scenario.startswith("enter-") else 1)
    assert f.disconnected == (1 if scenario.startswith("enter-") else 0)
    assert len(f.events) == (1 if scenario == "event-cancel" else 0)
