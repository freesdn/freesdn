"""Batch commands retain one honest outcome and preserve cancellation.

PostgreSQL is real; controller adapters and authenticated principals are
synthetic. Cancellation is exercised directly, other cases use HTTP-ASGI.
"""

import asyncio
from unittest.mock import patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterConfirmationRequiredError, AdapterReadOnlyError
from app.api.v1.endpoints import devices as endpoint
from app.core.dependencies import get_current_active_user
from tests.api.test_device_action_site_caps import make_action_fixture

MARKER = "owned-private-batch-diagnostic"
CONTROLS = {
    "clean-success",
    "clean-rejection",
    "all-denied",
    "mixed-scope",
    "missing-controller",
    "cancel-clean",
    "exit-cancel",
}
SCENARIOS = [
    "clean-success",
    "clean-rejection",
    "success-marker",
    "failure-marker",
    "action-error",
    "constructor-error",
    "enter-error",
    "enter-cleanup-error",
    "exit-error",
    "reject-exit-error",
    "duplicate-ids",
    "malformed-none",
    "malformed-dict",
    "malformed-string",
    "malformed-one",
    "readonly-exception",
    "confirmation-exception",
    "unsupported-result",
    "untrusted-error-code",
    "mixed-per-device",
    "all-denied",
    "mixed-scope",
    "missing-controller",
    "cancel-clean",
    "cancel-exit-error",
    "cancel-suppressed",
    "enter-cancel",
    "enter-cancel-cleanup",
    "exit-cancel",
]


def batch_cases():
    return [
        {"action": action, "scenario": scenario, "label": action + "-" + scenario}
        for action in ["batch-reboot", "batch-upgrade"]
        for scenario in SCENARIOS
    ]


async def make_batch_fixture(db, case):
    f = await make_action_fixture(
        db, {"action": case["action"], "level": "admin", "control": "org-admin"}
    )
    f.batch_case = case
    f.command_calls = []
    f.constructed = 0
    f.entered = 0
    f.exited = 0
    f.disconnected = 0
    f.requested = [f.ids["a"], f.ids["write"]]
    if case["scenario"] == "duplicate-ids":
        f.requested = [f.ids["a"], f.ids["a"], f.ids["write"], f.ids["a"]]
    if case["scenario"] == "all-denied":
        f.requested = [f.ids["foreign"], uuid4()]
    if case["scenario"] == "mixed-scope":
        f.requested = [f.ids["a"], f.ids["foreign"], uuid4()]
    if case["scenario"] == "missing-controller":
        for name in ["a", "write"]:
            f.devices[name].controller_id = None
        await db.commit()
    f.payload = {"device_ids": [str(d) for d in f.requested]}
    return f


def batch_adapter_patch(f):
    scenario = f.batch_case["scenario"]

    class Adapter:
        async def __aenter__(self):
            f.entered += 1
            if scenario in {"enter-error", "enter-cleanup-error"}:
                raise RuntimeError(MARKER)
            if scenario in {"enter-cancel", "enter-cancel-cleanup"}:
                raise asyncio.CancelledError()
            return self

        async def __aexit__(self, *args):
            f.exited += 1
            if scenario in {"exit-error", "reject-exit-error", "cancel-exit-error"}:
                raise RuntimeError(MARKER)
            if scenario == "exit-cancel":
                raise asyncio.CancelledError()
            return scenario == "cancel-suppressed"

        async def disconnect(self):
            f.disconnected += 1
            if scenario in {"enter-cleanup-error", "enter-cancel-cleanup"}:
                raise RuntimeError(MARKER)

        def __getattr__(self, method):
            assert method == (
                "reboot_device" if f.batch_case["action"] == "batch-reboot" else "upgrade_firmware"
            )

            async def command(mac):
                f.command_calls.append(mac)
                if scenario in {"cancel-clean", "cancel-exit-error", "cancel-suppressed"}:
                    raise asyncio.CancelledError()
                if scenario == "action-error":
                    raise RuntimeError(MARKER)
                if scenario == "readonly-exception":
                    raise AdapterReadOnlyError(MARKER)
                if scenario == "confirmation-exception":
                    raise AdapterConfirmationRequiredError(MARKER)
                if scenario == "malformed-none":
                    return None
                if scenario == "malformed-dict":
                    return {"success": True, "message": MARKER}
                if scenario == "malformed-string":
                    return AdapterResult(success="yes", message=MARKER)
                if scenario == "malformed-one":
                    return AdapterResult(success=1, message=MARKER)
                if scenario == "unsupported-result":
                    return AdapterResult.fail(MARKER, error_code="NOT_SUPPORTED", message=MARKER)
                if scenario == "untrusted-error-code":
                    return AdapterResult.fail(MARKER, error_code=[MARKER], message=MARKER)
                if scenario == "clean-rejection":
                    return AdapterResult.fail("Denied", error_code="READ_ONLY", message="Denied")
                if (
                    scenario in {"failure-marker", "reject-exit-error"}
                    or scenario == "mixed-per-device"
                    and len(f.command_calls) == 1
                ):
                    return AdapterResult.fail(MARKER, error_code="READ_ONLY", message=MARKER)
                return AdapterResult.ok(message="Accepted" if scenario in CONTROLS else MARKER)

            return command

    async def factory(device):
        f.constructed += 1
        if scenario == "constructor-error":
            raise RuntimeError(MARKER)
        return Adapter()

    return patch.object(endpoint, "_get_adapter_for_device", factory)


async def invoke_cancelled_batch(f):
    method = "reboot_device" if f.batch_case["action"] == "batch-reboot" else "upgrade_firmware"
    permission = "device:admin" if method == "reboot_device" else "firmware:upgrade"
    principal = f.app.dependency_overrides[get_current_active_user]()
    return await endpoint._batch_action(f.requested, method, principal, f.db, permission=permission)


def inspect_batch_response(f, result):
    scenario = f.batch_case["scenario"]
    rows = result["results"]
    unique = list(dict.fromkeys(str(i) for i in f.requested))
    assert len(rows) == len(unique) and {r["device_id"] for r in rows} == set(unique)
    assert all(type(r["success"]) is bool for r in rows)
    assert MARKER not in str(result)
    expected_calls = (
        0
        if scenario
        in {
            "constructor-error",
            "enter-error",
            "enter-cleanup-error",
            "all-denied",
            "missing-controller",
        }
        else 1
        if scenario == "mixed-scope"
        else 2
    )
    assert len(f.command_calls) == expected_calls
    assert len(f.command_calls) == len(set(f.command_calls))
    assert f.constructed == (0 if scenario in {"all-denied", "missing-controller"} else 1)
    assert f.entered == (
        0 if scenario in {"all-denied", "missing-controller", "constructor-error"} else 1
    )
    assert f.disconnected == (1 if scenario in {"enter-error", "enter-cleanup-error"} else 0)
    assert f.exited == (1 if expected_calls else 0)
    if scenario in CONTROLS:
        successes = 2 if scenario == "clean-success" else 1 if scenario == "mixed-scope" else 0
        assert sum(r["success"] for r in rows) == successes
        return
    outcomes = {r["device_id"]: r["outcome"] for r in rows}
    if scenario in {"success-marker", "exit-error", "duplicate-ids"}:
        assert set(outcomes.values()) == {"accepted"} and all(r["success"] for r in rows)
    elif scenario in {
        "failure-marker",
        "reject-exit-error",
        "readonly-exception",
        "confirmation-exception",
        "unsupported-result",
    }:
        assert set(outcomes.values()) == {"rejected"} and not any(r["success"] for r in rows)
    elif scenario in {"constructor-error", "enter-error", "enter-cleanup-error"}:
        assert set(outcomes.values()) == {"not_attempted"} and not any(r["success"] for r in rows)
    elif scenario == "mixed-per-device":
        assert (
            outcomes[str(f.ids["a"])] == "rejected" and outcomes[str(f.ids["write"])] == "accepted"
        )
    else:
        assert set(outcomes.values()) == {"unknown"} and not any(r["success"] for r in rows)
        assert all("verify device state before retrying" in r["message"].lower() for r in rows)
    if scenario in {"exit-error", "reject-exit-error"}:
        assert all(
            r["warning"] == "Controller cleanup failed; accepted commands must not be replayed."
            for r in rows
        )


@pytest.mark.parametrize("case", batch_cases(), ids=lambda c: c["label"])
async def test_batch_result_and_lifecycle(db_session, caplog, case):
    f = await make_batch_fixture(db_session, case)
    caplog.clear()
    with batch_adapter_patch(f):
        if "cancel" in case["scenario"]:
            with pytest.raises(asyncio.CancelledError):
                await invoke_cancelled_batch(f)
            entry_cancel = case["scenario"].startswith("enter-")
            assert f.disconnected == (1 if entry_cancel else 0)
            assert f.exited == (0 if entry_cancel else 1)
            assert len(f.command_calls) == (
                0 if entry_cancel else 2 if case["scenario"] == "exit-cancel" else 1
            )
        else:
            async with AsyncClient(
                transport=ASGITransport(app=f.app, raise_app_exceptions=False),
                base_url="http://owned-fixture",
            ) as client:
                response = await client.request(f.method, f.path, json=f.payload)
            assert response.status_code == 200, response.text
            inspect_batch_response(f, response.json())
    assert MARKER not in caplog.text
