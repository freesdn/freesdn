# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Four writes that told the operator "done" without the device agreeing.

1. FREEPBX QUEUE WRITES IGNORED THE AMI VERDICT
   AMI answers a refused action with ``Response: Error`` and a ``Message``
   header explaining why -- "Unable to add interface: Already there",
   "Interface not found", "No such queue" -- over a perfectly healthy
   connection. ``send_action`` returns that as an ordinary AMIMessage and
   raises nothing.

   ``AMIMessage.is_error`` has always existed, and both ``login()`` and
   ``send_action_collect()`` check it. The queue writes returned
   ``AdapterResult.ok(data=resp.headers)`` unconditionally, so adding an agent
   to a queue that refused it reported success and the operator saw the agent
   in FreeSDN's view while Asterisk had never accepted it.

   Worth stating precisely, against the original report: the three CALL-CONTROL
   writes (originate / hangup / transfer) already checked ``resp.is_success``.
   That is what made the queue ones look right at a glance -- same file, same
   shape, three lines shorter.

2. OPENWRT "RESTART SERVICE" REPORTED SUCCESS ON A REFUSAL
   ``client.restart_service`` swallows ubus failures and returns a
   ``{"reload_skipped": True, "reason": ...}`` sentinel. That is deliberate and
   RIGHT for the reload that follows a UCI write: the config is already
   committed, so a refused reload must not 503 a write that landed.

   It is wrong for the operator pressing Restart, where the restart IS the
   whole action and nothing was committed behind it. Inheriting the swallow
   meant ubus answering "Access denied" -- the common case, since OpenWrt
   24.10+ needs an explicit ``rc.exec`` ACL grant -- produced HTTP 200
   "Restarted dnsmasq" while nothing restarted.

3. PTZ PRESETS WERE SAVED TO FREESDN, RECALLED FROM THE CAMERA
   ``set_preset`` wrote ``camera.settings["ptz_presets"]`` and stopped, so the
   camera never recorded the position. That would merely be inert if recall
   were local too -- but ``control_ptz(action="preset")`` calls
   ``adapter.goto_preset`` on the real camera. So clicking "Front Gate" aimed
   the camera at whatever ITS OWN preset 1 happened to be: uninitialised, or
   set from the camera's native web UI, or left by a previous installer. A
   preset panel that aims the camera somewhere other than where you saved it is
   worse than one that does nothing.

   Both shipped camera adapters implement ``set_preset`` properly. Neither was
   called.

4. THERMAL THRESHOLDS WERE ECHOED BACK, NEVER APPLIED
   ``PUT /cameras/{id}/thermal/threshold`` stored the values in
   ``camera.settings``, wrote an audit row, and returned the operator's own
   numbers. An operator setting a 60°C fire-detection threshold got a green
   save, a matching audit entry, and a UI reading back what they typed -- while
   the camera kept its shipped thresholds and no alarm would ever fire.
   ``HikvisionAdapter.set_thermal_threshold`` has always existed, and the GET
   beside it already talks to the camera.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from app.adapters.base import AdapterResult
from app.adapters.freepbx.adapter import FreePBXAdapter
from app.adapters.openwrt.adapter import OpenWRTAdapter


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the FreePBX AMI verdict ───────────────────────────────────


class _AMIMessage:
    """The real AMIMessage's accessors, without a socket."""

    def __init__(self, response: str, message: str = "") -> None:
        self.headers = {"Response": response, "Message": message}

    @property
    def response(self) -> str:
        return self.headers.get("Response", "")

    @property
    def message(self) -> str:
        return self.headers.get("Message", "")

    @property
    def is_error(self) -> bool:
        return self.response.lower() == "error"

    @property
    def is_success(self) -> bool:
        return self.response.lower() == "success"


def _adapter_with_ami(resp: _AMIMessage) -> FreePBXAdapter:
    adapter = FreePBXAdapter.__new__(FreePBXAdapter)
    adapter._check_write_allowed = lambda *_a, **_kw: None  # type: ignore[method-assign]

    async def _reply(*_a, **_kw):
        return resp

    adapter._ami = SimpleNamespace(  # type: ignore[assignment]
        queue_add=_reply,
        queue_remove=_reply,
        queue_pause=_reply,
        reload_module=_reply,
    )
    adapter._rest = SimpleNamespace(api_available=False)  # type: ignore[assignment]
    return adapter


ERROR = _AMIMessage("Error", "Unable to add interface: Already there")
SUCCESS = _AMIMessage("Success", "Added interface to queue")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("queue_add_member", ("support", "SIP/101")),
        ("queue_remove_member", ("support", "SIP/101")),
        ("queue_pause_member", ("support", "SIP/101")),
        ("reload_pbx_config", ()),
    ],
)
async def test_a_refused_ami_write_is_a_failure(method: str, args: tuple) -> None:
    """
    The regression. Asterisk said Error over a healthy connection and the
    adapter reported success.
    """
    adapter = _adapter_with_ami(ERROR)
    result = await getattr(adapter, method)(*args, force=True)

    assert result.success is False, f"{method} still reports success on Response: Error"
    assert "Already there" in (result.error or "")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("queue_add_member", ("support", "SIP/101")),
        ("queue_remove_member", ("support", "SIP/101")),
        ("queue_pause_member", ("support", "SIP/101")),
        ("reload_pbx_config", ()),
    ],
)
async def test_an_accepted_ami_write_still_succeeds(method: str, args: tuple) -> None:
    """The fix must not have made every queue write fail instead."""
    adapter = _adapter_with_ami(SUCCESS)
    result = await getattr(adapter, method)(*args, force=True)
    assert result.success is True, result.error


async def test_a_response_less_reply_is_not_treated_as_an_error() -> None:
    """
    Some AMI actions answer with headers and no Response line. That is not a
    refusal, and failing it would break writes that work.
    """
    adapter = _adapter_with_ami(_AMIMessage("", ""))
    result = await adapter.queue_add_member("support", "SIP/101", force=True)
    assert result.success is True


def test_the_verdict_helper_is_what_the_queue_writes_use() -> None:
    for name in (
        "queue_add_member",
        "queue_remove_member",
        "queue_pause_member",
        "reload_pbx_config",
    ):
        code = _code(getattr(FreePBXAdapter, name))
        assert "_ami_write_result" in code, f"{name} bypasses the verdict check"


def test_the_call_control_writes_still_check_too() -> None:
    """
    These were already right. Pin them so the class stays closed rather than
    just this instance of it.
    """
    for name in ("originate_call", "hangup_call", "transfer_call"):
        code = _code(getattr(FreePBXAdapter, name))
        assert "resp.is_success" in code, f"{name} lost its verdict check"


def test_is_error_reads_the_header_the_helper_relies_on() -> None:
    """Premise: if AMIMessage.is_error changes shape, the helper moves with it."""
    from app.adapters.freepbx.ami_client import AMIMessage

    assert AMIMessage(headers={"Response": "Error"}).is_error is True
    assert AMIMessage(headers={"Response": "Success"}).is_error is False
    assert AMIMessage(headers={}).is_error is False


# ── 2. the OpenWrt restart ───────────────────────────────────────


def _openwrt(result) -> OpenWRTAdapter:
    adapter = OpenWRTAdapter.__new__(OpenWRTAdapter)

    async def _restart(_name):
        if isinstance(result, Exception):
            raise result
        return result

    adapter._api = SimpleNamespace(restart_service=_restart)  # type: ignore[assignment]
    return adapter


async def test_a_refused_restart_is_reported_as_a_failure() -> None:
    """
    The regression. ubus "Access denied" -- the common case on 24.10+ without
    an rc.exec ACL grant -- came back as 200 "Restarted dnsmasq".
    """
    adapter = _openwrt({"reload_skipped": True, "service": "dnsmasq", "reason": "Access denied"})
    result = await adapter.restart_service("dnsmasq")

    assert result.success is False
    assert "Access denied" in (result.error or "")
    assert result.error_code == "SERVICE_RESTART_REFUSED"


async def test_a_real_restart_still_succeeds() -> None:
    adapter = _openwrt({"code": 0})
    result = await adapter.restart_service("dnsmasq")
    assert result.success is True
    assert "dnsmasq" in (result.message or "")


async def test_a_raising_restart_is_still_a_failure() -> None:
    """The pre-existing exception path must survive the sentinel check."""
    adapter = _openwrt(RuntimeError("connection reset"))
    result = await adapter.restart_service("dnsmasq")
    assert result.success is False
    assert "connection reset" in (result.error or "")


async def test_the_service_allowlist_still_applies() -> None:
    adapter = _openwrt({"code": 0})
    result = await adapter.restart_service("rm -rf /")
    assert result.success is False
    assert result.error_code == "SERVICE_NOT_ALLOWED"


def test_the_client_still_swallows_for_the_reload_after_write_path() -> None:
    """
    The swallow is correct THERE and must not be "fixed" too: the UCI commit
    already landed, so a refused reload should not 503 a write that succeeded.
    Only the explicit-restart caller needed to stop inheriting it.
    """
    from app.adapters.openwrt.client import OpenWRTClient

    code = _code(OpenWRTClient.restart_service)
    assert "reload_skipped" in code
    # The docstring names the sentinel too, so match the RETURN, not the word.
    assert 'return {"reload_skipped": True' in _code(OpenWRTClient.reload_network)


# ── 3. PTZ presets ───────────────────────────────────────────────


def test_saving_a_preset_writes_to_the_camera() -> None:
    from app.modules.cameras.service import PTZService

    code = _code(PTZService.set_preset)
    assert "adapter.set_preset" in code, (
        "the Presets panel is still a notepad -- the camera never learns the position"
    )


def test_the_camera_write_happens_before_the_local_record() -> None:
    """
    Recording the name first would leave FreeSDN showing a preset the camera
    refused, which is the same lie in a smaller shape.
    """
    from app.modules.cameras.service import PTZService

    code = _code(PTZService.set_preset)
    assert code.index("adapter.set_preset") < code.index('camera.settings["ptz_presets"]')


def test_a_refused_preset_save_does_not_persist() -> None:
    from app.modules.cameras.service import PTZService

    code = _code(PTZService.set_preset)
    assert 'getattr(ptz_result, "success", True) is False' in code, (
        "AdapterResult(success=False) does not raise; it has to be checked"
    )


def test_recall_still_goes_to_the_camera() -> None:
    """
    The half that always worked, and the reason the other half mattered. If
    recall ever became local too, the severity of a local-only save changes.
    """
    from app.modules.cameras.service import PTZService

    assert "adapter.goto_preset" in _code(PTZService.control_ptz)


@pytest.mark.parametrize("adapter_module", ["hikvision", "onvif"])
def test_both_camera_adapters_implement_the_write(adapter_module: str) -> None:
    """Premise: the capability existed all along and simply was not called."""
    module = __import__(f"app.adapters.{adapter_module}.adapter", fromlist=["x"])
    # vars() also holds the imported BaseAdapter; pick the class this module
    # actually defines.
    cls = next(
        obj
        for name, obj in vars(module).items()
        if isinstance(obj, type) and name.endswith("Adapter") and obj.__module__ == module.__name__
    )
    assert callable(getattr(cls, "set_preset", None)), cls.__name__


# ── 4. thermal thresholds ────────────────────────────────────────


def test_the_threshold_reaches_the_camera() -> None:
    from app.modules.cameras.api import set_thermal_threshold

    code = _code(set_thermal_threshold)
    assert "adapter.set_thermal_threshold" in code, (
        "the endpoint still echoes the operator's own numbers back at them"
    )


def test_the_threshold_is_pushed_before_it_is_stored() -> None:
    from app.modules.cameras.api import set_thermal_threshold

    code = _code(set_thermal_threshold)
    assert code.index("adapter.set_thermal_threshold") < code.index(
        'camera.settings["thermal_threshold"]'
    ), "a refused threshold would still be shown as applied"


def test_a_refused_threshold_is_not_a_200() -> None:
    from app.modules.cameras.api import set_thermal_threshold

    code = _code(set_thermal_threshold)
    assert 'getattr(result, "success", True) is False' in code
    assert "502" in code


def test_the_thermal_read_path_was_always_live() -> None:
    """The asymmetry that made this easy to miss: GET talked to the camera."""
    from app.modules.cameras.api import get_thermal_data

    assert "adapter.get_thermal_capabilities" in _code(get_thermal_data)


def test_the_adapter_write_exists_and_checks_isapi_status() -> None:
    """
    ISAPI answers a refused write with HTTP 200 and a statusCode in the body,
    so the adapter's own check is what makes the endpoint's check meaningful.
    """
    from app.adapters.hikvision.adapter import HikvisionAdapter

    code = _code(HikvisionAdapter.set_thermal_threshold)
    assert "_isapi_write_result" in code


def test_adapter_result_failure_does_not_raise() -> None:
    """
    The shared premise behind all four fixes: a refused write is a RETURN
    value, not an exception, so every caller has to look at it.
    """
    failed = AdapterResult.fail("nope")
    assert failed.success is False
    assert AdapterResult.ok({}).success is True
