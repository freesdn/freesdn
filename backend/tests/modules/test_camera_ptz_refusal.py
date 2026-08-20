# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A PTZ command the camera refused must not be reported to the operator as "ok".

Background
----------
The adapters report refusal faithfully. Hikvision turns a non-1 ISAPI
``<statusCode>`` into ``AdapterResult.fail``; ONVIF does the same for a SOAP
fault or a device with no PTZ service. ``PTZService.control_ptz`` passes that
straight through as ``success``.

The endpoint discarded it. It hardcoded ``outcome = "ok"`` and returned
``{"status": "ok", **result}``, and ``PTZActionResponse`` declares only
``status`` -- so pydantic stripped ``success`` before the client could see it.

The operator-visible consequence was the bad part. The React mutation
(``PTZTab``) declares only ``onError``, so an HTTP 200 fires no toast at all:
the button clicks, nothing happens, and nothing says so. Meanwhile the audit
row recorded an ``UPDATE`` and the event bus published ``ptz_<action>`` with
``outcome=ok`` at HIGH priority, so any Fabric automation rule watching for
camera movement fired on movement that never happened.

These tests pin the refusal path, and pin that the success path is unchanged --
the latter matters because cameras are the maintainer's live fleet and turning
working PTZ into a 502 would be a worse bug than the one being fixed.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.modules.cameras import api as cameras_api


@pytest.fixture
def wiring(monkeypatch):
    """Stub everything around the handler; keep the handler itself real."""
    events: list[dict] = []
    audits: list[dict] = []

    async def _no_access_check(*_a, **_kw):
        return None

    class _FakeAudit:
        def __init__(self, db=None):
            pass

        async def log(self, **kw):
            audits.append(kw)

    async def _record(action, **kw):
        events.append({"action": action, **kw})

    monkeypatch.setattr(cameras_api, "_enforce_camera_access", _no_access_check)
    monkeypatch.setattr(cameras_api, "AuditService", _FakeAudit)
    monkeypatch.setattr(cameras_api, "org_scope_or_platform", lambda _u: uuid.uuid4())

    from app.modules.cameras import events as camera_events

    monkeypatch.setattr(camera_events, "record_camera_action", _record)

    return SimpleNamespace(events=events, audits=audits)


def _user():
    return SimpleNamespace(
        id=uuid.uuid4(),
        is_site_limited=False,
        accessible_site_ids=set(),
    )


def _service(success: bool | None):
    """A PTZService whose control_ptz reports the given success flag."""
    payload: dict = {"action": "right", "speed": 50, "preset": None}
    if success is not None:
        payload["success"] = success

    class _Svc:
        db = object()

        async def control_ptz(self, **_kw):
            return payload

    return _Svc()


async def _call(svc, wiring_):
    return await cameras_api.control_ptz(
        camera_id=uuid.uuid4(),
        current_user=_user(),
        ptz_service=svc,
        session=object(),
        action="right",
        speed=50,
        preset=None,
    )


# ── The regression ───────────────────────────────────────────────


async def test_refused_command_raises_instead_of_returning_ok(wiring) -> None:
    """The bug: success=False came back as HTTP 200 {"status": "ok"}."""
    with pytest.raises(HTTPException) as exc:
        await _call(_service(success=False), wiring)

    assert exc.value.status_code == 502
    assert "refused" in str(exc.value.detail).lower()


async def test_refused_command_publishes_outcome_failed_not_ok(wiring) -> None:
    """
    A Fabric rule watching camera movement must not fire on a refusal. The
    event was previously published with outcome="ok" at HIGH priority.
    """
    with pytest.raises(HTTPException):
        await _call(_service(success=False), wiring)

    assert wiring.events, "the finally block must still publish an event"
    assert wiring.events[-1]["outcome"] == "failed"


async def test_refusal_is_still_audited_but_marked_unsuccessful(wiring) -> None:
    """
    An attempted move is what an investigator needs to see, so the row stays --
    but it must not read as a completed action.
    """
    with pytest.raises(HTTPException):
        await _call(_service(success=False), wiring)

    assert wiring.audits, "the attempt must still be audited"
    assert wiring.audits[-1]["extra_metadata"]["succeeded"] is False


# ── The success path this must not disturb ───────────────────────


async def test_successful_command_still_returns_ok(wiring) -> None:
    out = await _call(_service(success=True), wiring)
    assert out["status"] == "ok"
    assert wiring.events[-1]["outcome"] == "ok"
    assert wiring.audits[-1]["extra_metadata"]["succeeded"] is True


async def test_adapter_that_reports_no_flag_is_treated_as_success(wiring) -> None:
    """
    Not every adapter reports the flag. Defaulting those to failure would break
    working PTZ on the live fleet -- a worse outcome than the bug being fixed.
    """
    out = await _call(_service(success=None), wiring)
    assert out["status"] == "ok"
    assert wiring.events[-1]["outcome"] == "ok"


# ── Guard against the response model swallowing it again ─────────


def test_endpoint_does_not_hardcode_the_outcome() -> None:
    """
    The defect was a literal `outcome = "ok"` on the success path, which no
    response-model change can fix because PTZActionResponse only carries
    `status`. Fail the build if that idiom returns.
    """
    import inspect
    import re

    src = inspect.getsource(cameras_api.control_ptz)
    assert re.search(r"succeeded\s*=", src), "the success flag is no longer read"
    assert 'outcome = "ok" if succeeded else "failed"' in src, (
        "control_ptz is deriving outcome from something other than the "
        "adapter's success flag again"
    )
