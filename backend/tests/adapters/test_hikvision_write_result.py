# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Hikvision: an HTTP 200 carrying a non-1 ``<statusCode>`` is a refused write.

Background
----------
ISAPI answers a REJECTED write with **HTTP 200** and puts the refusal in the
body::

    <ResponseStatus>
      <requestURL>/ISAPI/Image/channels/1/color</requestURL>
      <statusCode>4</statusCode>
      <statusString>Invalid Operation</statusString>
      <subStatusCode>notSupported</subStatusCode>
    </ResponseStatus>

Every write site in the adapter decided success with ``status_code == 200``
alone, so all of the above was reported to the caller as ``success: True``. In
a staged-write product that is the worst shape of bug available: the change is
marked applied, the audit log records an operator action that never happened,
and the camera keeps its old configuration. Motion detection, privacy masks,
line-crossing, intrusion detection, recording schedules and holiday schedules
all shared the defect -- i.e. exactly the settings someone only discovers were
wrong when they go looking for footage that was never recorded.

``_isapi_write_result`` is now the single decision point for all 21 write
sites. These tests pin its semantics, and pin that the write sites route
through it rather than re-deriving success from the status code.

Fail-open by design
-------------------
A body that is empty, unparseable, or not a ``ResponseStatus`` document counts
as success, exactly as before. This adapter runs against the maintainer's live
NVR fleet; inventing failures on an unrecognised-but-fine response would be a
worse regression than the bug being fixed. Only an explicit, well-formed
refusal flips the result. The "untouched" tests below are as load-bearing as
the "refused" ones.

No live device is contacted anywhere in this file.
"""

from __future__ import annotations

import inspect
import re
from types import SimpleNamespace

import pytest

from app.adapters.hikvision.adapter import _isapi_write_result

# ── Fixtures ─────────────────────────────────────────────────────


def _resp(text: str = "", status: int = 200):
    return SimpleNamespace(status_code=status, text=text)


def _response_status(code: str, string: str = "Invalid Operation", sub: str = "") -> str:
    sub_el = f"<subStatusCode>{sub}</subStatusCode>" if sub else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ResponseStatus version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">'
        "<requestURL>/ISAPI/Image/channels/1/color</requestURL>"
        f"<statusCode>{code}</statusCode>"
        f"<statusString>{string}</statusString>"
        f"{sub_el}"
        "</ResponseStatus>"
    )


# ── The regression ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("code", "label"),
    [
        ("3", "Device Busy"),
        ("4", "Invalid Operation"),
        ("5", "Invalid XML Format"),
        ("6", "Invalid XML Content"),
        ("7", "Reboot Required"),
    ],
)
def test_non_ok_status_code_is_a_failure(code: str, label: str) -> None:
    """The bug: every one of these was reported as a successful write."""
    out = _isapi_write_result(_resp(_response_status(code, label)))
    assert out["success"] is False, f"statusCode {code} ({label}) must not read as success"
    assert out["isapi_status_code"] == code


def test_status_string_reaches_the_operator() -> None:
    """
    A bare "failed" is not actionable. The device already said exactly what was
    wrong; that text is the whole value of parsing the body at all.
    """
    resp = _resp(_response_status("6", "Invalid XML Content", "badParameterValue"))
    assert resp.status_code == 200, "precondition: the device answered 200, not an error code"

    out = _isapi_write_result(resp)
    assert "Invalid XML Content" in out["error"]
    assert "badParameterValue" in out["error"]


def test_namespaced_xml_is_parsed() -> None:
    """
    ISAPI bodies carry a default xmlns. A namespace-naive `find("statusCode")`
    returns None against real firmware, which would silently restore the old
    always-succeeds behaviour while still looking like a fix.
    """
    out = _isapi_write_result(_resp(_response_status("4")))
    assert out["success"] is False


# ── Success and fail-open paths this must not disturb ────────────


def test_status_code_1_is_success() -> None:
    out = _isapi_write_result(_resp(_response_status("1", "OK")))
    assert out["success"] is True


def test_empty_body_is_success() -> None:
    """Many ISAPI endpoints answer a good write with no body at all."""
    assert _isapi_write_result(_resp("")).get("success") is True
    assert _isapi_write_result(_resp("   \n ")).get("success") is True


def test_unparseable_body_is_success() -> None:
    """Fail-open on garbage rather than inventing a failure on a live camera."""
    assert _isapi_write_result(_resp("<not xml at all")).get("success") is True


def test_non_response_status_document_is_success() -> None:
    """
    Some writes echo a domain document back instead of ResponseStatus. That is
    a normal success and must not be inspected for a statusCode.
    """
    body = "<MotionDetection><enabled>true</enabled></MotionDetection>"
    assert _isapi_write_result(_resp(body)).get("success") is True


def test_transport_failure_still_fails() -> None:
    """The pre-existing HTTP-level check must survive the refactor."""
    out = _isapi_write_result(_resp("", status=401))
    assert out["success"] is False
    assert "401" in out["error"]


# ── The sweep itself ─────────────────────────────────────────────


def test_no_write_site_still_derives_success_from_the_status_code_alone() -> None:
    """
    The defect was 21 copies of the same two-line idiom. A future write added
    by copy-pasting a neighbour would reintroduce it silently, so fail the
    build on the idiom itself rather than trusting review to catch it.
    """
    from app.adapters.hikvision import adapter as hik

    src = inspect.getsource(hik)
    offenders = re.findall(r"ok = \w+\.status_code == 200", src)
    assert not offenders, (
        f"{len(offenders)} write site(s) decide success from the status code alone; "
        "route them through _isapi_write_result()"
    )


def test_every_config_write_routes_through_the_helper() -> None:
    """
    Pin the specific setters. These are the ones whose silent failure is only
    discovered when the footage or the schedule turns out not to exist.
    """
    from app.adapters.hikvision import adapter as hik

    src = inspect.getsource(hik)
    for fn in (
        "set_motion_detection",
        "set_privacy_masks",
        "set_line_crossing",
        "set_intrusion_detection",
        "set_recording_schedule",
        "set_face_detection",
        "set_holidays",
        "set_holiday_schedule",
        "set_patrol",
        "set_image_settings",
        "set_thermal_threshold",
    ):
        assert f'context="{fn}"' in src, f"{fn} does not check the ISAPI response body"
