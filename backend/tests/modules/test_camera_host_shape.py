# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A camera or NVR host must be a hostname or an IP address, nothing else.

``_validate_host_not_ssrf`` guards every camera/NVR ``host`` / ``ip_address``
before the value is pasted into ``rtsp://{host}:554/...`` and
``http://{host}``. It checked IP literals against the block list and resolved
anything else, but a resolution failure counted as a pass and the string's
shape was never checked. A value carrying a port, path, userinfo or fragment
never resolves, so it passed, and once interpolated it named a different
authority from the one the check looked at. A bracketed IPv6 literal took the
same route around the block list. Both now fail validation.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.modules.cameras.schemas import (
    CameraCreateRequest,
    NVRConnectionTestRequest,
    _validate_host_not_ssrf,
)

# Shapes that are not a host. ``.invalid`` never resolves (RFC 6761), which is
# exactly the case the old code waved through.
NOT_A_HOST = [
    "camera.example.invalid:8080/x",
    "camera.example.invalid/#",
    "user@camera.example.invalid",
    "camera.example.invalid?x=1",
    "camera example.invalid",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "[not-an-address]",
]

REAL_HOSTS = [
    "camera-01.example.invalid",
    "nvr_backyard.example.invalid",
    "nvr.example.invalid.",
    "192.168.1.150",
    "10.0.0.7",
    "fd00::10",
    "[fd00::10]",
]


@pytest.mark.parametrize("host", NOT_A_HOST)
def test_validator_refuses_values_that_are_not_a_host(host: str) -> None:
    with pytest.raises(ValueError):
        _validate_host_not_ssrf(host)


@pytest.mark.parametrize("host", REAL_HOSTS)
def test_validator_keeps_accepting_real_hosts(host: str) -> None:
    assert _validate_host_not_ssrf(host) == host


SITE_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def test_request_schemas_build_with_a_real_host() -> None:
    """Control: the refusals below are about the host, not a missing field."""
    assert NVRConnectionTestRequest(host="192.168.1.150", username="u", password="p")
    assert CameraCreateRequest(name="cam", site_id=SITE_ID, ip_address="192.168.1.150")


@pytest.mark.parametrize("host", NOT_A_HOST)
def test_request_schemas_refuse_values_that_are_not_a_host(host: str) -> None:
    with pytest.raises(ValidationError):
        NVRConnectionTestRequest(host=host, username="u", password="p")
    with pytest.raises(ValidationError):
        CameraCreateRequest(name="cam", site_id=SITE_ID, ip_address=host)
