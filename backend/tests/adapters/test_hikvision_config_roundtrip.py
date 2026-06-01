# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hikvision config GET-modify-PUT round-trip (device-free, HTTP mocked).

Locks the write path the P2 audit+rollback envelope wraps: a config write reads
the device's current XML, patches ONLY the requested fields (preserving the rest),
and PUTs it back to the correct channel URL. Motion detection is the representative
case — every smart-config write (line/field/privacy/schedule) shares this shape.
No live device is contacted.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.adapters.hikvision.adapter import HikvisionAdapter

_NS = "http://www.hikvision.com/ver20/XMLSchema"
_MOTION_XML = (
    f'<MotionDetection version="2.0" xmlns="{_NS}">'
    "<enabled>false</enabled>"
    "<sensitivityLevel>20</sensitivityLevel>"
    "<MotionDetectionLayout><gridMap>00ff</gridMap></MotionDetectionLayout>"
    "</MotionDetection>"
)


class _Resp:
    def __init__(self, text: str = "", status: int = 200) -> None:
        self.text = text
        self.status_code = status


class _MockClient:
    """Records the PUT and serves a fixed GET — stands in for httpx.AsyncClient."""

    def __init__(self, get_text: str = _MOTION_XML, get_status: int = 200) -> None:
        self._get_text = get_text
        self._get_status = get_status
        self.put_body: str | None = None
        self.put_url: str | None = None

    async def get(self, url, timeout=None):
        return _Resp(self._get_text, self._get_status)

    async def put(self, url, content=None, headers=None, timeout=None):
        self.put_url = url
        self.put_body = content
        return _Resp("", 200)


def _adapter_with(client: _MockClient) -> HikvisionAdapter:
    a = HikvisionAdapter(host="192.0.2.1", username="admin", password="x", port=80)
    a._connected = True  # skip connect()
    a._client = client  # _http property returns _client
    return a


@pytest.mark.asyncio
async def test_get_motion_detection_parses_device_xml() -> None:
    a = _adapter_with(_MockClient())
    out = await a.get_motion_detection(channel=2)
    assert out == {"enabled": False, "sensitivity_level": 20, "grid_map": "00ff"}


@pytest.mark.asyncio
@patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: False)
async def test_set_motion_detection_patches_requested_fields() -> None:
    client = _MockClient()
    a = _adapter_with(client)
    result = await a.set_motion_detection(
        {"enabled": True, "sensitivity_level": 80, "grid_map": "ffff"}, channel=2, force=True
    )
    assert result["success"] is True
    # PUT targeted the requested channel...
    assert "/channels/2/motionDetection" in client.put_url
    # ...and carried the patched values (clean default-namespace serialization).
    assert "<enabled>true</enabled>" in client.put_body
    assert "<sensitivityLevel>80</sensitivityLevel>" in client.put_body
    assert "<gridMap>ffff</gridMap>" in client.put_body


@pytest.mark.asyncio
@patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: False)
async def test_set_only_patches_given_fields_preserving_others() -> None:
    client = _MockClient()
    a = _adapter_with(client)
    # Only toggle enabled — sensitivity (20) must survive into the PUT body.
    result = await a.set_motion_detection({"enabled": True}, channel=1, force=True)
    assert result["success"] is True
    assert "<enabled>true</enabled>" in client.put_body
    assert "<sensitivityLevel>20</sensitivityLevel>" in client.put_body


@pytest.mark.asyncio
@patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: False)
async def test_set_motion_detection_rejects_non_hex_grid_map() -> None:
    client = _MockClient()
    a = _adapter_with(client)
    # A non-hex grid_map must NOT be written (injection-safety); old value stays.
    await a.set_motion_detection({"grid_map": "../../etc"}, channel=1, force=True)
    assert "<gridMap>00ff</gridMap>" in client.put_body
    assert "../../etc" not in (client.put_body or "")


@pytest.mark.asyncio
@patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: False)
async def test_set_motion_detection_get_http_error_no_put() -> None:
    client = _MockClient(get_status=500)
    a = _adapter_with(client)
    result = await a.set_motion_detection({"enabled": True}, channel=1, force=True)
    assert result["success"] is False
    assert client.put_body is None  # never PUT after a failed read
