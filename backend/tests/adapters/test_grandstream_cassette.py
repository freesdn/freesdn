# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Grandstream adapter — replay against REAL recorded phone payloads.

Grandstream is a PHONE-FLEET adapter: the adapter is provisioning-oriented and
the real reads hit an individual phone. Record (lab) with a real phone:

    FREESDN_RECORD_FIXTURES=1 FREESDN_CASSETTE_DIR=<off-repo> \
    FREESDN_RECORD_HOST=<phone-ip> FREESDN_RECORD_USERNAME=admin \
    FREESDN_RECORD_PASSWORD=<phone-admin-pw> FREESDN_RECORD_MAC=<phone-mac>

Reads only (read-only-first on prod phones). Absent → SKIP. Structural only.
"""

from __future__ import annotations

import os

import pytest

from app.adapters.base import AdapterResult
from tests.adapters._cassette_adapter import cassette_adapter
from tests.fixtures_harness import use_cassette

# RFC1918 defaults for replay (pass the adapter's SSRF guard); env overrides at record.
_PHONE_IP = os.environ.get("FREESDN_RECORD_HOST", "192.168.0.21")
_PHONE_MAC = os.environ.get("FREESDN_RECORD_MAC", "00:0b:82:00:00:01")
_PHONE_PW = os.environ.get("FREESDN_RECORD_PASSWORD", "replay")


async def _adapter():
    return await cassette_adapter(
        "grandstream",
        host="grandstream.invalid",
        username="admin",
        password="replay",
    )


def _with_phone(adapter):
    # Register the target phone in the fleet; the per-phone client makes the
    # recorded HTTP calls. acknowledge_plaintext so an http-only lab phone works.
    adapter.add_phone(_PHONE_IP, mac=_PHONE_MAC, password=_PHONE_PW, acknowledge_plaintext=True)
    return adapter


@pytest.mark.parametrize(
    "cassette,method",
    [
        ("grandstream/get_device_status", "get_device_status"),
        ("grandstream/get_phone_config", "get_phone_config"),
    ],
)
@pytest.mark.asyncio
async def test_phone_reads_return_normalized(cassette: str, method: str) -> None:
    with use_cassette(cassette):
        async with await _adapter() as adapter:
            _with_phone(adapter)
            result = await getattr(adapter, method)(_PHONE_MAC)
    assert result is not None
    assert isinstance(result, (AdapterResult, dict))
