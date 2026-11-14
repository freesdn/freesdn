# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Read-only mode blocks OPNsense writes, not OPNsense ping and traceroute.

The client treats a POST as a read only when its last path segment starts with
a read verb (search, get, list, ...). Ping and traceroute POST to
``/api/diagnostics/interface/ping`` and ``.../traceroute``, which do not, so
read-only mode refused them. The diagnostics service passed ``force=True``
expecting that to get past the gate, and until 26.12 it did; since force no
longer lifts the lock, a monitor-only install could not ping from OPNsense at
all, while MikroTik and pfSense probes kept working. The two probe paths are
now classified as reads by exact match, and genuine diagnostics writes such as
flushing the ARP table stay refused.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.opnsense.client import OPNsenseClient, _is_read_only_post


def _client_with_device() -> OPNsenseClient:
    client = OPNsenseClient(
        host="192.0.2.1", api_key="k", api_secret="s", port=443, verify_ssl=False
    )
    response = MagicMock(status_code=200, text='{"response": "ok"}')
    response.json.return_value = {"response": "ok"}
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.request = AsyncMock(return_value=response)
    return client


@patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
async def test_ping_reaches_the_firewall_in_read_only_mode() -> None:
    client = _client_with_device()
    assert await client.ping("192.0.2.10", 3) == {"response": "ok"}
    client._client.request.assert_awaited_once()


@patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
async def test_traceroute_reaches_the_firewall_in_read_only_mode() -> None:
    client = _client_with_device()
    assert await client.traceroute("192.0.2.10") == {"response": "ok"}
    client._client.request.assert_awaited_once()


@patch("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
async def test_a_diagnostics_write_is_still_refused_in_read_only_mode() -> None:
    client = _client_with_device()
    with pytest.raises(AdapterError, match="ADAPTER_READ_ONLY"):
        await client.flush_arp(force=True)
    client._client.request.assert_not_awaited()


@pytest.mark.parametrize(
    "path",
    [
        "/api/diagnostics/interface/ping/extra",
        "/api/diagnostics/interface/pingX",
        "/api/diagnostics/interface/flushArp",
    ],
)
def test_only_the_exact_probe_paths_are_reads(path: str) -> None:
    assert _is_read_only_post(path) is False
