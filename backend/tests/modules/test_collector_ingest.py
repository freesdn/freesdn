# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Ingest test: the syslog receiver parses RFC 3164 / RFC 5424 and persists a
CollectorLog.

A capability audit flagged that the collector's UDP ports were not published in
compose. Investigation showed the deployment side is more involved than a 3-line
edit (privileged 162/514 on a non-root read-only container, the multi-worker
single-binder, and the VPN-overlay ``network_mode``/``ports`` conflict on the api
service) — that wiring is a dedicated-collector-service decision. The INGEST code
itself is real and correct, which is what this locks: the parse -> store path.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.modules.collector.services.syslog import SyslogReceiver

# The receiver only accepts packets from explicitly-allowed CIDRs (empty
# allowlist = deny all, a secure default), so the ingest tests below allow the
# test source network.
_ALLOW = [ipaddress.ip_network("203.0.113.0/24")]


def test_parse_rfc3164():
    recv = SyslogReceiver()
    parsed = recv._parse_rfc3164("<34>Oct 11 22:14:15 myhost su: 'su root' failed")
    assert parsed is not None
    assert parsed["facility"] == "auth"  # PRI 34 >> 3 == 4 (auth)
    assert parsed["severity"] == "critical"  # PRI 34 & 7 == 2 (critical)
    assert parsed["hostname"] == "myhost"
    assert parsed["app_name"] == "su"
    assert parsed["message"] == "'su root' failed"


def test_parse_rfc5424():
    recv = SyslogReceiver()
    parsed = recv._parse_rfc5424(
        "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - Event happened"
    )
    assert parsed is not None
    assert parsed["facility"] == "local4"  # PRI 165 >> 3 == 20 (local4)
    assert parsed["severity"] == "notice"  # PRI 165 & 7 == 5 (notice)
    assert parsed["hostname"] == "mymachine.example.com"
    assert parsed["app_name"] == "evntslog"
    assert parsed["message"] == "Event happened"


class _CaptureSession:
    """Async-context-manager session that records what was added."""

    def __init__(self, sink: list) -> None:
        self._sink = sink

    async def __aenter__(self) -> _CaptureSession:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    def add(self, obj) -> None:
        self._sink.append(obj)

    async def commit(self) -> None:
        pass


@pytest.mark.asyncio
async def test_process_parses_and_persists_a_collectorlog():
    added: list = []
    recv = SyslogReceiver(session_factory=lambda: _CaptureSession(added), allowlist=_ALLOW)

    await recv._process("<34>Oct 11 22:14:15 fw01 kernel: link down", "203.0.113.9")

    assert len(added) == 1
    log = added[0]
    assert log.source_type == "syslog"
    assert log.source_ip == "203.0.113.9"
    assert log.facility == "auth"
    assert log.message == "link down"
    assert log.raw_data.startswith("<34>")


@pytest.mark.asyncio
async def test_process_unparseable_falls_back_to_raw():
    added: list = []
    recv = SyslogReceiver(session_factory=lambda: _CaptureSession(added), allowlist=_ALLOW)

    await recv._process("this is not a syslog frame", "203.0.113.9")

    assert len(added) == 1
    # Unparseable input is still stored verbatim (never silently dropped).
    assert added[0].message == "this is not a syslog frame"
    assert added[0].facility is None


@pytest.mark.asyncio
async def test_process_rejects_source_outside_allowlist():
    """The source-IP allowlist is a real security control: a packet from a CIDR
    that isn't allowed is dropped before parsing, not stored."""
    added: list = []
    recv = SyslogReceiver(session_factory=lambda: _CaptureSession(added), allowlist=_ALLOW)

    await recv._process("<34>Oct 11 22:14:15 fw01 kernel: link down", "198.51.100.7")

    assert added == []  # 198.51.100.7 is outside 203.0.113.0/24
    assert recv._rejected_packets == 1
