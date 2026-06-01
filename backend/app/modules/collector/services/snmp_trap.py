# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SNMP Trap Receiver
====================================

asyncio UDP server for SNMPv1/v2c traps.
Pure Python BER decoding — no net-snmp dependency.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _task_error_handler(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Background task failed: %s", exc, exc_info=exc)


# SNMP ASN.1 / BER type tags
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_PDU_V1_TRAP = 0xA4
_TAG_PDU_V2_TRAP = 0xA7


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode BER length field. Returns (length, new_offset)."""
    b = data[offset]
    offset += 1
    if b & 0x80:
        n = b & 0x7F
        length = int.from_bytes(data[offset : offset + n], "big")
        offset += n
    else:
        length = b
    return length, offset


def _skip_ber_field(data: bytes, offset: int) -> int:
    """
    Walk one BER TLV (tag + length + value) and return the offset AFTER
    the value. Used by the v1 trap parser to skip fields whose contents
    we don't care about (agent-addr, generic-trap, specific-trap,
    timestamp) without making assumptions about their encoded length.

    NOTE(C4): The previous implementation skipped a hardcoded 32 bytes
    which silently corrupted any v1 trap whose fields didn't sum to
    exactly that length — most real-world traps.
    """
    if offset >= len(data):
        return offset
    # tag byte
    offset += 1
    if offset >= len(data):
        return len(data)
    length, offset = _decode_length(data, offset)
    return offset + length


def _decode_oid(data: bytes, offset: int, length: int) -> str:
    """Decode BER OID."""
    end = offset + length
    first = data[offset]
    parts = [first // 40, first % 40]
    offset += 1
    value = 0
    while offset < end:
        b = data[offset]
        offset += 1
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_value(data: bytes, offset: int) -> tuple[Any, int]:
    """Decode a single BER TLV value. Returns (value, new_offset)."""
    tag = data[offset]
    offset += 1
    length, offset = _decode_length(data, offset)
    raw = data[offset : offset + length]
    offset += length

    if tag == _TAG_INTEGER:
        value: Any = int.from_bytes(raw, "big", signed=True)
    elif tag == _TAG_OCTET_STRING:
        try:
            value = raw.decode("utf-8", errors="replace")
        except Exception:
            value = raw.hex()
    elif tag == _TAG_OID:
        value = _decode_oid(raw, 0, len(raw))
    elif tag == _TAG_NULL:
        value = None
    else:
        value = raw.hex()

    return value, offset


def _parse_snmp_trap(data: bytes, source_ip: str) -> dict | None:
    """Parse SNMPv1 or v2c trap PDU."""
    try:
        offset = 0
        if data[offset] != _TAG_SEQUENCE:
            return None
        offset += 1
        _, offset = _decode_length(data, offset)

        # Version (INTEGER)
        offset += 1  # tag
        length, offset = _decode_length(data, offset)
        offset += length

        # Community (OCTET STRING) — intentionally SKIPPED, never
        # decoded into a readable field. The community is a device credential and
        # must not land in the persisted log message (a free-text field that the
        # key-based redact_secrets cannot mask). A future configured-community
        # validation can decode+compare here, but the value must never be stored.
        offset += 1  # tag
        length, offset = _decode_length(data, offset)
        offset += length  # skip the community bytes

        # PDU
        pdu_tag = data[offset]
        offset += 1
        _, offset = _decode_length(data, offset)

        varbinds: list[dict] = []
        enterprise_oid = ""
        trap_type = "generic"

        if pdu_tag == _TAG_PDU_V1_TRAP:
            # Enterprise OID
            offset += 1  # tag
            length, offset = _decode_length(data, offset)
            enterprise_oid = _decode_oid(data, offset, length)
            offset += length
            # NOTE(C4): walk each TLV instead of skipping a hardcoded
            # 32 bytes. Fields are: agent-addr (NetworkAddress) +
            # generic-trap (INTEGER) + specific-trap (INTEGER) +
            # time-stamp (TimeTicks).
            for _ in range(4):
                offset = _skip_ber_field(data, offset)
                if offset >= len(data):
                    break
        elif pdu_tag == _TAG_PDU_V2_TRAP:
            trap_type = "v2c"
            # v2c PDU prefix: request-id INTEGER, error-status INTEGER,
            # error-index INTEGER (all to be skipped before the varbind
            # list).
            for _ in range(3):
                offset = _skip_ber_field(data, offset)
                if offset >= len(data):
                    break

        # VarBindList (SEQUENCE)
        if offset < len(data) and data[offset] == _TAG_SEQUENCE:
            offset += 1
            _, offset = _decode_length(data, offset)
            while offset < len(data):
                # VarBind SEQUENCE
                if data[offset] != _TAG_SEQUENCE:
                    break
                offset += 1
                _, offset = _decode_length(data, offset)
                # OID
                offset += 1  # tag
                oid_len, offset = _decode_length(data, offset)
                oid = _decode_oid(data, offset, oid_len)
                offset += oid_len
                # Value
                val, offset = _decode_value(data, offset)
                varbinds.append({"oid": oid, "value": val})

        return {
            "source_type": "snmp_trap",
            "source_ip": source_ip,
            "enterprise_oid": enterprise_oid or None,
            "trap_type": trap_type,
            "varbinds": varbinds,
            # the community is redacted (and not decoded above) — it
            # is a device credential and this message is returned by /collector/logs
            # + /logs/{id} to any collector.logs.read holder (operator/site_admin).
            "message": f"SNMP trap from {source_ip} (community=<redacted>)",
            "timestamp": datetime.now(UTC),
        }
    except Exception as exc:
        logger.debug("Failed to parse SNMP trap from %s: %s", source_ip, exc)
        return None


class _SNMPProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SNMPTrapReceiver) -> None:
        self._receiver = receiver

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._receiver._handle(data, addr[0])).add_done_callback(
            _task_error_handler
        )

    def error_received(self, exc: Exception) -> None:
        logger.warning("SNMP UDP error: %s", exc)


class SNMPTrapReceiver:
    """asyncio UDP server for SNMP v1/v2c traps."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 162,
        session_factory: Callable[[], AsyncSession] | None = None,
        resolver: Any = None,
        allowlist: list[ipaddress._BaseNetwork] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._session_factory = session_factory
        self._resolver = resolver
        self._allowlist = allowlist or []
        self._transport: asyncio.DatagramTransport | None = None
        # NOTE(C3): count packets rejected by allowlist for /status.
        self._rejected_packets: int = 0
        # NOTE(C2): count rows dropped because source IP couldn't be
        # mapped to a known device → org.
        self._dropped_unknown_source: int = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SNMPProtocol(self),
            local_addr=(self.host, self.port),
            reuse_port=hasattr(socket, "SO_REUSEPORT"),  # seamless rebind on reload
        )
        self._transport = transport  # type: ignore[assignment]
        logger.info("SNMP trap receiver listening on %s:%s/udp", self.host, self.port)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    async def _handle(self, data: bytes, source_ip: str) -> None:
        # NOTE(C3): allowlist check happens BEFORE parsing — never let
        # an unauthorised source consume CPU on BER decoding.
        from app.modules.collector.services.manager import ip_allowed

        if not ip_allowed(source_ip, self._allowlist):
            self._rejected_packets += 1
            logger.info(
                "collector.snmp_trap.rejected source_ip=%s reason=allowlist",
                source_ip,
            )
            return

        parsed = _parse_snmp_trap(data, source_ip)
        if not parsed:
            return

        # NOTE(C2): resolve source IP → (org_id, device_id). Drop the
        # row if we can't map it — otherwise we'd leak cross-tenant
        # data into the global bucket.
        if self._resolver is not None:
            resolved = await self._resolver.resolve(source_ip)
            if resolved is None:
                self._dropped_unknown_source += 1
                logger.info(
                    "collector.snmp_trap.dropped source_ip=%s reason=unknown_source",
                    source_ip,
                )
                return
            parsed["organization_id"], parsed["device_id"] = resolved

        # NOTE(C1): persistence is gated on session_factory being set
        # — historically this guard was always-False because the
        # singleton was constructed with session_factory=None.
        if self._session_factory is not None:
            try:
                from app.modules.collector.models import CollectorLog

                async with self._session_factory() as db:
                    db.add(CollectorLog(**parsed))
                    await db.commit()
            except Exception as exc:
                logger.warning("Failed to persist SNMP trap: %s", exc)
