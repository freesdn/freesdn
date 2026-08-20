# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
NetFlow v5: every stored record carried wrong numbers, and the flush lost batches.

Two defects, and the second was masked by the first.

1. WRONG FIELD INDICES
   ``_NF5_RECORD``'s format string was always correct. The INDICES reading it
   were not -- every single one::

       source_port  read rec[10]  -> dstport   (the ports were swapped)
       dest_port    read rec[11]  -> pad1      (hence ALWAYS 0)
       protocol     read rec[14]  -> tos
       bytes_in     read rec[8]   -> Last      } sysUptime millisecond counters,
       packets      read rec[7]   -> First     } not counts of anything

   Nothing raised. Every flow record the collector has ever written carries a
   byte count that is really a device uptime timestamp, a destination port of 0,
   and the ToS byte in the protocol column -- and those values aggregate into
   every top-talkers, bandwidth and protocol view in the Observability module.

2. HETEROGENEOUS INSERT BATCHES
   ``insert().values(list_of_dicts)`` derives its column list from the FIRST
   dict. ``app_name``/``app_category`` are attached only to flows the DPI
   classifier matched, so a batch is heterogeneous by design. Verified against
   the real compile path:

     first row classified, later one not  -> CompileError; _persist_batch retries
                                             then DROPS the batch (a minute of flows)
     first row unclassified, later one is -> compiles, and SILENTLY DISCARDS the
                                             later row's classification

   The masking: the classifier keys off ``dest_port``, which defect 1 pinned at
   0, so classification almost never matched and batches were almost always
   homogeneous. Fixing the parser alone would have converted a rare failure into
   a constant one.
"""

from __future__ import annotations

import socket
import struct
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import insert

from app.modules.collector.models import FlowRecord
from app.modules.collector.services import netflow as nf

# Distinct values throughout, so a mis-index cannot coincidentally match.
SRC_IP, DST_IP, NEXT_HOP = "10.1.2.3", "192.0.2.9", "10.0.0.1"
D_PKTS, D_OCTETS = 77, 999_999
FIRST, LAST = 111_111, 222_222
SPORT, DPORT, PROTO, TOS = 51234, 443, 6, 184


def _v5_packet() -> bytes:
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        int.from_bytes(socket.inet_aton(SRC_IP), "big"),
        int.from_bytes(socket.inet_aton(DST_IP), "big"),
        int.from_bytes(socket.inet_aton(NEXT_HOP), "big"),
        1,
        2,  # snmp in / out
        D_PKTS,
        D_OCTETS,
        FIRST,
        LAST,
        SPORT,
        DPORT,
        0,
        0x18,
        PROTO,
        TOS,  # pad1, tcp_flags, prot, tos
        64512,
        64513,  # src_as, dst_as
        24,
        24,
        0,  # src_mask, dst_mask, pad2
    )
    header = struct.pack("!HHIIIIBBH", 5, 1, 123456, 1_700_000_000, 0, 1, 0, 0, 0)
    return header + record


# ── Defect 1: the field mapping ──────────────────────────────────


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("source_ip", SRC_IP),
        ("dest_ip", DST_IP),
        ("source_port", SPORT),
        ("dest_port", DPORT),
        ("protocol", PROTO),
        ("bytes_in", D_OCTETS),
        ("packets", D_PKTS),
        ("bytes_out", 0),  # v5 is unidirectional
    ],
)
def test_every_v5_field_round_trips(field: str, expected: object) -> None:
    flow = nf._parse_v5(_v5_packet())[0]
    assert flow[field] == expected


def test_the_specific_values_the_old_indices_produced_are_gone() -> None:
    """
    Guard against a partial re-break. These are the exact wrong values the
    pre-fix indices yielded for this packet, so each assertion names a real
    regression rather than just "not equal to something".
    """
    flow = nf._parse_v5(_v5_packet())[0]
    assert flow["bytes_in"] != LAST, "bytes_in is reading the Last sysUptime again"
    assert flow["packets"] != FIRST, "packets is reading the First sysUptime again"
    assert flow["source_port"] != DPORT, "the ports are swapped again"
    assert flow["dest_port"] != 0, "dest_port is reading pad1 again"
    assert flow["protocol"] != TOS, "protocol is reading the ToS byte again"


def test_a_truncated_record_is_skipped_not_crashed() -> None:
    packet = _v5_packet()
    assert nf._parse_v5(packet[:-10]) == []


# ── Defect 2: heterogeneous insert batches ───────────────────────


def _row(**extra) -> dict:
    base = {
        "organization_id": uuid.uuid4(),
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "source_port": 1234,
        "dest_port": 443,
        "protocol": 6,
        "bytes_in": 100,
        "bytes_out": 0,
        "packets": 2,
        "bucket_time": datetime.now(UTC),
    }
    base.update(extra)
    return base


def _normalise(batch: list[dict]) -> list[dict]:
    """The normalisation _persist_batch performs before inserting."""
    keys: set[str] = set()
    for row in batch:
        keys.update(row)
    return [{k: row.get(k) for k in keys} for row in batch]


def _compiles(batch: list[dict]) -> bool:
    try:
        str(insert(FlowRecord).values(batch).compile(dialect=postgresql.dialect()))
        return True
    except Exception:
        return False


@pytest.mark.parametrize(
    "batch",
    [
        pytest.param([_row(), _row()], id="none-classified"),
        pytest.param([_row(app_name="https", app_category="web"), _row()], id="first-classified"),
        pytest.param([_row(), _row(app_name="https", app_category="web")], id="later-classified"),
        pytest.param(
            [
                _row(app_name="https", app_category="web"),
                _row(app_name="dns", app_category="infra"),
            ],
            id="all-classified",
        ),
    ],
)
def test_every_batch_shape_compiles_after_normalisation(batch: list[dict]) -> None:
    assert _compiles(_normalise(batch))


def test_first_classified_batch_used_to_fail_to_compile() -> None:
    """
    Negative control. Without normalisation this exact shape raises CompileError
    and the flush loop drops a whole minute of flows -- so the test above is not
    vacuous.
    """
    assert not _compiles([_row(app_name="https", app_category="web"), _row()])


def test_a_later_rows_classification_is_no_longer_discarded() -> None:
    """
    The quiet half. Un-normalised, this compiles fine and silently drops the
    second row's app_name -- data loss with no error anywhere.
    """
    batch = [_row(), _row(app_name="https", app_category="web")]

    raw_sql = str(insert(FlowRecord).values(batch).compile(dialect=postgresql.dialect()))
    assert "app_name" not in raw_sql, "precondition: un-normalised drops the column"

    fixed_sql = str(
        insert(FlowRecord).values(_normalise(batch)).compile(dialect=postgresql.dialect())
    )
    assert "app_name" in fixed_sql, "normalisation must preserve the classification"


def test_persist_batch_normalises() -> None:
    """Pin that the production path does this, not just the helper in this file."""
    import inspect

    src = inspect.getsource(nf.NetFlowReceiver._persist_batch)
    code = "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))
    assert "all_keys" in code, "_persist_batch no longer normalises the batch key set"
