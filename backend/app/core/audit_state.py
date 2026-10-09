# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded canonical local audit-state codec; no database or global key access."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Literal, TypedDict, cast
from uuid import UUID

MAX_REVISION = 2**63 - 1
INITIAL_STATE = b'{"state":"uninitialized","v":1}'
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class AuditPosition(TypedDict):
    id: str
    sequence: int | None
    timestamp: str
    hash: str | None


class AuditState(TypedDict):
    v: Literal[1]
    epoch: str
    tail: AuditPosition | None
    boundary: AuditPosition | None
    live_rows: int
    legacy_rows: int
    unsigned_history_rows: int


def _integer(value: object, *, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= MAX_REVISION:
        raise ValueError("Invalid audit state integer")


def _uuid(value: object) -> None:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Invalid audit state identity")


def position_key(position: AuditPosition) -> tuple[int, datetime, str]:
    return (
        position["sequence"] or 0,
        datetime.fromisoformat(position["timestamp"]),
        position["id"],
    )


def validate_position(position: object) -> None:
    if type(position) is not dict or set(position) != {"id", "sequence", "timestamp", "hash"}:
        raise ValueError("Invalid audit state position")
    _uuid(position["id"])
    sequence = position["sequence"]
    if sequence is not None:
        _integer(sequence, minimum=1)
    stamp = position["timestamp"]
    if not isinstance(stamp, str) or len(stamp) > 40:
        raise ValueError("Invalid audit state timestamp")
    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None or parsed.astimezone(UTC).isoformat() != stamp:
        raise ValueError("Audit state timestamp is not canonical UTC")
    signature = position["hash"]
    if signature is None:
        if sequence is not None:
            raise ValueError("Unsigned sequenced audit position")
    elif not isinstance(signature, str) or _HEX.fullmatch(signature) is None:
        raise ValueError("Invalid audit position signature")


def validate_state(state: object) -> None:
    keys = {"v", "epoch", "tail", "boundary", "live_rows", "legacy_rows", "unsigned_history_rows"}
    if (
        type(state) is not dict
        or set(state) != keys
        or type(state["v"]) is not int
        or state["v"] != 1
    ):
        raise ValueError("Invalid audit state format")
    _uuid(state["epoch"])
    for name in ("live_rows", "legacy_rows", "unsigned_history_rows"):
        _integer(state[name])
    if state["legacy_rows"] > state["live_rows"]:
        raise ValueError("Invalid legacy audit count")
    tail, boundary = state["tail"], state["boundary"]
    for position in (tail, boundary):
        if position is not None:
            validate_position(position)
    if tail is None and (state["live_rows"] or boundary is not None):
        raise ValueError("Missing audit tail")
    if boundary is not None and position_key(boundary) > position_key(tail):
        raise ValueError("Audit boundary follows tail")
    if not state["live_rows"] and tail != boundary:
        raise ValueError("Empty retained audit chain has no matching boundary")
    if state["live_rows"] and boundary is not None and position_key(boundary) >= position_key(tail):
        raise ValueError("Retained audit tail does not follow boundary")


def encode_state(state: object) -> bytes:
    validate_state(state)
    data = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > 8192:
        raise ValueError("Audit state exceeds bound")
    return data


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate audit state field")
        result[key] = value
    return result


def sign_state(revision: int, data: bytes, key: bytes) -> str:
    _integer(revision, minimum=1)
    if not isinstance(data, bytes) or not 1 <= len(data) <= 8192 or not key:
        raise ValueError("Invalid audit state signing input")
    message = b"freesdn.audit.chain-state.v1:" + str(revision).encode("ascii") + b":" + data
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def decode_state(
    revision: int, data: bytes, signature: str | None, key: bytes
) -> AuditState | None:
    _integer(revision)
    if not isinstance(data, bytes) or not 1 <= len(data) <= 8192:
        raise ValueError("Invalid audit state bytes")
    if revision == 0 and data == INITIAL_STATE and signature is None:
        return None
    if not isinstance(signature, str) or _HEX.fullmatch(signature) is None:
        raise ValueError("Invalid audit state signature")
    if not hmac.compare_digest(sign_state(revision, data, key), signature):
        raise ValueError("Audit state signature mismatch")
    state = json.loads(data, object_pairs_hook=_pairs)
    if encode_state(state) != data:
        raise ValueError("Audit state is not canonical")
    # encode_state above checked the complete shape, scalar bounds and canonical
    # encoding. The JSON decoder is the only untyped boundary here.
    return cast(AuditState, state)
