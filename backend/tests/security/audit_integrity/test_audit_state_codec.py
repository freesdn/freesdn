"""Reject malformed/tampered local seals without importing global application keys."""
from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.audit_state import INITIAL_STATE, MAX_REVISION, decode_state, encode_state, sign_state


def value():
    point = {"id": str(uuid4()), "sequence": 1, "timestamp": datetime.now(UTC).isoformat(), "hash": "a" * 64}
    return {"v": 1, "epoch": str(uuid4()), "tail": point, "boundary": None,
            "live_rows": 1, "legacy_rows": 0, "unsigned_history_rows": 0}


@pytest.mark.parametrize("part", ["bytes", "revision", "key", "signature"])
async def test_seal_binds_domain_revision_key_and_exact_bytes(part):
    key = b"owned-codec-synthetic-key"
    data = encode_state(value())
    signature = sign_state(1, data, key)
    args = [1, data, signature, key]
    if part == "bytes":
        args[1] = data.replace(b'"live_rows":1', b'"live_rows":2')
    elif part == "revision":
        args[0] = 2
    elif part == "key":
        args[3] = b"different-owned-key"
    else:
        args[2] = "b" * 64
    with pytest.raises(ValueError):
        decode_state(*args)
    assert decode_state(1, data, signature, key) is not None


@pytest.mark.parametrize("field,bad", [
    ("live_rows", -1), ("live_rows", True), ("live_rows", MAX_REVISION + 1),
    ("legacy_rows", 2), ("unsigned_history_rows", -1), ("v", True), ("v", 2),
    ("epoch", "bad"), ("epoch", None), ("tail", None), ("live_rows", 0),
], ids=["negative", "boolean", "overflow", "legacy_count", "unsigned_count", "boolean_version",
        "unknown_version", "bad_epoch", "null_epoch", "missing_tail", "missing_boundary"])
async def test_invalid_state_contract_refused(field, bad):
    state = value()
    state[field] = bad
    with pytest.raises(ValueError):
        encode_state(state)


@pytest.mark.parametrize("field,bad", [
    ("sequence", 0), ("sequence", True), ("sequence", MAX_REVISION + 1), ("hash", None),
    ("hash", "A" * 64), ("hash", "a" * 63), ("id", "bad"),
    ("timestamp", "2026-01-01T00:00:00"), ("timestamp", "2026-01-01T00:00:00+01:00"),
], ids=["zero_sequence", "bool_sequence", "overflow_sequence", "missing_hash", "uppercase_hash",
        "short_hash", "bad_identity", "naive_time", "noncanonical_time"])
async def test_invalid_signed_position_refused(field, bad):
    state = value()
    state["tail"][field] = bad
    with pytest.raises(ValueError):
        encode_state(state)


@pytest.mark.parametrize("mutation", ["duplicate", "whitespace", "unknown", "oversize"])
async def test_valid_hmac_does_not_excuse_malformed_serialization(mutation):
    key = b"owned-codec-synthetic-key"
    data = encode_state(value())
    if mutation == "duplicate":
        data = data.replace(b'{', b'{"v":1,', 1)
    elif mutation == "whitespace":
        data += b" "
    elif mutation == "unknown":
        data = data.replace(b'{', b'{"unknown":1,', 1)
    else:
        data += b" " * 8192
    if mutation == "oversize":
        with pytest.raises(ValueError):
            sign_state(1, data, key)
        with pytest.raises(ValueError):
            decode_state(1, data, "a" * 64, key)
    else:
        with pytest.raises(ValueError):
            decode_state(1, data, sign_state(1, data, key), key)


async def test_empty_retained_history_still_preserves_old_unsigned_disclosure():
    state = value()
    state["boundary"] = deepcopy(state["tail"])
    state["live_rows"] = 0
    state["unsigned_history_rows"] = 12
    key = b"owned-codec-synthetic-key"
    data = encode_state(state)
    assert decode_state(9, data, sign_state(9, data, key), key) == state
    assert decode_state(0, INITIAL_STATE, None, key) is None
    with pytest.raises(ValueError):
        decode_state(1, INITIAL_STATE, None, key)
