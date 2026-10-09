"""Bounded event/log admission, with explicit in-memory sinks for large inputs."""

import hashlib
import json

import pytest


def test_real_log_is_private_redacted_and_identified(attempt):
    value = b"prefix synthetic-password suffix\n"
    result = attempt.save_log("service.log", value, "synthetic-password")
    saved = attempt.path / result["path"]
    assert saved.read_bytes() == b"prefix [REDACTED] suffix\n"
    assert saved.stat().st_mode & 0o777 == 0o600
    assert result["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        attempt.save_log("service.log", b"replacement", "synthetic-password")
    assert saved.read_bytes() == b"prefix [REDACTED] suffix\n"


@pytest.mark.parametrize("name", ["../escape", "/absolute", "directory/file", "", ".", ".."])
def test_log_name_cannot_escape_its_owned_directory(attempt, name):
    with pytest.raises(ValueError):
        attempt.save_log(name, b"content", "synthetic-password")
    assert list((attempt.path / "logs").iterdir()) == []


def test_log_input_over_cap_is_refused_before_write(attempt, monkeypatch):
    writes = []
    monkeypatch.setattr(attempt, "_write", lambda *args: writes.append(len(args[-1])))
    with pytest.raises(ValueError):
        attempt.save_log("oversized.log", b"x" * (1024**2 + 1), "synthetic-password")
    assert writes == []


@pytest.mark.parametrize(
    "password", ["x", ""], ids=["short-redaction-marker", "empty-redaction-marker"]
)
def test_redaction_cannot_dispatch_over_cap_bytes(attempt, monkeypatch, password, record_property):
    writes = []
    monkeypatch.setattr(attempt, "_write", lambda *args: writes.append(len(args[-1])))
    try:
        with pytest.raises(ValueError):
            attempt.save_log("expansion.log", b"x" * 130000, password)
    finally:
        record_property("controlled_write_sink_lengths", json.dumps(writes))
    assert writes == []


def test_exact_log_input_cap_and_cumulative_cap_use_bounded_sink(
    attempt, monkeypatch, record_property
):
    writes = []
    monkeypatch.setattr(attempt, "_write", lambda *args: writes.append(len(args[-1])))
    data = b"x" * (1024**2)
    for index in range(16):
        result = attempt.save_log(f"log-{index}", data, "synthetic-password")
        assert result["bytes"] == len(data)
    with pytest.raises(ValueError):
        attempt.save_log("log-over", data, "synthetic-password")
    assert writes == [1024**2] * 16
    record_property("controlled_write_sink_lengths", json.dumps(writes))


def test_metadata_single_record_refuses_oversize_without_partial_file(attempt):
    attempt.record("case", name="x" * 63000)
    with pytest.raises(ValueError):
        attempt.record("case", name="x" * 65536)
    assert len(list((attempt.path / "events").iterdir())) == 1
    assert (attempt.path / "events/000-case.json").stat().st_size < 65536


def test_cumulative_metadata_budget_prevents_dispatch_to_bounded_sink(
    attempt, monkeypatch, record_property
):
    written = []
    initial = (attempt.path / "intent.json").stat().st_size
    monkeypatch.setattr(attempt, "_write", lambda *args: written.append(len(args[-1])))
    for _ in range(100):
        try:
            attempt.record("case", name="x" * 63000)
        except ValueError as exc:
            assert "metadata budget" in str(exc)
            break
    else:
        pytest.fail("metadata budget was not enforced")
    assert initial + sum(written) <= 2 * 1024**2
    assert initial + sum(written) + min(written) > 2 * 1024**2
    record_property("controlled_metadata_sink_lengths", json.dumps(written))


def test_actual_event_count_limit_preserves_all_previous_records(attempt):
    for index in range(128):
        attempt.record("case", name=f"event-{index}")
    files = sorted((attempt.path / "events").iterdir())
    previous = {p.name: p.read_bytes() for p in files}
    assert len(previous) == 128
    with pytest.raises(ValueError):
        attempt.record("case", name="over-limit")
    assert {p.name: p.read_bytes() for p in (attempt.path / "events").iterdir()} == previous
