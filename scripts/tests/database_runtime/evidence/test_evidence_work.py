"""Native retained-file hashing, refusal controls and bounded tree traversal."""

import hashlib
import os
import socket
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("count", [0, 1, 64])
def test_real_work_manifest_hashes_exact_small_files(attempt, count):
    expected = {}
    for index in range(count):
        value = f"owned-data-{index}".encode()
        path = attempt.work / f"data-{index:03d}"
        path.write_bytes(value)
        expected[path.name] = (len(value), hashlib.sha256(value).hexdigest())
    result = attempt.work_manifest()
    assert {r["path"]: (r["bytes"], r["sha256"]) for r in result["files"]} == expected
    assert result["bytes"] == sum(x[0] for x in expected.values())


def test_more_than_sixty_four_work_files_are_refused(attempt):
    for index in range(65):
        (attempt.work / f"data-{index:03d}").write_bytes(b"x")
    with pytest.raises(ValueError):
        attempt.work_manifest()
    assert len(list(attempt.work.iterdir())) == 65


@pytest.mark.parametrize("kind", ["symlink", "fifo", "socket", "hardlink"])
def test_nonregular_or_shared_work_file_is_refused_without_following(attempt, kind, monkeypatch):
    target = attempt.work / "target"
    sentinel = attempt.report.parent / "unrelated"
    sentinel.write_bytes(b"preserve-unrelated")
    peer = None
    if kind == "symlink":
        target.symlink_to(sentinel)
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "socket":
        peer = socket.socket(socket.AF_UNIX)
        monkeypatch.chdir(attempt.work)
        peer.bind("target")
    else:
        os.link(sentinel, target)
    try:
        with pytest.raises((ValueError, RuntimeError)):
            attempt.work_manifest()
    finally:
        if peer is not None:
            peer.close()
    assert sentinel.read_bytes() == b"preserve-unrelated"


def test_oversized_sparse_work_is_refused_without_hash_dispatch(
    attempt, monkeypatch, evidence, record_property
):
    path = attempt.work / "sparse"
    with path.open("wb") as stream:
        stream.truncate(64 * 1024**2 + 1)
    calls = []
    monkeypatch.setattr(evidence, "operate", lambda *_args, **_kwargs: calls.append(True))
    try:
        record_property("actual_owned_sparse_size_before_cleanup", path.stat().st_size)
        with pytest.raises(ValueError):
            attempt.work_manifest()
        assert calls == []
    finally:
        # Deliberate fixture cleanup: preserve size/call observation, not a64MiB
        # sparse all-zero input in the bounded artifact copier.
        path.unlink()


def test_expired_empty_manifest_is_refused_before_any_scan(evidence, tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(evidence, "time", SimpleNamespace(monotonic=lambda: now[0]))
    item = evidence.FixtureAttempt(tmp_path / "result.json", work_seconds=1)
    try:
        now[0] = 102
        with pytest.raises(TimeoutError):
            item.work_manifest()
    finally:
        item.close()


def test_retained_tree_has_a_finite_entry_budget(attempt, record_property):
    for index in range(129):
        (attempt.work / f"empty-{index:03d}").mkdir()
    record_property("actual_empty_directory_count", len(list(attempt.work.iterdir())))
    with pytest.raises(ValueError):
        attempt.work_manifest()
    assert len(list(attempt.work.iterdir())) == 129
