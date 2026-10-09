"""Adversarial backup-rehearsal safety tests; no Docker daemon required."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "check_queue_backup_recovery.py"


def module():
    spec = importlib.util.spec_from_file_location("queue_backup", SCRIPT)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def bundle():
    return {
        "appendonlydir/appendonly.aof.manifest": b"file appendonly.aof.1.base.rdb seq 1 type b\nfile appendonly.aof.1.incr.aof seq 1 type i\n",
        "appendonlydir/appendonly.aof.1.base.rdb": b"fixture base",
        "appendonlydir/appendonly.aof.1.incr.aof": b"fixture increment",
    }


@pytest.mark.parametrize(
    "change",
    [
        "missing-increment",
        "unlisted-file",
        "duplicate",
        "traversal",
        "type",
        "only-increment",
        "non-ascii",
        "empty",
    ],
)
def test_unsafe_or_incomplete_multipart_bundles_refused(change):
    tool, files = module(), bundle()
    manifest = "appendonlydir/appendonly.aof.manifest"
    if change == "missing-increment":
        del files["appendonlydir/appendonly.aof.1.incr.aof"]
    elif change == "unlisted-file":
        files["appendonlydir/unlisted.aof"] = b"other data"
    elif change == "duplicate":
        files[manifest] += files[manifest].splitlines(keepends=True)[-1]
    elif change == "traversal":
        files[manifest] = files[manifest].replace(
            b"appendonly.aof.1.base.rdb", b"../escape.rdb"
        )
    elif change == "type":
        files[manifest] = files[manifest].replace(b"type b", b"type i")
    elif change == "only-increment":
        files[manifest] = files[manifest].splitlines(keepends=True)[-1]
    elif change == "non-ascii":
        files[manifest] = b"\xff"
    else:
        files["appendonlydir/appendonly.aof.1.base.rdb"] = b""
    with pytest.raises(ValueError):
        tool.validate_bundle(files, "aof")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "path", "duplicate"])
def test_tar_never_extracts_links_traversal_or_duplicate_members(kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo("../escape" if kind == "path" else "dump.rdb")
        if kind in ("symlink", "hardlink"):
            entry.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            entry.linkname = "/etc/passwd"
        archive.addfile(entry)
        if kind == "duplicate":
            archive.addfile(entry)
    with pytest.raises(ValueError):
        module().unpack_fixture_tar(stream.getvalue())


def snapshot(*rows):
    return {"keys": len(rows), "rows": list(rows)}


def row(**kwargs):
    return {
        "db": 1,
        "key_b64": "ZGVmYXVsdA==",
        "type": "list",
        "value_sha256": "digest-in-order",
        "expires_at_ms": -1,
        **kwargs,
    }


@pytest.mark.parametrize("changed", ["value_sha256", "type", "expires_at_ms", "db"])
def test_changed_value_order_type_expiry_or_database_refused(changed):
    tool = module()
    before = row()
    after = {**before, changed: "different"}
    with pytest.raises(ValueError):
        tool.compare_snapshot(snapshot(before), snapshot(after), 10000)


def test_empty_or_extra_data_never_qualifies_as_successful_restore():
    tool = module()
    with pytest.raises(ValueError, match="restored_key_missing"):
        tool.compare_snapshot(snapshot(row()), snapshot(), 10000)
    with pytest.raises(ValueError, match="unexpected_restored_key"):
        tool.compare_snapshot(snapshot(), snapshot(row()), 10000)


def test_expired_keys_explicitly_counted_but_early_or_persistent_loss_refused():
    tool = module()
    result = tool.compare_snapshot(snapshot(row(expires_at_ms=100)), snapshot(), 101)
    assert result == {"expected_keys": 1, "restored_keys": 0, "expired_keys": 1}
    for expiry in (-1, 200):
        with pytest.raises(ValueError):
            tool.compare_snapshot(snapshot(row(expires_at_ms=expiry)), snapshot(), 101)


@pytest.mark.parametrize("failure", ["image", "copy", "cleanup", "ownership"])
def test_engine_failures_leave_private_incomplete_receipt_and_only_owned_cleanup(
    tmp_path, monkeypatch, failure
):
    tool = module()
    work = tmp_path / "work"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--backend-image",
            "backend",
            "--valkey-image",
            "valkey",
            "--work-dir",
            str(work),
        ],
    )
    calls, name, owner = [], None, None
    secret = "must-not-appear-in-public-receipt"

    def docker(argv, **kwargs):
        nonlocal name, owner
        calls.append(argv)
        command = argv[1]
        if command == "image":
            if failure == "image":
                raise OSError(secret)
            return subprocess.CompletedProcess(
                argv, 0, ("sha256:" + "a" * 64).encode(), b""
            )
        if command == "run":
            name = argv[argv.index("--name") + 1]
            owner = next(
                arg.split("=", 1)[1] for arg in argv if arg.startswith(tool.OWNER + "=")
            )
            assert "--network=none" in argv and "--read-only" in argv
            assert not any(
                arg in ("-v", "--volume", "--privileged", "-p") for arg in argv
            )
            return subprocess.CompletedProcess(argv, 0, ("b" * 64).encode(), b"")
        if command == "exec":
            assert json.loads((work / "report.json").read_text())["passed"] is False
            raise subprocess.TimeoutExpired(argv, 1, output=secret.encode())
        if command == "inspect":
            if failure == "cleanup":
                raise OSError(secret)
            result = {
                "Id": "b" * 64,
                "Config": {
                    "Labels": {
                        tool.OWNER: "someone-else" if failure == "ownership" else owner
                    }
                },
            }
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([result]).encode(), b""
            )
        if command == "rm":
            assert argv[-1] == "b" * 64
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError("Unexpected command")

    monkeypatch.setattr(tool.subprocess, "run", docker)
    assert tool.main() == 2
    raw = (work / "report.json").read_text()
    report = json.loads(raw)
    assert not report["passed"] and not report["production_replay_authorized"]
    assert secret not in raw
    assert report["cleanup_complete"] is (failure in ("image", "copy"))
    assert [argv[-1] for argv in calls if argv[1] == "rm"] == (
        ["b" * 64] if failure == "copy" else []
    )
    assert all(p.stat().st_mode & 0o077 == 0 for p in work.iterdir())
    if failure in ("cleanup", "ownership"):
        assert json.loads((work / "cleanup-required.json").read_text()) == {
            name: "b" * 64
        }


def test_optimized_python_cannot_skip_qualification_assertions(tmp_path):
    response = subprocess.run(
        [
            sys.executable,
            "-O",
            str(SCRIPT),
            "--backend-image",
            "unused",
            "--valkey-image",
            "unused",
            "--work-dir",
            str(tmp_path / "unused"),
        ],
        capture_output=True,
        check=False,
    )
    assert (
        response.returncode != 0 and b"without Python optimization" in response.stderr
    )
    assert not (tmp_path / "unused").exists()
