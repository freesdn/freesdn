"""Safety boundaries for the offline legacy queue inventory command."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "inventory_legacy_queues.py"


def module():
    spec = importlib.util.spec_from_file_location("queue_inventory", SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def source():
    return {
        "Id": "a" * 64,
        "Image": "sha256:" + "b" * 64,
        "State": {"Running": True, "StartedAt": "fixture-start"},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True},
        "Config": {"Labels": {"freesdn.queue-inventory.disposable-copy": "true"}},
        "NetworkSettings": {"Ports": {"6379/tcp": None}, "Networks": {"none": {}}},
        "Mounts": [{"Type": "volume", "Destination": "/data", "RW": False}],
    }


@pytest.mark.parametrize(
    "path,value,reason",
    [
        (("HostConfig", "NetworkMode"), "bridge", "source_not_network_isolated"),
        (
            ("HostConfig", "PortBindings"),
            {"6379/tcp": [{"HostPort": "6379"}]},
            "source_not_network_isolated",
        ),
        (
            ("NetworkSettings", "Networks"),
            {"none": {}, "live": {}},
            "source_not_network_isolated",
        ),
        (("HostConfig", "ReadonlyRootfs"), False, "source_container_not_restricted"),
        (("HostConfig", "Privileged"), True, "source_container_not_restricted"),
        (
            ("HostConfig", "RestartPolicy"),
            {"Name": "always"},
            "source_container_not_restricted",
        ),
        (("Config", "Labels"), {}, "source_not_marked_disposable_copy"),
        (
            ("Config", "Healthcheck"),
            {"Test": ["CMD", "writer"]},
            "source_healthcheck_enabled",
        ),
        (("State", "Running"), False, "source_not_running"),
        (("State", "Paused"), True, "source_not_running"),
    ],
)
def test_unsafe_source_refused(path, value, reason):
    tool, info = module(), source()
    info[path[0]][path[1]] = value
    with pytest.raises(tool.Refusal, match=reason):
        tool.validate_source(info)


def test_persistent_writes_refused_but_read_only_backups_and_tmpfs_supported():
    tool, info = module(), source()
    tool.validate_source(info)
    info["Mounts"][0]["RW"] = True
    with pytest.raises(tool.Refusal, match="source_has_writable_persistent_mount"):
        tool.validate_source(info)
    info["Mounts"][0]["Type"] = "tmpfs"
    tool.validate_source(info)


@pytest.mark.parametrize("failure_point", ["inspect", "start", "cleanup"])
def test_engine_failure_leaves_private_incomplete_receipt(
    tmp_path, monkeypatch, failure_point
):
    tool = module()
    work = tmp_path / "run"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--source-container",
            "source",
            "--backend-image",
            "trusted",
            "--work-dir",
            str(work),
        ],
    )
    calls = []
    name = None
    info = source()
    secret = "fixture-credential-must-never-be-in-receipt"

    def docker(argv, **kwargs):
        nonlocal name
        calls.append(argv)
        if argv[1] == "inspect":
            if failure_point == "inspect":
                raise OSError(secret)
            if argv[-1] in ("source", info["Id"]):
                payload = info
            else:
                if failure_point == "cleanup":
                    raise OSError(secret)
                payload = {
                    "Id": "c" * 64,
                    "Config": {"Labels": {tool.OWNER_LABEL: name}},
                }
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([payload]).encode(), b""
            )
        if argv[1] == "image":
            return subprocess.CompletedProcess(
                argv, 0, ("sha256:" + "d" * 64).encode(), b""
            )
        if argv[1] == "create":
            name = argv[argv.index("--name") + 1]
            return subprocess.CompletedProcess(argv, 0, ("c" * 64).encode(), b"")
        if argv[1] == "start":
            # This receipt already exists even if the process/engine disappears.
            assert (
                json.loads((work / "receipt.json").read_text())["inventory_complete"]
                is False
            )
            raise subprocess.TimeoutExpired(argv, 1, output=secret.encode())
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(tool.subprocess, "run", docker)
    assert tool.main() == 2
    receipt_text = (work / "receipt.json").read_text()
    receipt = json.loads(receipt_text)
    assert not receipt["inventory_complete"] and not receipt["replay_authorized"]
    assert receipt["probe_removed"] is (failure_point != "cleanup")
    assert secret not in receipt_text
    assert all(p.stat().st_mode & 0o077 == 0 for p in work.iterdir())
    assert not any(argv[1] in ("exec", "network", "volume") for argv in calls)
    removed = [argv[-1] for argv in calls if argv[1] == "rm"]
    assert removed == (["c" * 64] if failure_point == "start" else [])


@pytest.mark.parametrize("mode", ["world-readable", "symlink", "directory", "fifo"])
def test_bad_auth_file_refused_before_docker(tmp_path, monkeypatch, mode):
    import os

    tool = module()
    auth = tmp_path / "auth.json"
    if mode == "directory":
        auth.mkdir()
    elif mode == "fifo":
        os.mkfifo(auth, mode=0o600)
    elif mode == "symlink":
        target = tmp_path / "target"
        target.write_text('{"password":"private"}')
        target.chmod(0o600)
        auth.symlink_to(target)
    else:
        auth.write_text('{"password":"private"}')
        auth.chmod(0o644)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--source-container",
            "source",
            "--backend-image",
            "trusted",
            "--auth-file",
            str(auth),
            "--work-dir",
            str(tmp_path / "run"),
        ],
    )

    def unexpected(*args, **kwargs):
        raise AssertionError("Docker should not be called")

    monkeypatch.setattr(tool.subprocess, "run", unexpected)
    assert tool.main() == 2
    assert not json.loads((tmp_path / "run/receipt.json").read_text())[
        "inventory_complete"
    ]


def test_namespace_peer_resolved_by_container_id_even_when_named_differently(
    tmp_path, monkeypatch
):
    tool = module()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--source-container",
            "source-alias",
            "--backend-image",
            "trusted",
            "--work-dir",
            str(tmp_path / "run"),
        ],
    )
    calls = []

    def docker(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "ps":
            payload = b"peer-id\n"
        elif argv[1:3] == ["inspect", "--format={{.HostConfig.NetworkMode}}"]:
            payload = b"container:a-different-source-alias\n"
        else:
            payload = json.dumps([source()]).encode()
        return subprocess.CompletedProcess(argv, 0, payload, b"")

    monkeypatch.setattr(tool.subprocess, "run", docker)
    assert tool.main() == 2
    receipt = json.loads((tmp_path / "run/receipt.json").read_text())
    assert receipt["failure_code"] == "source_has_network_namespace_peer"
    assert not any(argv[1] in ("create", "start", "rm") for argv in calls)


def test_qualification_refuses_optimized_python(tmp_path):
    script = SCRIPT.parent / "check_queue_inventory.py"
    work = tmp_path / "should-not-exist"
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            str(script),
            "--backend-image",
            "unused",
            "--valkey-image",
            "unused",
            "--work-dir",
            str(work),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert "without Python optimization" in result.stderr
    assert not work.exists()
