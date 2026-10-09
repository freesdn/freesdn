"""An unavailable Docker engine must leave a usable partial recovery receipt."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "check_report_recovery.py"


@pytest.mark.parametrize("cleanup_available", [False, True])
def test_partial_failure_reports_every_owned_resource(
    tmp_path, monkeypatch, cleanup_available
):
    spec = importlib.util.spec_from_file_location("report_recovery_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    work = tmp_path / "private-run"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--backend",
            "new",
            "--postgres",
            "pg",
            "--valkey",
            "vk",
            "--work-dir",
            str(work),
        ],
    )
    calls = []

    def docker(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "image":
            return subprocess.CompletedProcess(
                argv, 0, b"sha256:synthetic-image\n", b""
            )
        if argv[1:3] == ["network", "create"]:
            return subprocess.CompletedProcess(argv, 0, b"synthetic-network\n", b"")
        if argv[1] == "run":
            raise OSError("Synthetic lost engine during fixture start")
        if not cleanup_available:
            raise OSError("Synthetic engine still unavailable during cleanup")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(module.subprocess, "run", docker)
    with pytest.raises(OSError):
        module.main()
    report = json.loads((work / "report.json").read_text())
    assert report["passed"] is False
    assert report["failure_type"] == "OSError"
    assert report["owned_resources_removed"] is cleanup_available
    assert {item["kind"] for item in report["cleanup"]} == {"container", "network"}
    assert all(
        item["name"].startswith("freesdn-report-recovery-")
        for item in report["cleanup"]
    )
    assert any(argv[1] == "rm" for argv in calls)
    assert any(argv[1:3] == ["network", "rm"] for argv in calls)
    secrets = json.loads((work / "synthetic-secrets.json").read_text())
    assert not any(value in (work / "report.json").read_text() for value in secrets)
