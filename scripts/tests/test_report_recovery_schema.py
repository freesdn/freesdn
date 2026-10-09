"""The recovery CLI must qualify the exact image schema and every restored copy."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "check_report_recovery.py"


def run_fixture(tmp_path, monkeypatch, declared, installed):
    spec = importlib.util.spec_from_file_location("owned_recovery_schema", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    work = tmp_path / "owned-recovery"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--backend",
            "owned",
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
        data = b""
        if argv[1] == "image":
            data = ("sha256:" + "a" * 64 + "\n").encode()
        elif argv[1] == "exec":
            if argv[-2:] == ["id", "-u"]:
                data = b"1001\n"
            elif "ScriptDirectory" in argv[-1]:
                data = json.dumps(declared).encode()
            elif "psql" in argv:
                statement = kwargs.get("input", b"").decode()
                if "version_num" in statement:
                    database = argv[argv.index("-d") + 1]
                    data = installed.get(database, installed["freesdn"]).encode()
            elif (
                len(argv) >= 5
                and argv[1] == "exec"
                and argv[3:5] == ["python", "/tmp/report_recovery_probe.py"]
            ):
                data = b'REPORT_RECOVERY_RESULT={"passed": true}\n'
            elif "pg_dump" in argv:
                data = b"owned synthetic dump"
            elif "tar" in argv and "-cf" in argv:
                data = b"owned synthetic archive"
            elif "cat" in argv:
                data = b"{}"
        return subprocess.CompletedProcess(argv, 0, data, b"")

    monkeypatch.setattr(module.subprocess, "run", docker)
    return module, work, calls


@pytest.mark.parametrize(
    ("declared", "installed", "valid"),
    [
        (["020_inapp_event_outbox"], "020_inapp_event_outbox", True),
        (["021_future_revision"], "021_future_revision", True),
        (["018_report_recovery_epoch"], "018_report_recovery_epoch", True),
        (["020_inapp_event_outbox"], "018_report_recovery_epoch", False),
        ([], "018_report_recovery_epoch", False),
        (
            ["018_report_recovery_epoch", "019_other"],
            "018_report_recovery_epoch",
            False,
        ),
        ("018_report_recovery_epoch", "018_report_recovery_epoch", False),
        ({"head": "018_report_recovery_epoch"}, "018_report_recovery_epoch", False),
        ([None], "018_report_recovery_epoch", False),
        ([""], "018_report_recovery_epoch", False),
        (["x" * 33], "018_report_recovery_epoch", False),
        (["bad\nrevision"], "018_report_recovery_epoch", False),
        (
            ["020_inapp_event_outbox"],
            "020_inapp_event_outbox\n018_report_recovery_epoch",
            False,
        ),
        (["020_inapp_event_outbox"], "", False),
    ],
)
def test_cli_validates_the_actual_single_image_head_before_any_delivery(
    tmp_path, monkeypatch, declared, installed, valid
):
    module, work, calls = run_fixture(tmp_path, monkeypatch, declared, {"freesdn": installed})
    if valid:
        assert module.main() == 0
    else:
        with pytest.raises(AssertionError):
            module.main()
    report = json.loads((work / "report.json").read_text())
    assert report["passed"] is valid and report["owned_resources_removed"]
    probes = [
        argv
        for argv in calls
        if len(argv) >= 5
        and argv[1] == "exec"
        and argv[3:5] == ["python", "/tmp/report_recovery_probe.py"]
    ]
    if valid:
        assert len(probes) == 7
        assert report["database_revisions"] == dict.fromkeys(
            ["freesdn", "unsafe_restore", "missing_epoch", "safe_restore"], declared[0]
        )
    else:
        assert probes == []
    secrets = json.loads((work / "synthetic-secrets.json").read_text())
    assert not any(value in (work / "report.json").read_text() for value in secrets)


@pytest.mark.parametrize(
    ("database", "prior_probes"),
    [("unsafe_restore", 2), ("missing_epoch", 3), ("safe_restore", 4)],
)
def test_each_restored_database_must_match_before_running_its_mail_probe(
    tmp_path, monkeypatch, database, prior_probes
):
    # 018 is intentional: the old hardcoded initial gate accepts it, then
    # silently skips verification of the restored copy's schema.
    module, work, calls = run_fixture(
        tmp_path,
        monkeypatch,
        ["018_report_recovery_epoch"],
        {"freesdn": "018_report_recovery_epoch", database: "017_sla_report_delivery"},
    )
    with pytest.raises(AssertionError):
        module.main()
    report = json.loads((work / "report.json").read_text())
    assert report["passed"] is False and report["owned_resources_removed"]
    assert (
        len(
            [
                argv
                for argv in calls
                if len(argv) >= 5
                and argv[1] == "exec"
                and argv[3:5] == ["python", "/tmp/report_recovery_probe.py"]
            ]
        )
        == prior_probes
    )
