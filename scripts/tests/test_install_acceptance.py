"""Keep a qualification mistake from mounting customer data or publishing ports."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("duration", ["-1", "1", "59", "1801", "999999"])
def test_unbounded_or_too_short_soak_refused(module, duration):
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        module.soak_duration(duration)


@pytest.fixture
def module(monkeypatch):
    scripts = Path(__file__).parents[1]
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "install_acceptance", scripts / "check_install_acceptance.py"
    )
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture
def plan(module):
    return {
        "services": {
            name: {"image": "sha256:fixture", "volumes": []} for name in module.SERVICES
        },
        "networks": {"default": {"internal": True}},
        "volumes": {"fixture": {}},
    }


@pytest.mark.parametrize(
    "mutation",
    [
        ("ports", ["8000:8000"]),
        ("privileged", True),
        ("devices", ["/dev/net/tun"]),
        ("network_mode", "host"),
        ("image", "moving-tag:latest"),
        ("build", {"context": "."}),
    ],
)
def test_unsafe_service_configurations_refused(module, plan, tmp_path, mutation):
    plan["services"]["api"][mutation[0]] = mutation[1]
    with pytest.raises(ValueError):
        module.validate_plan(plan, tmp_path, tmp_path, {"backend": "sha256:fixture"})


@pytest.mark.parametrize(
    "unsafe",
    [
        "external",
        "host-volume",
        "external-network",
        "extra-service",
        "outside-file",
        "writable-bind",
        "missing-bind",
    ],
)
def test_host_access_and_foreign_resources_refused(module, plan, tmp_path, unsafe):
    root = tmp_path / "source"
    root.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    path = root / "public.conf"
    path.write_text("fixture")
    if unsafe == "external":
        plan["volumes"]["fixture"]["external"] = True
    elif unsafe == "host-volume":
        plan["volumes"]["fixture"]["driver_opts"] = {"device": "/"}
    elif unsafe == "external-network":
        plan["networks"]["default"]["internal"] = False
    elif unsafe == "extra-service":
        plan["services"]["unknown"] = {}
    else:
        if unsafe == "outside-file":
            path = tmp_path / "outside"
            path.write_text("private")
        elif unsafe == "missing-bind":
            path = root / "absent"
        plan["services"]["api"]["volumes"] = [
            {
                "type": "bind",
                "source": str(path),
                "read_only": unsafe != "writable-bind",
            }
        ]
    with pytest.raises(ValueError):
        module.validate_plan(plan, root, work, {"backend": "sha256:fixture"})


def test_engine_failure_preserves_partial_private_receipt(
    module, monkeypatch, tmp_path
):
    work = tmp_path / "private"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check",
            "--work-dir",
            str(work),
            "--source",
            str(tmp_path),
            *[
                item
                for name in ("backend", "postgres", "logdb", "valkey", "edge")
                for item in ("--" + name, "fixture")
            ],
        ],
    )

    def unavailable(*args, **kwargs):
        raise OSError("fixture engine unavailable")

    monkeypatch.setattr(module.subprocess, "run", unavailable)
    with pytest.raises(OSError):
        module.main()
    report = json.loads((work / "report.json").read_text())
    assert report["passed"] is False
    assert report["failure_type"] == "OSError"
    assert report["owned_resources_removed"] is True
    assert work.stat().st_mode & 0o777 == 0o700
    assert (work / "report.json").stat().st_mode & 0o777 == 0o600


def test_existing_work_directory_is_untouched(module, monkeypatch, tmp_path):
    sentinel = tmp_path / "keep"
    sentinel.write_text("private")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check",
            "--work-dir",
            str(tmp_path),
            "--source",
            str(tmp_path),
            *[
                item
                for name in ("backend", "postgres", "logdb", "valkey", "edge")
                for item in ("--" + name, "fixture")
            ],
        ],
    )
    with pytest.raises(SystemExit):
        module.main()
    assert sentinel.read_text() == "private"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep"]


@pytest.fixture
def policy_state():
    policies = ["policy_compression"] * 4 + ["policy_retention"] * 4 + [
        "policy_refresh_continuous_aggregate"
    ] * 3
    return {
        "settings": {
            "max_worker_processes": "32",
            "timescaledb.max_background_workers": "16",
            "max_parallel_workers": "8",
        },
        "jobs": [
            {
                "job_id": index + 1000,
                "proc_name": name,
                "scheduled": True,
                "last_run_status": "Success",
                "total_runs": 1,
                "total_successes": 1,
                "total_failures": 0,
            }
            for index, name in enumerate(policies)
        ],
    }


def test_default_postgres_pool_cannot_hide_failed_maintenance(module, policy_state):
    policy_state["settings"]["max_worker_processes"] = "8"
    with pytest.raises(ValueError, match="worker pool"):
        module.logdb_policies_ready(policy_state)


def test_scheduled_policy_completion_is_required(module, policy_state):
    assert module.logdb_policies_ready(policy_state)
    job = policy_state["jobs"][0]
    job.update(last_run_status=None, total_runs=None, total_successes=None,
               total_failures=None)
    assert module.logdb_policies_ready(policy_state) is False


@pytest.mark.parametrize("mutation", [
    "missing", "extra", "duplicate", "wrong-kind", "disabled", "failed",
    "recovered-failure", "inconsistent", "negative", "boolean-count",
    "string-count", "disabled-workers", "parallel-starvation",
])
def test_incomplete_or_unhealthy_maintenance_refused(module, policy_state, mutation):
    job = policy_state["jobs"][0]
    if mutation == "missing":
        policy_state["jobs"].pop()
    elif mutation == "extra":
        policy_state["jobs"].append(dict(job))
    elif mutation == "duplicate":
        policy_state["jobs"][1]["job_id"] = job["job_id"]
    elif mutation == "wrong-kind":
        job["proc_name"] = "policy_telemetry"
    elif mutation == "disabled":
        job["scheduled"] = False
    elif mutation == "failed":
        job["last_run_status"] = "Failed"
    elif mutation == "recovered-failure":
        job.update(total_runs=2, total_failures=1)
    elif mutation == "inconsistent":
        job["total_runs"] = 3
    elif mutation == "negative":
        job["total_successes"] = -1
    elif mutation == "boolean-count":
        job["total_successes"] = True
    elif mutation == "string-count":
        job["total_successes"] = "1"
    elif mutation == "disabled-workers":
        policy_state["settings"]["timescaledb.max_background_workers"] = "0"
    elif mutation == "parallel-starvation":
        policy_state["settings"]["max_parallel_workers"] = "32"
    with pytest.raises(ValueError):
        module.logdb_policies_ready(policy_state)
