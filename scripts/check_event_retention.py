#!/usr/bin/env python3
"""Qualify bounded retention against fresh TimescaleDB with no published ports.

Uses only already-present image IDs, an internal network, and tmpfs database
storage. No production URLs, existing databases or volumes are accepted.
--work-dir must be NEW, absolute and on a POSIX filesystem enforcing 0700/0600.
Only report.json is shareable; generated env and raw failure logs are private.
"""

import argparse
import json
import math
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

from qualification.bounded_command import capture_command
from qualification.owned_resources import (
    cleanup_resources,
    inspect_owned,
    plan_resource,
    remember_identity,
)


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--backend", required=True)
    parser.add_argument("--logdb", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir
    if (
        os.name != "posix"
        or not work.is_absolute()
        or work.exists()
        or work.is_symlink()
    ):
        parser.error("work-dir must be a new absolute private POSIX directory")
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error("filesystem must enforce private directory permissions")
    os.umask(0o077)
    prefix = "freesdn-retention-" + uuid.uuid4().hex[:12]
    resources, failures = [], []
    report = {
        "passed": False,
        "published_ports": False,
        "hardware_access": False,
        "existing_volumes_used": False,
        "scope": "synthetic event retention, not production capacity or soak",
    }

    def private(name, data):
        with (work / name).open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            if os.fstat(stream.fileno()).st_mode & 0o077:
                raise RuntimeError("filesystem cannot protect fixture secrets")
            stream.write(data)

    def command(*args, check=True, timeout=120, deadline=None):
        # This wrapper captures small engine metadata/probe responses. Database
        # SQL/dump/restore streaming uses a separate path and needs its own bounds.
        if not args:
            raise ValueError("A metadata command is required")
        for value in (timeout,) if deadline is None else (timeout, deadline):
            if type(value) not in (int, float):
                raise ValueError("Finite command timeout and deadline required")
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError("Finite command timeout and deadline required")
        if timeout <= 0 or timeout > 360:
            raise ValueError("Finite positive command timeout within 360 seconds required")
        command_deadline = time.monotonic() + timeout
        if deadline is not None:
            command_deadline = min(command_deadline, deadline)
        argv = [args_docker, *args]
        captured = capture_command(
            argv, deadline=command_deadline,
            max_output_bytes=4 * 1024 * 1024, max_input_bytes=1,
        )
        result = subprocess.CompletedProcess(
            argv, captured.returncode, captured.stdout, captured.stderr
        )
        if check and result.returncode:
            private(
                "failure-" + uuid.uuid4().hex + ".log", result.stdout + result.stderr
            )
            raise RuntimeError("Docker command failed; inspect private failure log")
        return result

    args_docker = args.docker

    def create(name, *options, image, command_args=()):
        resource = plan_resource(resources, "container", name, prefix)
        result = command(
            "create",
            "--name",
            name,
            "--label",
            "freesdn.qualification=" + prefix,
            "--network",
            prefix,
            *options,
            image,
            *command_args,
        )
        identity = remember_identity(resource, result.stdout)
        info = inspect_owned(resource, command)
        assert info["Config"]["Labels"]["freesdn.qualification"] == prefix
        assert not info["HostConfig"]["PortBindings"]
        assert not any(m["Type"] == "volume" for m in info["Mounts"])
        command("start", identity)
        return identity

    try:
        images = {
            k: command("image", "inspect", "--format", "{{.Id}}", value)
            .stdout.decode()
            .strip()
            for k, value in [("backend", args.backend), ("logdb", args.logdb)]
        }
        assert all(v.startswith("sha256:") and len(v) == 71 for v in images.values())
        report["images"] = images
        network = plan_resource(resources, "network", prefix, prefix)
        remember_identity(
            network,
            command(
                "network",
                "create",
                "--internal",
                "--label",
                "freesdn.qualification=" + prefix,
                prefix,
            )
            .stdout,
        )
        password = secrets.token_urlsafe(48)
        private(
            "database.env",
            (
                "POSTGRES_DB=freesdn\nPOSTGRES_USER=freesdn\nPOSTGRES_PASSWORD="
                + password
                + "\n"
            ).encode(),
        )
        pg = create(
            prefix + "-pg",
            "--network-alias",
            "logdb",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--cpus",
            "2",
            "--tmpfs",
            "/var/lib/postgresql:rw,size=768m,mode=1777",
            "--env-file",
            str(work / "database.env"),
            image=images["logdb"],
            command_args=("postgres", "-c", "timescaledb.max_background_workers=0"),
        )
        for _ in range(90):
            if (
                command(
                    "exec",
                    pg,
                    "pg_isready",
                    "-U",
                    "freesdn",
                    "-d",
                    "freesdn",
                    check=False,
                ).returncode
                == 0
            ):
                break
            time.sleep(1)
        else:
            private("database-failure.log", command("logs", pg, check=False).stdout)
            raise RuntimeError("Isolated database did not become ready")
        url = "postgresql+asyncpg://freesdn:" + password + "@logdb/freesdn"
        env = {
            "DATABASE_URL": url,
            "LOGDB_URL": url,
            "SECRET_KEY": secrets.token_urlsafe(48),
            "ENCRYPTION_SALT": secrets.token_urlsafe(48),
            "POSTGRES_PASSWORD": password,
            "REDIS_PASSWORD": password,
            "REDIS_URL": "redis://:" + password + "@unused-broker:6379/0",
            "ENVIRONMENT": "production",
            "ADAPTER_READ_ONLY": "true",
            "PYTHONPATH": "/app",
            "PYTHONDONTWRITEBYTECODE": "1",
            "FREESDN_RETENTION_FIXTURE": "isolated-disposable",
        }
        private(
            "application.env",
            "".join(k + "=" + v + "\n" for k, v in env.items()).encode(),
        )
        probe = (
            Path(__file__).resolve().parent / "qualification/event_retention_probe.py"
        )
        app = create(
            prefix + "-app",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory",
            "512m",
            "--memory-swap",
            "512m",
            "--cpus",
            "2",
            "--tmpfs",
            "/tmp:rw,size=64m",
            "--entrypoint",
            "sleep",
            "--mount",
            "type=bind,src=" + str(probe) + ",dst=/probe.py,readonly",
            "--env-file",
            str(work / "application.env"),
            image=images["backend"],
            command_args=("infinity",),
        )
        command("exec", app, "python", "scripts/migrate_logdb.py", timeout=120)
        result = command("exec", app, "python", "/probe.py", timeout=360)
        lines = [
            s.removeprefix("EVENT_RETENTION_RESULT=")
            for s in result.stdout.decode().splitlines()
            if s.startswith("EVENT_RETENTION_RESULT=")
        ]
        assert len(lines) == 1
        report.update(json.loads(lines[0]))
        assert report["passed"]
    except BaseException as error:
        report["error_type"] = type(error).__name__
        failures.append(error)
    finally:
        report["probe_passed"] = report["passed"]
        cleanup = cleanup_resources(resources, command, failures, anonymous_volumes=True)
        report["cleanup"] = cleanup
        report["owned_resources_removed"] = all(row["removed"] for row in cleanup)
        report["passed"] = bool(report["probe_passed"] and not failures)
        report["qualification_complete"] = not failures
        try:
            private("report.json", json.dumps(report, indent=2).encode())
        except BaseException as report_error:
            failures.append(report_error)
    if failures:
        raise BaseExceptionGroup(
            "Retention qualification, cleanup or reporting failed; original errors retained",
            failures,
        )
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "cases": len(report["cases"]),
                "owned_resources_removed": True,
            }
        )
    )


if __name__ == "__main__":
    main()
