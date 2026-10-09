#!/usr/bin/env python3
"""Rehearse the shipped Lite stack and encrypted offline recovery on Linux Docker.

Only NEW private --work-dir and freshly generated Compose projects are used.
No ports, hardware, external relay, customer credentials or existing volumes are
used. Images must already exist; they are resolved once and never pulled here.
The source must be a reviewed public export, not a live deployment directory.
Private dumps, configuration, test keys and logs are retained under --work-dir.
Only report.json is intended to be shared. This is a bounded synthetic Lite
recovery drill, NOT qualification of a customer upgrade, HA or production RTO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import time
import uuid
from collections import Counter
from pathlib import Path

from install_config import configure
from qualification.bounded_command import capture_command

SERVICES = {
    "postgres",
    "logdb",
    "redis",
    "api",
    "worker",
    "scheduler",
    "edge",
    "pg-backup",
}
APP_SERVICES = ("scheduler", "worker", "api")


def logdb_policies_ready(state: dict) -> bool:
    """Require real scheduler successes, not merely an accepting DB socket.

    This inventory applies to the fresh isolated fixture's shipped migration.
    Extension telemetry and its internal history policy are not application
    policies. Telemetry cannot reach the Internet on this internal network.
    """
    settings = state["settings"]
    slots = int(settings["max_worker_processes"])
    background = int(settings["timescaledb.max_background_workers"])
    parallel = int(settings["max_parallel_workers"])
    if background < 2 or parallel < 0 or slots < background + parallel + 2:
        raise ValueError("LogDB worker pool cannot accommodate configured workers")
    expected = {
        "policy_compression": 4,
        "policy_retention": 4,
        "policy_refresh_continuous_aggregate": 3,
    }
    jobs = state["jobs"]
    if Counter(job["proc_name"] for job in jobs) != expected:
        raise ValueError("Incomplete or unexpected application policy inventory")
    identities = [job["job_id"] for job in jobs]
    if len(set(identities)) != len(jobs):
        raise ValueError("Duplicate application policy identity")
    ready = True
    for job in jobs:
        if job["scheduled"] is not True:
            raise ValueError("Application maintenance policy is disabled")
        for field in ("total_runs", "total_successes", "total_failures"):
            value = job[field]
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("Invalid application policy execution count")
        if job["total_failures"] or job["last_run_status"] == "Failed":
            raise ValueError("Application maintenance policy failed")
        if not job["total_successes"] or job["last_run_status"] != "Success":
            ready = False
        elif job["total_runs"] != job["total_successes"]:
            raise ValueError("Inconsistent application policy execution counts")
    return ready


def soak_duration(value: str) -> int:
    seconds = int(value)
    if seconds != 0 and not 60 <= seconds <= 1800:
        raise argparse.ArgumentTypeError(
            "soak must be 0 (disabled) or 60..1800 seconds"
        )
    return seconds


def validate_plan(plan: dict, root: Path, work: Path, images: dict) -> None:
    """Refuse unexpected exposure, host mounts or externally owned resources."""
    if set(plan["services"]) != SERVICES:
        raise ValueError("Unexpected services in Lite plan")
    if set(plan.get("networks", {})) != {"default"} or not plan["networks"][
        "default"
    ].get("internal"):
        raise ValueError("Qualification requires one internal network")
    for volume in plan.get("volumes", {}).values():
        if volume.get("external") or volume.get("driver_opts"):
            raise ValueError("Existing or host-backed volumes are forbidden")
    for service in plan["services"].values():
        if (
            service.get("ports")
            or service.get("privileged")
            or service.get("devices")
            or service.get("network_mode")
        ):
            raise ValueError(
                "Qualification must not expose ports or privileged networking"
            )
        if service.get("image") not in images.values() or service.get("build"):
            raise ValueError("Only resolved candidate images are allowed")
        for mount in service.get("volumes", []):
            if mount["type"] == "bind":
                path = Path(mount["source"]).resolve()
                if (
                    not mount.get("read_only")
                    or not path.is_file()
                    or not (path.is_relative_to(root) or path.is_relative_to(work))
                ):
                    raise ValueError("Unexpected host bind mount")
            elif mount["type"] != "volume":
                raise ValueError("Unexpected mount type")


def main() -> None:
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--soak-seconds", type=soak_duration, default=0)
    parser.add_argument("--report-disk-pressure", action="store_true")
    for image in ("backend", "postgres", "logdb", "valkey", "edge"):
        parser.add_argument("--" + image, required=True)
    args = parser.parse_args()
    work = args.work_dir
    if os.name != "posix" or not work.is_absolute() or work.exists():
        parser.error("--work-dir must be a NEW absolute private POSIX directory")
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error("--work-dir must enforce mode 0700")
    source = args.source.resolve()
    prefix = "freesdn-install-" + uuid.uuid4().hex[:12]
    projects: dict[str, dict] = {}
    auxiliary: list[str] = []
    anonymous_volumes: set[str] = set()
    report = {
        "cases": [],
        "passed": False,
        "published_ports": False,
        "hardware_access": False,
        "external_mail": False,
        "scope": "synthetic Lite installation, recreation and offline encrypted recovery",
        "limits": [
            "Fresh empty broker on recovery; customer queues and HA migration are not exercised",
            "No customer hardware, external mail, public ACME or browser-rendering acceptance",
            "Tiny synthetic dataset; timings are not production RTO/RPO or capacity guarantees",
            "Same-candidate recreation is not a legacy-version upgrade",
            "Lite TLS mode uses a private Caddy CA trusted only inside this fixture",
        ],
    }
    started = time.monotonic()

    def private(name, data):
        path = work / name
        with path.open("wb") as stream:
            os.chmod(path, 0o600)
            stream.write(data)
        return path

    def command(*argv, data=None, check=True, timeout=180, deadline=None):
        if deadline is None:
            # Archive/dump consumers retain their existing path until their
            # separate bounded streaming sink qualification is complete.
            result = subprocess.run(
                [args.docker, *argv],
                input=data,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        else:
            for name, value in (("deadline", deadline), ("timeout", timeout)):
                if type(value) not in (int, float):
                    raise ValueError(f"A finite numeric {name} is required")
                try:
                    finite = math.isfinite(value)
                except OverflowError:
                    finite = False
                if not finite or (name == "timeout" and value <= 0):
                    raise ValueError("A finite positive timeout and finite deadline are required")
            result = capture_command(
                [args.docker, *argv], input_data=data,
                deadline=min(deadline, time.monotonic() + timeout),
                max_output_bytes=4 * 1024**2, max_input_bytes=1024**2,
            )
        if check and result.returncode:
            private(
                "failure-" + uuid.uuid4().hex + ".log", result.stdout + result.stderr
            )
            raise RuntimeError("Docker command failed; inspect private failure log")
        return result

    def case(name, details=None):
        report["cases"].append({"case": name, "details": details})
        print("PASS", name, flush=True)

    def compose(project, *argv, **kwargs):
        return command(
            "compose",
            "--project-name",
            project,
            "-f",
            str(work / (project + ".json")),
            *argv,
            **kwargs,
        )

    def container(project, service, *, deadline=None):
        value = compose(project, "ps", "-aq", service, deadline=deadline).stdout.decode().strip()
        if not value or "\n" in value:
            raise RuntimeError("Expected exactly one owned service container")
        info = json.loads(command("inspect", value, deadline=deadline).stdout)[0]
        assert info["Config"]["Labels"]["com.docker.compose.project"] == project
        assert info["Config"]["Labels"]["freesdn.qualification"] == prefix
        planned = {v["name"] for v in projects[project]["volumes"].values()}
        for mount in info.get("Mounts", []):
            if mount["Type"] == "volume" and mount["Name"] not in planned:
                assert mount["Name"] not in original_volumes
                anonymous_volumes.add(mount["Name"])
        return value

    def put(container_id, path, data):
        command(
            "exec",
            "-i",
            container_id,
            "python",
            "-c",
            "import sys;from pathlib import Path;p=Path(sys.argv[1]);p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)",
            path,
            data=data,
        )

    def logdb_policies(project):
        # One work deadline includes discovery, queries, parsing, diagnostics,
        # policy validation and logs. Child teardown can add its bounded grace.
        deadline = time.monotonic() + 90

        def remaining():
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise RuntimeError("LogDB application policies did not complete")
            return seconds

        database = container(project, "logdb", deadline=deadline)
        remaining()
        environment = projects[project]["services"]["logdb"]["environment"]
        query = """
            SELECT json_build_object(
              'settings', (SELECT json_object_agg(name, setting) FROM pg_settings
                WHERE name IN ('max_worker_processes', 'max_parallel_workers',
                               'timescaledb.max_background_workers')),
              'jobs', (SELECT coalesce(json_agg(row_to_json(j)), '[]') FROM (
                SELECT job_id, proc_name, scheduled, last_run_status,
                       total_runs, total_successes, total_failures
                FROM timescaledb_information.jobs
                LEFT JOIN timescaledb_information.job_stats USING (job_id)
                WHERE proc_name IN ('policy_compression', 'policy_retention',
                                    'policy_refresh_continuous_aggregate')
                ORDER BY job_id
              ) j)
            );
        """
        while True:
            remaining()
            result = command(
                "exec", "-i", database, "psql", "-X", "-v", "ON_ERROR_STOP=1",
                "-U", environment["POSTGRES_USER"],
                "-d", environment["POSTGRES_DB"], "-At", data=query.encode(),
                deadline=deadline,
            )
            remaining()
            value = json.loads(result.stdout)
            private("logdb-policy-state.json", json.dumps(value).encode())
            ready = logdb_policies_ready(value)
            remaining()
            if ready:
                logs = command("logs", database, deadline=deadline)
                if b"failed to start a background worker" in logs.stdout + logs.stderr:
                    raise RuntimeError("LogDB scheduler exhausted its worker pool")
                remaining()
                return value
            time.sleep(min(2, remaining()))

    def probe(project, mode):
        api = container(project, "api")
        ca = command(
            "exec",
            container(project, "edge"),
            "cat",
            "/data/caddy/pki/authorities/local/root.crt",
        ).stdout
        put(api, "/tmp/qualification-ca.crt", ca)
        put(
            api,
            "/tmp/install-probe.py",
            (
                Path(__file__).parent / "qualification/install_acceptance_probe.py"
            ).read_bytes(),
        )
        if (work / "probe-state.json").exists():
            put(
                api,
                "/tmp/install-probe-state.json",
                (work / "probe-state.json").read_bytes(),
            )
        put(
            api,
            "/tmp/scheduled_backup_probe.py",
            (Path(__file__).parent / "qualification/scheduled_backup_probe.py").read_bytes(),
        )
        result = command(
            "exec",
            "-e",
            "PYTHONPATH=/app",
            api,
            "python",
            "/tmp/install-probe.py",
            mode,
            timeout=600,
        )
        private(
            "probe-" + mode + "-" + uuid.uuid4().hex + ".log",
            result.stdout + result.stderr,
        )
        line = [
            line
            for line in result.stdout.decode().splitlines()
            if line.startswith("INSTALL_RESULT=")
        ]
        assert len(line) == 1
        value = json.loads(line[0].split("=", 1)[1])
        assert value["passed"]
        private(
            "probe-state.json",
            command("exec", api, "cat", "/tmp/install-probe-state.json").stdout,
        )
        return value

    def capacity_probe(project, mode):
        api = container(project, "api")
        put(
            api,
            "/tmp/capacity-probe.py",
            (Path(__file__).parent / "qualification/capacity_probe.py").read_bytes(),
        )
        # probe() establishes verified TLS trust and the private fixture state.
        result = command(
            "exec",
            "-e",
            "PYTHONPATH=/app",
            "-e",
            "FREESDN_CAPACITY_FIXTURE=isolated-disposable",
            api,
            "python",
            "/tmp/capacity-probe.py",
            mode,
            str(args.soak_seconds),
            timeout=max(180, args.soak_seconds + 180),
        )
        private("capacity-" + mode + ".log", result.stdout + result.stderr)
        lines = [
            line
            for line in result.stdout.decode().splitlines()
            if line.startswith("CAPACITY_RESULT=")
        ]
        assert len(lines) == 1
        value = json.loads(lines[0].split("=", 1)[1])
        private("capacity-" + mode + ".json", json.dumps(value, indent=2).encode())
        assert value["passed"], "Capacity acceptance failed; inspect private receipt"
        private(
            "probe-state.json",
            command("exec", api, "cat", "/tmp/install-probe-state.json").stdout,
        )
        return value

    original_volumes: set[str] = set()
    try:
        original_volumes = set(
            command("volume", "ls", "-q").stdout.decode().splitlines()
        )
        images = {
            name: command(
                "image", "inspect", "--format", "{{.Id}}", getattr(args, name)
            )
            .stdout.decode()
            .strip()
            for name in ("backend", "postgres", "logdb", "valkey", "edge")
        }
        report["images"] = images
        # Configure an isolated installation using the same helper as install.sh.
        root = work / "installation"
        root.mkdir(mode=0o700)
        shutil.copyfile(source / ".env.lite.example", root / ".env.lite.example")
        path, fresh = configure(root, "lite")
        assert fresh and path.stat().st_mode & 0o777 == 0o600
        env_text = path.read_text()
        env_text += (
            "\nADAPTER_READ_ONLY=true\nBACKUP_GPG_RECIPIENT=\nBACKUP_GPG_PUBLIC_KEY_PATH="
            + str(source / "secrets/.gitkeep")
            + "\n"
        )
        env_text += (
            "BACKEND_IMAGE="
            + images["backend"]
            + "\nPOSTGRES_IMAGE="
            + images["postgres"]
            + "\nLOGDB_IMAGE="
            + images["logdb"]
            + "\nEDGE_IMAGE="
            + images["edge"]
            + "\n"
        )
        private("installation/.env.lite", env_text.encode())
        raw = command(
            "compose",
            "--env-file",
            str(path),
            "--project-directory",
            str(source),
            "-f",
            str(source / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ).stdout
        original = json.loads(raw)
        assert set(original["services"]) == SERVICES
        case(
            "Lite installer generates private credentials and resolves the shipped core services"
        )

        def plan_for(label, restored=False):
            project = prefix + "-" + label
            plan = json.loads(json.dumps(original))
            plan.pop("name", None)
            for name, service in plan["services"].items():
                service.pop("build", None)
                service.pop("ports", None)
                service["restart"] = "no"
                service["image"] = (
                    images["valkey"] if name == "redis" else service["image"]
                )
                service.setdefault("labels", {})["freesdn.qualification"] = prefix
                if name == "edge":
                    service["environment"]["CADDY_SITE_ADDRESS"] = "localhost"
                if restored and name in APP_SERVICES:
                    service["environment"]["JWT_SIGNING_KEY"] = signing_key
                    service["environment"]["SLA_REPORT_DELIVERY_EPOCH"] = epoch
                # A private fixture relay/origin is not configured, so mail stays off.
            used = {
                v["source"]
                for svc in plan["services"].values()
                for v in svc.get("volumes", [])
                if v["type"] == "volume"
            }
            plan["volumes"] = {
                name: {
                    "name": project + "_" + name,
                    "labels": {"freesdn.qualification": prefix},
                }
                for name in used
            }
            # Docker chooses a non-overlapping private subnet. No route to devices.
            plan["networks"] = {
                "default": {
                    "name": project + "_default",
                    "driver": "bridge",
                    "internal": True,
                    "labels": {"freesdn.qualification": prefix},
                }
            }
            validate_plan(plan, source, work, images)
            private(project + ".json", json.dumps(plan).encode())
            projects[project] = plan
            return project

        import secrets

        signing_key = secrets.token_urlsafe(48)
        epoch = str(uuid.uuid4())
        primary = plan_for("source")
        boot = time.monotonic()
        compose(
            primary,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "240",
            "postgres",
            "logdb",
            "redis",
            "api",
            "worker",
            "scheduler",
            "edge",
            timeout=300,
        )
        report["initial_ready_seconds"] = round(time.monotonic() - boot, 3)
        case(
            "real Lite API, worker, scheduler and Caddy start with shipped budgets and fresh volumes",
            {"ready_seconds": report["initial_ready_seconds"]},
        )
        case(
            "all eleven LogDB application policies run successfully under the real scheduler",
            logdb_policies(primary),
        )
        case(
            "real edge setup, duplicate-admin refusal, login, dashboard reads and PDF/CSV downloads",
            probe(primary, "seed"),
        )
        # Exercise the shipped maintenance command, not a mounted development
        # checkout: a missing Docker COPY previously left upgrades without it.
        vpn_audit = json.loads(command(
            "exec", container(primary, "api"), "python", "-m",
            "scripts.encrypt_vpn_site_configs", "--batch-size", "1",
            "--max-batches", "1",
        ).stdout)
        assert vpn_audit["mode"] == "audit" and vpn_audit["complete"]
        assert vpn_audit["examined"] == vpn_audit["updated"] == 0
        case("production image includes the read-only legacy VPN audit command", vpn_audit)
        if args.report_disk_pressure:
            api_plan = projects[primary]["services"]["api"]
            original_tmpfs = list(api_plan.get("tmpfs", []))
            api_plan["tmpfs"] = original_tmpfs + [
                "/qualification-reports:rw,noexec,nosuid,size=16m,uid=1001,gid=1001,mode=0700"
            ]
            api_plan["environment"]["SLA_REPORTS_DIR"] = "/qualification-reports"
            validate_plan(projects[primary], source, work, images)
            private(primary + ".json", json.dumps(projects[primary]).encode())
            compose(
                primary,
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "240",
                "api",
                timeout=300,
            )
            # Restore the CA and private authentication state after recreation.
            api = container(primary, "api")
            put(
                api,
                "/tmp/qualification-ca.crt",
                command(
                    "exec",
                    container(primary, "edge"),
                    "cat",
                    "/data/caddy/pki/authorities/local/root.crt",
                ).stdout,
            )
            put(
                api,
                "/tmp/install-probe-state.json",
                (work / "probe-state.json").read_bytes(),
            )
            case(
                "bounded report-volume ENOSPC refuses phantom reports and recovers",
                capacity_probe(primary, "pressure"),
            )
            api_plan["tmpfs"] = original_tmpfs
            del api_plan["environment"]["SLA_REPORTS_DIR"]
            private(primary + ".json", json.dumps(projects[primary]).encode())
            compose(
                primary,
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "240",
                "api",
                timeout=300,
            )
            case(
                "persistent report archives survive the isolated pressure drill",
                probe(primary, "verify"),
            )
        if args.soak_seconds:
            case(
                "concurrent authenticated reads, report generation, events and five queues",
                capacity_probe(primary, "soak"),
            )
            resources = []
            for service in (
                "postgres",
                "logdb",
                "redis",
                "api",
                "worker",
                "scheduler",
                "edge",
            ):
                info = json.loads(
                    command("inspect", container(primary, service)).stdout
                )[0]
                assert not info["State"]["OOMKilled"] and info["State"]["Running"]
                resources.append(
                    {
                        "service": service,
                        "oom_killed": False,
                        "restart_count": info["RestartCount"],
                        "memory_limit": info["HostConfig"]["Memory"],
                    }
                )
            report["post_soak_resources"] = resources
        compose(primary, "up", "-d", "--no-build", "--pull", "never", "pg-backup")
        backup = container(primary, "pg-backup")
        assert not anonymous_volumes, (
            "Backup client inherited an unwanted anonymous volume"
        )
        case(
            "backup client masks the inherited database volume; backups remain persistent"
        )
        for _ in range(30):
            r = command(
                "exec", backup, "cat", "/backups/.metrics/pg_backup.prom", check=False
            )
            if b"freesdn_pg_backup_enabled 0" in r.stdout:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Unconfigured backup did not fail closed")
        listing = command("exec", backup, "find", "/backups", "-type", "f").stdout
        assert b".sql" not in listing
        case("unconfigured backup remains disabled and writes no plaintext dumps")

        # Recreate app containers while retaining only this project's volumes.
        compose(
            primary,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            "--wait",
            "--wait-timeout",
            "240",
            "api",
            "worker",
            "scheduler",
            "edge",
            timeout=300,
        )
        case(
            "candidate recreation preserves login, setup closure and report archive bytes",
            probe(primary, "verify"),
        )

        # Generate a disposable encryption key entirely offline. Real operator
        # private keys belong outside the controller; this is test material only.
        keybox = prefix + "-keybox"
        auxiliary.append(keybox)
        command(
            "run",
            "-d",
            "--name",
            keybox,
            "--label",
            "freesdn.qualification=" + prefix,
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--entrypoint",
            "sleep",
            images["postgres"],
            "infinity",
        )
        command("exec", keybox, "sh", "-c", "mkdir -m 700 /tmp/gnupg")
        command(
            "exec",
            keybox,
            "gpg",
            "--homedir",
            "/tmp/gnupg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Qualification <qualification@example.test>",
            "rsa2048",
            "encrypt",
            "1d",
        )
        public = command(
            "exec", keybox, "gpg", "--homedir", "/tmp/gnupg", "--armor", "--export"
        ).stdout
        private("test-public.asc", public)
        fingerprint = command(
            "exec",
            keybox,
            "gpg",
            "--homedir",
            "/tmp/gnupg",
            "--with-colons",
            "--list-keys",
        ).stdout.decode()
        fingerprint = next(
            line.split(":")[9]
            for line in fingerprint.splitlines()
            if line.startswith("fpr:")
        )
        private(
            "test-private.asc",
            command(
                "exec",
                keybox,
                "gpg",
                "--homedir",
                "/tmp/gnupg",
                "--armor",
                "--export-secret-keys",
            ).stdout,
        )

        # Fence application writers before the coordinated snapshot. The test
        # database has no configured controllers, plugins or external mail.
        compose(primary, "stop", *APP_SERVICES)
        plan = projects[primary]
        backup_plan = plan["services"]["pg-backup"]
        backup_plan["environment"]["BACKUP_GPG_RECIPIENT"] = fingerprint
        for mount in backup_plan["volumes"]:
            if mount["type"] == "bind":
                mount["source"] = str(work / "test-public.asc")
        validate_plan(plan, source, work, images)
        private(primary + ".json", json.dumps(plan).encode())
        compose(
            primary,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            "pg-backup",
        )
        backup = container(primary, "pg-backup")
        for _ in range(120):
            result = command(
                "exec",
                backup,
                "cat",
                "/backups/.metrics/pg_backup.last_success",
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Encrypted backup pair did not complete")
        compose(primary, "stop", "pg-backup")
        command("cp", backup + ":/backups/.", str(work / "database-backups"))
        backups = sorted((work / "database-backups").glob("*.sql.gz.gpg"))
        assert len(backups) == 2 and not list(
            (work / "database-backups").glob("*.partial")
        )
        report["backup_sha256"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in backups
        }
        case(
            "shipped backup service creates a completed encrypted PostgreSQL/Timescale pair after writer fencing"
        )

        # Retain all application files, including report archives and encrypted
        # local backups. Read-only source mounts are never attached to targets.
        archive_paths = {}
        for mount in plan["services"]["api"].get("volumes", []):
            if mount["type"] != "volume":
                continue
            name = mount["source"]
            utility = prefix + "-archive-" + name
            auxiliary.append(utility)
            archive = command(
                "run",
                "--rm",
                "--name",
                utility,
                "--label",
                "freesdn.qualification=" + prefix,
                "--network",
                "none",
                "--user",
                "0:0",
                "--entrypoint",
                "tar",
                "--mount",
                "type=volume,src="
                + plan["volumes"][name]["name"]
                + ",dst=/volume,readonly",
                images["postgres"],
                "-C",
                "/volume",
                "-cpf",
                "-",
                ".",
            ).stdout
            archive_paths[name] = private(name + ".tar", archive)
        report["archive_sha256"] = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in archive_paths.items()
        }
        # Stop the remaining source services before opening any target writer.
        compose(primary, "stop")
        assert not compose(primary, "ps", "-q", "--status", "running").stdout.strip()
        recovery_start = time.monotonic()
        target = plan_for("recovered", restored=True)
        compose(
            target,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "120",
            "postgres",
            "logdb",
            "redis",
            timeout=180,
        )
        # Decrypt in the offline key container, then restore with checked exit
        # codes. Timescale restore mode is switched in the same psql connection.
        for kind, database in (("freesdn", "freesdn"), ("logdb", "freesdn_logs")):
            archive = next(p for p in backups if p.name.startswith(kind + "_"))
            decrypted = command(
                "exec",
                "-i",
                keybox,
                "gpg",
                "--homedir",
                "/tmp/gnupg",
                "--batch",
                "--decrypt",
                data=archive.read_bytes(),
            ).stdout
            import gzip

            sql = gzip.decompress(decrypted)
            db = container(target, "postgres" if kind == "freesdn" else "logdb")
            command(
                "exec",
                "-i",
                db,
                "psql",
                "-U",
                "freesdn",
                "-d",
                "postgres",
                "-Xq",
                "-v",
                "ON_ERROR_STOP=1",
                data=(
                    f'DROP DATABASE "{database}" WITH (FORCE);\nCREATE DATABASE "{database}" TEMPLATE template0;\n'
                ).encode(),
            )
            if kind == "logdb":
                sql = (
                    b"CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT public.timescaledb_pre_restore();\n"
                    + sql
                    + b"\nSELECT public.timescaledb_post_restore();\n"
                )
            command(
                "exec",
                "-i",
                db,
                "psql",
                "-U",
                "freesdn",
                "-d",
                database,
                "-Xq",
                "-v",
                "ON_ERROR_STOP=1",
                data=sql,
                timeout=240,
            )
        # Create application containers so their correctly owned volumes exist,
        # but do not start them until file restoration and key cutover complete.
        compose(
            target,
            "create",
            "--no-build",
            "--pull",
            "never",
            "api",
            "worker",
            "scheduler",
            "edge",
        )
        for name, archive in archive_paths.items():
            utility = prefix + "-restore-" + name
            auxiliary.append(utility)
            command(
                "run",
                "--rm",
                "-i",
                "--name",
                utility,
                "--label",
                "freesdn.qualification=" + prefix,
                "--network",
                "none",
                "--user",
                "0:0",
                "--entrypoint",
                "tar",
                "--mount",
                "type=volume,src="
                + projects[target]["volumes"][name]["name"]
                + ",dst=/volume",
                images["postgres"],
                "-C",
                "/volume",
                "-xpf",
                "-",
                data=archive.read_bytes(),
            )
        compose(
            target,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "240",
            "api",
            "worker",
            "scheduler",
            "edge",
            timeout=300,
        )
        details = probe(target, "recovered")
        report["bounded_recovery_seconds"] = round(time.monotonic() - recovery_start, 3)
        case(
            "fresh target restores real login, databases and report files; old JWTs denied after independent key cutover",
            details,
        )
        assert report["backup_sha256"] == {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in backups
        }
        case(
            "original encrypted backups and source volumes remain intact during recovery"
        )
        report["passed"] = True
    except Exception as exc:
        report["failure_type"] = type(exc).__name__
        raise
    finally:
        cleanup_errors = []
        # Retain private logs before removing only this invocation's projects.
        for project in projects:
            try:
                private(
                    project + "-logs.txt",
                    compose(project, "logs", "--no-color", check=False).stdout,
                )
                result = compose(
                    project, "down", "--volumes", "--timeout", "30", check=False
                )
                if result.returncode:
                    cleanup_errors.append(project)
            except (
                OSError,
                subprocess.SubprocessError,
                RuntimeError,
                AssertionError,
                ValueError,
                KeyError,
            ):
                cleanup_errors.append(project)
        for name in auxiliary:
            try:
                found = command("inspect", name, check=False)
                if found.returncode == 0:
                    assert (
                        json.loads(found.stdout)[0]["Config"]["Labels"].get(
                            "freesdn.qualification"
                        )
                        == prefix
                    )
                    if command("rm", "-f", "-v", name, check=False).returncode:
                        cleanup_errors.append(name)
            except (
                OSError,
                subprocess.SubprocessError,
                RuntimeError,
                AssertionError,
                ValueError,
                KeyError,
            ):
                cleanup_errors.append(name)
        for name in sorted(anonymous_volumes):
            try:
                found = command("volume", "inspect", name, check=False)
                if (
                    found.returncode == 0
                    and command("volume", "rm", name, check=False).returncode
                ):
                    cleanup_errors.append(name)
            except (OSError, subprocess.SubprocessError, RuntimeError):
                cleanup_errors.append(name)
        report["tracked_anonymous_volumes"] = sorted(anonymous_volumes)
        report["owned_resources_removed"] = not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if cleanup_errors:
            report["passed"] = False
        private("report.json", json.dumps(report, indent=2).encode())
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
