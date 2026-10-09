#!/usr/bin/env python3
"""Rehearse an auth upgrade and isolated backup recovery with disposable Docker resources.

Requires a retained backend image at a supported pre-016 revision and the candidate production
backend image. Tests actual ASGI routes, PostgreSQL dumps/restores and Valkey,
without dependency overrides. No ports, customer credentials, existing volumes,
hardware, migrations of production databases or deployment cutovers are used.

--work-dir must be a NEW private POSIX directory. It retains synthetic dump/state
and failure logs (0600) for investigation; NEVER publish that directory. Only
report.json is designed for a release evidence bundle. The scope is application
authentication and both vault derivations, not a full database runtime/HA upgrade.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--legacy-backend", required=True)
    parser.add_argument(
        "--legacy-revision",
        choices=("011_plugin_review_user_uq", "015_proxmox_task_tracking"),
        default="015_proxmox_task_tracking",
        help="Expected retained image schema; 011 is the published v26.09.0 image",
    )
    parser.add_argument("--backend", required=True)
    parser.add_argument("--postgres", required=True)
    parser.add_argument("--valkey", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir
    if os.name != "posix" or not work.is_absolute() or work.exists():
        parser.error("--work-dir must be a new absolute private POSIX directory")
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error(
            "--work-dir filesystem must enforce private directory permissions (0700)"
        )
    prefix = "freesdn-auth-recovery-" + uuid.uuid4().hex[:12]
    password, vault_key, salt, signing_key = [
        secrets.token_urlsafe(48) for _ in range(4)
    ]
    login_password = "Aa1!" + secrets.token_urlsafe(24)
    containers = []
    report = {
        "cases": [],
        "published_ports": False,
        "hardware_access": False,
        "scope": "authentication upgrade/recovery, not database runtime or HA queue migration",
    }
    probe = Path(__file__).parent / "qualification/auth_recovery_probe.py"
    state = b""
    dump = b""

    def private(name, data):
        path = work / name
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(data)

    private(
        "synthetic-secrets.json",
        json.dumps([password, vault_key, salt, signing_key, login_password]).encode(),
    )

    def command(*argv, data=None, check=True, timeout=120):
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            private(
                "failure-" + uuid.uuid4().hex + ".log", result.stdout + result.stderr
            )
            raise AssertionError(
                "Docker qualification command failed; inspect private failure log"
            )
        return result

    def sql(statement, database="freesdn"):
        return (
            command(
                "exec",
                "-i",
                prefix + "-pg",
                "psql",
                "-U",
                "freesdn",
                "-d",
                database,
                "-XqAt",
                "-v",
                "ON_ERROR_STOP=1",
                data=statement.encode(),
            )
            .stdout.decode()
            .strip()
        )

    def case(message, details=None):
        report["cases"].append({"case": message, "details": details})
        print("PASS", message, flush=True)

    def copy_input(container, destination, data):
        command(
            "exec",
            "-i",
            container,
            "python",
            "-c",
            "import sys,os; from pathlib import Path; "
            "p=Path(sys.argv[1]); p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o600)",
            destination,
            data=data,
        )

    def application(label, image, database="freesdn", key=""):
        name = prefix + "-" + label
        env = {
            "DATABASE_URL": f"postgresql+asyncpg://freesdn:{password}@pg/{database}",
            "LOGDB_URL": f"postgresql+asyncpg://freesdn:{password}@pg/{database}",
            "POSTGRES_PASSWORD": password,
            "SECRET_KEY": vault_key,
            "ENCRYPTION_SALT": salt,
            "JWT_SIGNING_KEY": key,
            "REDIS_URL": f"redis://:{password}@redis:6379/0",
            "REDIS_PASSWORD": password,
            "REDIS_HOST": "redis",
            "ENVIRONMENT": "production",
            "ADAPTER_READ_ONLY": "true",
            "PYTHONPATH": "/app",
            "PYTHONDONTWRITEBYTECODE": "1",
            "RECOVERY_PROBE_PASSWORD": login_password,
        }
        containers.append(name)
        command(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            prefix,
            "--label",
            "freesdn.qualification=" + prefix,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/tmp",
            "--entrypoint",
            "sleep",
            *[item for k, v in env.items() for item in ("-e", k + "=" + v)],
            image,
            "infinity",
        )
        assert command("exec", name, "id", "-u").stdout.strip() == b"1001"
        copy_input(name, "/tmp/auth-recovery-probe.py", probe.read_bytes())
        if state:
            copy_input(name, "/tmp/auth-recovery-state.json", state)
        return name

    def run_probe(container, *mode):
        nonlocal state
        response = command(
            "exec", container, "python", "/tmp/auth-recovery-probe.py", *mode
        )
        lines = [
            line.removeprefix("AUTH_RECOVERY_RESULT=")
            for line in response.stdout.decode().splitlines()
            if line.startswith("AUTH_RECOVERY_RESULT=")
        ]
        assert len(lines) == 1
        result = json.loads(lines[0])
        assert result["passed"] is True
        state = command(
            "exec", container, "cat", "/tmp/auth-recovery-state.json"
        ).stdout
        return result

    def restore(database):
        sql(f'CREATE DATABASE "{database}"', "postgres")
        command(
            "exec",
            "-i",
            prefix + "-pg",
            "pg_restore",
            "-U",
            "freesdn",
            "-d",
            database,
            "--exit-on-error",
            data=dump,
        )

    # Resolve tags once, then run only those exact retained image IDs.
    images = {
        key: command("image", "inspect", "--format", "{{.Id}}", value)
        .stdout.decode()
        .strip()
        for key, value in {
            "legacy": args.legacy_backend,
            "candidate": args.backend,
            "postgres": args.postgres,
            "valkey": args.valkey,
        }.items()
    }
    report["images"] = images
    started = time.monotonic()
    network_created = False
    try:
        command(
            "network",
            "create",
            "--internal",
            "--label",
            "freesdn.qualification=" + prefix,
            prefix,
        )
        network_created = True
        for alias, image, extra, cmd in (
            (
                "pg",
                images["postgres"],
                [
                    "-e",
                    "POSTGRES_USER=freesdn",
                    "-e",
                    "POSTGRES_DB=freesdn",
                    "-e",
                    "POSTGRES_PASSWORD=" + password,
                ],
                [],
            ),
            (
                "redis",
                images["valkey"],
                [],
                ["valkey-server", "--requirepass", password],
            ),
        ):
            name = prefix + "-" + alias
            containers.append(name)
            command(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                prefix,
                "--network-alias",
                alias,
                "--label",
                "freesdn.qualification=" + prefix,
                *extra,
                image,
                *cmd,
            )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if (
                command(
                    "exec", prefix + "-pg", "pg_isready", "-h", "127.0.0.1", check=False
                ).returncode
                == 0
            ):
                break
            time.sleep(0.3)
        else:
            raise AssertionError("PostgreSQL did not become ready")
        legacy = application("legacy", images["legacy"])
        command("exec", legacy, "python", "scripts/migrate.py")
        assert (
            sql("SELECT version_num FROM alembic_version")
            == args.legacy_revision
        )
        report["legacy_schema_revision"] = args.legacy_revision
        assert sql("SELECT to_regclass('core.token_revocations') IS NULL") == "t"
        case(
            "legacy image creates the explicitly expected pre-016 revision without durable revocation table",
            run_probe(legacy, "seed"),
        )
        command("stop", "-t", "2", legacy)
        candidate = application("candidate", images["candidate"])
        command("exec", candidate, "python", "scripts/migrate.py")
        expected_head = (
            command(
                "exec",
                candidate,
                "python",
                "-c",
                "from alembic.config import Config; from alembic.script import ScriptDirectory; "
                "print(ScriptDirectory.from_config(Config('alembic.ini')).get_current_head())",
            )
            .stdout.decode()
            .strip()
        )
        assert (
            expected_head
            and sql("SELECT version_num FROM alembic_version") == expected_head
        )
        assert sql("SELECT to_regclass('core.token_revocations') IS NOT NULL") == "t"
        report["candidate_schema_revision"] = expected_head
        case(
            "fenced old-to-new upgrade rejects all four legacy token families; vault ciphertext unchanged",
            run_probe(candidate, "upgraded"),
        )
        dump = command(
            "exec", prefix + "-pg", "pg_dump", "-U", "freesdn", "-d", "freesdn", "-Fc"
        ).stdout
        private("synthetic-snapshot.dump", dump)
        case(
            "real current-schema dump captures active remembered session before later logout"
        )
        case(
            "post-snapshot logout really denies the old access token and issues later-version tokens",
            run_probe(candidate, "post-snapshot"),
        )
        command("stop", "-t", "2", candidate)
        restore("unsafe_restore")
        unsafe = application("unsafe", images["candidate"], "unsafe_restore")
        case(
            "negative control: restored DB with original signing key revives access, refresh, reset and MFA",
            run_probe(unsafe, "negative", "snapshot"),
        )
        command("stop", "-t", "2", unsafe)
        restore("unsafe_increment")
        sql("UPDATE core.users SET token_version=token_version+1", "unsafe_increment")
        increment = application("increment", images["candidate"], "unsafe_increment")
        case(
            "negative control: restored token version plus one accepts later-issued tokens in all four families",
            run_probe(increment, "negative", "later"),
        )
        command("stop", "-t", "2", increment)
        restore("safe_restore")
        recovered = application(
            "recovered", images["candidate"], "safe_restore", signing_key
        )
        case(
            "auth-only key cutover rejects 12 old tokens; fresh login/refresh/reset/MFA work once; vault intact",
            run_probe(recovered, "recovered"),
        )
        command("stop", "-t", "2", recovered)
        command(
            "exec",
            "-e",
            "VALKEYCLI_AUTH=" + password,
            prefix + "-redis",
            "valkey-cli",
            "FLUSHALL",
        )
        restarted = application(
            "restarted", images["candidate"], "safe_restore", signing_key
        )
        case(
            "fresh process and empty cache retain old-token rejection, fresh login and both vault derivations",
            run_probe(restarted, "restart"),
        )
        private("synthetic-final-state.json", state)
        report["passed"] = True
    except BaseException as exc:
        report["passed"] = False
        report["failure_type"] = type(exc).__name__
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        cleanup = []
        removals = [
            ("container", name, ("rm", "-fv", name)) for name in reversed(containers)
        ]
        if network_created:
            removals.append(("network", prefix, ("network", "rm", prefix)))
        for kind, name, argv in removals:
            item = {"kind": kind, "name": name, "removed": False}
            try:
                item["removed"] = command(*argv, check=False).returncode == 0
            except (OSError, subprocess.SubprocessError) as exc:
                # A stopped engine must not erase the partial test report or
                # prevent attempts to clean the rest of our own resources.
                # Names identify only newly created qualification fixtures.
                item["error_type"] = type(exc).__name__
            cleanup.append(item)
        report["cleanup"] = cleanup
        report["owned_resources_removed"] = all(item["removed"] for item in cleanup)
        if not report["owned_resources_removed"]:
            report["passed"] = False
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if not report["owned_resources_removed"]:
            raise AssertionError("Some owned qualification resources need cleanup")


if __name__ == "__main__":
    main()
