#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Qualify report-mail restore safety using disposable exact-image containers.

Runs real PostgreSQL dumps/restores and loopback TLS SMTP. No published ports,
customer backups, hardware, external mail, existing containers or volume mounts.
The new private --work-dir holds synthetic credentials/dumps: do not publish it.
Only report.json is designed for inclusion in release evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from uuid import uuid4


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
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
        parser.error("--work-dir filesystem must enforce private directory permissions (0700)")
    prefix = "freesdn-report-recovery-" + uuid4().hex[:12]
    password, vault_key, salt = [secrets.token_urlsafe(48) for _ in range(3)]
    original_epoch, new_epoch = str(uuid4()), str(uuid4())
    containers = []
    network_created = False
    state, archives, dump = b"", b"", b""
    report = {
        "cases": [],
        "published_ports": False,
        "hardware_access": False,
        "external_mail": False,
        "scope": "synthetic report-mail recovery, not full DB/queue/HA recovery",
    }

    def private(name, data):
        path = work / name
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(data)

    private("synthetic-secrets.json", json.dumps([password, vault_key, salt]).encode())

    def command(*argv, data=None, check=True, timeout=120):
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            private("failure-" + uuid4().hex + ".log", result.stdout + result.stderr)
            raise AssertionError("Qualification command failed; inspect private failure log")
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

    def copy_input(container, destination, data):
        command(
            "exec",
            "-i",
            container,
            "python",
            "-c",
            "import sys; from pathlib import Path; p=Path(sys.argv[1]); "
            "p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o600)",
            destination,
            data=data,
        )

    def application(label, database, epoch, images):
        name = prefix + "-" + label
        env = {
            "DATABASE_URL": f"postgresql+asyncpg://freesdn:{password}@pg/{database}",
            "LOGDB_URL": f"postgresql+asyncpg://freesdn:{password}@pg/{database}",
            "POSTGRES_PASSWORD": password,
            "SECRET_KEY": vault_key,
            "ENCRYPTION_SALT": salt,
            "REDIS_URL": f"redis://:{password}@redis:6379/0",
            "REDIS_PASSWORD": password,
            "REDIS_HOST": "redis",
            "ENVIRONMENT": "production",
            "ADAPTER_READ_ONLY": "true",
            "PYTHONPATH": "/app",
            "PYTHONDONTWRITEBYTECODE": "1",
            "FRONTEND_URL": "https://console.example.test",
            "SLA_REPORT_DELIVERY_EPOCH": epoch,
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
            images["backend"],
            "infinity",
        )
        assert command("exec", name, "id", "-u").stdout.strip() == b"1001"
        for filename in ["report_recovery_probe.py", "report_smtp_peer.py"]:
            copy_input(
                name,
                "/tmp/" + filename,
                (Path(__file__).parent / "qualification" / filename).read_bytes(),
            )
        if state:
            copy_input(name, "/tmp/report-recovery-state.json", state)
        if archives:
            command("exec", "-i", name, "tar", "-xf", "-", "-C", "/tmp", data=archives)
        return name

    def probe(container, mode, description):
        response = command("exec", container, "python", "/tmp/report_recovery_probe.py", mode)
        lines = [
            line.removeprefix("REPORT_RECOVERY_RESULT=")
            for line in response.stdout.decode().splitlines()
            if line.startswith("REPORT_RECOVERY_RESULT=")
        ]
        assert len(lines) == 1
        result = json.loads(lines[0])
        assert result["passed"] is True
        report["cases"].append({"case": description, **result})
        print("PASS", description, flush=True)

    declared_revisions = None

    def verify_database_revision(database="freesdn"):
        installed = sql(
            "SELECT version_num FROM alembic_version ORDER BY version_num", database
        ).splitlines()
        if (
            not isinstance(declared_revisions, list)
            or len(declared_revisions) != 1
            or not isinstance(declared_revisions[0], str)
            or not declared_revisions[0]
            or len(declared_revisions[0]) > 32
            or not all(
                char.isascii() and (char.isalnum() or char in "_-")
                for char in declared_revisions[0]
            )
            or installed != declared_revisions
        ):
            raise AssertionError(
                "Database revision does not match the image's single migration head"
            )
        report.setdefault("database_revisions", {})[database] = declared_revisions[0]

    def restore(database):
        # Names below are fixed harness constants, never customer input.
        assert database in {"unsafe_restore", "missing_epoch", "safe_restore"}
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
        verify_database_revision(database)

    images = {
        key: command("image", "inspect", "--format", "{{.Id}}", value).stdout.decode().strip()
        for key, value in {
            "backend": args.backend,
            "postgres": args.postgres,
            "valkey": args.valkey,
        }.items()
    }
    report["images"] = images
    started = time.monotonic()
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
        for alias, image, extra, cmd in [
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
        ]:
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
        source = application("source", "freesdn", original_epoch, images)
        command("exec", source, "python", "scripts/migrate.py")
        declared_revisions = json.loads(
            command(
                "exec",
                source,
                "python",
                "-c",
                "import json; from alembic.config import Config; "
                "from alembic.script import ScriptDirectory; "
                "print(json.dumps(ScriptDirectory.from_config(Config('alembic.ini')).get_heads()))",
            ).stdout
        )
        verify_database_revision()
        probe(source, "seed", "current image creates approved pending notice")
        state = command("exec", source, "cat", "/tmp/report-recovery-state.json").stdout
        archives = command(
            "exec", source, "tar", "-cf", "-", "-C", "/tmp", "report-recovery-archives"
        ).stdout
        dump = command(
            "exec", prefix + "-pg", "pg_dump", "-U", "freesdn", "-d", "freesdn", "-Fc"
        ).stdout
        private("snapshot.dump", dump)
        private("archives.tar", archives)
        private("state.json", state)
        report["snapshot_sha256"] = hashlib.sha256(dump).hexdigest()
        report["archive_tar_sha256"] = hashlib.sha256(archives).hexdigest()
        probe(source, "send", "original relay accepts mail after the snapshot")
        command("stop", "-t", "2", source)
        restore("unsafe_restore")
        unsafe = application("unsafe", "unsafe_restore", original_epoch, images)
        probe(
            unsafe,
            "send",
            "negative control: unchanged epoch replays the same restored notice and Message-ID",
        )
        command("stop", "-t", "2", unsafe)
        restore("missing_epoch")
        missing = application("missing", "missing_epoch", "", images)
        probe(
            missing,
            "quarantine",
            "empty epoch quarantines restored notice and pauses its schedule without SMTP",
        )
        command("stop", "-t", "2", missing)
        restore("safe_restore")
        recovered = application("recovered", "safe_restore", new_epoch, images)
        probe(
            recovered,
            "quarantine",
            "rotated epoch preserves identity/archive and quarantines restored notice without SMTP",
        )
        probe(
            recovered,
            "reapprove",
            "explicit review permits a new notice only; old notice stays unknown",
        )
        archives = command(
            "exec",
            recovered,
            "tar",
            "-cf",
            "-",
            "-C",
            "/tmp",
            "report-recovery-archives",
        ).stdout
        command("stop", "-t", "2", recovered)
        # This is an owned, fresh fixture cache; never an existing service.
        command(
            "exec",
            "-e",
            "VALKEYCLI_AUTH=" + password,
            prefix + "-redis",
            "valkey-cli",
            "FLUSHALL",
        )
        restarted = application("restarted", "safe_restore", new_epoch, images)
        probe(
            restarted,
            "restart",
            "new process and empty cache do not replay quarantined or accepted notices",
        )
        assert (
            hashlib.sha256((work / "snapshot.dump").read_bytes()).hexdigest()
            == report["snapshot_sha256"]
        )
        report["snapshot_unchanged"] = True
        report["passed"] = True
    except BaseException as exc:
        report["passed"] = False
        report["failure_type"] = type(exc).__name__
        raise
    finally:
        cleanup = []
        removals = [("container", name, ("rm", "-fv", name)) for name in reversed(containers)]
        if network_created:
            removals.append(("network", prefix, ("network", "rm", prefix)))
        for kind, name, argv in removals:
            item = {"kind": kind, "name": name, "removed": False}
            try:
                item["removed"] = command(*argv, check=False).returncode == 0
            except (OSError, subprocess.SubprocessError) as exc:
                item["error_type"] = type(exc).__name__
            cleanup.append(item)
        report["cleanup"] = cleanup
        report["owned_resources_removed"] = all(item["removed"] for item in cleanup)
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        if not all(item["removed"] for item in cleanup):
            report["passed"] = False
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if not report.get("passed"):
            print("FAILED; inspect private report.json and failure logs", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
