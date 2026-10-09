#!/usr/bin/env python3
"""Qualify concurrent startup migrations in disposable real database containers.

Uses an internal network and synthetic credentials/data. Three independent
startup scripts must wait behind a database lock before any schema writes.
Terminating the lock owner must release all waiters without container restarts.
No existing database, volume, hardware or published port is used.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

LOCK = 0x4652454553444E
LOCK_QUERY = (
    "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
    f"AND classid={LOCK >> 32} AND objid={LOCK & 0xFFFFFFFF} AND objsubid=1"
)


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--backend", required=True)
    parser.add_argument("--postgres", required=True)
    parser.add_argument("--logdb", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    prefix = "freesdn-startup-" + uuid.uuid4().hex[:10]
    password, key, salt = [secrets.token_hex(32) for _ in range(3)]
    containers, processes = [], []
    report = {"cases": [], "production_access": False, "published_ports": False}

    def clean(value):
        for secret in (password, key, salt):
            value = value.replace(secret, "[REDACTED]")
        return value

    def command(*argv, data=None, check=True):
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if check and result.returncode:
            raise AssertionError(clean(result.stderr)[-2000:])
        return result

    def sql(container, statement):
        return command(
            "exec",
            "-i",
            container,
            "psql",
            "-U",
            "freesdn",
            "-d",
            "freesdn",
            "-XqAt",
            "-v",
            "ON_ERROR_STOP=1",
            data=statement,
        ).stdout.strip()

    def case(message):
        report["cases"].append(message)
        print("PASS", message, flush=True)

    command(
        "network",
        "create",
        "--internal",
        "--label",
        "freesdn.qualification=" + prefix,
        prefix,
    )
    try:
        for alias, image in [("postgres", args.postgres), ("logdb", args.logdb)]:
            name = prefix + "-" + alias
            command(
                "run",
                "-d",
                "--name",
                name,
                "--label",
                "freesdn.qualification=" + prefix,
                "--network",
                prefix,
                "--network-alias",
                alias,
                "-e",
                "POSTGRES_USER=freesdn",
                "-e",
                "POSTGRES_DB=freesdn",
                "-e",
                "POSTGRES_PASSWORD=" + password,
                image,
            )
            containers.append(name)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if (
                    command(
                        "exec", name, "pg_isready", "-h", "127.0.0.1", check=False
                    ).returncode
                    == 0
                ):
                    break
                time.sleep(0.1)
            else:
                raise AssertionError(alias + " did not start")
        backend = prefix + "-backend"
        env = {
            "DATABASE_URL": f"postgresql+asyncpg://freesdn:{password}@postgres/freesdn",
            "LOGDB_URL": f"postgresql+asyncpg://freesdn:{password}@logdb/freesdn",
            "SECRET_KEY": key,
            "ENCRYPTION_SALT": salt,
            "POSTGRES_PASSWORD": password,
            "ENVIRONMENT": "development",
            "PYTHONPATH": "/app",
            "ADAPTER_READ_ONLY": "true",
        }
        command(
            "run",
            "-d",
            "--name",
            backend,
            "--label",
            "freesdn.qualification=" + prefix,
            "--network",
            prefix,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/tmp",
            "--entrypoint",
            "sleep",
            *[item for k, v in env.items() for item in ("-e", k + "=" + v)],
            args.backend,
            "infinity",
        )
        containers.append(backend)
        report["images"] = {
            name: json.loads(command("inspect", name).stdout)[0]["Image"]
            for name in containers
        }
        assert command("exec", backend, "id", "-u").stdout.strip() == "1001"
        case("real production backend runs migrations as UID 1001 on a read-only root")
        with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
            os.chmod(temporary, 0o700)
            for alias, script in [
                ("postgres", "migrate.py"),
                ("logdb", "migrate_logdb.py"),
            ]:
                database = prefix + "-" + alias
                holder = subprocess.Popen(
                    [
                        args.docker,
                        "exec",
                        "-i",
                        database,
                        "psql",
                        "-U",
                        "freesdn",
                        "-d",
                        "freesdn",
                        "-XqAt",
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                processes.append(holder)
                holder.stdin.write(
                    "SET application_name='freesdn_startup_qualification_holder'; BEGIN; "
                    f"SELECT pg_advisory_xact_lock({LOCK}); SELECT pg_sleep(120); COMMIT;"
                )
                holder.stdin.close()
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if (
                        sql(
                            database,
                            LOCK_QUERY + " AND granted",
                        )
                        == "1"
                    ):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("Migration barrier was not acquired")
                waiters = []
                handles = []
                try:
                    for index in range(3):
                        output = Path(temporary) / f"{alias}-{index}.log"
                        handle = output.open("w")
                        handles.append(handle)
                        proc = subprocess.Popen(
                            [
                                args.docker,
                                "exec",
                                backend,
                                "python",
                                "scripts/" + script,
                            ],
                            stdout=handle,
                            stderr=subprocess.STDOUT,
                        )
                        processes.append(proc)
                        waiters.append((proc, output))
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline:
                        assert all(proc.poll() is None for proc, _ in waiters), (
                            "A waiting migration exited early"
                        )
                        if (
                            sql(
                                database,
                                LOCK_QUERY + " AND NOT granted",
                            )
                            == "3"
                        ):
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError(
                            alias + " startup scripts did not serialize"
                        )
                    assert (
                        sql(
                            database,
                            "SELECT count(*) FROM pg_namespace WHERE nspname IN ('core','analytics')",
                        )
                        == "0"
                    )
                    case(
                        alias
                        + ": three concurrent startups wait before any application DDL"
                    )
                    sql(
                        database,
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='freesdn_startup_qualification_holder'",
                    )
                    holder.wait(timeout=15)
                    for proc, output in waiters:
                        proc.wait(timeout=120)
                        assert proc.returncode == 0, clean(output.read_text())[-2000:]
                    case(
                        alias
                        + ": terminated lock owner releases all three successful migrations"
                    )
                    assert (
                        sql(
                            database,
                            LOCK_QUERY,
                        )
                        == "0"
                    )
                    command("exec", backend, "python", "scripts/" + script)
                    case(
                        alias
                        + ": subsequent startup is idempotent and no guard lock is leaked"
                    )
                finally:
                    for handle in handles:
                        handle.close()
            assert (
                sql(
                    prefix + "-logdb",
                    "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_schema IN ('analytics','vpn','events','agents')",
                )
                == "4"
            )
            assert (
                sql(
                    prefix + "-logdb",
                    "SELECT count(*) FROM timescaledb_information.continuous_aggregates",
                )
                == "3"
            )
            assert (
                sql(
                    prefix + "-logdb",
                    "SELECT count(*) FROM timescaledb_information.jobs WHERE proc_name='policy_retention'",
                )
                == "4"
            )
            case(
                "LogDB retains exactly four application hypertables, three aggregates and four retention policies"
            )
        report["passed"] = True
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=15)
        for container in reversed(containers):
            command("rm", "-fv", container, check=False)
        command("network", "rm", prefix, check=False)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
