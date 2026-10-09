#!/usr/bin/env python3
"""Qualify the shipped PostgreSQL standby scripts on disposable named volumes.

Checks initial streaming, restart, durable volume recreation, primary loss and
explicit manual promotion. This is not automatic failover or multi-host HA.
"""

import argparse
import io
import json
import secrets
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

# The runtime marker the shipped database images write. MUST match the literal
# in docker/Dockerfile.postgres and docker/Dockerfile.logdb;
# scripts/tests/test_runtime_marker_parity.py gates that. It was hardcoded as
# the Alpine value in two scripts, and the Debian revert left them demanding a
# marker no shipped image writes -- which failed this script outright.
EXPECTED_DATABASE_RUNTIME = "postgresql-18-debian-trixie-v1"


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--image", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    prefix = "freesdn-pg-ha-" + uuid.uuid4().hex[:10]
    password = secrets.token_hex(24)
    containers, volumes, cases = [], [], []
    root = Path(__file__).resolve().parent.parent

    def run(*command, data=None, check=True):
        result = subprocess.run(
            [args.docker, *command],
            input=data,
            capture_output=True,
            timeout=120,
            check=False,
        )
        if check and result.returncode:
            raise AssertionError(
                result.stderr.decode().replace(password, "[REDACTED]")[-2000:]
            )
        return result.stdout.decode().strip()

    def copy(name, path, dest):
        payload = path.read_text().encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo(Path(dest).name)
            info.mode, info.size = 0o755, len(payload)
            archive.addfile(info, io.BytesIO(payload))
        run("cp", "-", name + ":" + str(Path(dest).parent), data=buffer.getvalue())

    def sql(name, query, check=True):
        return run(
            "exec",
            "-i",
            name,
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "freesdn",
            "-d",
            "freesdn",
            data=query.encode(),
            check=check,
        )

    def wait(name, query, expected):
        for _ in range(100):
            if sql(name, query, check=False) == expected:
                return
            time.sleep(0.3)
        raise AssertionError("Database did not reach expected state: " + query)

    def create(role, volume):
        name = prefix + "-" + role
        extra = [] if role == "primary" else ["--entrypoint", "/standby-entrypoint.sh"]
        run(
            "create",
            "--name",
            name,
            "--label",
            "freesdn.qualification=" + prefix,
            "--network",
            prefix,
            "--network-alias",
            role,
            "--memory",
            "768m",
            "--cpus",
            "2",
            "--mount",
            "type=volume,src=" + volume + ",dst=/var/lib/postgresql",
            "-e",
            "POSTGRES_USER=freesdn",
            "-e",
            "POSTGRES_DB=freesdn",
            "-e",
            "POSTGRES_PASSWORD=" + password,
            "-e",
            "REPL_USER=repl",
            "-e",
            "REPL_PASSWORD=" + password,
            "-e",
            "PRIMARY_HOST=primary",
            "-e",
            "PRIMARY_PORT=5432",
            *extra,
            args.image,
        )
        containers.append(name)
        if role == "primary":
            copy(
                name,
                root / "docker/postgres/init-replication.sh",
                "/docker-entrypoint-initdb.d/20-init-replication.sh",
            )
        else:
            copy(
                name,
                root / "docker/postgres/standby-entrypoint.sh",
                "/standby-entrypoint.sh",
            )
        run("start", name)
        return name

    def passed(message):
        cases.append(message)
        print("PASS", message, flush=True)

    created_network = False
    try:
        run(
            "network",
            "create",
            "--internal",
            "--label",
            "freesdn.qualification=" + prefix,
            prefix,
        )
        created_network = True
        for role in ("primary", "standby"):
            volume = prefix + "-" + role
            run(
                "volume", "create", "--label", "freesdn.qualification=" + prefix, volume
            )
            volumes.append(volume)
        primary = create("primary", volumes[0])
        wait(primary, "SELECT 1", "1")
        # The temporary init server also accepts local socket connections.
        for _ in range(100):
            if run("exec", primary, "cat", "/proc/1/comm", check=False) == "postgres":
                break
            time.sleep(0.3)
        sql(
            primary,
            "CREATE TABLE qualification(id int PRIMARY KEY, value text); INSERT INTO qualification VALUES (1,'before bootstrap')",
        )
        standby = create("standby", volumes[1])
        wait(standby, "SELECT pg_is_in_recovery()", "t")
        wait(standby, "SELECT value FROM qualification WHERE id=1", "before bootstrap")
        assert (
            run("exec", standby, "sh", "-c", 'cat "$PGDATA/FREESDN_RUNTIME"')
            == EXPECTED_DATABASE_RUNTIME
        )
        passed("physical bootstrap carries runtime marker and initial rows")
        sql(primary, "INSERT INTO qualification VALUES (2,'streamed')")
        wait(standby, "SELECT value FROM qualification WHERE id=2", "streamed")
        wait(
            primary,
            "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'",
            "1",
        )
        passed("WAL streaming delivers subsequent commits")
        run("restart", standby)
        wait(standby, "SELECT count(*) FROM qualification", "2")
        passed("standby restart keeps replicated data")
        # Recreate container while retaining the NAMED PG18 volume; this catches
        # accidental storage on the base image's anonymous volume.
        run("rm", "-f", standby)
        containers.remove(standby)
        standby = create("standby", volumes[1])
        wait(standby, "SELECT count(*) FROM qualification", "2")
        mounts = json.loads(run("inspect", "--format", "{{json .Mounts}}", standby))
        assert [
            (m["Name"], m["Destination"]) for m in mounts if m["Type"] == "volume"
        ] == [(volumes[1], "/var/lib/postgresql")]
        passed("container recreation retains the intended PostgreSQL 18 named volume")
        run("stop", primary)
        assert sql(standby, "SELECT pg_is_in_recovery()") == "t"
        sql(standby, "SELECT pg_promote(wait=>true,wait_seconds=>30)")
        wait(standby, "SELECT pg_is_in_recovery()", "f")
        sql(standby, "INSERT INTO qualification VALUES (3,'after manual promotion')")
        assert sql(standby, "SELECT count(*) FROM qualification") == "3"
        passed("manual promotion after primary stop permits new writes")
    finally:
        for name in reversed(containers):
            run("rm", "-f", name, check=False)
        for name in reversed(volumes):
            run("volume", "rm", name, check=False)
        if created_network:
            run("network", "rm", prefix, check=False)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {"cases": cases, "automatic_failover": False, "multi_host": False},
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
