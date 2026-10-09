#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded PostgreSQL ENOSPC/restart drill on a new, owned tmpfs volume.

Linux Docker only. No published ports, customer volumes, host-root filler files,
network peers or hardware. A keeper preserves the tmpfs across database restart.
Only report.json is shareable; the private work directory contains test secrets.
This exercises PostgreSQL storage failure, not application/HA or physical-disk RTO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

MOUNT = "/var/lib/postgresql"
FILLER = MOUNT + "/.freesdn-pressure-fill"


def bounded_size(value: str) -> int:
    try:
        size = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("volume size must be an integer") from exc
    if not 512 <= size <= 1024:
        raise argparse.ArgumentTypeError("volume must be 512..1024 MiB")
    return size


def validate_volume(info: dict, name: str, owner: str, mib: int) -> None:
    expected = {"type": "tmpfs", "device": "tmpfs", "o": f"size={mib}m,mode=1777"}
    if (
        info.get("Name") != name
        or info.get("Driver") != "local"
        or info.get("Options") != expected
        or info.get("Labels", {}).get("freesdn.qualification") != owner
    ):
        raise RuntimeError("Volume ownership or bounded tmpfs definition differs")


def validate_container(info: dict, volume: str, owner: str) -> None:
    mounts = info.get("Mounts", [])
    if (
        info.get("Config", {}).get("Labels", {}).get("freesdn.qualification") != owner
        or info.get("HostConfig", {}).get("NetworkMode") != "none"
        or info.get("HostConfig", {}).get("PortBindings")
        or len(mounts) != 1
        or mounts[0].get("Type") != "volume"
        or mounts[0].get("Name") != volume
        or mounts[0].get("Destination") != MOUNT
        or mounts[0].get("RW") is not True
    ):
        raise RuntimeError(
            "Container has unexpected ownership, network, ports or mounts"
        )


def validate_filesystem(mounts: str, stats: str, mib: int) -> int:
    rows = [line.split() for line in mounts.splitlines()]
    rows = [row for row in rows if len(row) >= 4 and row[1] == MOUNT]
    if len(rows) != 1 or rows[0][2] != "tmpfs" or "rw" not in rows[0][3].split(","):
        raise RuntimeError("Refuse pressure outside the exact writable tmpfs mount")
    try:
        block, total, free = map(int, stats.split())
    except ValueError as exc:
        raise RuntimeError("Cannot verify filesystem bounds") from exc
    if (
        block <= 0
        or total <= 0
        or not 0 <= free <= total
        or block * total != mib * 1024 * 1024
    ):
        raise RuntimeError("Filesystem does not match the configured size bound")
    return block * free


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--postgres",
        required=True,
        help="Existing local PostgreSQL image; never pulled",
    )
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--volume-mib", type=bounded_size, default=512)
    args = parser.parse_args()
    work = args.work_dir
    if work.is_symlink() or (
        work.exists() and (not work.is_dir() or any(work.iterdir()))
    ):
        parser.error("work directory must be new or empty and not a symlink")
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    work.chmod(0o700)
    os.umask(0o077)
    owner = "freesdn-pg-pressure-" + uuid.uuid4().hex[:12]
    volume = owner + "-data"
    owned: list[str] = []
    volume_created = False
    password = secrets.token_urlsafe(48)
    report: dict = {
        "passed": False,
        "scope": "synthetic PostgreSQL storage pressure and restart",
        "published_ports": False,
        "original_volumes_used": False,
        "volume_mib": args.volume_mib,
        "fixture_id": owner,
        "cases": [],
        "cleanup_errors": [],
    }
    started = time.monotonic()

    def docker(*command: str, check: bool = True, timeout: int = 90):
        result = subprocess.run(
            ["docker", *command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            (work / "failure.log").write_text(
                (result.stdout + result.stderr).replace(password, "[REDACTED]")
            )
            raise RuntimeError("Docker operation failed; private diagnostic retained")
        return result

    def inspect(kind: str, name: str) -> dict:
        return json.loads(docker(kind, "inspect", name).stdout)[0]

    def case(name: str, **details) -> None:
        report["cases"].append({"case": name, "details": details})
        print("PASS", name, flush=True)

    def create(alias: str, image: str, *, keeper: bool = False) -> str:
        limits = str(args.volume_mib + 128) + "m" if keeper else "1g"
        name = owner + "-" + alias
        # Track the name before Docker can create it: a client timeout does not
        # prove that the daemon failed to create the resource.
        owned.append(name)
        command = [
            "create",
            "--name",
            name,
            "--label",
            "freesdn.qualification=" + owner,
            "--network",
            "none",
            "--memory",
            limits,
            "--memory-swap",
            limits,
            "--cpus",
            "1",
            "--no-healthcheck",
            "--mount",
            f"type=volume,src={volume},dst={MOUNT}",
            "--env-file",
            str(work / "fixture.env"),
        ]
        if keeper:
            command += ["--entrypoint", "sleep", image, "infinity"]
        else:
            command += [image]
        cid = docker(*command).stdout.strip()
        validate_container(inspect("container", cid), volume, owner)
        docker("start", cid)
        return cid

    def sql(container: str, statement: str, *, check: bool = True):
        return docker(
            "exec",
            container,
            "psql",
            "-X",
            "-h",
            "127.0.0.1",
            "-U",
            "audit_owner",
            "-d",
            "pressure_fixture",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            statement,
            check=check,
            timeout=30,
        )

    def wait_ready(container: str) -> None:
        for _ in range(90):
            result = sql(container, "SELECT 1", check=False)
            if result.returncode == 0 and result.stdout.strip() == "1":
                return
            time.sleep(1)
        raise RuntimeError("Owned PostgreSQL did not become ready")

    try:
        image = json.loads(docker("image", "inspect", "--", args.postgres).stdout)[0][
            "Id"
        ]
        report["postgres_image"] = image
        if docker("volume", "inspect", volume, check=False).returncode == 0:
            raise RuntimeError("Refuse an existing volume name")
        (work / "fixture.env").write_text(
            f"POSTGRES_USER=audit_owner\nPOSTGRES_DB=pressure_fixture\nPOSTGRES_PASSWORD={password}\n"
            f"PGPASSWORD={password}\nPGDATA={MOUNT}/pressure\nLC_ALL=C\n"
        )
        # An ambiguous create failure must never yield a clean resource receipt.
        volume_created = True
        docker(
            "volume",
            "create",
            "--driver",
            "local",
            "--label",
            "freesdn.qualification=" + owner,
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            f"o=size={args.volume_mib}m,mode=1777",
            volume,
        )
        validate_volume(inspect("volume", volume), volume, owner, args.volume_mib)
        keeper = create("keeper", image, keeper=True)
        pg = create("postgres", image)
        wait_ready(pg)
        sql(
            pg,
            "CREATE TABLE pressure_records (id bigint PRIMARY KEY, payload text NOT NULL);"
            "INSERT INTO pressure_records SELECT i, md5(i::text) FROM generate_series(1,1000) AS i;",
        )
        fingerprint_sql = "SELECT count(*),md5(string_agg(id::text||':'||payload,',' ORDER BY id)) FROM pressure_records"
        fingerprint = sql(pg, fingerprint_sql).stdout.strip()
        cluster = sql(
            pg, "SELECT system_identifier FROM pg_control_system()"
        ).stdout.strip()
        sql(pg, "CHECKPOINT")
        mount_text = docker("exec", keeper, "cat", "/proc/mounts").stdout
        stats = docker("exec", keeper, "stat", "-f", "-c", "%S %b %a", MOUNT).stdout
        free = validate_filesystem(mount_text, stats, args.volume_mib)
        case(
            "owned PostgreSQL starts on a verified bounded tmpfs",
            free_bytes=free,
            seed_fingerprint_sha256=hashlib.sha256(fingerprint.encode()).hexdigest(),
        )
        fill = docker(
            "exec",
            keeper,
            "dd",
            "if=/dev/zero",
            "of=" + FILLER,
            "bs=1048576",
            f"count={args.volume_mib + 1}",
            "conv=fsync",
            check=False,
        )
        (work / "fill.log").write_text(fill.stdout + fill.stderr)
        if (
            fill.returncode == 0
            or "no space left on device" not in (fill.stdout + fill.stderr).lower()
        ):
            raise RuntimeError("Filler did not reach verified ENOSPC")
        filled = int(docker("exec", keeper, "stat", "-c", "%s", FILLER).stdout.strip())
        stats = docker("exec", keeper, "stat", "-f", "-c", "%S %b %a", MOUNT).stdout
        remaining = validate_filesystem(mount_text, stats, args.volume_mib)
        if remaining != 0:
            raise RuntimeError("Filesystem still reports free space")
        write = sql(
            pg,
            "BEGIN; SET LOCAL statement_timeout='15s';"
            "INSERT INTO pressure_records SELECT i,md5(random()::text)"
            " FROM generate_series(1001,100000) AS i; COMMIT;",
            check=False,
        )
        (work / "pressure-write.log").write_text(write.stdout + write.stderr)
        if write.returncode == 0:
            raise RuntimeError(
                "Database unexpectedly committed the pressure transaction"
            )
        server_log = docker("logs", pg, check=False)
        (work / "postgres-pressure.log").write_text(
            (server_log.stdout + server_log.stderr).replace(password, "[REDACTED]")
        )
        if (
            "no space left on device"
            not in (write.stderr + server_log.stdout + server_log.stderr).lower()
        ):
            raise RuntimeError(
                "Write failed without an explicit PostgreSQL storage-full error"
            )
        case(
            "real ENOSPC rejects the database transaction",
            filler_bytes=filled,
            free_bytes=remaining,
            write_exit_code=write.returncode,
        )
        # This exact file is the only filler, on the independently verified owned volume.
        validate_volume(inspect("volume", volume), volume, owner, args.volume_mib)
        docker("exec", keeper, "rm", "--", FILLER)
        before_restart = inspect("container", pg)
        if before_restart["State"].get("OOMKilled") or inspect("container", keeper)[
            "State"
        ].get("OOMKilled"):
            raise RuntimeError(
                "Memory failure would invalidate the filesystem-pressure result"
            )
        docker("restart", pg)
        wait_ready(pg)
        if sql(pg, fingerprint_sql).stdout.strip() != fingerprint:
            raise RuntimeError("Original data or failed-transaction atomicity changed")
        if (
            sql(pg, "SELECT system_identifier FROM pg_control_system()").stdout.strip()
            != cluster
        ):
            raise RuntimeError("Restart initialized a different cluster")
        case(
            "original cluster and rows survive restart; failed transaction leaves no rows"
        )
        sql(pg, "INSERT INTO pressure_records VALUES (1001,'recovered-write')")
        sql(pg, "CHECKPOINT")
        if sql(pg, "SELECT count(*) FROM pressure_records").stdout.strip() != "1001":
            raise RuntimeError("Writes did not recover")
        case("new committed writes and checkpoint succeed after space recovery")
        report["passed"] = True
    except (
        RuntimeError,
        ValueError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        report["failure_type"] = type(exc).__name__
        (work / "driver-failure.txt").write_text(
            str(exc).replace(password, "[REDACTED]")
        )
    finally:
        for cid in reversed(owned):
            try:
                info = inspect("container", cid)
                if info["Config"]["Labels"].get("freesdn.qualification") != owner:
                    raise RuntimeError("Refuse cleanup of foreign container")
                docker("rm", "-fv", cid)
            except (
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                OSError,
                subprocess.SubprocessError,
            ) as exc:
                report["cleanup_errors"].append(type(exc).__name__)
        if volume_created:
            try:
                validate_volume(
                    inspect("volume", volume), volume, owner, args.volume_mib
                )
                docker("volume", "rm", volume)
            except (
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                OSError,
                subprocess.SubprocessError,
            ) as exc:
                report["cleanup_errors"].append(type(exc).__name__)
        report["owned_resources_removed"] = not report["cleanup_errors"]
        report["passed"] = report["passed"] and report["owned_resources_removed"]
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (work / "report.json").write_text(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
