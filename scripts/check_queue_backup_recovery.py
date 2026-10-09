#!/usr/bin/env python3
"""Qualify saved RDB/multipart AOF loading with owned synthetic fixtures only.

No source-container/volume argument exists: this is NOT a customer migration tool.
All containers use network=none (clients share only an owned namespace), no ports,
read-only roots and bounded tmpfs. Only report.json is intended for publication.
--work-dir must be NEW and private on a POSIX filesystem. Existing backups, images,
networks and hardware are never modified. Requires retained trusted images.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

OWNER = "freesdn.queue-backup-qualification"
MAX_BUNDLE = 64 * 1024 * 1024


def validate_bundle(files, mode):
    """Refuse unsafe/incomplete fixture bundles before copying into scratch."""
    if (
        mode not in ("rdb", "aof")
        or not files
        or sum(map(len, files.values())) > MAX_BUNDLE
    ):
        raise ValueError("invalid_or_oversized_bundle")
    if any(not isinstance(v, bytes) or not v for v in files.values()):
        raise ValueError("empty_or_invalid_backup_member")
    if mode == "rdb":
        if set(files) != {"dump.rdb"}:
            raise ValueError("rdb_bundle_members")
        return
    manifest = "appendonlydir/appendonly.aof.manifest"
    try:
        lines = files[manifest].decode("ascii").splitlines()
    except (KeyError, UnicodeError) as exc:
        raise ValueError("missing_or_invalid_aof_manifest") from exc
    names, identities = set(), set()
    kinds = []
    for line in lines:
        match = re.fullmatch(
            r"file (appendonly\.aof\.[1-9][0-9]*\.(?:base\.(?:rdb|aof)|incr\.aof)) seq ([1-9][0-9]*) type ([bi])",
            line,
        )
        if not match:
            raise ValueError("unsupported_aof_manifest_record")
        name, sequence, kind = match.groups()
        if name in names or (sequence, kind) in identities:
            raise ValueError("duplicate_aof_manifest_record")
        if (kind == "b") != (".base." in name):
            raise ValueError("aof_manifest_type_mismatch")
        names.add(name)
        identities.add((sequence, kind))
        kinds.append(kind)
    # The generated fixture always has one base followed by incremental data.
    # This narrow gate deliberately does not claim every Redis/Valkey format.
    if not kinds or kinds[0] != "b" or kinds.count("b") != 1 or "i" not in kinds:
        raise ValueError("unsupported_aof_layout")
    expected = {manifest, *("appendonlydir/" + name for name in names)}
    if set(files) - {"dump.rdb"} != expected:
        raise ValueError("missing_or_unexpected_aof_member")


def compare_snapshot(expected, observed, now_ms):
    """Compare every logical key; allow only explicitly observed elapsed TTLs."""

    def index(snapshot):
        rows = snapshot["rows"]
        result = {(r["db"], r["key_b64"]): r for r in rows}
        if len(result) != len(rows) or snapshot["keys"] != len(rows):
            raise ValueError("invalid_snapshot")
        return result

    before, after = index(expected), index(observed)
    expired = 0
    for key, row in before.items():
        if key not in after:
            if 0 < row["expires_at_ms"] <= now_ms:
                expired += 1
                continue
            raise ValueError("restored_key_missing")
        if after.pop(key) != row:
            raise ValueError("restored_value_order_or_expiry_changed")
    if after:
        raise ValueError("unexpected_restored_key")
    return {
        "expected_keys": len(before),
        "restored_keys": observed["keys"],
        "expired_keys": expired,
    }


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in sorted(files.items()):
            if name != "dump.rdb" and not re.fullmatch(
                r"appendonlydir/[a-zA-Z0-9.]+", name
            ):
                raise ValueError("unsafe_backup_path")
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(data), 0o600, 1001, 1001
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def unpack_fixture_tar(raw):
    if len(raw) > MAX_BUNDLE:
        raise ValueError("fixture_bundle_too_large")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for entry in archive:
            if entry.isdir() and entry.name.rstrip("/") == "appendonlydir":
                continue
            if not entry.isfile() or entry.name in files or entry.size > MAX_BUNDLE:
                raise ValueError("unsafe_fixture_tar_member")
            if entry.name != "dump.rdb" and not re.fullmatch(
                r"appendonlydir/[a-zA-Z0-9.]+", entry.name
            ):
                raise ValueError("unsafe_fixture_tar_path")
            stream = archive.extractfile(entry)
            if stream is None:
                raise ValueError("missing_fixture_tar_member")
            files[entry.name] = stream.read(MAX_BUNDLE + 1)
    return files


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--valkey-image", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir
    if os.name != "posix" or not work.is_absolute() or work.exists():
        parser.error("--work-dir must be a NEW absolute private POSIX directory")
    os.umask(0o077)
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error("private filesystem permissions required")
    scripts = Path(__file__).parent
    prefix = "freesdn-queue-backup-" + uuid.uuid4().hex[:12]
    owned = {}
    sequence = 0
    options = {
        "password": secrets.token_urlsafe(32),
        "argument_secret": secrets.token_urlsafe(32),
        "result_secret": secrets.token_urlsafe(32),
    }
    (work / "synthetic-secrets.json").write_text(json.dumps(list(options.values())))
    auth = work / "auth.json"
    auth.write_text(json.dumps({"password": options["password"]}))
    report = {
        "passed": False,
        "cases": [],
        "hardware_access": False,
        "published_ports": False,
        "customer_backup_qualified": False,
        "authoritative_source_verified": False,
        "production_replay_authorized": False,
        "ha_cutover_qualified": False,
        "cleanup_complete": False,
    }
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def command(*argv, data=None, check=True, timeout=60):
        response = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and response.returncode:
            (work / ("failure-" + uuid.uuid4().hex + ".log")).write_bytes(
                response.stdout + response.stderr
            )
            raise RuntimeError("Docker fixture command failed; see private logs")
        return response

    def inspect(name):
        return json.loads(command("inspect", name).stdout)[0]

    def remove(name):
        found = command("inspect", name, check=False)
        if found.returncode:
            # Missing after an uncertain creation is safe only if the daemon can
            # enumerate containers successfully and the owned name is absent.
            names = (
                command("ps", "-a", "--format={{.Names}}").stdout.decode().splitlines()
            )
            if name in names:
                raise RuntimeError("Owned fixture inspect failed")
            owned.pop(name, None)
            return
        obj = json.loads(found.stdout)[0]
        if obj["Config"].get("Labels", {}).get(OWNER) != prefix:
            raise RuntimeError("Fixture ownership mismatch")
        if owned[name] and owned[name] != obj["Id"]:
            raise RuntimeError("Fixture identity changed")
        command("rm", "-f", obj["Id"])
        del owned[name]

    def case(label, details=None):
        report["cases"].append({"case": label, "details": details})
        print("PASS", label, flush=True)

    def server(label, files=None, mode="rdb"):
        nonlocal sequence
        sequence += 1
        name = prefix + "-" + label + "-" + str(sequence)
        owned[name] = None
        response = command(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            OWNER + "=" + prefix,
            "--label",
            "freesdn.queue-inventory.disposable-copy=true",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/data:rw,mode=1777,size=128m",
            "--tmpfs",
            "/tmp:rw,mode=1777,size=16m",
            "--memory=384m",
            "--memory-swap=384m",
            "--pids-limit=64",
            "--user=1001:1001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--no-healthcheck",
            "--entrypoint=sleep",
            report["images"]["valkey"],
            "infinity",
        )
        owned[name] = response.stdout.decode().strip()
        if files:
            command(
                "exec",
                "-i",
                name,
                "tar",
                "-xpf",
                "-",
                "-C",
                "/data",
                data=tar_bytes(files),
            )
        config = (
            'bind 127.0.0.1\nport 6379\nsave ""\ndir /data\nmaxmemory 96mb\nmaxmemory-policy noeviction\n'
            "appendonly "
            + ("yes" if mode == "aof" else "no")
            + "\naof-load-truncated no\nauto-aof-rewrite-percentage 0\n"
            "daemonize yes\nlogfile /tmp/restore.log\nrequirepass "
            + options["password"]
            + "\n"
        )
        command(
            "exec",
            "-i",
            name,
            "sh",
            "-c",
            "umask 077; cat > /tmp/fixture.conf",
            data=config.encode(),
        )
        command("exec", name, "valkey-server", "/tmp/fixture.conf")
        return name

    def client(name, mode, extra=None, *, original=False):
        nonlocal sequence
        sequence += 1
        helper = prefix + "-client-" + str(sequence)
        owned[helper] = None
        script = (
            scripts
            / "qualification"
            / ("queue_inventory_fixture.py" if original else "queue_backup_fixture.py")
        )
        loader = "import json,sys; p=json.load(sys.stdin); n={'__name__':'fixture_import'}; exec(compile(p['script'],'fixture.py','exec'),n); print(json.dumps(n['main'](p['options']),sort_keys=True))"
        response = command(
            "create",
            "-i",
            "--name",
            helper,
            "--label",
            OWNER + "=" + prefix,
            "--network",
            "container:" + owned[name],
            "--read-only",
            "--tmpfs",
            "/tmp:rw,mode=1777,size=32m",
            "--user=1001:1001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--memory-swap=512m",
            "--pids-limit=64",
            "--entrypoint=python",
            report["images"]["backend"],
            "-c",
            loader,
        )
        owned[helper] = response.stdout.decode().strip()
        try:
            response = command(
                "start",
                "-ai",
                helper,
                data=json.dumps(
                    {
                        "script": script.read_text(),
                        "options": {**options, "mode": mode, **(extra or {})},
                    }
                ).encode(),
                timeout=120,
            )
            (work / ("client-" + str(sequence) + ".json")).write_bytes(response.stdout)
            return json.loads(response.stdout)
        finally:
            remove(helper)

    def backup(name):
        response = command(
            "exec", name, "tar", "-cf", "-", "-C", "/data", "dump.rdb", "appendonlydir"
        )
        return unpack_fixture_tar(response.stdout)

    def inventory(name, label):
        destination = work / label
        result = subprocess.run(
            [
                sys.executable,
                str(scripts / "inventory_legacy_queues.py"),
                "--docker",
                args.docker,
                "--source-container",
                owned[name],
                "--backend-image",
                report["images"]["backend"],
                "--auth-file",
                str(auth),
                "--work-dir",
                str(destination),
            ],
            capture_output=True,
            timeout=240,
            check=False,
        )
        (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
        receipt = json.loads((destination / "receipt.json").read_text())
        assert (
            result.returncode == 0
            and receipt["inventory_complete"]
            and receipt["probe_removed"]
        ), receipt
        assert not receipt["replay_authorized"] and not receipt["cutover_qualified"]
        return receipt

    try:
        report["images"] = {
            kind: command("image", "inspect", "--format={{.Id}}", image)
            .stdout.decode()
            .strip()
            for kind, image in (
                ("backend", args.backend_image),
                ("valkey", args.valkey_image),
            )
        }
        assert all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            for value in report["images"].values()
        )
        source = server("source")
        seeded = client(source, "clean", original=True)
        report["transport_versions"] = seeded["versions"]
        rdb_expected = client(source, "prepare-rdb")
        aof_expected = client(source, "prepare-aof")
        assert aof_expected != rdb_expected, "AOF must contain newer state than the RDB"
        # Shutdown of this OWNED fixture fences all writes and flushes its AOF.
        # No rewrite occurs while the complete multipart directory is copied.
        command(
            "exec",
            "-i",
            source,
            "sh",
            "-c",
            "read -r REDISCLI_AUTH; export REDISCLI_AUTH; valkey-cli shutdown nosave",
            data=(options["password"] + "\n").encode(),
        )
        saved = backup(source)
        validate_bundle(saved, "aof")
        original_hashes = {k: hashlib.sha256(v).hexdigest() for k, v in saved.items()}
        (work / "original-backup.tar").write_bytes(tar_bytes(saved))
        (work / "original-backup-manifest.json").write_text(
            json.dumps(
                {
                    "image_id": report["images"]["valkey"],
                    "files": original_hashes,
                    "rdb_expected": rdb_expected,
                    "aof_expected": aof_expected,
                },
                indent=2,
            )
        )
        case(
            "complete-fenced-backup-captured",
            {
                "files": len(saved),
                "rdb_keys": rdb_expected["keys"],
                "aof_keys": aof_expected["keys"],
            },
        )
        restored_for_review = None
        for label, mode, files, expected in (
            ("rdb-only-load", "rdb", {"dump.rdb": saved["dump.rdb"]}, rdb_expected),
            (
                "aof-only-load",
                "aof",
                {k: v for k, v in saved.items() if k != "dump.rdb"},
                aof_expected,
            ),
            ("mixed-backup-loads-newer-aof", "aof", saved, aof_expected),
        ):
            validate_bundle(files, mode)
            target = server(label, files, mode)
            assert client(target, "ready")["ready"]
            observed = client(target, "disable-persistence")
            comparison = compare_snapshot(expected, observed, int(time.time() * 1000))
            receipt = inventory(target, label + "-inventory")
            compare_snapshot(
                expected, client(target, "snapshot"), int(time.time() * 1000)
            )
            case(
                label,
                {**comparison, "inventory_complete": receipt["inventory_complete"]},
            )
            if label == "mixed-backup-loads-newer-aof":
                restored_for_review = target
            else:
                remove(target)
        for label, files in (
            (
                "aof-only-wrong-mode-empty-detected",
                {k: v for k, v in saved.items() if k != "dump.rdb"},
            ),
            ("mixed-wrong-mode-stale-rdb-detected", saved),
        ):
            target = server(label, files, "rdb")
            assert client(target, "ready")["ready"]
            try:
                compare_snapshot(
                    aof_expected, client(target, "snapshot"), int(time.time() * 1000)
                )
            except ValueError:
                case(label)
            else:
                raise AssertionError("Wrong persistence mode falsely accepted")
            remove(target)
        incr = next(k for k in saved if k.endswith(".incr.aof"))
        for label, files in (
            (
                "missing-increment-refused",
                {k: v for k, v in saved.items() if k != incr},
            ),
            (
                "missing-manifest-refused",
                {k: v for k, v in saved.items() if not k.endswith(".manifest")},
            ),
            (
                "unlisted-member-refused",
                {**saved, "appendonlydir/unknown.aof": b"unexpected"},
            ),
        ):
            try:
                validate_bundle(files, "aof")
            except ValueError:
                case(label)
            else:
                raise AssertionError("Incomplete multipart backup accepted")
        corrupt_rdb = bytearray(saved["dump.rdb"])
        corrupt_rdb[-1] ^= 0xFF
        for label, mode, files in (
            (
                "rdb-checksum-corruption-refused",
                "rdb",
                {"dump.rdb": bytes(corrupt_rdb)},
            ),
            ("truncated-increment-refused", "aof", {**saved, incr: saved[incr][:-5]}),
            (
                "malformed-increment-refused",
                "aof",
                {**saved, incr: b"!" + saved[incr][1:]},
            ),
        ):
            target = server(label, files, mode)
            assert not client(target, "ready")["ready"], "Damaged backup became ready"
            (work / (label + ".log")).write_bytes(
                command("exec", target, "cat", "/tmp/restore.log").stdout
            )
            case(label)
            remove(target)
        expiry_source = server("expiry-source", {"dump.rdb": saved["dump.rdb"]})
        expiry_expected = client(expiry_source, "expire-result-and-save")
        command(
            "exec",
            "-i",
            expiry_source,
            "sh",
            "-c",
            "read -r REDISCLI_AUTH; export REDISCLI_AUTH; valkey-cli shutdown nosave",
            data=(options["password"] + "\n").encode(),
        )
        expiry_files = unpack_fixture_tar(
            command(
                "exec", expiry_source, "tar", "-cf", "-", "-C", "/data", "dump.rdb"
            ).stdout
        )
        time.sleep(1.6)
        expiry_target = server("expiry-target", expiry_files)
        expiry_observed = client(expiry_target, "snapshot")
        compared = compare_snapshot(
            expiry_expected, expiry_observed, int(time.time() * 1000)
        )
        assert compared["expired_keys"] == 1
        inventory(expiry_target, "expired-result-inventory")
        case("expired-result-accounted-without-authorizing-replay", compared)
        remove(expiry_target)
        remove(expiry_source)
        assert restored_for_review is not None
        review = client(restored_for_review, "review")
        assert (
            len(review["decisions"]) == 120 and len(review["quarantined_reserved"]) == 1
        )
        (work / "synthetic-reviewed-manifest.json").write_text(
            json.dumps(review, indent=2)
        )
        # An abandoned empty target before first write leaves retained source
        # backups available. This says nothing about rollback after device writes.
        abandoned = server("prewrite-rollback")
        assert client(abandoned, "snapshot")["keys"] == 0
        remove(abandoned)
        assert backup(source) == saved
        case("prewrite-target-abandonment-preserves-backup")
        worker_target = server("worker-target")
        consumed = client(worker_target, "consume-reviewed", {"review": review})
        case("reviewed-empty-target-real-celery-consumption", consumed)
        compare_snapshot(
            aof_expected,
            client(restored_for_review, "snapshot"),
            int(time.time() * 1000),
        )
        assert backup(source) == saved
        assert (
            hashlib.sha256((work / "original-backup.tar").read_bytes()).hexdigest()
            == hashlib.sha256(tar_bytes(saved)).hexdigest()
        )
        case("original-backup-and-isolated-copy-unchanged-after-consumption")
        report["passed"] = True
    except (
        AssertionError,
        RuntimeError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        tarfile.TarError,
        KeyboardInterrupt,
    ) as exc:
        report["failure_type"] = type(exc).__name__
        (work / "failure.txt").write_text(str(exc))
    finally:
        failures = []
        for name in list(owned):
            try:
                remove(name)
            except (
                RuntimeError,
                OSError,
                subprocess.SubprocessError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
            ):
                failures.append(name)
        report["cleanup_complete"] = not failures
        if failures:
            report["passed"] = False
            (work / "cleanup-required.json").write_text(
                json.dumps({name: owned[name] for name in failures}, indent=2)
            )
        # Never expose passwords, raw queue envelopes, task arguments or results.
        encoded = json.dumps(report, indent=2, sort_keys=True)
        if any(secret in encoded for secret in options.values()):
            report = {
                "passed": False,
                "failure_type": "unsafe_receipt",
                "cleanup_complete": not failures,
            }
            encoded = json.dumps(report, indent=2)
        temporary = work / "report-final.json"
        temporary.write_text(encoded + "\n")
        temporary.replace(work / "report.json")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "cases": len(report.get("cases", [])),
                "cleanup_complete": report["cleanup_complete"],
            }
        ),
        flush=True,
    )
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
