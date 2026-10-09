#!/usr/bin/env python3
"""Qualify offline queue inventory using owned real Valkey and Celery fixtures.

Creates disposable network=none containers plus an owned internal network for
a negative isolation check: no ports, production volumes,
external hardware, live credentials or task execution. --work-dir must be NEW,
private and POSIX. Only report.json is intended for release evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path


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
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error("private filesystem permissions required")
    os.umask(0o077)
    prefix = "freesdn-queue-fixture-" + uuid.uuid4().hex[:12]
    source = prefix + "-source"
    owned = []
    guard_network = prefix + "-guard-network"
    network_attempted = False
    report = {
        "passed": False,
        "cases": [],
        "published_ports": False,
        "hardware_access": False,
        "job_replay": False,
    }
    options = {
        "password": secrets.token_urlsafe(32),
        "argument_secret": secrets.token_urlsafe(40),
        "result_secret": secrets.token_urlsafe(40),
    }
    (work / "synthetic-secrets.json").write_text(json.dumps(list(options.values())))
    auth = work / "auth.json"
    auth.write_text(json.dumps({"password": options["password"]}))
    scripts = Path(__file__).parent
    fixture_script = (scripts / "qualification/queue_inventory_fixture.py").read_text()
    counter = 0

    def command(*argv, data=None, timeout=60, check=True):
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            (work / ("failure-" + uuid.uuid4().hex + ".log")).write_bytes(
                result.stdout + result.stderr
            )
            raise AssertionError("Docker fixture command failed; see private logs")
        return result

    def case(label, details=None):
        report["cases"].append({"case": label, "details": details})
        print("PASS", label, flush=True)

    def fixture(mode):
        nonlocal counter
        counter += 1
        name = prefix + "-client-" + str(counter)
        owned.append(name)
        loader = "import json,sys; p=json.load(sys.stdin); n={'__name__':'fixture_import'}; exec(compile(p['script'],'queue_inventory_fixture.py','exec'),n); print(json.dumps(n['main'](p['options']),sort_keys=True))"
        command(
            "create",
            "-i",
            "--name",
            name,
            "--label",
            "freesdn.queue-qualification=" + prefix,
            "--network",
            "container:" + source,
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--user",
            "1001:1001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint",
            "python",
            args.backend_image,
            "-c",
            loader,
        )
        opts = {**options, "mode": mode}
        if mode == "change-during-probe":
            opts["probe_script"] = (
                scripts / "qualification/queue_inventory_probe.py"
            ).read_text()
        try:
            output = command(
                "start",
                "-ai",
                name,
                data=json.dumps({"script": fixture_script, "options": opts}).encode(),
                timeout=120,
            )
            (work / f"fixture-{counter}.json").write_bytes(output.stdout)
            return json.loads(output.stdout)
        finally:
            command("rm", "-f", name)
            owned.remove(name)

    def inventory(label, complete, *, extra=(), code=None):
        target = work / label
        before = fixture("snapshot")
        result = subprocess.run(
            [
                sys.executable,
                str(scripts / "inventory_legacy_queues.py"),
                "--docker",
                args.docker,
                "--source-container",
                source,
                "--backend-image",
                args.backend_image,
                "--auth-file",
                str(auth),
                "--work-dir",
                str(target),
                *extra,
            ],
            capture_output=True,
            timeout=240,
            check=False,
        )
        (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
        receipt = json.loads((target / "receipt.json").read_text())
        assert result.returncode == (0 if complete else 2), receipt
        assert receipt["inventory_complete"] is complete and receipt["probe_removed"]
        assert not receipt["replay_authorized"] and not receipt["cutover_qualified"]
        if code:
            assert receipt["failure_code"] == code, receipt
        assert fixture("snapshot") == before, "Inventory changed fixture keys/expiry"
        assert all(secret not in json.dumps(receipt) for secret in options.values())
        assert all(p.stat().st_mode & 0o077 == 0 for p in target.iterdir())
        case(label, receipt)
        if (target / "probe-output.json").exists():
            return json.loads((target / "probe-output.json").read_text())
        return {"receipt": receipt}

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
        owned.append(source)
        command(
            "run",
            "-d",
            "--name",
            source,
            "--label",
            "freesdn.queue-qualification=" + prefix,
            "--label",
            "freesdn.queue-inventory.disposable-copy=true",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/data:rw,mode=1777,size=128m",
            "--tmpfs",
            "/tmp",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--no-healthcheck",
            "--user",
            "1001:1001",
            "--entrypoint",
            "sleep",
            args.valkey_image,
            "infinity",
        )
        config = (
            'bind 127.0.0.1\nport 6379\nsave ""\nappendonly no\ndir /data\nmaxmemory 96mb\nmaxmemory-policy noeviction\nrequirepass '
            + options["password"]
            + "\n"
        )
        command(
            "exec",
            "-i",
            source,
            "sh",
            "-c",
            "umask 077; cat > /tmp/inventory-valkey.conf",
            data=config.encode(),
        )
        command("exec", "-d", source, "valkey-server", "/tmp/inventory-valkey.conf")
        fixture("empty")
        inventory("empty-all-databases", True)
        seeded = fixture("clean")
        report["transport_versions"] = seeded["versions"]
        output = inventory("all-queues-priorities-and-reserved", True)
        rows = output["private"]["inventory"]["messages"]
        assert len(rows) == 120 and sum(r["location"] == "reserved" for r in rows) == 1
        observed = {}
        for row in sorted(rows, key=lambda x: x.get("fifo_index", -1)):
            if row["location"] == "queued":
                observed.setdefault(
                    f"{row['db']}/{row['queue']}/{row['priority_bucket']}", []
                ).append(row["task_id"])
        assert observed == seeded["expected_fifo"]
        case(
            "fifo-order-preserved-in-manifest",
            {"physical_lists": len(observed), "jobs": len(rows)},
        )
        assert output["receipt"]["review_counts"]["completion_unknown"] == 120
        case("missing-results-never-authorize-retry")
        fixture("expired-result")
        expired = inventory("expired-result-stays-unknown", True)
        assert expired["receipt"]["review_counts"]["completion_unknown"] == 120
        assert "terminal_result_present" not in expired["receipt"]["review_counts"]
        fixture("ambiguous")
        output = inventory("duplicates-conflicts-overlap-completed-reserved", True)
        reasons = output["receipt"]["review_counts"]
        assert all(
            reasons.get(k, 0) > 0
            for k in (
                "cross_database_duplicate",
                "conflicting_execution_payload",
                "queued_reserved_overlap",
                "terminal_result_present",
                "conflicting_result_metadata",
            )
        )
        fixture("orphans")
        output = inventory(
            "orphan-reservations-refused",
            False,
            code="unsupported_or_inconsistent_records",
        )
        assert output["receipt"]["issue_counts"]["reserved_hash_without_index"] == 1
        assert output["receipt"]["issue_counts"]["reserved_index_without_hash"] == 1
        fixture("unsupported")
        output = inventory(
            "unknown-prefix-database-protocol-and-pickle-refused",
            False,
            code="unsupported_or_inconsistent_records",
        )
        assert output["receipt"]["issue_counts"]["unsupported_database"] == 1
        assert (
            output["receipt"]["issue_counts"]["unsupported_or_malformed_envelope"] == 3
        )
        # Probe has no writable root or /tmp mount. The marker cannot be created.
        assert (
            b"forbidden-unpickle"
            not in (
                work
                / "unknown-prefix-database-protocol-and-pickle-refused"
                / "receipt.json"
            ).read_bytes()
        )
        fixture("oversized")
        inventory(
            "oversized-envelope-refused",
            False,
            extra=("--max-value-bytes", "65536"),
            code="value_byte_limit",
        )
        fixture("clean")
        inventory("key-cap-refused", False, extra=("--max-keys", "2"), code="key_limit")
        inventory(
            "record-cap-refused",
            False,
            extra=("--max-records", "2"),
            code="record_limit",
        )
        inventory(
            "byte-cap-refused",
            False,
            extra=("--max-total-bytes", "4096"),
            code="total_byte_limit",
        )
        changed = fixture("change-during-probe")
        assert (
            changed["receipt"]["failure_code"] == "source_changed_during_inventory"
        ), changed["receipt"]
        assert not changed["receipt"]["inventory_complete"]
        case("write-then-delete-detected-with-identical-final-keys", changed["receipt"])
        fixture("enable-persistence")
        inventory(
            "persistence-enabled-copy-refused", False, code="source_persistence_enabled"
        )
        fixture("disable-persistence")
        network_attempted = True
        command(
            "network",
            "create",
            "--internal",
            "--label",
            "freesdn.queue-qualification=" + prefix,
            guard_network,
        )
        for label, network, readonly, marked, code in (
            (
                "network-attached-source-refused",
                guard_network,
                True,
                True,
                "source_not_network_isolated",
            ),
            (
                "unmarked-source-refused",
                "none",
                True,
                False,
                "source_not_marked_disposable_copy",
            ),
            (
                "writable-root-source-refused",
                "none",
                False,
                True,
                "source_container_not_restricted",
            ),
            (
                "namespace-peer-refused",
                "container:" + source,
                True,
                True,
                "source_has_network_namespace_peer",
            ),
        ):
            guard = prefix + "-" + label
            owned.append(guard)
            command(
                "run",
                "-d",
                "--name",
                guard,
                "--label",
                "freesdn.queue-qualification=" + prefix,
                "--label",
                "freesdn.queue-inventory.disposable-copy=" + str(marked).lower(),
                "--network",
                network,
                *(["--read-only"] if readonly else []),
                "--tmpfs",
                "/data",
                "--no-healthcheck",
                "--entrypoint",
                "sleep",
                args.valkey_image,
                "infinity",
            )
            selected = source if label == "namespace-peer-refused" else guard
            inventory(label, False, extra=("--source-container", selected), code=code)
            command("rm", "-f", guard)
            owned.remove(guard)
        report["passed"] = True
    finally:
        cleanup = []
        for name in reversed(owned):
            try:
                inspection = json.loads(command("inspect", name).stdout)[0]
                assert (
                    inspection["Config"]["Labels"].get("freesdn.queue-qualification")
                    == prefix
                )
                command("rm", "-f", inspection["Id"])
                cleanup.append({"name": name, "removed": True})
            except (
                OSError,
                subprocess.SubprocessError,
                ValueError,
                KeyError,
                AssertionError,
            ):
                cleanup.append({"name": name, "removed": False})
        if network_attempted:
            try:
                inspection = json.loads(
                    command("network", "inspect", guard_network).stdout
                )[0]
                if (
                    inspection.get("Labels", {}).get("freesdn.queue-qualification")
                    != prefix
                ):
                    raise AssertionError("Network ownership mismatch")
                command("network", "rm", inspection["Id"])
                cleanup.append({"name": guard_network, "removed": True})
            except (
                OSError,
                subprocess.SubprocessError,
                ValueError,
                KeyError,
                AssertionError,
            ):
                cleanup.append({"name": guard_network, "removed": False})
        report["owned_resources_removed"] = all(item["removed"] for item in cleanup)
        if not report["owned_resources_removed"]:
            report["passed"] = False
        (work / "cleanup.json").write_text(json.dumps(cleanup, indent=2))
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
