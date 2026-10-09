#!/usr/bin/env python3
"""Inventory an isolated disposable Redis/Valkey copy; never replay or migrate jobs.

Read docker/redis/QUEUE-INVENTORY first. Source must be running with network=none,
read-only root/persistent mounts, no healthcheck/restart policy, persistence OFF,
and label freesdn.queue-inventory.disposable-copy=true. Use only a second copy of
retained backups. The tool does NOT select the authoritative source for you.

--auth-file: optional private POSIX JSON file {"username": "...", "password": "..."}.
--work-dir: NEW private absolute POSIX directory. Only receipt.json is shareable.
Exit 0 = complete inventory, NOT safe replay; 2 = refused/incomplete. Always review
private reconciliation and retained application/device evidence before any replay.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path

COPY_LABEL = "freesdn.queue-inventory.disposable-copy"
OWNER_LABEL = "freesdn.queue-inventory.probe"


class Refusal(Exception):
    pass


def validate_source(source):
    host, config, state = source["HostConfig"], source["Config"], source["State"]
    if not state["Running"] or state.get("Paused") or state.get("Restarting"):
        raise Refusal("source_not_running")
    if (
        host["NetworkMode"] != "none"
        or host.get("PortBindings")
        or any(v for v in source["NetworkSettings"].get("Ports", {}).values())
        or set(source["NetworkSettings"].get("Networks", {})) - {"none"}
    ):
        raise Refusal("source_not_network_isolated")
    if (
        not host.get("ReadonlyRootfs")
        or host.get("Privileged")
        or host.get("PidMode")
        or host.get("IpcMode") == "host"
        or host.get("Devices")
        or host.get("CapAdd")
        or host.get("RestartPolicy", {}).get("Name", "no") not in ("", "no")
    ):
        raise Refusal("source_container_not_restricted")
    if config.get("Labels", {}).get(COPY_LABEL) != "true":
        raise Refusal("source_not_marked_disposable_copy")
    if config.get("Healthcheck", {}).get("Test", ["NONE"]) != ["NONE"]:
        raise Refusal("source_healthcheck_enabled")
    if any(m.get("RW") and m["Type"] != "tmpfs" for m in source.get("Mounts", [])):
        raise Refusal("source_has_writable_persistent_mount")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--source-container", required=True)
    parser.add_argument(
        "--backend-image",
        required=True,
        help="retained trusted FreeSDN image with Python/redis",
    )
    parser.add_argument("--auth-file", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--max-keys", type=int, default=10000)
    parser.add_argument("--max-records", type=int, default=10000)
    parser.add_argument("--max-value-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    work = args.work_dir
    if os.name != "posix" or not work.is_absolute() or work.exists():
        parser.error("--work-dir must be a NEW absolute private POSIX directory")
    work.mkdir(mode=0o700)
    if work.stat().st_mode & 0o077:
        parser.error("--work-dir filesystem must enforce 0700 permissions")
    receipt = {
        "schema_version": 1,
        "inventory_complete": False,
        "source_unchanged": False,
        "replay_authorized": False,
        "cutover_qualified": False,
        "backup_provenance_verified": False,
        "authoritative_source_verified": False,
        "failure_code": None,
        "probe_removed": True,
    }
    name = "freesdn-queue-inventory-" + uuid.uuid4().hex[:16]
    probe_id = None
    create_attempted = False

    def private(name, data):
        with (work / name).open("xb") as stream:
            os.chmod(stream.fileno(), 0o600)
            stream.write(data)

    def command(*argv, data=None, timeout=30, check=True):
        response = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if check and response.returncode:
            private(
                "failure-" + uuid.uuid4().hex + ".log",
                response.stdout + response.stderr,
            )
            raise Refusal("docker_command_failed")
        return response

    def inspect(identifier):
        return json.loads(command("inspect", "--type=container", identifier).stdout)[0]

    def assert_no_peers(source_id):
        for identifier in (
            command("ps", "-q", "--no-trunc").stdout.decode().splitlines()
        ):
            mode = (
                command("inspect", "--format={{.HostConfig.NetworkMode}}", identifier)
                .stdout.decode()
                .strip()
            )
            if (
                mode.startswith("container:")
                and inspect(mode.partition(":")[2])["Id"] == source_id
            ):
                raise Refusal("source_has_network_namespace_peer")

    private("receipt.json", (json.dumps(receipt, indent=2) + "\n").encode())
    try:
        limits = {
            k: getattr(args, k)
            for k in ("max_keys", "max_records", "max_value_bytes", "max_total_bytes")
        }
        caps = {
            "max_keys": 100000,
            "max_records": 100000,
            "max_value_bytes": 8 * 1024 * 1024,
            "max_total_bytes": 128 * 1024 * 1024,
        }
        if (
            any(not 1 <= v <= caps[k] for k, v in limits.items())
            or not 1 <= args.timeout <= 600
        ):
            raise Refusal("invalid_limit")
        credentials = {}
        if args.auth_file:
            # Open without following symlinks; require an owned regular private file.
            fd = os.open(args.auth_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                    or info.st_size > 8192
                ):
                    raise Refusal("auth_file_not_private_regular_file")
                credentials = json.loads(stream.read(8193))
            if (
                not isinstance(credentials, dict)
                or set(credentials) - {"username", "password"}
                or any(
                    not isinstance(v, str) or len(v) > 4096
                    for v in credentials.values()
                )
            ):
                raise Refusal("invalid_auth_file")
        source = inspect(args.source_container)
        validate_source(source)
        source_id = source["Id"]
        if not re.fullmatch(r"[0-9a-f]{64}", source_id):
            raise Refusal("invalid_source_id")
        assert_no_peers(source_id)
        image = (
            command("image", "inspect", "--format={{.Id}}", args.backend_image)
            .stdout.decode()
            .strip()
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise Refusal("invalid_probe_image_id")
        private(
            "source.json",
            json.dumps(
                {
                    "container_id": source_id,
                    "image_id": source["Image"],
                    "started_at": source["State"]["StartedAt"],
                    "mounts": source.get("Mounts", []),
                    "probe_image_id": image,
                },
                indent=2,
            ).encode(),
        )
        receipt["probe_image_id"] = image
        script = (
            Path(__file__).parent / "qualification/queue_inventory_probe.py"
        ).read_text()
        payload = json.dumps(
            {"script": script, "options": {**limits, **credentials}}
        ).encode()
        loader = "import json,sys; p=json.load(sys.stdin); exec(compile(p['script'],'queue_inventory_probe.py','exec'),{'__name__':'__main__','OPTIONS':p['options']})"
        create_attempted = True
        response = command(
            "create",
            "-i",
            "--name",
            name,
            "--label",
            OWNER_LABEL + "=" + name,
            "--network",
            "container:" + source_id,
            "--read-only",
            "--user",
            "1001:1001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--memory-swap=512m",
            "--pids-limit=64",
            "--entrypoint",
            "python",
            image,
            "-c",
            loader,
        )
        probe_id = response.stdout.decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", probe_id):
            raise Refusal("invalid_probe_container_id")
        response = command("start", "-ai", probe_id, data=payload, timeout=args.timeout)
        private("probe-output.json", response.stdout)
        output = json.loads(response.stdout)
        receipt.update(output["receipt"])
        final_source = inspect(source_id)
        validate_source(final_source)
        if (
            final_source["State"]["StartedAt"] != source["State"]["StartedAt"]
            or final_source["Image"] != source["Image"]
            or final_source.get("Mounts") != source.get("Mounts")
        ):
            raise Refusal("source_container_changed")
        assert_no_peers(source_id)
    except Refusal as exc:
        receipt.update(
            inventory_complete=False, source_unchanged=False, failure_code=str(exc)
        )
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        KeyboardInterrupt,
    ):
        receipt.update(
            inventory_complete=False,
            source_unchanged=False,
            failure_code="inventory_failed",
        )
    finally:
        if create_attempted:
            try:
                owned = inspect(probe_id or name)
                if owned["Config"].get("Labels", {}).get(OWNER_LABEL) != name:
                    raise Refusal("probe_ownership_mismatch")
                command("rm", "-f", owned["Id"])
            except (
                Refusal,
                OSError,
                subprocess.SubprocessError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
            ):
                receipt.update(
                    inventory_complete=False, probe_removed=False, cleanup_required=True
                )
                private(
                    "cleanup.json",
                    json.dumps(
                        {"owned_probe_name": name, "owned_probe_id": probe_id}
                    ).encode(),
                )
        private(
            "receipt-final.json",
            (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
        )
        os.replace(work / "receipt-final.json", work / "receipt.json")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["inventory_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
