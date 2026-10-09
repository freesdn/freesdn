#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Inspect, inventory and scan the source-built FFmpeg component in a local image.

Linux qualification tool. Containers are created but never started. This checks
recorded source pins and runtime hashes; it is not a signed image attestation or
proof that an arbitrary binary was reproducibly compiled from the claimed source.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from uuid import uuid4

IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
RECIPE_FILES = (
    "build.sh",
    "package.sh",
    "install-runtime.sh",
    "source-lock.json",
    "verified-inputs.sha256",
    "posix-ioctl.patch",
    "ffmpeg-devel.asc",
    "NOTICE",
)


class QualificationError(RuntimeError):
    """An incomplete check must fail without printing raw subprocess output."""


def run_bounded(
    args: list[str],
    *,
    limit: int = 2 * 1024 * 1024,
    timeout: float = 60,
    env: dict[str, str] | None = None,
) -> bytes:
    """Bound CLI output, wall time and owned-process lifetime on Linux."""
    if sys.platform != "linux":
        raise QualificationError("Native image qualification requires Linux")
    with subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env
    ) as child:
        data = bytearray()
        selector = selectors.DefaultSelector()
        try:
            assert child.stdout is not None
            selector.register(child.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QualificationError("Qualification subprocess timed out")
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data) + len(chunk) > limit:
                        raise QualificationError(
                            "Qualification subprocess output exceeded its limit"
                        )
                    data.extend(chunk)
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
            if child.returncode:
                raise QualificationError("Qualification subprocess failed")
            return bytes(data)
        finally:
            selector.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def docker_json(*args: str) -> object:
    return json.loads(run_bounded(["docker", *args]))


def unpack_regular_file(payload: bytes, basename: str, maximum: int) -> bytes:
    """Read one bounded regular file without extracting archive paths to disk."""
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise QualificationError("Image file archive has unexpected entries")
        member = members[0]
        if not member.isfile() or member.name != basename or not 0 <= member.size <= maximum:
            raise QualificationError("Image file archive is not the expected bounded regular file")
        stream = archive.extractfile(member)
        if stream is None:
            raise QualificationError("Image file archive is unreadable")
        data = stream.read(maximum + 1)
        if len(data) != member.size:
            raise QualificationError("Image file size is inconsistent")
        return data


def image_file(container: str, path: str, maximum: int = 1024 * 1024) -> bytes:
    payload = run_bounded(["docker", "cp", f"{container}:{path}", "-"], limit=maximum + 64 * 1024)
    return unpack_regular_file(payload, PurePosixPath(path).name, maximum)


def runtime_files(data: bytes) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(
            r"([a-f0-9]{64})  (usr/local/(?:bin/[a-z0-9-]+|lib/lib(?:av|sw)[a-z0-9]+\.so\.[0-9.]+))",
            line,
        )
        if not match or match[2] in entries:
            raise QualificationError("Runtime hash inventory contains an invalid or duplicate path")
        entries[match[2]] = match[1]
    binaries = {"usr/local/bin/" + n for n in ["ffmpeg", "ffprobe", "ffplay", "qt-faststart"]}
    if not binaries <= entries.keys() or len(entries) != 11:
        raise QualificationError("Runtime hash inventory is incomplete")
    if any(p.startswith("usr/local/bin/") and p not in binaries for p in entries):
        raise QualificationError("Runtime hash inventory contains an unexpected executable")
    families = {
        PurePosixPath(p).name.split(".so.", 1)[0] for p in entries if p.startswith("usr/local/lib/")
    }
    if families != {
        "libavcodec",
        "libavdevice",
        "libavfilter",
        "libavformat",
        "libavutil",
        "libswresample",
        "libswscale",
    }:
        raise QualificationError("Runtime hash inventory does not cover every shared media library")
    return entries


def inspect_payload(container: str, recipe: Path) -> dict:
    expected = json.loads((recipe / "source-lock.json").read_text())
    version = expected.get("version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not DIGEST.fullmatch(
        expected.get("source_sha256", "")
    ):
        raise QualificationError("Checked-out native source lock is invalid")
    if expected.get("source_url") != f"https://ffmpeg.org/releases/ffmpeg-{version}.tar.xz":
        raise QualificationError("Native source URL does not match the locked release")
    prefix = "/usr/share/freesdn-sources/ffmpeg/"
    recipe_hashes = {}
    for name in [*RECIPE_FILES, f"ffmpeg-{version}.tar.xz.asc"]:
        actual = image_file(container, prefix + name)
        if actual != (recipe / name).read_bytes():
            raise QualificationError("Image recipe differs from the checked-out source")
        recipe_hashes[name] = hashlib.sha256(actual).hexdigest()
    archive = image_file(container, prefix + f"ffmpeg-{version}.tar.xz", 32 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != expected["source_sha256"]:
        raise QualificationError("Image source archive does not match its trusted pin")
    inventory = image_file(container, prefix + "runtime-files.sha256")
    files = runtime_files(inventory)
    for path, digest in files.items():
        if (
            hashlib.sha256(image_file(container, "/" + path, 128 * 1024 * 1024)).hexdigest()
            != digest
        ):
            raise QualificationError("Image runtime file does not match the recorded build hash")
    return {
        "version": version,
        "source_url": expected["source_url"],
        "source_sha256": expected["source_sha256"],
        "runtime_files": files,
        "runtime_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        "recipe_hashes": recipe_hashes,
    }


def component_sbom(identity: dict, image_id: str) -> dict:
    version = identity["version"]
    component = {
        "type": "application",
        "name": "ffmpeg",
        "version": version,
        "bom-ref": f"pkg:generic/ffmpeg@{version}",
        "purl": f"pkg:generic/ffmpeg@{version}",
        "cpe": f"cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*",
        "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
        "hashes": [
            {"alg": "SHA-256", "content": identity["runtime_files"]["usr/local/bin/ffmpeg"]}
        ],
        "externalReferences": [
            {
                "type": "distribution",
                "url": identity["source_url"],
                "hashes": [{"alg": "SHA-256", "content": identity["source_sha256"]}],
            }
        ],
        "properties": [
            {
                "name": "freesdn:identity-source",
                "value": "Verified bundled source pin and runtime hash ledger; explicit inventory, not automatic binary discovery",
            },
            {
                "name": "freesdn:runtime-inventory-sha256",
                "value": identity["runtime_inventory_sha256"],
            },
        ],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "container",
                "name": "freesdn-native-media-consumer",
                "version": image_id,
                "bom-ref": image_id,
            }
        },
        "components": [component],
        "dependencies": [{"ref": image_id, "dependsOn": [component["bom-ref"]]}],
    }


def validate_scan(result: object, *, control: bool, now: datetime | None = None) -> int:
    if not isinstance(result, dict) or not isinstance(result.get("matches"), list):
        raise QualificationError("Native scanner returned an incomplete result")
    descriptor = result.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
        raise QualificationError("Native scanner identity is invalid")
    configuration = descriptor.get("configuration")
    matching = configuration.get("match") if isinstance(configuration, dict) else None
    stock = matching.get("stock") if isinstance(matching, dict) else None
    if not isinstance(stock, dict) or stock.get("using-cpes") is not True:
        raise QualificationError("Native CPE matching was not enabled")
    database = descriptor.get("db")
    db = database.get("status") if isinstance(database, dict) else None
    if not isinstance(db, dict):
        raise QualificationError("Native vulnerability database status is missing")
    if db.get("valid") is not True:
        raise QualificationError("Native vulnerability database is invalid")
    try:
        built = datetime.fromisoformat(db["built"].replace("Z", "+00:00"))
        age = (now or datetime.now(UTC)) - built
    except (KeyError, TypeError, ValueError):
        raise QualificationError("Native vulnerability database age is unknown") from None
    if age < -timedelta(minutes=10) or age > timedelta(hours=24):
        raise QualificationError("Native vulnerability database is not current")
    if result.get("ignoredMatches"):
        raise QualificationError("Native scanner suppressed findings")
    configuration = descriptor.get("configuration", {})
    if (
        configuration.get("ignore")
        or configuration.get("only-fixed")
        or configuration.get("only-notfixed")
        or configuration.get("ignore-states")
    ):
        raise QualificationError("Native scanner policy may hide findings")
    matches = result["matches"]
    if any(
        not isinstance(m, dict)
        or not isinstance(m.get("artifact"), dict)
        or not isinstance(m.get("vulnerability"), dict)
        for m in matches
    ):
        raise QualificationError("Native scanner returned malformed matches")
    if control:
        if not matches or any(
            m.get("artifact", {}).get("name") != "ffmpeg"
            or m.get("artifact", {}).get("version") != "4.0"
            or not m.get("vulnerability", {}).get("id")
            for m in matches
        ):
            raise QualificationError("Known-vulnerable metadata control did not match")
    elif matches:
        raise QualificationError("Native component has vulnerability matches requiring review")
    return len(matches)


def scan_component(sbom: dict, work: Path) -> dict:
    grype = shutil.which("grype")
    if not grype:
        raise QualificationError("Grype is required for source-built native media")
    config = work / "grype.yaml"
    config.write_text(
        json.dumps(
            {
                "check-for-app-update": False,
            "match-upstream-kernel-headers": True,
                "ignore": [],
                "match": {"stock": {"using-cpes": True}},
                "db": {"cache-dir": str(work / "db"), "auto-update": True},
            }
        )
    )
    control = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "application",
                "name": "ffmpeg",
                "version": "4.0",
                "purl": "pkg:generic/ffmpeg@4.0",
                "cpe": "cpe:2.3:a:ffmpeg:ffmpeg:4.0:*:*:*:*:*:*:*",
                "description": "Synthetic scanner control only; no old executable installed or run",
            }
        ],
    }
    rows = {}
    for name, document in [("control", control), ("native", sbom)]:
        path = work / (name + ".cdx.json")
        path.write_text(json.dumps(document, indent=2))
        raw = run_bounded(
            [grype, "-c", str(config), "sbom:" + str(path), "-o", "json"],
            limit=64 * 1024 * 1024,
            timeout=600,
        )
        (work / (name + "-findings.json")).write_bytes(raw)
        result = json.loads(raw)
        rows[name] = {
            "matches": validate_scan(result, control=name == "control"),
            "database": result["descriptor"]["db"]["status"],
            "scanner_version": result["descriptor"]["version"],
            "scan_sha256": hashlib.sha256(raw).hexdigest(),
            "sbom_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return rows


def qualify(image: str, recipe: Path, work: Path, report: dict) -> None:
    if not shutil.which("docker") or not shutil.which("grype"):
        raise QualificationError("Docker and Grype are both required")
    metadata = docker_json("image", "inspect", image)
    if (
        not isinstance(metadata, list)
        or len(metadata) != 1
        or not IMAGE_ID.fullmatch(metadata[0].get("Id", ""))
    ):
        raise QualificationError("Local image identity could not be resolved")
    image_id = metadata[0]["Id"]
    report["image_id"] = image_id
    owner = "freesdn-native-inventory-" + uuid4().hex
    args = [
        "docker",
        "create",
        "--pull=never",
        "--name",
        owner,
        "--label",
        "freesdn.qualification=" + owner,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--entrypoint",
        "/bin/false",
    ]
    for volume in metadata[0].get("Config", {}).get("Volumes") or {}:
        if (
            not isinstance(volume, str)
            or not re.fullmatch(r"/[A-Za-z0-9_/-]+", volume)
            or volume == "/"
            or ".." in PurePosixPath(volume).parts
        ):
            raise QualificationError("Image declares an unsupported volume path")
        args += ["--tmpfs", volume + ":rw,size=1m,mode=1777"]
    container = run_bounded([*args, image_id]).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", container):
        raise QualificationError("Owned inspection container identity is invalid")
    try:
        info = docker_json("inspect", container)[0]
        if (
            info["Config"].get("Labels", {}).get("freesdn.qualification") != owner
            or info["State"]["Running"]
            or info["HostConfig"]["NetworkMode"] != "none"
            or info["HostConfig"].get("PortBindings")
            or any(m["Type"] == "volume" for m in info["Mounts"])
        ):
            raise QualificationError("Inspection container safety contract failed")
        identity = inspect_payload(container, recipe)
        report["identity"] = identity
    finally:
        info = docker_json("inspect", container)[0]
        if info["Config"].get("Labels", {}).get("freesdn.qualification") != owner:
            raise QualificationError("Refusing to remove an unowned inspection container")
        run_bounded(["docker", "rm", container])
        report["owned_resources_removed"] = True
    report["scans"] = scan_component(component_sbom(identity, image_id), work)
    report["passed"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="Existing local image reference; never pulled or started"
    )
    parser.add_argument(
        "--recipe", type=Path, default=Path(__file__).resolve().parents[1] / "backend/ffmpeg-build"
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        help="New private directory for evidence; must not exist",
    )
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        "passed": False,
        "owned_resources_removed": False,
        "image_execution": False,
        "explicit_native_inventory": True,
        "not_signed_image_provenance": True,
    }
    try:
        qualify(args.image, args.recipe, args.work_dir, report)
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = (
            str(error)
            if isinstance(error, QualificationError)
            else "Native qualification could not complete"
        )
    (args.work_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] and report["owned_resources_removed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
