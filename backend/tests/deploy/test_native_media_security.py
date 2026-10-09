"""Native media security coverage must reject missing evidence and clean-looking failures."""

import importlib.util
import io
import os
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


@pytest.fixture
def native(monkeypatch):
    path = Path(__file__).resolve().parents[3] / "scripts/check_native_media_security.py"
    spec = importlib.util.spec_from_file_location("native_media_security_test", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def tar_payload(name="source-lock.json", data=b"{}", kind=tarfile.REGTYPE):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.size = len(data) if kind == tarfile.REGTYPE else 0
        member.linkname = "/outside"
        archive.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


@pytest.mark.parametrize(
    "name,kind,maximum",
    [
        ("../source-lock.json", tarfile.REGTYPE, 100),
        ("/source-lock.json", tarfile.REGTYPE, 100),
        ("other.json", tarfile.REGTYPE, 100),
        ("source-lock.json", tarfile.SYMTYPE, 100),
        ("source-lock.json", tarfile.LNKTYPE, 100),
        ("source-lock.json", tarfile.REGTYPE, 1),
    ],
)
def test_tar_traversal_links_and_oversize_are_rejected(native, name, kind, maximum):
    with pytest.raises(native.QualificationError):
        native.unpack_regular_file(tar_payload(name, kind=kind), "source-lock.json", maximum)


def test_regular_file_can_be_read_without_filesystem_extraction(native, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert native.unpack_regular_file(tar_payload(), "source-lock.json", 100) == b"{}"
    assert not list(tmp_path.iterdir())


def manifest():
    paths = ["usr/local/bin/" + x for x in ["ffmpeg", "ffprobe", "ffplay", "qt-faststart"]]
    paths += [
        "usr/local/lib/" + x + ".so.1.2.3"
        for x in [
            "libavcodec",
            "libavdevice",
            "libavfilter",
            "libavformat",
            "libavutil",
            "libswresample",
            "libswscale",
        ]
    ]
    return ("\n".join("a" * 64 + "  " + p for p in paths) + "\n").encode()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.replace(b"usr/local/bin/ffmpeg", b"usr/local/bin/../../etc/passwd"),
        lambda s: s.replace(b"usr/local/bin/ffmpeg", b"usr/local/bin/unexpected"),
        lambda s: b"\n".join(s.splitlines()[:-1]),
        lambda s: s + s.splitlines()[0] + b"\n",
        lambda s: s.replace(b"libswscale", b"libswunknown"),
        lambda s: s.replace(b"a" * 64, b"not-a-hash", 1),
    ],
)
def test_incomplete_or_unsafe_runtime_inventory_blocks(native, mutation):
    with pytest.raises(native.QualificationError):
        native.runtime_files(mutation(manifest()))


def test_complete_runtime_inventory_includes_every_binary_and_library(native):
    assert len(native.runtime_files(manifest())) == 11


def valid_scan():
    return {
        "matches": [],
        "ignoredMatches": [],
        "descriptor": {
            "name": "grype",
            "version": "0.119.0",
            "configuration": {"match": {"stock": {"using-cpes": True}}, "ignore": []},
            "db": {"status": {"valid": True, "built": datetime.now(UTC).isoformat()}},
        },
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("matches"),
        lambda d: d.update(matches=None),
        lambda d: d.update(matches=[None]),
        lambda d: d.update(ignoredMatches=[{"reason": "suppressed"}]),
        lambda d: d["descriptor"].update(name="unexpected"),
        lambda d: d["descriptor"]["configuration"]["match"]["stock"].update({"using-cpes": False}),
        lambda d: d["descriptor"]["configuration"]["match"]["stock"].update({"using-cpes": "true"}),
        lambda d: d["descriptor"]["configuration"].update(ignore=[{"vulnerability": "hidden"}]),
        lambda d: d["descriptor"]["configuration"].update({"only-fixed": True}),
        lambda d: d["descriptor"]["db"]["status"].update(valid=False),
        lambda d: d["descriptor"]["db"]["status"].update(built="invalid"),
        lambda d: d["descriptor"]["db"]["status"].update(
            built=(datetime.now(UTC) - timedelta(days=2)).isoformat()
        ),
        lambda d: d["descriptor"]["db"]["status"].update(
            built=(datetime.now(UTC) + timedelta(days=2)).isoformat()
        ),
    ],
)
def test_clean_looking_incomplete_or_suppressed_scan_never_passes(native, mutate):
    data = valid_scan()
    mutate(data)
    with pytest.raises(native.QualificationError):
        native.validate_scan(data, control=False)


def test_empty_positive_control_does_not_prove_scanner_coverage(native):
    with pytest.raises(native.QualificationError, match="control"):
        native.validate_scan(valid_scan(), control=True)


def test_known_vulnerable_control_and_clean_real_result_have_distinct_rules(native):
    control = valid_scan()
    control["matches"] = [
        {"artifact": {"name": "ffmpeg", "version": "4.0"}, "vulnerability": {"id": "CONTROL-CVE"}}
    ]
    assert native.validate_scan(control, control=True) == 1
    with pytest.raises(native.QualificationError, match="vulnerability"):
        native.validate_scan(control, control=False)
    assert native.validate_scan(valid_scan(), control=False) == 0


def test_bounded_command_rejects_excessive_output(native):
    with pytest.raises(native.QualificationError, match="limit"):
        native.run_bounded([sys.executable, "-c", "print('x' * 1000000)"], limit=1024)


def test_bounded_command_reaps_its_timed_out_child(native, tmp_path):
    pid_file = tmp_path / "pid"
    program = "from pathlib import Path;import os,sys,time;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(20)"
    with pytest.raises(native.QualificationError, match="timed out"):
        native.run_bounded([sys.executable, "-c", program, str(pid_file)], timeout=1)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_nonzero_command_cannot_return_clean_looking_json(native):
    with pytest.raises(native.QualificationError, match="failed"):
        native.run_bounded([sys.executable, "-c", "print('{}');raise SystemExit(7)"])


@pytest.fixture
def docker_fixture(native, monkeypatch):
    calls = []
    image = "sha256:" + "a" * 64
    container = "b" * 64
    state = {"owner": None, "removed": False}
    monkeypatch.setattr(native.shutil, "which", lambda name: "/tools/" + name)

    def run(args, **kwargs):
        calls.append(args)
        assert args[0] == "docker"
        if args[1] == "create":
            state["owner"] = args[args.index("--name") + 1]
            return (container + "\n").encode()
        if args[1] == "rm":
            assert args[2] == container
            state["removed"] = True
            return container.encode()
        raise AssertionError(args)

    def inspect(*args):
        if args[:2] == ("image", "inspect"):
            return [{"Id": image, "Config": {"Volumes": {"/config": {}}}}]
        assert args == ("inspect", container)
        return [
            {
                "Config": {"Labels": {"freesdn.qualification": state["owner"]}},
                "State": {"Running": False},
                "HostConfig": {"NetworkMode": "none", "PortBindings": {}},
                "Mounts": [{"Type": "tmpfs"}],
            }
        ]

    monkeypatch.setattr(native, "run_bounded", run)
    monkeypatch.setattr(native, "docker_json", inspect)
    return calls, state, image


def test_failed_payload_inspection_removes_only_owned_unstarted_container(
    native, monkeypatch, docker_fixture, tmp_path
):
    calls, state, image = docker_fixture

    def fail(*args):
        raise native.QualificationError("incomplete payload")

    monkeypatch.setattr(native, "inspect_payload", fail)
    report = {"passed": False, "owned_resources_removed": False}
    with pytest.raises(native.QualificationError, match="payload"):
        native.qualify("mutable:tag", tmp_path, tmp_path, report)
    assert state["removed"] and report["owned_resources_removed"] and not report["passed"]
    create = calls[0]
    assert create[-1] == image and "--pull=never" in create
    assert create[create.index("--network") + 1] == "none"
    assert create[create.index("--tmpfs") + 1].startswith("/config:")
    assert all(call[1] not in {"start", "run", "pull", "volume"} for call in calls)


def test_unowned_container_is_never_deleted(native, monkeypatch, docker_fixture, tmp_path):
    calls, state, _ = docker_fixture
    original = native.docker_json

    def inspect(*args):
        value = original(*args)
        if args[0] == "inspect":
            value[0]["Config"]["Labels"]["freesdn.qualification"] = "other-owner"
        return value

    monkeypatch.setattr(native, "docker_json", inspect)
    report = {"passed": False, "owned_resources_removed": False}
    with pytest.raises(native.QualificationError, match="unowned"):
        native.qualify("mutable:tag", tmp_path, tmp_path, report)
    assert not state["removed"] and not report["owned_resources_removed"]
    assert not any(call[1] == "rm" for call in calls)


@pytest.mark.parametrize("field", ["descriptor", "configuration", "match", "stock", "db"])
def test_malformed_scanner_metadata_is_refused(native, field):
    value = valid_scan()
    if field == "descriptor":
        value[field] = None
    elif field in {"configuration", "db"}:
        value["descriptor"][field] = None
    elif field == "match":
        value["descriptor"]["configuration"][field] = None
    else:
        value["descriptor"]["configuration"]["match"][field] = None
    with pytest.raises(native.QualificationError):
        native.validate_scan(value, control=False)


@pytest.fixture
def payload_fixture(native, monkeypatch, tmp_path):
    import hashlib
    import json

    recipe = tmp_path / "recipe"
    recipe.mkdir()
    archive = b"synthetic upstream source material for hash-validation tests"
    lock = {
        "version": "9.0.2",
        "source_url": "https://ffmpeg.org/releases/ffmpeg-9.0.2.tar.xz",
        "source_sha256": hashlib.sha256(archive).hexdigest(),
    }
    files = {}
    prefix = "/usr/share/freesdn-sources/ffmpeg/"
    for name in [*native.RECIPE_FILES, "ffmpeg-9.0.2.tar.xz.asc"]:
        data = (
            json.dumps(lock).encode()
            if name == "source-lock.json"
            else ("recipe-fixture:" + name).encode()
        )
        (recipe / name).write_bytes(data)
        files[prefix + name] = data
    files[prefix + "ffmpeg-9.0.2.tar.xz"] = archive
    paths = native.runtime_files(manifest())
    hashes = []
    for path in paths:
        data = ("binary-fixture:" + path).encode()
        files["/" + path] = data
        hashes.append(hashlib.sha256(data).hexdigest() + "  " + path)
    files[prefix + "runtime-files.sha256"] = ("\n".join(hashes) + "\n").encode()

    def read(_container, path, maximum=1024 * 1024):
        if path not in files:
            raise native.QualificationError("Image file missing")
        assert len(files[path]) <= maximum
        return files[path]

    monkeypatch.setattr(native, "image_file", read)
    return recipe, files, prefix


def test_identity_covers_source_pin_all_runtime_files_and_checked_out_recipe(
    native, payload_fixture
):
    recipe, _, _ = payload_fixture
    identity = native.inspect_payload("owned", recipe)
    assert identity["version"] == "9.0.2" and len(identity["runtime_files"]) == 11
    assert set(identity["recipe_hashes"]) == {*native.RECIPE_FILES, "ffmpeg-9.0.2.tar.xz.asc"}


@pytest.mark.parametrize(
    "relative",
    [
        "source-lock.json",
        "package.sh",
        "ffmpeg-9.0.2.tar.xz",
        "ffmpeg-9.0.2.tar.xz.asc",
        "/usr/local/bin/ffmpeg",
        "/usr/local/lib/libavcodec.so.1.2.3",
    ],
)
def test_wrong_recipe_source_or_runtime_hash_cannot_be_qualified(native, payload_fixture, relative):
    recipe, files, prefix = payload_fixture
    files[relative if relative.startswith("/") else prefix + relative] = b"tampered"
    with pytest.raises(native.QualificationError):
        native.inspect_payload("owned", recipe)


@pytest.fixture
def image_audit(monkeypatch):
    import subprocess

    path = Path(__file__).resolve().parents[3] / "scripts/security-audit.py"
    spec = importlib.util.spec_from_file_location("native_image_audit_test", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "DOCKER_IMAGES", ["native:tag"])
    monkeypatch.setattr(module, "NATIVE_MEDIA_IMAGES", {"native:tag"})
    monkeypatch.setattr(module, "tool_available", lambda _: True)
    image = "sha256:" + "c" * 64
    report = {
        "passed": True,
        "image_id": image,
        "owned_resources_removed": True,
        "image_execution": False,
        "explicit_native_inventory": True,
        "scans": {"control": {"matches": 60}, "native": {"matches": 0}},
    }
    return module, image, report, subprocess


def test_native_audit_uses_exact_trivy_image_identity(image_audit, monkeypatch):
    import json

    audit, image, report, subprocess = image_audit
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0] == "trivy":
            payload = {"Metadata": {"ImageID": image}, "Results": [{"Vulnerabilities": []}]}
        else:
            assert args[args.index("--image") + 1] == image
            assert "native:tag" not in args
            payload = report
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")

    monkeypatch.setattr(audit, "run_cmd", run)
    assert audit.scan_docker_images().passed
    assert len(calls) == 2


@pytest.mark.parametrize(
    "mutate,exit_code",
    [
        (lambda r: r.update(passed=False), 0),
        (lambda r: r.update(owned_resources_removed=False), 0),
        (lambda r: r.update(image_execution=True), 0),
        (lambda r: r.update(image_id="sha256:" + "d" * 64), 0),
        (lambda r: r.pop("scans"), 0),
        (lambda r: r["scans"]["control"].update(matches=0), 0),
        (lambda r: r["scans"]["control"].update(matches=True), 0),
        (lambda r: r["scans"]["native"].update(matches=False), 0),
        (lambda r: r["scans"].update(native=None), 0),
        (lambda _r: None, 7),
    ],
)
def test_clean_package_scan_cannot_mask_incomplete_native_scan(
    image_audit, monkeypatch, mutate, exit_code
):
    import json

    audit, image, report, subprocess = image_audit
    mutate(report)

    def run(args, **kwargs):
        payload = (
            {"Metadata": {"ImageID": image}, "Results": [{}]} if args[0] == "trivy" else report
        )
        return subprocess.CompletedProcess(
            args, 0 if args[0] == "trivy" else exit_code, json.dumps(payload), ""
        )

    monkeypatch.setattr(audit, "run_cmd", run)
    result = audit.scan_docker_images()
    assert not result.passed and "scan errors" in result.summary


def test_missing_trivy_image_identity_refuses_native_scan(image_audit, monkeypatch):
    import json

    audit, _, _, subprocess = image_audit
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps({"Results": [{}]}), "")

    monkeypatch.setattr(audit, "run_cmd", run)
    assert not audit.scan_docker_images().passed
    assert len(calls) == 1
